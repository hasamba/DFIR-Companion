import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createHash, X509Certificate } from "node:crypto";
import { readDerFacts, rdnSetDiffers } from "../../src/analysis/tlsDerRead.js";
import { readSuricataCertificates } from "../../src/analysis/tlsSession.js";
import { addTls, emptyTlsObservations } from "../../src/analysis/tlsGraphJoin.js";
import { tlsFamilies } from "../../src/analysis/tlsGraphRows.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";

// #997: chain members decoded from their DER bytes — subject, issuer, serial, names, validity —
// instead of carrying a sha256 and nothing else. Node's own X.509 reader; no new dependency.

const FIX = join(__dirname, "..", "fixtures", "tls");
const leafPem = readFileSync(join(FIX, "fixture-leaf.pem"));
const caPem = readFileSync(join(FIX, "fixture-ca.pem"));
const leafDer = new X509Certificate(leafPem).raw;
const caDer = new X509Certificate(caPem).raw;
const b64 = (b: Buffer) => b.toString("base64");
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

describe("readDerFacts", () => {
  it("decodes subject, issuer, serial, names, validity and the CA bit from DER", () => {
    const f = readDerFacts(leafDer)!;
    expect(f.decoded).toBe("der");
    expect(f.subject).toBe("C=US, O=Fixture Org, CN=fixture.example.invalid");
    expect(f.issuer).toBe("C=US, O=Fixture Org, CN=fixture.example.invalid");
    expect(f.serial).toMatch(/^[0-9a-f]+$/);
    // Every SAN value in certificate order; tlsSession.ts picks the DNS names by its own rule.
    expect(f.sanNames).toEqual(["fixture.example.invalid", "*.fixture.example.invalid", "203.0.113.7"]);
    expect(f.notBefore).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(Date.parse(f.notAfter!)).toBeGreaterThan(Date.parse(f.notBefore!));
    expect(f.ca).toBe(false);
    expect(readDerFacts(caDer)!.ca).toBe(true);
  });

  it("garbage, empty bytes and a truncated certificate decode to nothing", () => {
    expect(readDerFacts(Buffer.from("not a certificate"))).toBeUndefined();
    expect(readDerFacts(Buffer.alloc(0))).toBeUndefined();
    expect(readDerFacts(leafDer.subarray(0, 200))).toBeUndefined();
  });

  it("an RDN comparison is a set comparison: order and separators do not make a difference; a component does", () => {
    expect(rdnSetDiffers("CN=a, O=b, C=US", "C=US\nO=b\nCN=a")).toBe(false);
    expect(rdnSetDiffers("CN=a,O=b,C=US", "C=US, O=b, CN=a")).toBe(false);
    expect(rdnSetDiffers("CN=a, O=b", "CN=a, O=c")).toBe(true);
    expect(rdnSetDiffers("CN=a", "CN=a, O=b")).toBe(true);
  });
});

describe("a Suricata chain with decodable members", () => {
  const row = {
    timestamp: "2026-01-01T00:00:00Z",
    flow_id: 1,
    src_ip: "10.0.0.5",
    dest_ip: "203.0.113.9",
    dest_port: 443,
    tls: {
      sni: "fixture.example.invalid",
      subject: "C=US, O=Fixture Org, CN=fixture.example.invalid",
      issuerdn: "C=US, O=Fixture Org, CN=fixture.example.invalid",
      chain: [b64(leafDer), b64(caDer)],
    },
  };

  it("every chain member carries its decoded facts; the leaf keeps the record's own and says they agree", () => {
    const certs = readSuricataCertificates(row, "");
    expect(certs).toHaveLength(2);
    const leaf = certs.find((c) => c.cert?.value === sha(leafDer))!;
    const ca = certs.find((c) => c.cert?.value === sha(caDer))!;
    expect(leaf.certificate?.subject).toBe("C=US, O=Fixture Org, CN=fixture.example.invalid");
    expect(leaf.certificate?.decoded).toBe("der");
    expect(leaf.certificate?.decodedDiffers).toBeUndefined();
    expect(leaf.certificate?.dnsNames).toEqual(["fixture.example.invalid", "*.fixture.example.invalid"]);
    expect(ca.certificate?.subject).toBe("C=US, O=Fixture Org, CN=Fixture Root CA");
    expect(ca.certificate?.ca).toBe(true);
    expect(ca.certificate?.decoded).toBe("der");
  });

  it("a leaf whose stated subject disagrees with its bytes says so — a state, never a pick", () => {
    const bad = { ...row, tls: { ...row.tls, subject: "CN=something-else.invalid" } };
    const leaf = readSuricataCertificates(bad, "").find((c) => c.cert?.value === sha(leafDer))!;
    // The record's own stated subject is kept as stated; the difference is a fact beside it.
    expect(leaf.certificate?.subject).toBe("CN=something-else.invalid");
    expect(leaf.certificate?.decodedDiffers).toEqual(["subject"]);
  });

  it("the words and the envelope carry the decoding", () => {
    const s = emptyTlsObservations();
    for (const c of readSuricataCertificates(row, "")) addTls(s, c);
    const [rows] = tlsFamilies(s, 100);
    const caRow = rows.find((r) => r.description.includes("Fixture Root CA"))!;
    expect(caRow.description).toContain("decoded from the DER");
    expect(caRow.description).toContain("subject C=US, O=Fixture Org, CN=Fixture Root CA");
    expect(canonicalEventEnvelopeSchema.safeParse(caRow.canonical).success).toBe(true);
    expect(caRow.canonical?.tls?.certificate?.decoded).toBe("der");
    const bad = { ...row, tls: { ...row.tls, subject: "CN=something-else.invalid" } };
    const s2 = emptyTlsObservations();
    for (const c of readSuricataCertificates(bad, "")) addTls(s2, c);
    const leafRow = tlsFamilies(s2, 100)[0].find((r) => r.description.includes("something-else"))!;
    expect(leafRow.description).toContain("record subject differs from the DER's");
    expect(leafRow.canonical?.tls?.certificate?.decodedDiffers).toEqual(["subject"]);
  });

  it("an unreadable chain entry still carries its sha256 and nothing else", () => {
    const junk = {
      ...row,
      tls: { ...row.tls, chain: [b64(leafDer), Buffer.from("junk-der").toString("base64")] },
    };
    const certs = readSuricataCertificates(junk, "");
    const j = certs.find((c) => c.cert?.value === sha(Buffer.from("junk-der")))!;
    expect(j.certificate).toEqual({});
  });
});
