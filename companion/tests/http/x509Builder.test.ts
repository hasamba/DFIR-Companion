import { describe, expect, it } from "vitest";
import { X509Certificate, createPublicKey, generateKeyPairSync } from "node:crypto";
import { buildCertificatePem, ipBytes } from "../../src/http/x509Builder.js";

const DAY = 86_400_000;

function rsa() {
  return generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
}

describe("buildCertificatePem (#2285)", () => {
  const caKey = rsa();
  const caPub = createPublicKey(caKey);
  const now = new Date("2026-11-04T10:00:00Z");
  const caPem = buildCertificatePem({
    subjectCommonName: "DFIR Companion Local CA test",
    issuerCommonName: "DFIR Companion Local CA test",
    publicKey: caPub,
    signingKey: caKey,
    issuerPublicKey: caPub,
    notBefore: now,
    notAfter: new Date(now.getTime() + 3650 * DAY),
    isCa: true,
  });

  it("produces a self-signed CA certificate Node parses and verifies", () => {
    const ca = new X509Certificate(caPem);
    expect(ca.ca).toBe(true);
    expect(ca.verify(caPub)).toBe(true);
    expect(ca.checkPrivateKey(caKey)).toBe(true);
    expect(ca.subject).toContain("CN=DFIR Companion Local CA test");
    expect(new Date(ca.validTo).getUTCFullYear()).toBe(2036);
  });

  it("issues a server certificate that chains to the CA and carries the SANs", () => {
    const leafKey = rsa();
    const leafPem = buildCertificatePem({
      subjectCommonName: "server",
      issuerCommonName: "DFIR Companion Local CA test",
      publicKey: createPublicKey(leafKey),
      signingKey: caKey,
      issuerPublicKey: caPub,
      notBefore: now,
      notAfter: new Date(now.getTime() + 825 * DAY),
      isCa: false,
      dnsNames: ["localhost", "dfir.example.test"],
      ipAddresses: ["127.0.0.1", "::1", "fd00::5"],
    });
    const leaf = new X509Certificate(leafPem);
    const ca = new X509Certificate(caPem);
    expect(leaf.ca).toBe(false);
    expect(leaf.verify(caPub)).toBe(true);
    expect(leaf.checkIssued(ca)).toBe(true);
    expect(leaf.checkHost("dfir.example.test")).toBe("dfir.example.test");
    expect(leaf.checkIP("127.0.0.1")).toBe("127.0.0.1");
    expect(leaf.checkIP("::1")).toBe("::1");
    expect(leaf.checkIP("fd00::5")).toBe("fd00::5");
    expect(leaf.keyUsage).toContain("1.3.6.1.5.5.7.3.1");
  });

  it("switches to GeneralizedTime from 2050", () => {
    const pem = buildCertificatePem({
      subjectCommonName: "late",
      issuerCommonName: "late",
      publicKey: caPub,
      signingKey: caKey,
      issuerPublicKey: caPub,
      notBefore: now,
      notAfter: new Date("2051-01-02T03:04:05Z"),
      isCa: true,
    });
    expect(new Date(new X509Certificate(pem).validTo).toISOString()).toBe("2051-01-02T03:04:05.000Z");
  });
});

describe("ipBytes", () => {
  it("encodes IPv4 and compressed IPv6", () => {
    expect([...ipBytes("10.1.2.3")]).toEqual([10, 1, 2, 3]);
    expect(ipBytes("::1").toString("hex")).toBe("00000000000000000000000000000001");
    expect(ipBytes("fe80::1:2").toString("hex")).toBe("fe800000000000000000000000010002");
    expect(ipBytes("2001:db8:0:0:0:0:0:1").toString("hex")).toBe("20010db8000000000000000000000001");
  });
});
