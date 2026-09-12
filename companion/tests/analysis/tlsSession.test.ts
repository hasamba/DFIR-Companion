import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  readZeekSsl,
  readZeekX509,
  readSuricataTls,
  readSuricataCertificates,
  certIdentity,
  tallyTls,
  mapTlsRows,
  TLS_SHAPES_MAX,
  type TlsObservation,
} from "../../src/analysis/tlsSession.js";
import { parseNetworkLogs } from "../../src/analysis/networkImport.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { SiemEvent } from "../../src/analysis/siemImport.js";

// #933 item 6, prerequisite phase: a TLS record says what it establishes.

const ZEEK_SSL = {
  ts: 1700000000.5,
  uid: "CAbc1",
  "id.orig_h": "10.0.0.5",
  "id.orig_p": 51234,
  "id.resp_h": "203.0.113.9",
  "id.resp_p": 443,
  version: "TLSv13",
  cipher: "TLS_AES_256_GCM_SHA384",
  server_name: "cdn.example.net",
  resumed: false,
  established: true,
  validation_status: "ok",
  subject: "CN=cdn.example.net",
  issuer: "CN=R3,O=Let's Encrypt,C=US",
  cert_chain_fuids: ["FaBc1", "FaBc2"],
  ja3: "e7d705a3286e19ea42f587b344ee6865",
  ja3s: "eb1d94daa7e0344597e756a1fb6e7054",
};

const ZEEK_X509 = {
  ts: 1700000000.5,
  id: "FaBc1",
  "certificate.version": 3,
  "certificate.serial": "03A1B2C3",
  "certificate.subject": "CN=cdn.example.net",
  "certificate.issuer": "CN=R3,O=Let's Encrypt,C=US",
  "certificate.not_valid_before": 1699000000,
  "certificate.not_valid_after": 1706000000,
  "certificate.key_alg": "rsaEncryption",
  "certificate.sig_alg": "sha256WithRSAEncryption",
  "certificate.key_type": "rsa",
  "certificate.key_length": 2048,
  "san.dns": ["cdn.example.net", "www.example.net", "static.example.net"],
  "basic_constraints.ca": false,
};

const SURICATA_TLS = {
  timestamp: "2023-11-14T22:13:20.500000+0000",
  flow_id: 1,
  event_type: "tls",
  src_ip: "10.0.0.5",
  src_port: 51234,
  dest_ip: "203.0.113.9",
  dest_port: 443,
  tls: {
    subject: "CN=cdn.example.net",
    issuerdn: "CN=R3, O=Let's Encrypt, C=US",
    serial: "03:A1:B2:C3",
    fingerprint: "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01",
    sni: "cdn.example.net",
    version: "TLS 1.3",
    notbefore: "2023-11-03T09:46:40",
    notafter: "2024-01-23T10:13:20",
    ja3: { hash: "e7d705a3286e19ea42f587b344ee6865", string: "771,4865-4866,..." },
    ja3s: { hash: "eb1d94daa7e0344597e756a1fb6e7054" },
  },
};

const rows = (obs: TlsObservation[]) => {
  const tally = new Map();
  for (const o of obs) tallyTls(o, tally);
  return mapTlsRows(tally, 2000);
};

describe("readZeekSsl — every field the record carries, absent apart from empty", () => {
  it("reads the ssl.log spellings", () => {
    const o = readZeekSsl(ZEEK_SSL, "");
    expect(o).toMatchObject({
      source: "zeek-ssl",
      src: "10.0.0.5",
      dst: "203.0.113.9",
      port: 443,
      sni: "cdn.example.net",
      version: "TLSv13",
      cipher: "TLS_AES_256_GCM_SHA384",
      established: true,
      resumed: false,
      validation: "ok",
      subject: "CN=cdn.example.net",
      issuer: "CN=R3,O=Let's Encrypt,C=US",
      ja3: "e7d705a3286e19ea42f587b344ee6865",
      ja3s: "eb1d94daa7e0344597e756a1fb6e7054",
      certChainFuids: ["FaBc1", "FaBc2"],
      uid: "CAbc1",
      timestamp: "2023-11-14T22:13:20.500Z",
    });
    // no serial and no fingerprint: no certificate identity
    expect(o.cert).toBeUndefined();
  });
  it("an absent field is undefined; an empty string is its own value", () => {
    const { server_name: _s, validation_status: _v, ...noSni } = ZEEK_SSL;
    const o = readZeekSsl({ ...noSni, cipher: "" }, "");
    expect(o.sni).toBeUndefined();
    expect(o.validation).toBeUndefined();
    expect(o.cipher).toBe("");
  });
  it("reads the observer from observer.name, then observer.hostname, then host.name, and says which", () => {
    expect(
      readZeekSsl({ ...ZEEK_SSL, observer: { name: "sensor-a" }, host: { name: "shipper" } }, "").observer,
    ).toEqual({
      name: "sensor-a",
      sourceField: "observer.name",
    });
    expect(readZeekSsl({ ...ZEEK_SSL, observer: { hostname: "sensor-b" } }, "").observer).toEqual({
      name: "sensor-b",
      sourceField: "observer.hostname",
    });
    expect(readZeekSsl({ ...ZEEK_SSL, host: { name: "shipper" } }, "").observer).toEqual({
      name: "shipper",
      sourceField: "host.name",
    });
    expect(readZeekSsl(ZEEK_SSL, "").observer).toBeUndefined();
  });
  it("Zeek 6 cert_chain_fps is a fingerprint", () => {
    const o = readZeekSsl(
      { ...ZEEK_SSL, cert_chain_fps: ["AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01"] },
      "",
    );
    expect(o.cert).toEqual({
      kind: "fingerprint",
      value: "abcdef0123456789abcdef0123456789abcdef01",
      alg: "sha1",
    });
  });
});

describe("readZeekX509 — a certificate's identity is issuer + serial, else a fingerprint", () => {
  it("reads the x509.log spellings and mints certid-v1 from issuer and serial only", () => {
    const o = readZeekX509(ZEEK_X509, "");
    expect(o.source).toBe("zeek-x509");
    expect(o.cert).toEqual({
      kind: "identity",
      value: certIdentity("CN=R3,O=Let's Encrypt,C=US", "03A1B2C3"),
    });
    expect(o.certificate).toMatchObject({
      subject: "CN=cdn.example.net",
      issuer: "CN=R3,O=Let's Encrypt,C=US",
      serial: "03a1b2c3",
      names: ["cdn.example.net", "www.example.net", "static.example.net"],
      notBefore: "2023-11-03T08:26:40.000Z",
      notAfter: "2024-01-23T08:53:20.000Z",
      ca: false,
    });
    expect(o.locatorId).toBe("FaBc1");
  });
  it("certid-v1 is stable across schema variants and serial spellings", () => {
    const a = certIdentity("CN=R3,O=Let's Encrypt,C=US", "03A1B2C3");
    expect(a).toBe(certIdentity("CN=R3,O=Let's Encrypt,C=US", "03:a1:b2:c3"));
    expect(a).toBe(certIdentity("CN=R3,O=Let's Encrypt,C=US", "0003a1b2c3"));
    expect(a).toBe(certIdentity(" CN=R3,O=Let's Encrypt,C=US ", "3a1b2c3"));
    expect(a).not.toBe(certIdentity("CN=R3,O=Let's Encrypt,C=US", "03a1b2c4"));
    expect(a).toMatch(/^certid-v1:[0-9a-f]{32}$/);
    const { "basic_constraints.ca": _c, "san.dns": _s, ...bare } = ZEEK_X509;
    expect(readZeekX509(bare, "").cert).toEqual(readZeekX509(ZEEK_X509, "").cert);
  });
  it("a fingerprint, when the build writes one, is the identity", () => {
    const o = readZeekX509(
      { ...ZEEK_X509, fingerprint: "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01" },
      "",
    );
    expect(o.cert).toEqual({
      kind: "fingerprint",
      value: "abcdef0123456789abcdef0123456789abcdef01",
      alg: "sha1",
    });
  });
});

describe("readSuricataTls — the nested tls object, every spelling", () => {
  it("reads sni, subject, issuerdn, serial, fingerprint, validity, ja3/ja3s objects", () => {
    const o = readSuricataTls(SURICATA_TLS, "");
    expect(o).toMatchObject({
      source: "suricata-tls",
      src: "10.0.0.5",
      dst: "203.0.113.9",
      port: 443,
      sni: "cdn.example.net",
      version: "TLS 1.3",
      subject: "CN=cdn.example.net",
      issuer: "CN=R3, O=Let's Encrypt, C=US",
      ja3: "e7d705a3286e19ea42f587b344ee6865",
      ja3s: "eb1d94daa7e0344597e756a1fb6e7054",
      cert: { kind: "fingerprint", value: "abcdef0123456789abcdef0123456789abcdef01", alg: "sha1" },
    });
    expect(o.established).toBeUndefined(); // Suricata has no such field
    expect(o.resumed).toBeUndefined();
    expect(o.certificate?.serial).toBe("03a1b2c3");
    expect(o.certificate?.notBefore).toBe("2023-11-03T09:46:40Z");
  });
  it("session_resumed, issuer alias, string ja3, and a DER leaf's sha256", () => {
    const der = Buffer.from("not really a certificate, but bytes");
    const o = readSuricataTls(
      {
        ...SURICATA_TLS,
        tls: {
          sni: "a.example",
          session_resumed: true,
          issuer: "CN=X",
          ja3: "e7d705a3286e19ea42f587b344ee6865",
          certificate: der.toString("base64"),
          subjectaltname: ["a.example", "b.example"],
        },
      },
      "",
    );
    expect(o.resumed).toBe(true);
    expect(o.issuer).toBe("CN=X");
    expect(o.ja3).toBe("e7d705a3286e19ea42f587b344ee6865");
    expect(o.cert).toEqual({
      kind: "fingerprint",
      value: createHash("sha256").update(der).digest("hex"),
      alg: "sha256",
    });
    expect(o.certificate?.names).toEqual(["a.example", "b.example"]);
  });
  it("serial + issuerdn without a fingerprint is a cert identity; subject alone is none", () => {
    const withSerial = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", issuerdn: "CN=X", serial: "01" } },
      "",
    );
    expect(withSerial.cert).toEqual({ kind: "identity", value: certIdentity("CN=X", "01") });
    const noSerial = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", subject: "CN=a", issuerdn: "CN=X" } },
      "",
    );
    expect(noSerial.cert).toBeUndefined();
  });
});

describe("TLS rows — one per shape, every shown fact keyed", () => {
  const base = (): TlsObservation => readZeekSsl(ZEEK_SSL, "");

  it("folds records of one shape and counts them; the row says what one record says", () => {
    const r = rows([base(), { ...base(), timestamp: "2023-11-14T22:14:00.000Z", uid: "CAbc2" }]);
    expect(r).toHaveLength(1);
    const e = r[0];
    expect(e.description).toContain("TLS 10.0.0.5 → 203.0.113.9:443");
    expect(e.description).toContain("[sni: cdn.example.net]");
    expect(e.description).toContain("[TLSv13, cipher TLS_AES_256_GCM_SHA384]");
    expect(e.description).toContain(
      "[cert: subject CN=cdn.example.net; issuer CN=R3,O=Let's Encrypt,C=US; identity unavailable]",
    );
    expect(e.description).toContain("[chain check: ok]");
    expect(e.description).toContain("[ja3 e7d705a3…6865] [ja3s eb1d94da…7054]");
    expect(e.description).toContain("— 2 TLS records");
    expect(e.description).not.toMatch(/[0-9a-f]{32}/i);
    expect(e.description).not.toContain("handshake");
    expect(e.severity).toBe("Info");
    expect(e.mitre).toEqual([]);
    expect(e.asset).toBeUndefined();
    expect(e.srcIp).toBe("10.0.0.5");
    expect(e.dstIp).toBe("203.0.113.9");
    expect(e.canonical?.tls).toMatchObject({
      sni: "cdn.example.net",
      established: true,
      validation: "ok",
      ja3: "e7d705a3286e19ea42f587b344ee6865",
      certificate: { subject: "CN=cdn.example.net", identity: "unavailable" },
      locator: { uid: "CAbc1", certChainFuids: ["FaBc1", "FaBc2"] },
      records: 2,
    });
  });

  it("each keyed fact separates rows", () => {
    const variants: Array<Partial<TlsObservation>> = [
      { version: "TLSv12" },
      { cipher: "TLS_AES_128_GCM_SHA256" },
      { curve: "secp256r1" },
      { established: false },
      { resumed: true },
      { validation: "self signed certificate" },
      { ja3: "00000000000000000000000000000000" },
      { ja3s: undefined },
      { sni: undefined },
      { subject: "CN=other.example" },
      { cert: { kind: "fingerprint", value: "ab".repeat(20), alg: "sha1" } },
      { observer: { name: "sensor-b", sourceField: "observer.name" } },
      { sniMatchesCert: false },
      { dst: "203.0.113.10" },
      { port: 8443 },
    ];
    for (const v of variants) {
      const r = rows([base(), { ...base(), ...v }]);
      expect(r, JSON.stringify(v)).toHaveLength(2);
    }
  });

  it("two observers within one import stay two rows; the observer is in the envelope, never the asset", () => {
    const a = { ...base(), observer: { name: "sensor-a", sourceField: "observer.name" as const } };
    const b = { ...base(), observer: { name: "sensor-b", sourceField: "observer.name" as const } };
    const r = rows([a, b, a]);
    expect(r).toHaveLength(2);
    expect(r.every((e) => e.asset === undefined)).toBe(true);
    expect(r.find((e) => e.description.includes("2 TLS"))?.canonical?.tls?.observer).toEqual({
      name: "sensor-a",
      sourceField: "observer.name",
    });
  });

  it("says not established, session resumed, and no certificate observed as the record has them", () => {
    const failed = rows([{ ...base(), established: false }])[0];
    expect(failed.description).toContain("[not established]");
    const resumedNoCert = rows([
      {
        ...base(),
        resumed: true,
        subject: undefined,
        issuer: undefined,
        cert: undefined,
        certChainFuids: undefined,
      },
    ])[0];
    expect(resumedNoCert.description).toContain("[session resumed]");
    expect(resumedNoCert.description).toContain("[no server certificate observed in this record]");
    const resumedWithCert = rows([{ ...base(), resumed: true }])[0];
    expect(resumedWithCert.description).toContain("[session resumed]");
    expect(resumedWithCert.description).toContain("[cert: subject");
    const noSni = rows([{ ...base(), sni: undefined }])[0];
    expect(noSni.description).toContain("[no SNI]");
  });

  it("a certificate row per identity, attributes from the first observation, marked lossy", () => {
    const x = readZeekX509(ZEEK_X509, "");
    const { "basic_constraints.ca": _c, ...variant } = ZEEK_X509;
    const y = readZeekX509({ ...variant, id: "FaBc9", "san.dns": ["cdn.example.net"] }, "");
    const r = rows([x, y]);
    expect(r).toHaveLength(1);
    expect(r[0].description).toContain("[certificate: cert identity certid-v");
    expect(r[0].description).toContain("subject CN=cdn.example.net; issuer CN=R3,O=Let's Encrypt,C=US");
    expect(r[0].description).toContain("valid 2023-11-03T08:26:40.000Z–2024-01-23T08:53:20.000Z");
    expect(r[0].description).toContain(
      "covers 3 names: cdn.example.net, www.example.net, static.example.net",
    );
    expect(r[0].description).toContain("— 2 certificate records");
    expect(r[0].description).toMatch(/ #[A-Za-z0-9_-]{22}$/);
    expect(r[0].canonical?.tls?.certificate?.names).toHaveLength(3);
    expect(r[0].canonical?.tls?.locator?.id).toBe("FaBc1");
  });

  it("a long or hostile value is shown neutralised and the row is marked", () => {
    const hostile = rows([
      { ...base(), sni: `${"z".repeat(200)}.example`, subject: "CN=/tmp/payload.exe] [chain check: ok" },
    ])[0];
    expect(hostile.description).not.toMatch(/\[chain check: ok\] \[chain check/);
    expect(hostile.description).toContain("(chain check: ok");
    expect(hostile.description.length).toBeLessThanOrEqual(600);
    expect(hostile.description).toMatch(/ #[A-Za-z0-9_-]{22}$/);
    // two hostile subjects differing past the shown width are two rows with two descriptions
    const a = rows([{ ...base(), subject: `CN=${"q".repeat(300)}1` }])[0];
    const b = rows([{ ...base(), subject: `CN=${"q".repeat(300)}2` }])[0];
    expect(a.aggKey).not.toBe(b.aggKey);
    expect(a.description).not.toBe(b.description);
  });

  it("a chain FUID is an observed certificate; a cert identity is never a bare hex run", () => {
    const fuidOnly = rows([
      { ...base(), subject: undefined, issuer: undefined, cert: undefined, certChainFuids: ["Fleaf"] },
    ])[0];
    expect(fuidOnly.description).not.toContain("no certificate observed");
    expect(fuidOnly.description).toContain("[cert: identity unavailable]");
    const x = rows([readZeekX509(ZEEK_X509, "")])[0];
    expect(x.description).toMatch(/cert identity certid-v1:[0-9a-f]{8}…[0-9a-f]{4}/);
    expect(x.description).not.toMatch(/[0-9a-f]{32}/i);
  });

  it("distinct shapes are bounded during ingestion; the rest fold into one overflow row", () => {
    const tally = new Map();
    for (let i = 0; i < TLS_SHAPES_MAX + 50; i++) tallyTls({ ...base(), subject: `CN=cert-${i}` }, tally);
    expect(tally.size).toBe(TLS_SHAPES_MAX + 1);
    const r = mapTlsRows(tally, 5);
    const over = r.find((e) => e.description.startsWith("[overflow:"))!;
    expect(over.description).toContain(
      "50 TLS records in shapes beyond 8192 distinct ones folded; none shown",
    );
    expect(over.canonical?.tls?.records).toBe(50);
  });

  it("Zeek's SNI-matches-certificate check is a keyed fact, said either way", () => {
    const yes = rows([readZeekSsl({ ...ZEEK_SSL, sni_matches_cert: true }, "")])[0];
    const no = rows([readZeekSsl({ ...ZEEK_SSL, sni_matches_cert: false }, "")])[0];
    expect(yes.description).toContain("[SNI matches the certificate]");
    expect(no.description).toContain("[SNI does not match the certificate]");
    expect(yes.aggKey).not.toBe(no.aggKey);
    expect(rows([base()])[0].description).not.toContain("matches the certificate");
  });

  it("a flattened observer spelling is read too, and keeps two sensors apart", () => {
    const a = readZeekSsl({ ...ZEEK_SSL, "observer.name": "sensor-a" }, "");
    const b = readZeekSsl({ ...ZEEK_SSL, "observer.name": "sensor-b" }, "");
    expect(a.observer).toEqual({ name: "sensor-a", sourceField: "observer.name" });
    expect(rows([a, b])).toHaveLength(2);
  });

  it("a Suricata leaf and chain become one certificate row each, deduplicated, beside the session", () => {
    const leaf = Buffer.from("leaf-bytes").toString("base64");
    const ca = Buffer.from("ca-bytes").toString("base64");
    const rec = { ...SURICATA_TLS, tls: { ...SURICATA_TLS.tls, certificate: leaf, chain: [leaf, ca] } };
    const certs = readSuricataCertificates(rec, "");
    expect(certs).toHaveLength(2);
    expect(certs[0].certificate?.subject).toBe("CN=cdn.example.net");
    expect(certs[1].certificate).toEqual({});
    const r = rows([readSuricataTls(rec, ""), ...certs]);
    expect(r.filter((e) => e.description.startsWith("[certificate:"))).toHaveLength(2);
    expect(r.filter((e) => e.description.startsWith("TLS "))).toHaveLength(1);
  });

  it("keyed facts the words do not show still keep rows apart after import", () => {
    const at = (o: TlsObservation) => ({ ...o, timestamp: "2023-11-14T22:13:20.500Z" });
    const pairs: Array<[TlsObservation, TlsObservation]> = [
      [
        at({ ...base(), observer: { name: "sensor-a", sourceField: "observer.name" } }),
        at({ ...base(), observer: { name: "sensor-b", sourceField: "observer.name" } }),
      ],
      [at({ ...base(), established: true }), at({ ...base(), established: undefined })],
      [at({ ...base(), resumed: false }), at({ ...base(), resumed: undefined })],
    ];
    for (const [a, b] of pairs) {
      const r = rows([a, b]);
      expect(r).toHaveLength(2);
      expect(r[0].description).not.toBe(r[1].description);
    }
  });

  it("a resumed Suricata session with no certificate puts no certificate in the envelope", () => {
    const o = readSuricataTls({ ...SURICATA_TLS, tls: { sni: "a.example", session_resumed: true } }, "");
    expect(o.certificate).toBeUndefined();
    const e = rows([o])[0];
    expect(e.description).toContain("[no server certificate observed in this record]");
    expect(e.canonical?.tls?.certificate).toBeUndefined();
  });

  it("a chain-only Suricata record attaches the record's fields to the first chain entry", () => {
    const leaf = Buffer.from("leaf-bytes").toString("base64");
    const ca = Buffer.from("ca-bytes").toString("base64");
    const rec = { ...SURICATA_TLS, tls: { ...SURICATA_TLS.tls, chain: [leaf, ca] } };
    const certs = readSuricataCertificates(rec, "");
    expect(certs).toHaveLength(2);
    expect(certs[0].certificate?.subject).toBe("CN=cdn.example.net");
    expect(certs[1].certificate).toEqual({});
  });

  it("a Zeek row and a Suricata row of one shape are two rows, in either order", () => {
    const z = readZeekSsl(
      {
        ts: 1700000000.5,
        "id.orig_h": "10.0.0.5",
        "id.resp_h": "203.0.113.9",
        "id.resp_p": 443,
        server_name: "a.example",
      },
      "",
    );
    const su = readSuricataTls({ ...SURICATA_TLS, tls: { sni: "a.example" } }, "");
    expect(rows([z, su])).toHaveLength(2);
    expect(rows([su, z])).toHaveLength(2);
  });

  it("malformed or empty base64 never becomes a certificate fingerprint", () => {
    for (const bad of ["!!!!", "????", "", "abc"]) {
      const o = readSuricataTls({ ...SURICATA_TLS, tls: { sni: "a.example", certificate: bad } }, "");
      expect(o.cert, bad).toBeUndefined();
      expect(
        readSuricataCertificates({ ...SURICATA_TLS, tls: { certificate: bad, chain: [bad] } }, ""),
        bad,
      ).toEqual([]);
    }
    const ok = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", certificate: Buffer.from("x").toString("base64") } },
      "",
    );
    expect(ok.cert?.alg).toBe("sha256");
  });

  it("a validity bound is a time or nothing, and never escapes its span", () => {
    const evil = readZeekX509(
      {
        ...ZEEK_X509,
        "certificate.not_valid_before": "x] [SNI matches the certificate] [x",
        "certificate.not_valid_after": "d41d8cd98f00b204e9800998ecf8427e",
      },
      "",
    );
    expect(evil.certificate?.notBefore).toBeUndefined();
    expect(evil.certificate?.notAfter).toBeUndefined();
    const e = rows([evil])[0];
    expect(e.description).not.toContain("[SNI matches");
    expect(e.description).not.toMatch(/[0-9a-f]{32}/i);
    expect(e.description).not.toContain("valid ");
  });

  it("a malformed leaf never hands its facts to a chain entry", () => {
    const ca = Buffer.from("ca-bytes").toString("base64");
    const certs = readSuricataCertificates(
      {
        ...SURICATA_TLS,
        tls: { certificate: "!!!!", chain: [ca], subject: "CN=leaf", issuerdn: "CN=Leaf CA" },
      },
      "",
    );
    expect(certs).toHaveLength(1);
    expect(certs[0].certificate).toEqual({});
  });

  it("overflow rows are partitioned by source", () => {
    const tally = new Map();
    for (let i = 0; i < TLS_SHAPES_MAX; i++) tallyTls({ ...base(), subject: `CN=cert-${i}` }, tally);
    tallyTls({ ...base(), subject: "CN=zeek-extra" }, tally);
    tallyTls(
      { ...readSuricataTls({ ...SURICATA_TLS, tls: { sni: "x.example" } }, ""), subject: "CN=suri-extra" },
      tally,
    );
    const overflows = mapTlsRows(tally, TLS_SHAPES_MAX + 5).filter((e) =>
      e.description.startsWith("[overflow:"),
    );
    expect(overflows).toHaveLength(2);
    expect(overflows.map((e) => e.sources?.[0]).sort()).toEqual(["Suricata", "Zeek"]);
  });

  it("a malformed fingerprint or serial is rejected, never cleaned into a valid one", () => {
    const valid = "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01";
    const bad = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", fingerprint: "aa:zz:" + valid.slice(3) } },
      "",
    );
    expect(bad.cert).toBeUndefined();
    const shortHex = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", fingerprint: "ab:cd" } },
      "",
    );
    expect(shortHex.cert).toBeUndefined();
    expect(certIdentity("CN=X", "zz:01")).toBeUndefined();
    expect(
      readSuricataTls({ ...SURICATA_TLS, tls: { sni: "a.example", issuerdn: "CN=X", serial: "zz:01" } }, "")
        .cert,
    ).toBeUndefined();
    expect(readZeekX509({ ...ZEEK_X509, "certificate.serial": "not hex" }, "").cert).toBeUndefined();
    expect(
      readZeekX509({ ...ZEEK_X509, "certificate.serial": "not hex" }, "").certificate?.serial,
    ).toBeUndefined();
  });

  it("a chain-only session presents its first chain entry as the certificate, keyed and shown", () => {
    const rec = (leaf: string) => ({
      ...SURICATA_TLS,
      tls: { sni: "a.example", chain: [Buffer.from(leaf).toString("base64")] },
    });
    const a = readSuricataTls(rec("leaf-a"), "");
    const b = readSuricataTls(rec("leaf-b"), "");
    expect(a.cert?.alg).toBe("sha256");
    expect(a.cert).not.toEqual(b.cert);
    const r = rows([a, b]);
    expect(r).toHaveLength(2);
    expect(r[0].description).not.toContain("no certificate observed");
    expect(r[0].description).toContain("[cert: sha256 ");
  });

  it("undocumented serial spellings and a 32-hex fingerprint yield nothing", () => {
    expect(certIdentity("CN=X", "01-02")).toBeUndefined();
    expect(certIdentity("CN=X", "0x0102")).toBeUndefined();
    expect(certIdentity("CN=X", "01:02 03")).toBe(certIdentity("CN=X", "010203")); // colon or space, byte-wise
    expect(certIdentity("CN=X", "01:02")).toBe(certIdentity("CN=X", "0102"));
    expect(certIdentity("CN=X", "0102")).toBe(certIdentity("CN=X", "0102"));
    const md5 = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", fingerprint: "00112233445566778899aabbccddeeff" } },
      "",
    );
    expect(md5.cert).toBeUndefined();
  });

  it("a client certificate is read, keyed and shown apart from the server's", () => {
    const base2 = { ts: 1700000000.5, "id.orig_h": "10.0.0.1", "id.resp_h": "203.0.113.1", "id.resp_p": 443 };
    const a = readZeekSsl(
      { ...base2, client_cert_chain_fuids: ["Fclient-a"], client_subject: "CN=user-a] [chain check: ok" },
      "",
    );
    const b = readZeekSsl({ ...base2, client_cert_chain_fuids: ["Fclient-b"] }, "");
    expect(a.clientCert).toEqual({ subject: "CN=user-a] [chain check: ok", chainFuids: ["Fclient-a"] });
    const r = rows([a, b]);
    expect(r).toHaveLength(2);
    const ra = r.find((e) => e.description.includes("user-a"))!;
    expect(ra.description).toContain("[no server certificate observed in this record]");
    expect(ra.description).toContain(
      "[client cert: subject CN=user-a) (chain check: ok; identity unavailable]",
    );
    expect(ra.description).not.toMatch(/\] \[chain check: ok\]/);
    expect(ra.canonical?.tls?.clientCertificate).toEqual({
      subject: "CN=user-a] [chain check: ok",
      chainFuids: ["Fclient-a"],
    });
    const fp = readZeekSsl({ ...base2, client_cert_chain_fps: ["ab".repeat(20)] }, "");
    expect(fp.clientCert?.ref).toEqual({ kind: "fingerprint", value: "ab".repeat(20), alg: "sha1" });
  });

  it("a direction-flipped Zeek session (ssl_history ^) attributes client and server the right way round", () => {
    const flipped = readZeekSsl(
      {
        ts: 1700000000.5,
        "id.orig_h": "203.0.113.9",
        "id.orig_p": 443,
        "id.resp_h": "10.0.0.5",
        "id.resp_p": 53000,
        ssl_history: "^HCS",
        server_name: "a.example",
        client_subject: "CN=user",
      },
      "",
    );
    expect(flipped).toMatchObject({ src: "10.0.0.5", dst: "203.0.113.9", port: 443, directionFlipped: true });
    const e = rows([flipped])[0];
    expect(e.description).toContain("TLS 10.0.0.5 → 203.0.113.9:443");
    expect(e.description).toContain("[TLS client was the connection responder]");
    expect(e.canonical?.network?.source?.address).toBe("10.0.0.5");
    expect(e.canonical?.network?.destination?.address).toBe("203.0.113.9");
    expect(e.canonical?.tls?.clientCertificate?.subject).toBe("CN=user");
    expect(readZeekSsl({ ...ZEEK_SSL, ssl_history: "HCSI" }, "").directionFlipped).toBeUndefined();
  });

  it("a Zeek x509 client certificate keeps its role, apart from the same certificate as a server's", () => {
    const fp = "ab".repeat(20);
    const asClient = readZeekX509(
      { ...ZEEK_X509, fingerprint: fp, client_cert: true, host_cert: true, "certificate.subject": "CN=user" },
      "",
    );
    const asServer = readZeekX509({ ...ZEEK_X509, fingerprint: fp, client_cert: false, host_cert: true }, "");
    const unknown = readZeekX509({ ...ZEEK_X509, fingerprint: fp }, "");
    expect(asClient.role).toBe("client");
    expect(asServer.role).toBe("server");
    expect(unknown.role).toBeUndefined();
    const r = rows([asClient, asServer, unknown]);
    expect(r).toHaveLength(3);
    const c = r.find((e) => e.description.includes("client-presented"))!;
    expect(c.canonical?.tls?.certificateRole).toBe("client");
    expect(r.find((e) => e.description.includes("server-presented"))?.canonical?.tls?.certificateRole).toBe(
      "server",
    );
    // false/false establishes no side: no claim, and no folding with a positively identified server leaf
    const neither = readZeekX509({ ...ZEEK_X509, fingerprint: fp, client_cert: false, host_cert: false }, "");
    expect(neither.role).toBeUndefined();
    expect(rows([neither, asServer])).toHaveLength(2);
    expect(rows([neither])[0].description).not.toContain("presented");
  });

  it("Suricata 8 tls.client is the client's certificate: keyed apart, shown apart, certificate rows by role", () => {
    const rec = (who: string) => ({
      ...SURICATA_TLS,
      tls: {
        sni: "a.example",
        client: {
          subject: `CN=${who}`,
          issuerdn: "CN=Corp CA",
          fingerprint: `${who === "alice" ? "ab" : "cd"}`.repeat(20),
          certificate: Buffer.from(who).toString("base64"),
        },
      },
    });
    const alice = readSuricataTls(rec("alice"), "");
    const bob = readSuricataTls(rec("bob"), "");
    expect(alice.clientCert).toMatchObject({ subject: "CN=alice", issuer: "CN=Corp CA" });
    expect(alice.clientCert?.ref?.value).toBe("ab".repeat(20));
    const r = rows([alice, bob]);
    expect(r).toHaveLength(2);
    expect(r[0].description).toContain("[client cert: subject CN=");
    const certs = readSuricataCertificates(rec("alice"), "");
    expect(certs).toHaveLength(1);
    expect(certs[0].role).toBe("client");
    expect(certs[0].certificate?.subject).toBe("CN=alice");
    expect(rows(certs)[0].description).toContain("client-presented");
  });

  it("an issuer+serial client certificate is a cert identity, never a fingerprint", () => {
    const o = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", client: { issuerdn: "CN=Corp CA", serial: "01" } } },
      "",
    );
    expect(o.clientCert?.ref?.kind).toBe("identity");
    const e = rows([o])[0];
    expect(e.description).toContain("[client cert: issuer CN=Corp CA; cert identity certid-v1:");
    expect(e.description).not.toContain("fp certid");
    expect(e.canonical?.tls?.clientCertificate?.identity).toMatch(/^certid-v1:/);
    expect(e.canonical?.tls?.clientCertificate?.fingerprint).toBeUndefined();
  });

  it("certificate facts with no identity are still certificate evidence, keyed", () => {
    const withSan = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", subjectaltname: ["only.example"] } },
      "",
    );
    const without = readSuricataTls({ ...SURICATA_TLS, tls: { sni: "a.example" } }, "");
    expect(rows([withSan])[0].description).not.toContain("no server certificate observed");
    expect(rows([withSan, without])).toHaveLength(2);
    expect(rows([without, withSan])).toHaveLength(2);
  });

  it("identity-less client facts (a serial, SANs, validity) are client-certificate evidence, keyed", () => {
    const rec = (client: Record<string, unknown> | undefined) => ({
      ...SURICATA_TLS,
      tls: { sni: "a.example", ...(client ? { client } : {}) },
    });
    const serial1 = readSuricataTls(
      rec({ serial: "01", subjectaltname: ["alice.example"], notbefore: "2025-01-01T00:00:00Z" }),
      "",
    );
    const serial2 = readSuricataTls(rec({ serial: "02" }), "");
    const none = readSuricataTls(rec(undefined), "");
    expect(serial1.clientCert?.facts).toMatchObject({
      serial: "01",
      names: ["alice.example"],
      notBefore: "2025-01-01T00:00:00Z",
    });
    expect(rows([serial1, serial2, none])).toHaveLength(3);
    const e = rows([serial1])[0];
    expect(e.description).toContain("[client cert:");
    expect(e.canonical?.tls?.clientCertificate).toMatchObject({ serial: "01", names: ["alice.example"] });
  });

  it("a Suricata fingerprint field is SHA-1 only: a 64-hex value there never keys with a DER-derived sha256", () => {
    const sha256OfX = createHash("sha256").update(Buffer.from("x")).digest("hex");
    const claimed = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", fingerprint: sha256OfX } },
      "",
    );
    const derived = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", certificate: Buffer.from("x").toString("base64") } },
      "",
    );
    expect(claimed.cert).toBeUndefined();
    expect(derived.cert?.alg).toBe("sha256");
    expect(rows([claimed, derived])).toHaveLength(2);
    expect(
      readSuricataTls({ ...SURICATA_TLS, tls: { sni: "a.example", client: { fingerprint: sha256OfX } } }, "")
        .clientCert?.ref,
    ).toBeUndefined();
    // Zeek may write either digest
    expect(readZeekX509({ ...ZEEK_X509, fingerprint: sha256OfX }, "").cert?.alg).toBe("sha256");
  });

  it("SAN lists that agree on the first 64 names and differ after are two rows, server and client alike", () => {
    const sans = (tail: string) => [...Array.from({ length: 64 }, (_, i) => `n${i}.example`), tail];
    const srvA = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", subjectaltname: sans("tail-a.example") } },
      "",
    );
    const srvB = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", subjectaltname: sans("tail-b.example") } },
      "",
    );
    expect(srvA.certificate?.names).toHaveLength(64);
    expect(srvA.certificate?.namesTotal).toBe(65);
    expect(rows([srvA, srvB])).toHaveLength(2);
    const cliA = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", client: { subjectaltname: sans("tail-a.example") } } },
      "",
    );
    const cliB = readSuricataTls(
      { ...SURICATA_TLS, tls: { sni: "a.example", client: { subjectaltname: sans("tail-b.example") } } },
      "",
    );
    expect(rows([cliA, cliB])).toHaveLength(2);
    const x = readZeekX509({ ...ZEEK_X509, "san.dns": sans("tail-a.example") }, "");
    expect(rows([x])[0].description).toContain("covers 65 names:");
  });

  it("a client chain FUID is a locator, not a shape: F1 and F2 fold; a different client fingerprint does not", () => {
    const base2 = {
      ts: 1700000000.5,
      "id.orig_h": "10.0.0.1",
      "id.resp_h": "203.0.113.1",
      "id.resp_p": 443,
      client_subject: "CN=user",
    };
    const f1 = readZeekSsl({ ...base2, client_cert_chain_fuids: ["F1"] }, "");
    const f2 = readZeekSsl({ ...base2, client_cert_chain_fuids: ["F2"] }, "");
    const r = rows([f1, f2]);
    expect(r).toHaveLength(1);
    expect(r[0].canonical?.tls?.records).toBe(2);
    expect(r[0].canonical?.tls?.clientCertificate?.chainFuids).toEqual(["F1"]);
    const other = readZeekSsl({ ...base2, client_cert_chain_fps: ["ab".repeat(20)] }, "");
    expect(rows([f1, other])).toHaveLength(2);
  });

  it("a chain-only record and a certificate-absent record are two rows, in either order", () => {
    const base2 = {
      ts: 1700000000.5,
      "id.orig_h": "10.0.0.1",
      "id.resp_h": "203.0.113.1",
      "id.resp_p": 443,
      server_name: "a.example",
    };
    const withChain = readZeekSsl({ ...base2, cert_chain_fuids: ["F1"] }, "");
    const without = readZeekSsl(base2, "");
    for (const order of [
      [withChain, without],
      [without, withChain],
    ]) {
      const r = rows(order);
      expect(r).toHaveLength(2);
      expect(r.filter((e) => e.description.includes("no server certificate observed"))).toHaveLength(1);
    }
    // …while two chain-only records with different FUIDs are one row
    expect(rows([withChain, readZeekSsl({ ...base2, cert_chain_fuids: ["F2"] }, "")])).toHaveLength(1);
  });

  it("the negotiated curve is read, keyed, shown and enveloped", () => {
    const a = readZeekSsl({ ...ZEEK_SSL, curve: "x25519" }, "");
    const b = readZeekSsl({ ...ZEEK_SSL, curve: "secp256r1" }, "");
    const r = rows([a, b]);
    expect(r).toHaveLength(2);
    expect(r[0].description).toContain("curve x25519]");
    expect(r[0].canonical?.tls?.curve).toBe("x25519");
  });

  it("an unreadable explicit leaf beside a valid chain is a certificate observed with no identity", () => {
    const rec = {
      ...SURICATA_TLS,
      tls: { sni: "a.example", certificate: "!!!!", chain: [Buffer.from("chain-cert").toString("base64")] },
    };
    const o = readSuricataTls(rec, "");
    expect(o.cert).toBeUndefined();
    expect(o.certificateSeen).toBe(true);
    const none = readSuricataTls({ ...SURICATA_TLS, tls: { sni: "a.example" } }, "");
    const r = rows([o, none]);
    expect(r).toHaveLength(2);
    const seen = r.find((e) => !e.description.includes("no server certificate observed"))!;
    expect(seen.description).toContain("[cert: identity unavailable]");
    // the chain entry is a chain row, never given the leaf's identity
    expect(readSuricataCertificates(rec, "")).toHaveLength(1);
  });

  it("selects the most-seen rows first under a budget", () => {
    const many = [
      ...Array.from({ length: 3 }, () => base()),
      ...Array.from({ length: 5 }, (_, i) => ({ ...base(), sni: `s${i}.example` })),
    ];
    const tally = new Map();
    for (const o of many) tallyTls(o, tally);
    const r = mapTlsRows(tally, 2);
    expect(r).toHaveLength(2);
    expect(r[0].description).toContain("3 TLS records");
  });
});

describe("through the network importer", () => {
  const afterImport = (events: SiemEvent[]): ForensicEvent[] =>
    correlateEvents(
      events.map(({ aggKey: _k, ...e }, i) => ({
        ...e,
        id: `t${i}`,
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: e.sources?.length ? e.sources : ["Zeek"],
      })),
    );

  it("ssl and x509 rows are Info events; the SNI is the only indicator; SAN names and fingerprints are not", () => {
    const r = parseNetworkLogs(
      JSON.stringify([
        { ...ZEEK_SSL, _path: "ssl" },
        { ...ZEEK_X509, _path: "x509" },
      ]),
    );
    expect(r.events.filter((e) => e.description.startsWith("TLS "))).toHaveLength(1);
    expect(r.events.filter((e) => e.description.startsWith("[certificate:"))).toHaveLength(1);
    const values = r.iocs.map((i) => `${i.type}:${i.value}`);
    expect(values).toContain("domain:cdn.example.net");
    expect(values).not.toContain("domain:www.example.net");
    expect(values).not.toContain("domain:static.example.net");
    expect(values.some((v) => v.startsWith("hash:"))).toBe(false);
  });

  it("a Suricata tls record is a row too, and its fingerprint never joins a file event", () => {
    const r = parseNetworkLogs(JSON.stringify([SURICATA_TLS]));
    const row = r.events.find((e) => e.description.startsWith("TLS "))!;
    expect(row.description).toContain(
      "[cert: subject CN=cdn.example.net; issuer CN=R3, O=Let's Encrypt, C=US; fp abcdef01…ef01]",
    );
    expect(row.description).not.toMatch(/[0-9a-f]{40}/i);
    const file: ForensicEvent = {
      id: "f1",
      timestamp: "2023-11-14T22:13:20.500Z",
      description: "File created",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sha256: "ab".repeat(32),
    };
    expect(correlateEvents([...afterImport([row]), file])).toHaveLength(2);
  });

  it("a subject or SAN carrying a path or a hash run never joins a file event", () => {
    const evil = {
      ...ZEEK_X509,
      _path: "x509",
      "certificate.subject": "CN=/tmp/payload.exe",
      "san.dns": ["C:\\Windows\\Temp\\drop.exe", "d41d8cd98f00b204e9800998ecf8427e.example"],
    };
    const r = parseNetworkLogs(JSON.stringify([evil]));
    const row = r.events.find((e) => e.description.startsWith("[certificate:"))!;
    const file: ForensicEvent = {
      id: "f1",
      timestamp: "2023-11-14T22:13:21.000Z",
      description: "File created",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      path: "/tmp/payload.exe",
      md5: "d41d8cd98f00b204e9800998ecf8427e",
    };
    expect(correlateEvents([...afterImport([row]), file])).toHaveLength(2);
  });
});
