import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  isTlsHostname,
  readZeekSsl,
  readZeekX509,
  readSuricataTls,
  readSuricataCertificates,
  TLS_SHAPES_MAX,
} from "../../src/analysis/tlsSession.js";
import {
  addTls,
  emptyTlsObservations,
  joinSessionsToCertificates,
  TLS_OBSERVATIONS_MAX,
  type TlsObservations,
} from "../../src/analysis/tlsGraphJoin.js";
import {
  buildTlsGraph,
  TLS_JA3_CONCENTRATED_MIN_SESSIONS,
  TLS_MANY_NAMES_LEAD,
  TLS_NODES_MAX,
  type TlsNode,
} from "../../src/analysis/tlsGraphNodes.js";
import { mapTlsGraphRows, tlsFamilies } from "../../src/analysis/tlsGraphRows.js";
import { parseNetworkLogs } from "../../src/analysis/networkImport.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { SiemEvent } from "../../src/analysis/siemImport.js";

// #933 item 6, second half (#997): the relationships one upload establishes between certificates,
// names, client addresses and time — and the one join Zeek's own FUID allows.

type Row = Record<string, unknown>;

const T0 = 1700000000;
const ssl = (over: Row = {}): Row => ({
  ts: T0,
  uid: "C1",
  "id.orig_h": "10.0.0.5",
  "id.resp_h": "203.0.113.9",
  "id.resp_p": 443,
  version: "TLSv13",
  server_name: "cdn.example.net",
  established: true,
  validation_status: "ok",
  subject: "CN=cdn.example.net",
  issuer: "CN=R3,O=Let's Encrypt,C=US",
  cert_chain_fuids: ["Fleaf", "Fint"],
  ...over,
});
const x509 = (over: Row = {}): Row => ({
  ts: T0,
  id: "Fleaf",
  "certificate.serial": "03A1B2C3",
  "certificate.subject": "CN=cdn.example.net",
  "certificate.issuer": "CN=R3,O=Let's Encrypt,C=US",
  "certificate.not_valid_before": T0 - 1_000_000,
  "certificate.not_valid_after": T0 + 6_000_000,
  "san.dns": ["cdn.example.net", "*.example.net"],
  host_cert: true,
  client_cert: false,
  ...over,
});
const FP_A = "a".repeat(64);
const FP_B = "b".repeat(64);

function store(sessions: Row[], certs: Row[] = []): TlsObservations {
  const s = emptyTlsObservations();
  for (const c of certs) addTls(s, readZeekX509(c, ""));
  for (const r of sessions) addTls(s, readZeekSsl(r, ""));
  return s;
}
const graphOf = (s: TlsObservations) => buildTlsGraph(s, joinSessionsToCertificates(s));
const node = (nodes: TlsNode[], kind: TlsNode["kind"], idPart: string) =>
  nodes.find((n) => n.kind === kind && n.id.includes(idPart));

describe("session ↔ certificate by Zeek's own FUID", () => {
  it("a session with no identity of its own takes the x509 record's identity and says so, keyed and enveloped", () => {
    const s = store([ssl()], [x509()]);
    const [j] = joinSessionsToCertificates(s);
    expect(j.cert?.kind).toBe("identity");
    expect(j.certFrom).toBe("x509");
    const [rows] = tlsFamilies(s, 100);
    const row = rows.find((r) => r.description.startsWith("TLS "))!;
    expect(row.description).toContain("cert identity certid-v1:");
    expect(row.description).toContain("— identity from the x509 record]");
    expect(row.canonical?.tls?.certificate?.identityFrom).toBe("x509 record");
    // the joined identity is a keyed fact: the same session without the x509 record is another row
    const alone = tlsFamilies(store([ssl()]), 100)[0].find((r) => r.description.startsWith("TLS "))!;
    expect(alone.aggKey).not.toBe(row.aggKey);
    expect(alone.description).toContain("identity unavailable");
  });

  it("the x509 fingerprint wins over issuer+serial; a session with its own fps keeps it when they agree", () => {
    const s = store([ssl({ cert_chain_fps: [FP_A] })], [x509({ fingerprint: FP_A })]);
    const [j] = joinSessionsToCertificates(s);
    expect(j.cert).toEqual({ kind: "fingerprint", value: FP_A, alg: "sha256" });
    expect(j.certFrom).toBeUndefined();
    expect(j.certJoinNote).toBeUndefined();
  });

  it("a disagreeing x509 fingerprint is named and the record's own identity kept", () => {
    const s = store([ssl({ cert_chain_fps: [FP_A] })], [x509({ fingerprint: FP_B })]);
    const [j] = joinSessionsToCertificates(s);
    expect(j.cert?.value).toBe(FP_A);
    expect(j.certJoinNote).toBe("disagrees with this record");
    const row = tlsFamilies(s, 100)[0].find((r) => r.description.startsWith("TLS "))!;
    expect(row.description).toContain("x509 record for this chain disagrees, not joined");
  });

  it("two x509 records for one id with different identities join nothing", () => {
    const s = store([ssl()], [x509({ fingerprint: FP_A }), x509({ fingerprint: FP_B })]);
    const [j] = joinSessionsToCertificates(s);
    expect(j.cert).toBeUndefined();
    expect(j.certJoinNote).toBe("records disagree");
  });

  it("an x509 record on another sensor, or with a sensor when the session has none, never joins", () => {
    const other = store([ssl({ "observer.name": "a" })], [x509({ "observer.name": "b" })]);
    expect(joinSessionsToCertificates(other)[0].cert).toBeUndefined();
    const mixed = store([ssl()], [x509({ "observer.name": "b" })]);
    expect(joinSessionsToCertificates(mixed)[0].cert).toBeUndefined();
  });

  it("a session whose subject/issuer differ from the x509 record's keeps the identity and says so", () => {
    const s = store([ssl({ subject: "CN=other" })], [x509()]);
    const [j] = joinSessionsToCertificates(s);
    expect(j.certFrom).toBe("x509");
    expect(j.certJoinNote).toBe("subject/issuer differ");
  });

  it("a client chain FUID joins the x509 record marked client_cert", () => {
    const s = store(
      [ssl({ client_cert_chain_fuids: ["Fcli"], client_subject: "CN=user" })],
      [x509({ id: "Fcli", client_cert: true, host_cert: false, "certificate.serial": "77" })],
    );
    const [j] = joinSessionsToCertificates(s);
    expect(j.clientCert?.ref?.kind).toBe("identity");
    expect(j.clientCert?.from).toBe("x509");
    // and a server-role x509 record never fills a client chain
    const wrong = store(
      [ssl({ client_cert_chain_fuids: ["Fcli"], client_subject: "CN=user" })],
      [x509({ id: "Fcli", "certificate.serial": "77" })],
    );
    expect(joinSessionsToCertificates(wrong)[0].clientCert?.ref).toBeUndefined();
  });

  it("past the certificate bound a missing x509 record is 'not among those read', never silently unavailable", () => {
    const s = emptyTlsObservations();
    s.certsTotal = TLS_OBSERVATIONS_MAX + 1;
    addTls(s, readZeekSsl(ssl(), ""));
    const [j] = joinSessionsToCertificates(s);
    expect(j.certJoinNote).toBe("not among those read");
  });

  it("a Suricata session carries its certificate inline and is never joined", () => {
    const s = emptyTlsObservations();
    addTls(
      s,
      readSuricataTls(
        {
          timestamp: "2023-11-14T22:13:20.5+0000",
          src_ip: "10.0.0.5",
          dest_ip: "203.0.113.9",
          dest_port: 443,
          tls: { sni: "cdn.example.net", fingerprint: "ab".repeat(20) },
        },
        "",
      ),
    );
    const [j] = joinSessionsToCertificates(s);
    expect(j.cert?.alg).toBe("sha1");
    expect(j.certFrom).toBeUndefined();
  });
});

describe("certificate node — what one sensor's sessions show beside one identity", () => {
  it("names, server endpoints, client addresses, range, chain checks; every count is of addresses", () => {
    const s = store(
      [
        ssl({ uid: "C1", server_name: "a.example.net" }),
        ssl({ uid: "C2", ts: T0 + 3600, server_name: "b.example.net", "id.orig_h": "10.0.0.6" }),
        ssl({
          uid: "C3",
          ts: T0 + 7200,
          "id.resp_h": "203.0.113.10",
          validation_status: "self signed certificate",
        }),
      ],
      [x509()],
    );
    const g = graphOf(s);
    const c = node(g.nodes, "certificate", "certid-v1")!;
    expect(c.names.count).toBe(3);
    expect(c.servers.count).toBe(2);
    expect(c.clientAddresses.count).toBe(2);
    expect(c.sessions).toBe(3);
    expect(c.chainChecks.values).toEqual(["ok", "self signed certificate"]);
    const [row] = mapTlsGraphRows(g, 100);
    expect(row.description).toMatch(/^TLS-graph certificate cert identity certid-v1:/);
    expect(row.description).toContain(
      "[presented under: 3 names — a.example.net, b.example.net, cdn.example.net]",
    );
    expect(row.description).toContain("[at server addresses: 2 — 203.0.113.10:443, 203.0.113.9:443]");
    expect(row.description).toContain("[client addresses: 2]");
    expect(row.description).toContain("[chain check: ok, self signed certificate]");
    expect(row.description).toContain("[observed 2023-11-14 22:13 → 2023-11-15 00:13]");
    expect(row.description).toMatch(/— 3 session records, 1 certificate record #/);
    expect(row.description).not.toMatch(/client(?!\saddresses)/);
    expect(row.description).not.toMatch(/operator|malicious|benign|C2/);
    expect(row.srcIp).toBeUndefined();
    expect(row.dstIp).toBeUndefined();
    expect(row.severity).toBe("Info");
    expect(row.mitre).toEqual([]);
    expect(canonicalEventEnvelopeSchema.safeParse(row.canonical).success).toBe(true);
    expect(row.canonical?.tlsGraph?.clientAddresses?.count).toBe(2);
    expect(row.canonical?.tlsGraph?.basis).toBe(
      "records in this upload only; no contact with any observed infrastructure",
    );
    expect(row.canonical?.tlsGraph?.sensor).toEqual({ state: "not named" });
    expect(row.description).toContain("[sensor not named in the records]");
  });

  it("a CDN certificate on 200 names is a lead with both alternatives named and no verdict", () => {
    const sessions = Array.from({ length: 200 }, (_, i) =>
      ssl({ uid: `C${i}`, ts: T0 + i, server_name: `site${i}.example.net` }),
    );
    const g = graphOf(store(sessions, [x509()]));
    const c = node(g.nodes, "certificate", "certid-v1")!;
    expect(c.leads.map((l) => l.kind)).toEqual(["many-names"]);
    expect(c.rank).toBe(2);
    const [row] = mapTlsGraphRows(g, 100);
    expect(row.description).toContain(
      "[lead: one certificate presented under 200 names — shared hosting, a CDN or an inspection proxy present one certificate for many names; the records do not say which; a cluster proves nothing on its own — strengthen it with a process that made the connection or a payload]",
    );
    expect(row.description).not.toMatch(/same operator|malicious/);
    expect(TLS_MANY_NAMES_LEAD).toBe(8);
  });

  it("a name not among the certificate's listed DNS names is a lead; wildcards cover one label only", () => {
    const g = graphOf(
      store(
        [
          ssl({ uid: "C1", server_name: "cdn.example.net" }),
          ssl({ uid: "C2", server_name: "a.example.net" }),
          ssl({ uid: "C3", server_name: "a.b.example.net" }),
          ssl({ uid: "C4", server_name: "example.net" }),
          ssl({ uid: "C5", server_name: "CDN.EXAMPLE.NET." }),
        ],
        [x509()],
      ),
    );
    const c = node(g.nodes, "certificate", "certid-v1")!;
    expect(c.notListed).toEqual({ count: 2, listed: ["a.b.example.net", "example.net"] });
    expect(c.leads.map((l) => l.kind)).toEqual(["name-not-listed"]);
    const [row] = mapTlsGraphRows(g, 100);
    expect(row.description).toContain(
      "[lead: presented under 2 names not among the 2 DNS names listed by the retained certificate record: a.b.example.net, example.net;",
    );
  });

  it("no coverage claim without typed DNS names, with a truncated list, with an invalid SNI, or past the certificate bound", () => {
    const noSan = graphOf(store([ssl()], [x509({ "san.dns": undefined, "san.email": ["a@example.net"] })]));
    expect(node(noSan.nodes, "certificate", "certid")!.notListed).toEqual({
      state: "not compared",
      reason: "the certificate record lists no DNS names",
    });
    const many = Array.from({ length: 65 }, (_, i) => `n${i}.example.net`);
    const truncated = graphOf(store([ssl()], [x509({ "san.dns": many })]));
    expect(node(truncated.nodes, "certificate", "certid")!.notListed).toEqual({
      state: "not compared",
      reason: "the certificate's DNS-name list was truncated at 64",
    });
    const invalid = graphOf(store([ssl({ server_name: "not a name/" })], [x509()]));
    expect(node(invalid.nodes, "certificate", "certid")!.notListed).toEqual({ count: 0, listed: [] });
    const s = store([ssl({ server_name: "evil.example" })], [x509()]);
    s.certsTotal = TLS_OBSERVATIONS_MAX + 5;
    const past = graphOf(s);
    const c = node(past.nodes, "certificate", "certid")!;
    expect(c.notListed).toEqual({
      state: "not compared",
      reason: "certificate records beyond the retained bound",
    });
    expect(c.issuerString).toBeUndefined();
    const [row] = mapTlsGraphRows(past, 100);
    expect(row.description).toContain("[certificate records: 1 of 65,541 read]");
    expect(row.canonical?.tlsGraph?.coverage.certificatesTotal).toBe(TLS_OBSERVATIONS_MAX + 5);
  });

  it("an issuer string shared by several identities is a string count, never 'signs'", () => {
    const g = graphOf(
      store(
        [ssl({ uid: "C1" }), ssl({ uid: "C2", cert_chain_fuids: ["F2"] })],
        [x509(), x509({ id: "F2", "certificate.serial": "0055", "certificate.subject": "CN=other.example" })],
      ),
    );
    const c = node(g.nodes, "certificate", "certid")!;
    expect(c.issuerString).toBe(2);
    const row = mapTlsGraphRows(g, 100).find((r) => r.description.includes("issuer string"))!;
    expect(row.description).toContain("[issuer string shared by 2 certificate identities in this upload]");
    expect(row.description).not.toContain("signs");
  });

  it("certificate records for one identity that disagree are a state; derived claims are suppressed", () => {
    const g = graphOf(
      store(
        [ssl({ server_name: "evil.example" })],
        [x509(), x509({ ts: T0 + 1, "certificate.subject": "CN=forged", "san.dns": ["forged.example"] })],
      ),
    );
    const c = node(g.nodes, "certificate", "certid")!;
    expect(c.certificate?.disagree).toEqual(["subject", "names"]);
    expect(c.notListed).toEqual({
      state: "not compared",
      reason: "certificate records for this identity disagree",
    });
    expect(c.leads).toEqual([]);
    const [row] = mapTlsGraphRows(g, 100);
    expect(row.description).toContain("[certificate records for this identity disagree: subject, names]");
  });

  it("an absent fact is not a disagreement: a chain member with no facts beside the leaf", () => {
    const der = Buffer.from("leaf-der").toString("base64");
    const s = emptyTlsObservations();
    const row = {
      timestamp: "2023-11-14T22:13:20.5+0000",
      src_ip: "10.0.0.5",
      dest_ip: "203.0.113.9",
      dest_port: 443,
      tls: { sni: "a.example", subject: "CN=a", certificate: der, chain: [der] },
    };
    const other = {
      ...row,
      tls: {
        sni: "b.example",
        subject: "CN=b",
        certificate: Buffer.from("other").toString("base64"),
        chain: [der],
      },
    };
    for (const r of [row, other]) {
      addTls(s, readSuricataTls(r, ""));
      for (const c of readSuricataCertificates(r, "")) addTls(s, c);
    }
    const g = graphOf(s);
    const fp = createHash("sha256").update("leaf-der").digest("hex");
    expect(node(g.nodes, "certificate", fp)!.certificate?.disagree).toEqual([]);
  });

  it("a self-signed certificate on a raw address: no SNI counted, chain check as written, no lead, no verdict", () => {
    const g = graphOf(
      store(
        [
          ssl({ uid: "C1", server_name: undefined, validation_status: "self signed certificate" }),
          ssl({
            uid: "C2",
            server_name: undefined,
            validation_status: "self signed certificate",
            ts: T0 + 5,
          }),
        ],
        [x509({ "certificate.issuer": "CN=cdn.example.net" })],
      ),
    );
    const c = node(g.nodes, "certificate", "certid")!;
    expect(c.noSni).toBe(2);
    expect(c.leads).toEqual([]);
    const [row] = mapTlsGraphRows(g, 100);
    expect(row.description).toContain("[no SNI in 2 sessions]");
    expect(row.description).toContain("[chain check: self signed certificate]");
    expect(row.description).not.toMatch(/malicious|suspicious|lead/);
  });

  it("sessions with no readable time are counted and excluded from the range", () => {
    const g = graphOf(store([ssl({ uid: "C1" }), ssl({ uid: "C2", ts: "not a time" })], [x509()]));
    const c = node(g.nodes, "certificate", "certid")!;
    expect(c.untimed).toBe(1);
    const [row] = mapTlsGraphRows(g, 100);
    expect(row.description).toContain("[1 session with no readable time excluded from the range]");
  });
});

describe("name node — the certificates a name was served with", () => {
  const renewed = (over: Row = {}) =>
    store(
      [
        ssl({ uid: "C1", ts: T0 }),
        ssl({ uid: "C2", ts: T0 + 100 }),
        ssl({ uid: "C3", ts: T0 + 200, cert_chain_fuids: ["F2"] }),
        ssl({ uid: "C4", ts: T0 + 300, cert_chain_fuids: ["F2"] }),
      ],
      [x509(), x509({ id: "F2", "certificate.serial": "0099", ...over })],
    );

  it("a renewed certificate with the same names is a sequence fact, not a lead", () => {
    const g = graphOf(renewed());
    const n = node(g.nodes, "name", "cdn.example.net")!;
    expect(n.certificates?.size).toBe(2);
    expect(n.leads).toEqual([]);
    expect(n.rank).toBe(1);
    const row = mapTlsGraphRows(g, 100).find((r) => r.description.startsWith("TLS-graph name"))!;
    expect(row.description).toContain("[name: cdn.example.net]");
    expect(row.description).toContain(
      "[served with: 2 certificates in sequence — a renewal or a replacement; the records do not say which; the later certificate lists the same DNS names — cert identity certid-v1:",
    );
    expect(row.description).toMatch(/\(2023-11-14 22:13 → 2023-11-14 22:15\)/);
  });

  it("different name lists say nothing about sameness; alternation is the lead, worded as ranges", () => {
    const g = graphOf(renewed({ "san.dns": ["cdn.example.net"] }));
    const row = mapTlsGraphRows(g, 100).find((r) => r.description.startsWith("TLS-graph name"))!;
    expect(row.description).not.toContain("same DNS names");
    const alt = graphOf(
      store(
        [
          ssl({ uid: "C1", ts: T0 }),
          ssl({ uid: "C2", ts: T0 + 100, cert_chain_fuids: ["F2"] }),
          ssl({ uid: "C3", ts: T0 + 200 }),
        ],
        [x509(), x509({ id: "F2", "certificate.serial": "0099" })],
      ),
    );
    const n = node(alt.nodes, "name", "cdn.example.net")!;
    expect(n.leads.map((l) => l.kind)).toEqual(["certificates-alternate"]);
    const altRow = mapTlsGraphRows(alt, 100).find((r) => r.description.startsWith("TLS-graph name"))!;
    expect(altRow.description).toContain(
      "[lead: served with 2 certificates in alternation — observation ranges overlap; the records do not say both were served at one instant; a cluster proves nothing on its own",
    );
  });

  it("a name with one certificate at one address is not a node; two addresses make it one", () => {
    const one = graphOf(store([ssl({ uid: "C1" }), ssl({ uid: "C2" })], [x509()]));
    expect(node(one.nodes, "name", "cdn.example.net")).toBeUndefined();
    const two = graphOf(
      store([ssl({ uid: "C1" }), ssl({ uid: "C2", "id.resp_h": "203.0.113.10" })], [x509()]),
    );
    const n = node(two.nodes, "name", "cdn.example.net")!;
    expect(n.servers.count).toBe(2);
    expect(n.identityUnavailable).toBe(0);
  });

  it("sessions whose identity was unavailable are counted on the name", () => {
    const g = graphOf(
      store(
        [ssl({ uid: "C1" }), ssl({ uid: "C2", cert_chain_fuids: ["Fnone"], "id.resp_h": "203.0.113.10" })],
        [x509()],
      ),
    );
    const n = node(g.nodes, "name", "cdn.example.net")!;
    expect(n.identityUnavailable).toBe(1);
    const row = mapTlsGraphRows(g, 100).find((r) => r.description.startsWith("TLS-graph name"))!;
    expect(row.description).toContain("[certificate identity unavailable in 1 session]");
  });
});

describe("client certificate and JA3 nodes", () => {
  it("an mTLS client certificate seen at two servers", () => {
    const g = graphOf(
      store([
        ssl({ uid: "C1", client_cert_chain_fps: [FP_A], client_subject: "CN=user", server_name: "a.corp" }),
        ssl({
          uid: "C2",
          client_cert_chain_fps: [FP_A],
          client_subject: "CN=user",
          server_name: "b.corp",
          "id.resp_h": "10.0.0.9",
          "id.resp_p": 8443,
        }),
      ]),
    );
    const c = node(g.nodes, "client-certificate", FP_A)!;
    expect(c.servers.count).toBe(2);
    expect(c.clientAddresses.count).toBe(1);
    expect(c.rank).toBe(1);
    const row = mapTlsGraphRows(g, 100).find((r) =>
      r.description.startsWith("TLS-graph client certificate"),
    )!;
    expect(row.description).toContain("[presented by: 1 client address — 10.0.0.5]");
    expect(row.description).toContain("[presented to: 2 servers — 10.0.0.9:8443, 203.0.113.9:443]");
    expect(row.description).toContain("[under: 2 names — a.corp, b.corp]");
    expect(row.description).not.toMatch(/[0-9a-f]{40}/i);
  });

  it("a JA3 concentrated on few destinations is a lead; every JA3 row says it is a library signature", () => {
    const n = TLS_JA3_CONCENTRATED_MIN_SESSIONS;
    const sessions = Array.from({ length: n }, (_, i) =>
      ssl({
        uid: `C${i}`,
        ts: T0 + i,
        ja3: "e7d705a3286e19ea42f587b344ee6865",
        "id.orig_h": `10.0.0.${(i % 3) + 1}`,
      }),
    );
    const g = graphOf(store(sessions));
    const j = node(g.nodes, "ja3", "e7d705a3")!;
    expect(j.leads.map((l) => l.kind)).toEqual(["ja3-concentrated"]);
    const row = mapTlsGraphRows(g, 100).find((r) => r.description.startsWith("TLS-graph ja3"))!;
    expect(row.description).toMatch(/^TLS-graph ja3 e7d705a3…6865 /);
    expect(row.description).toContain(
      `[lead: ${n} sessions from 3 client addresses to only 1 server address — concentrated; a cluster proves nothing on its own`,
    );
    expect(row.description).toContain(
      "[a TLS library signature — every client with the same stack shares it; never an identity]",
    );
  });

  it("a JA3 seen from a fleet of addresses is a count, no lead, no 'fleet'", () => {
    const sessions = Array.from({ length: 150 }, (_, i) =>
      ssl({
        uid: `C${i}`,
        ts: T0 + i,
        ja3: "e7d705a3286e19ea42f587b344ee6865",
        "id.orig_h": `10.0.${Math.floor(i / 250)}.${i % 250}`,
        "id.resp_h": `203.0.113.${i % 20}`,
      }),
    );
    const g = graphOf(store(sessions));
    const j = node(g.nodes, "ja3", "e7d705a3")!;
    expect(j.leads).toEqual([]);
    expect(j.clientAddresses.count).toBe(150);
    const row = mapTlsGraphRows(g, 100).find((r) => r.description.startsWith("TLS-graph ja3"))!;
    expect(row.description).toContain("[client addresses: 150]");
    expect(row.description).not.toMatch(/fleet|lead/);
  });

  it("a JA3S is a node of its own: the servers that presented it, the names, the client addresses — a server library signature, never an identity (#997)", () => {
    const sessions = [1, 2, 3].map((i) =>
      ssl({
        uid: `S${i}`,
        ts: T0 + i,
        ja3s: "f4febc55ea12b31ae17cfb7e614afda8",
        "id.resp_h": i === 3 ? "203.0.113.10" : "203.0.113.9",
        "id.orig_h": `10.0.0.${i}`,
      }),
    );
    const g = graphOf(store(sessions));
    const j = node(g.nodes, "ja3s", "f4febc55")!;
    expect(j.servers.values).toEqual(["203.0.113.10:443", "203.0.113.9:443"]);
    expect(j.clientAddresses.count).toBe(3);
    expect(j.names.values).toEqual(["cdn.example.net"]);
    expect(j.leads).toEqual([]);
    const row = mapTlsGraphRows(g, 100).find((r) => r.description.startsWith("TLS-graph ja3s"))!;
    expect(row.description).toMatch(/^TLS-graph ja3s f4febc55…fda8 /);
    expect(row.description).toContain("[server addresses: 2 — 203.0.113.10:443, 203.0.113.9:443]");
    expect(row.description).toContain("[client addresses: 3]");
    expect(row.description).toContain(
      "[a TLS library signature of the server stack — every server with the same stack shares it; never an identity]",
    );
    expect(row.canonical?.tlsGraph?.node.kind).toBe("ja3s");
    expect(canonicalEventEnvelopeSchema.safeParse(row.canonical).success).toBe(true);
    // Seen once: not a node, like JA3.
    expect(
      node(graphOf(store([ssl({ ja3s: "f4febc55ea12b31ae17cfb7e614afda8" })])).nodes, "ja3s", "f4febc55"),
    ).toBeUndefined();
  });

  it("a JA3 seen once is not a node", () => {
    const g = graphOf(store([ssl({ ja3: "e7d705a3286e19ea42f587b344ee6865" })]));
    expect(node(g.nodes, "ja3", "e7d705a3")).toBeUndefined();
  });
});

describe("identity, bounds, sensors", () => {
  it("the same upload twice folds; a different edge set is another row; a uid alone never splits", () => {
    const a = mapTlsGraphRows(graphOf(store([ssl({ uid: "C1" }), ssl({ uid: "C2" })], [x509()])), 100)[0];
    const b = mapTlsGraphRows(graphOf(store([ssl({ uid: "C9" }), ssl({ uid: "C8" })], [x509()])), 100)[0];
    expect(a.aggKey).toBe(b.aggKey);
    const c = mapTlsGraphRows(
      graphOf(store([ssl({ uid: "C1", server_name: "x.example.net" })], [x509()])),
      100,
    )[0];
    expect(c.aggKey).not.toBe(a.aggKey);
    expect(a.aggKey).not.toContain("C1");
  });

  it("records with a sensor name never share a node with records without one; two sensors are two nodes", () => {
    const g = graphOf(
      store(
        [
          ssl({ uid: "C1", "observer.name": "s1" }),
          ssl({ uid: "C2" }),
          ssl({ uid: "C3", "observer.name": "s2" }),
        ],
        [x509({ "observer.name": "s1" }), x509(), x509({ "observer.name": "s2" })],
      ),
    );
    const certs = g.nodes.filter((n) => n.kind === "certificate");
    expect(certs.map((n) => n.sensor).sort()).toEqual(["", "s1", "s2"]);
    const rows = mapTlsGraphRows(g, 100);
    expect(rows.find((r) => r.description.includes("@ s1"))?.canonical?.tlsGraph?.sensor).toEqual({
      name: "s1",
    });
  });

  it("past the session bound every node says the coverage; the extra sessions still fold into session rows", () => {
    const s = emptyTlsObservations();
    for (let i = 0; i < TLS_OBSERVATIONS_MAX + 3; i++)
      addTls(s, readZeekSsl(ssl({ uid: `C${i}`, ts: T0 + (i % 7) }), ""));
    expect(s.sessions).toHaveLength(TLS_OBSERVATIONS_MAX);
    expect(s.sessionsTotal).toBe(TLS_OBSERVATIONS_MAX + 3);
    const [sessionRows, graphRows] = tlsFamilies(s, 100);
    const tls = sessionRows.find((r) => r.description.startsWith("TLS "))!;
    expect(tls.description).toContain(`— ${TLS_OBSERVATIONS_MAX + 3} TLS records`);
    expect(graphRows).toHaveLength(0); // no identity, no ja3: nothing to graph
    const withJa3 = emptyTlsObservations();
    for (let i = 0; i < TLS_OBSERVATIONS_MAX + 3; i++)
      addTls(withJa3, readZeekSsl(ssl({ uid: `C${i}`, ja3: "e7d705a3286e19ea42f587b344ee6865" }), ""));
    const [, rows] = tlsFamilies(withJa3, 100);
    expect(rows[0].description).toContain("[graph over 65,536 of 65,539 session records]");
    expect(rows[0].canonical?.tlsGraph?.coverage).toEqual({
      sessionsRead: TLS_OBSERVATIONS_MAX,
      sessionsTotal: TLS_OBSERVATIONS_MAX + 3,
      certificatesRead: 0,
      certificatesTotal: 0,
    });
  });

  it("distinct values are tracked to 256 and said as at least", () => {
    const sessions = Array.from({ length: 300 }, (_, i) =>
      ssl({ uid: `C${i}`, server_name: `n${i}.example.net` }),
    );
    const g = graphOf(store(sessions, [x509()]));
    const c = node(g.nodes, "certificate", "certid")!;
    expect(c.names.atLeast).toBe(true);
    expect(c.names.count).toBe(256);
    const [row] = mapTlsGraphRows(g, 100);
    expect(row.description).toContain("[presented under: 256+ names —");
    expect(c.notListed).toEqual({ state: "not compared", reason: "more names than the graph tracks (256)" });
  });

  it("retention is order-independent: the top nodes by rank, sessions, time and id survive either order", () => {
    const mk = (i: number) =>
      ssl({ uid: `C${i}`, ts: T0 + i, ja3: i.toString(16).padStart(32, "0"), "id.orig_h": "10.0.0.5" });
    // every ja3 needs ≥2 sessions to be a node
    const forward: Row[] = [];
    for (let i = 0; i < TLS_NODES_MAX + 10; i++) forward.push(mk(i), { ...mk(i), uid: `D${i}` });
    const a = graphOf(store(forward));
    const b = graphOf(store([...forward].reverse()));
    const ids = (g: ReturnType<typeof graphOf>) =>
      g.nodes
        .filter((n) => n.kind === "ja3")
        .map((n) => n.id)
        .sort();
    expect(ids(a)).toHaveLength(TLS_NODES_MAX);
    expect(ids(a)).toEqual(ids(b));
    expect(a.overflow.get("ja3||zeek-ssl")?.count).toBe(10);
    const over = mapTlsGraphRows(a, 20000).find((r) => r.description.startsWith("[overflow"))!;
    expect(over.description).toContain(
      "10 ja3 nodes beyond the retained bound folded; none shown] [sensor not named in the records]",
    );
  });

  it("a hostile SNI is neutralised inside its span and the node row never unions with a file event", () => {
    const g = graphOf(
      store(
        [
          ssl({ uid: "C1", server_name: "/tmp/payload.exe] [lead: fake" }),
          ssl({ uid: "C2", server_name: "d41d8cd98f00b204e9800998ecf8427e.example" }),
        ],
        [x509()],
      ),
    );
    const [row] = mapTlsGraphRows(g, 100);
    expect(row.description).not.toContain("] [lead: fake");
    expect(row.description).not.toMatch(/[0-9a-f]{32}/);
    const asEvent = (e: Omit<SiemEvent, "id" | "mitreTechniques">, i: number): ForensicEvent =>
      ({
        ...e,
        id: `t${i}`,
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: ["Zeek"],
      }) as unknown as ForensicEvent;
    const { aggKey: _k, ...siem } = row;
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
    expect(correlateEvents([asEvent(siem, 0), file])).toHaveLength(2);
  });
});

describe("code review round — Codex findings", () => {
  it("1. certificate shapes never evict session shapes: separate tallies", () => {
    const s = emptyTlsObservations();
    addTls(s, readZeekSsl(ssl({ uid: "C1" }), ""));
    for (let i = 0; i < TLS_SHAPES_MAX + 1; i++)
      addTls(s, readZeekX509(x509({ id: `F${i}`, "certificate.serial": (i + 1).toString(16) }), ""));
    const [rows] = tlsFamilies(s, 100000);
    const sessions = rows.filter((r) => r.description.startsWith("TLS "));
    expect(sessions).toHaveLength(1);
    expect(sessions[0].description).not.toContain("overflow");
    expect(rows.filter((r) => r.description.startsWith("[overflow"))).toHaveLength(1);
  });

  it("1b. late sessions merge after the retained ones and never displace them", () => {
    const s = emptyTlsObservations();
    for (let i = 0; i < TLS_OBSERVATIONS_MAX; i++)
      addTls(s, readZeekSsl(ssl({ uid: `C${i}`, server_name: `n${i % 2}` }), ""));
    for (let i = 0; i < TLS_SHAPES_MAX + 3; i++)
      addTls(s, readZeekSsl(ssl({ uid: `L${i}`, server_name: `late${i}` }), ""));
    const [rows] = tlsFamilies(s, 100000);
    const kept = rows.filter((r) => r.description.startsWith("TLS "));
    expect(kept.filter((r) => /\[sni: n[01]\]/.test(r.description))).toHaveLength(2);
    const over = rows.find((r) => r.description.startsWith("[overflow"))!;
    expect(over.description).toContain(`${TLS_SHAPES_MAX + 3 - (TLS_SHAPES_MAX - 2)} TLS records`);
  });

  it("2. a Suricata record with fingerprint and DER keys its session and its certificate row one way; fingerprint-only facts reach the node", () => {
    const der = Buffer.from("leaf-der-2").toString("base64");
    const both = {
      timestamp: "2023-11-14T22:13:20.5+0000",
      src_ip: "10.0.0.5",
      dest_ip: "203.0.113.9",
      dest_port: 443,
      tls: {
        sni: "evil.example",
        subject: "CN=a",
        fingerprint: "ab".repeat(20),
        certificate: der,
        subjectaltname: ["a.example"],
      },
    };
    const s = emptyTlsObservations();
    addTls(s, readSuricataTls(both, ""));
    for (const c of readSuricataCertificates(both, "")) addTls(s, c);
    const g = graphOf(s);
    const fp = createHash("sha256").update("leaf-der-2").digest("hex");
    const c = node(g.nodes, "certificate", fp)!;
    expect(c.certificate?.records).toBe(1);
    expect(c.certificate?.subject).toBe("CN=a");
    expect(c.notListed).toEqual({ count: 1, listed: ["evil.example"] });
    // fingerprint only, no DER: the session's inline facts feed the node; no certificate record is counted
    const fpOnly = { ...both, tls: { ...both.tls, certificate: undefined } };
    const s2 = emptyTlsObservations();
    addTls(s2, readSuricataTls(fpOnly, ""));
    const c2 = node(graphOf(s2).nodes, "certificate", "ab".repeat(20))!;
    expect(c2.certificate?.records).toBe(0);
    expect(c2.certificate?.subject).toBe("CN=a");
    expect(c2.notListed).toEqual({ count: 1, listed: ["evil.example"] });
    const [row] = mapTlsGraphRows(graphOf(s2), 10);
    expect(row.description).toMatch(/— 1 session record #/);
  });

  it("3. identities, listings and descriptions are the same in any upload order — past 8 and past 256 edges too", () => {
    const many = (n: number) =>
      Array.from({ length: n }, (_, i) =>
        ssl({
          uid: `C${i}`,
          ts: T0 + i,
          server_name: `n${String(i).padStart(3, "0")}.example.net`,
          "id.orig_h": `10.0.${i >> 8}.${i & 255}`,
        }),
      );
    for (const n of [12, 300]) {
      const fwd = mapTlsGraphRows(graphOf(store(many(n), [x509()])), 10)[0];
      const rev = mapTlsGraphRows(graphOf(store([...many(n)].reverse(), [x509()])), 10)[0];
      expect(rev.aggKey).toBe(fwd.aggKey);
      expect(rev.description).toBe(fwd.description);
      expect(rev.canonical?.tlsGraph).toEqual(fwd.canonical?.tlsGraph);
    }
    // a name node's spans and shown name too
    const alt = [
      ssl({ uid: "C1", ts: T0, server_name: "CDN.Example.NET" }),
      ssl({ uid: "C2", ts: T0 + 100, cert_chain_fuids: ["F2"] }),
    ];
    const certs = [x509(), x509({ id: "F2", "certificate.serial": "0099" })];
    const a = mapTlsGraphRows(graphOf(store(alt, certs)), 10).find((r) =>
      r.description.startsWith("TLS-graph name"),
    )!;
    const b = mapTlsGraphRows(graphOf(store([...alt].reverse(), [...certs].reverse())), 10).find((r) =>
      r.description.startsWith("TLS-graph name"),
    )!;
    expect(a.aggKey).toBe(b.aggKey);
    expect(a.description).toBe(b.description);
    expect(a.description).toContain("[name: cdn.example.net]");
  });

  it("4. untimed identities are never 'in sequence'; the envelope says the order is not established", () => {
    const g = graphOf(
      store(
        [ssl({ uid: "C1", ts: "not a time" }), ssl({ uid: "C2", ts: T0 + 100, cert_chain_fuids: ["F2"] })],
        [x509(), x509({ id: "F2", "certificate.serial": "0099" })],
      ),
    );
    const n = node(g.nodes, "name", "cdn.example.net")!;
    expect(n.order).toBe("not established");
    expect(n.sameNames).toBeUndefined();
    const row = mapTlsGraphRows(g, 10).find((r) => r.description.startsWith("TLS-graph name"))!;
    expect(row.description).toContain(
      "[served with: 2 certificates — their order is not established by the readable times — ",
    );
    expect(row.description).not.toContain("in sequence");
    expect(row.canonical?.tlsGraph?.order).toBe("not established");
  });

  it("5. a role-marked and an unmarked x509 record for one FUID with different identities are a disagreement", () => {
    const s = store(
      [ssl()],
      [
        x509({ fingerprint: FP_A }),
        x509({ fingerprint: FP_B, host_cert: undefined, client_cert: undefined }),
      ],
    );
    const [j] = joinSessionsToCertificates(s);
    expect(j.cert).toBeUndefined();
    expect(j.certJoinNote).toBe("records disagree");
    const c = store(
      [ssl({ client_cert_chain_fuids: ["Fcli"], client_subject: "CN=user" })],
      [
        x509({ id: "Fcli", client_cert: true, host_cert: false, fingerprint: FP_A }),
        x509({ id: "Fcli", host_cert: undefined, client_cert: undefined, fingerprint: FP_B }),
      ],
    );
    expect(joinSessionsToCertificates(c)[0].clientCert?.joinNote).toBe("records disagree");
  });

  it("6. an IP SAN is not a DNS name; an IP or wildcard SNI is never compared", () => {
    expect(isTlsHostname("1.2.3.4", "san")).toBe(false);
    expect(isTlsHostname("*.example.net", "san")).toBe(true);
    expect(isTlsHostname("*.example.net", "sni")).toBe(false);
    expect(isTlsHostname("a.example.net", "sni")).toBe(true);
    const sur = readSuricataTls(
      {
        timestamp: "2023-11-14T22:13:20.5+0000",
        src_ip: "10.0.0.5",
        dest_ip: "203.0.113.9",
        dest_port: 443,
        tls: {
          sni: "a",
          fingerprint: "ab".repeat(20),
          subjectaltname: ["1.2.3.4", "a.example.net", "*.b.example"],
        },
      },
      "",
    );
    expect(sur.certificate?.dnsNames).toEqual(["a.example.net", "*.b.example"]);
    const g = graphOf(
      store(
        [
          ssl({ uid: "C1", server_name: "203.0.113.9" }),
          ssl({ uid: "C2", server_name: "*.example.net" }),
          ssl({ uid: "C3", server_name: "x.example.net" }),
        ],
        [x509()],
      ),
    );
    expect(node(g.nodes, "certificate", "certid")!.notListed).toEqual({ count: 0, listed: [] });
  });

  it("7. duplicate certificate records change the shown count but never the identity", () => {
    const one = mapTlsGraphRows(graphOf(store([ssl()], [x509()])), 10)[0];
    const two = mapTlsGraphRows(graphOf(store([ssl()], [x509(), x509({ ts: T0 + 1 })])), 10)[0];
    expect(two.aggKey).toBe(one.aggKey);
    expect(two.description).toContain("2 certificate records");
    expect(one.description).toContain("1 certificate record");
    // and a span's session count is an aggregate too
    const certs = [x509(), x509({ id: "F2", "certificate.serial": "0099" })];
    const a = mapTlsGraphRows(
      graphOf(
        store(
          [ssl({ uid: "C1", ts: T0 }), ssl({ uid: "C2", ts: T0 + 100, cert_chain_fuids: ["F2"] })],
          certs,
        ),
      ),
      10,
    );
    const b = mapTlsGraphRows(
      graphOf(
        store(
          [
            ssl({ uid: "C1", ts: T0 }),
            ssl({ uid: "C3", ts: T0 }),
            ssl({ uid: "C2", ts: T0 + 100, cert_chain_fuids: ["F2"] }),
          ],
          certs,
        ),
      ),
      10,
    );
    const nameA = a.find((r) => r.description.startsWith("TLS-graph name"))!;
    const nameB = b.find((r) => r.description.startsWith("TLS-graph name"))!;
    expect(nameA.aggKey).toBe(nameB.aggKey);
  });

  it("8. overflow rows keep their partition's sensor and sources", () => {
    const rows: Row[] = [];
    for (let i = 0; i < TLS_NODES_MAX + 2; i++) {
      const r = ssl({
        uid: `C${i}`,
        ts: T0 + i,
        ja3: i.toString(16).padStart(32, "0"),
        "observer.name": "s1",
      });
      rows.push(r, { ...r, uid: `D${i}` });
    }
    const zeek = mapTlsGraphRows(graphOf(store(rows)), 20000).find((r) =>
      r.description.startsWith("[overflow"),
    )!;
    expect(zeek.description).toContain("@ s1");
    expect(zeek.canonical?.tlsGraph?.sensor).toEqual({ name: "s1" });
    expect(zeek.sources).toEqual(["Zeek"]);
    const s = emptyTlsObservations();
    for (let i = 0; i < TLS_NODES_MAX + 2; i++)
      for (const k of [0, 1])
        addTls(
          s,
          readSuricataTls(
            {
              timestamp: `2023-11-14T22:13:20.${k}+0000`,
              src_ip: "10.0.0.5",
              dest_ip: "203.0.113.9",
              dest_port: 443,
              tls: { sni: "a.example", ja3: { hash: i.toString(16).padStart(32, "0") } },
            },
            "",
          ),
        );
    const sur = mapTlsGraphRows(graphOf(s), 20000).find((r) => r.description.startsWith("[overflow"))!;
    expect(sur.sources).toEqual(["Suricata"]);
    expect(sur.aggKey).not.toBe(zeek.aggKey);
  });
});

describe("through the network importer", () => {
  it("ssl + x509 in one upload: the session row carries the joined identity and graph rows appear beside it", () => {
    const r = parseNetworkLogs(
      JSON.stringify([
        { ...ssl({ uid: "C1", server_name: "a.example.net" }), _path: "ssl" },
        { ...ssl({ uid: "C2", server_name: "b.example.net", "id.resp_h": "203.0.113.10" }), _path: "ssl" },
        { ...x509(), _path: "x509" },
      ]),
    );
    const sessions = r.events.filter((e) => e.description.startsWith("TLS "));
    expect(sessions).toHaveLength(2);
    expect(sessions.every((e) => e.description.includes("identity from the x509 record"))).toBe(true);
    const graph = r.events.filter((e) => e.description.startsWith("TLS-graph "));
    expect(graph.map((e) => e.canonical?.tlsGraph?.node.kind)).toEqual(["certificate"]);
    expect(graph[0].canonical?.event.type).toBe("tls-graph");
    expect(graph[0].origin).toBe("wire");
    // SAN names are still not indicators; the graph mints none
    const values = r.iocs.map((i) => `${i.type}:${i.value}`);
    expect(values).not.toContain("domain:example.net");
    expect(values.some((v) => v.startsWith("hash:"))).toBe(false);
  });

  it("a Suricata tls upload builds the same nodes from inline certificates", () => {
    const rows = Array.from({ length: 3 }, (_, i) => ({
      timestamp: `2023-11-14T22:1${i}:20.5+0000`,
      event_type: "tls",
      src_ip: "10.0.0.5",
      dest_ip: "203.0.113.9",
      dest_port: 443,
      tls: { sni: `s${i}.example.net`, fingerprint: "ab".repeat(20), subject: "CN=x" },
    }));
    const r = parseNetworkLogs(JSON.stringify(rows));
    const cert = r.events.find((e) => e.description.startsWith("TLS-graph certificate"))!;
    expect(cert.description).toContain(
      "[presented under: 3 names — s0.example.net, s1.example.net, s2.example.net]",
    );
    expect(cert.sources).toEqual(["Suricata"]);
  });
});
