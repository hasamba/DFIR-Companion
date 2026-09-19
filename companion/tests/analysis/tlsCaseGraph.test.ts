import { describe, it, expect } from "vitest";
import {
  buildTlsCaseGraph,
  TLS_CASE_NODES_MAX,
  TLS_CASE_OBSERVATIONS_MAX,
} from "../../src/analysis/tlsCaseGraph.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import type { TlsGraphBlock } from "../../src/analysis/canonicalTls.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #997, the cross-upload / cross-sensor half: the TLS-graph rows every upload wrote, merged by
// node identity at read time — each edge still names the sensor and upload that observed it,
// differences between sensors are stated, and nothing becomes "the same operator".

const FP = "a".repeat(64);
const edge = (listed: string[], over: Partial<TlsGraphBlock["names"]> = {}) => ({
  count: listed.length,
  listed,
  ...over,
});

const block = (over: Partial<TlsGraphBlock>): TlsGraphBlock => ({
  node: { kind: "certificate", id: FP, alg: "sha256" },
  sensor: { name: "sensor-a" },
  names: edge(["a.example.net"]),
  servers: edge(["203.0.113.9:443"]),
  clientAddresses: edge(["10.0.0.5"]),
  first: "2026-01-01T00:00:00.000Z",
  last: "2026-01-01T01:00:00.000Z",
  sessions: 3,
  leads: [],
  coverage: { sessionsRead: 3, sessionsTotal: 3, certificatesRead: 1, certificatesTotal: 1 },
  basis: "records in this upload only; no contact with any observed infrastructure",
  ...over,
});

let seq = 0;
const row = (b: Partial<TlsGraphBlock>, over: Partial<ForensicEvent> = {}): ForensicEvent =>
  ({
    id: `e${++seq}`,
    timestamp: "2026-01-01T00:00:00.000Z",
    description: "TLS-graph …",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Zeek"],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "tls-graph" },
      tlsGraph: block(b),
      time: { observed: "2026-01-01T00:00:00.000Z", normalized: "2026-01-01T00:00:00.000Z" },
      evidence: { rawRecords: [{ source: "zeek-ssl", locator: `ssl.log:${seq}` }] },
      producer: { importer: "network", parserVersion: "1", mappingVersion: "tls-graph-v1" },
    }),
    ...over,
  }) as unknown as ForensicEvent;

describe("the case-wide TLS graph", () => {
  it("one certificate seen by two sensors in two uploads is one node with two observations and the union of edges", () => {
    const g = buildTlsCaseGraph([
      row({}, { importBatchId: "u1", importedAt: "2026-02-01T00:00:00Z" }),
      row(
        {
          sensor: { name: "sensor-b" },
          names: edge(["b.example.net"]),
          first: "2026-01-02T00:00:00.000Z",
          last: "2026-01-03T00:00:00.000Z",
          sessions: 5,
        },
        { importBatchId: "u2", importedAt: "2026-02-02T00:00:00Z" },
      ),
      row({ node: { kind: "name", id: "a.example.net" }, names: undefined, certificates: edge([FP]) }),
    ]);
    expect(g.nodes).toHaveLength(2);
    const cert = g.nodes.find((n) => n.kind === "certificate")!;
    expect(cert.id).toBe(FP);
    expect(cert.observations).toHaveLength(2);
    expect(cert.observations.map((o) => o.sensor)).toEqual(["sensor-a", "sensor-b"]);
    expect(cert.observations.map((o) => o.upload?.id)).toEqual(["u1", "u2"]);
    expect(cert.sessions).toBe(8);
    expect(cert.sensors).toBe(2);
    expect(cert.uploads).toBe(2);
    expect(cert.first).toBe("2026-01-01T00:00:00.000Z");
    expect(cert.last).toBe("2026-01-03T00:00:00.000Z");
    expect(cert.names).toEqual({ count: 2, listed: ["a.example.net", "b.example.net"] });
    // What each sensor saw is stated, never resolved.
    expect(cert.crossFacts).toContain(
      "names differ between sensors: sensor-a only a.example.net; sensor-b only b.example.net",
    );
    expect(cert.crossFacts.join(" ")).not.toMatch(/operator|moved|malicious/);
  });

  it("an incomplete edge (at least) is unioned as at least, and the sensor comparison is withheld", () => {
    const g = buildTlsCaseGraph([
      row({ names: edge(["a.example.net"], { atLeast: true, count: 300 }) }),
      row({ sensor: { name: "sensor-b" }, names: edge(["b.example.net"]) }),
    ]);
    const cert = g.nodes[0];
    expect(cert.names.atLeast).toBe(true);
    expect(cert.crossFacts.some((f) => f.startsWith("names differ"))).toBe(false);
    expect(cert.crossFacts).toContain("names not compared between sensors: a sensor's list is incomplete");
  });

  it("a name node's certificate spans are unioned with each sensor's own range", () => {
    const g = buildTlsCaseGraph([
      row({
        node: { kind: "name", id: "a.example.net" },
        names: undefined,
        certificates: edge([FP]),
        spans: [
          {
            identity: FP,
            alg: "sha256",
            first: "2026-01-01T00:00:00.000Z",
            last: "2026-01-01T01:00:00.000Z",
            sessions: 3,
          },
        ],
      }),
      row({
        node: { kind: "name", id: "a.example.net" },
        sensor: { name: "sensor-b" },
        names: undefined,
        certificates: edge(["b".repeat(64)]),
        spans: [
          {
            identity: "b".repeat(64),
            alg: "sha256",
            first: "2026-01-05T00:00:00.000Z",
            last: "2026-01-06T00:00:00.000Z",
            sessions: 2,
          },
        ],
      }),
    ]);
    const name = g.nodes[0];
    expect(name.kind).toBe("name");
    expect(name.certificates).toEqual({ count: 2, listed: [FP, "b".repeat(64)] });
    expect(name.spans.map((s) => `${s.identity.slice(0, 4)}@${s.sensor}`)).toEqual([
      `aaaa@sensor-a`,
      `bbbb@sensor-b`,
    ]);
    expect(name.crossFacts).toContain(
      "served with different certificates on different sensors: sensor-a only aaaaaaaa…aaaa; sensor-b only bbbbbbbb…bbbb",
    );
  });

  it("leads keep their sensor; folded rows and non-graph rows are ignored; JA3S passes through", () => {
    const g = buildTlsCaseGraph([
      row({ leads: [{ kind: "many-names", words: "presented under 9 names — …" }] }),
      row({ node: { kind: "certificate", id: "" }, folded: true, records: 12 }),
      row({ node: { kind: "ja3s", id: "f".repeat(32) }, names: edge([]), sessions: 2 }),
      {
        id: "x",
        timestamp: "",
        description: "not a graph row",
        severity: "Info",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
      } as unknown as ForensicEvent,
    ]);
    expect(g.nodes.map((n) => n.kind).sort()).toEqual(["certificate", "ja3s"]);
    expect(g.nodes.find((n) => n.kind === "certificate")!.leads).toEqual([
      { sensor: "sensor-a", kind: "many-names", words: "presented under 9 names — …" },
    ]);
    expect(g.rowsRead).toBe(3);
    expect(g.folded).toBe(12);
  });

  it("is bounded: nodes past the cap are counted, observations past the cap are counted per node", () => {
    const many = Array.from({ length: TLS_CASE_NODES_MAX + 2 }, (_, i) =>
      row({ node: { kind: "name", id: `n${i}.example.net` }, names: undefined }),
    );
    const g = buildTlsCaseGraph(many);
    expect(g.nodes).toHaveLength(TLS_CASE_NODES_MAX);
    expect(g.notShown).toBe(2);
    const obs = Array.from({ length: TLS_CASE_OBSERVATIONS_MAX + 3 }, (_, i) =>
      row({ sensor: { name: `s${i}` } }),
    );
    const one = buildTlsCaseGraph(obs).nodes[0];
    expect(one.observations).toHaveLength(TLS_CASE_OBSERVATIONS_MAX);
    expect(one.observationsNotShown).toBe(3);
    expect(one.sensors).toBe(TLS_CASE_OBSERVATIONS_MAX + 3);
  });

  it("orders leads first, then the most sessions", () => {
    const g = buildTlsCaseGraph([
      row({ node: { kind: "name", id: "quiet.example.net" }, names: undefined, sessions: 1 }),
      row({ node: { kind: "name", id: "busy.example.net" }, names: undefined, sessions: 50 }),
      row({
        node: { kind: "name", id: "lead.example.net" },
        names: undefined,
        sessions: 2,
        leads: [{ kind: "certificates-alternate", words: "…" }],
      }),
    ]);
    expect(g.nodes.map((n) => n.id)).toEqual(["lead.example.net", "busy.example.net", "quiet.example.net"]);
  });
});
