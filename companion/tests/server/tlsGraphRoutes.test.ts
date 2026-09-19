// #997 (cross-upload half): GET /cases/:id/tls-graph reads the case's TLS-graph rows from the
// forensic timeline AND the super-timeline (every graph row is Info, so after demote they live in
// the second) and merges them by node identity at read time.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { createApp } from "../../src/server.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { TlsGraphBlock } from "../../src/analysis/canonicalTls.js";

const FP = "c".repeat(64);
function graphRow(id: string, sensor: string, names: string[], importBatchId: string): ForensicEvent {
  const block: TlsGraphBlock = {
    node: { kind: "certificate", id: FP, alg: "sha256" },
    sensor: { name: sensor },
    names: { count: names.length, listed: names },
    servers: { count: 1, listed: ["203.0.113.9:443"] },
    clientAddresses: { count: 1, listed: ["10.0.0.5"] },
    first: "2026-01-01T00:00:00.000Z",
    last: "2026-01-01T01:00:00.000Z",
    sessions: 2,
    leads: [],
    coverage: { sessionsRead: 2, sessionsTotal: 2, certificatesRead: 0, certificatesTotal: 0 },
    basis: "records in this upload only; no contact with any observed infrastructure",
  };
  return {
    id,
    timestamp: "2026-01-01T00:00:00.000Z",
    description: `TLS-graph certificate ${FP.slice(0, 8)}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Zeek"],
    importBatchId,
    canonical: createCanonicalEvent({
      event: { category: "network", type: "tls-graph" },
      tlsGraph: block,
      time: { observed: "2026-01-01T00:00:00.000Z", normalized: "2026-01-01T00:00:00.000Z" },
      evidence: { rawRecords: [{ source: "zeek-ssl", locator: `ssl.log:${id}` }] },
      producer: { importer: "network", parserVersion: "1", mappingVersion: "tls-graph-v1" },
    }),
  };
}

describe("GET /cases/:id/tls-graph", () => {
  it("501 without a state store", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-tls-graph-"));
    const app = createApp(new CaseStore(root), {});
    const res = await request(app).get("/cases/c1/tls-graph");
    expect(res.status).toBe(501);
  });

  it("merges forensic-timeline and super-timeline rows into one node per identity", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-tls-graph-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const superTimelineStore = new SuperTimelineStore(store);
    const app = createApp(store, { stateStore, superTimelineStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save({
      ...emptyState("c1"),
      forensicTimeline: [graphRow("f1", "sensor-a", ["a.example.net"], "u1")],
    });
    await superTimelineStore.append("c1", [graphRow("s1", "sensor-b", ["b.example.net"], "u2")]);
    const res = await request(app).get("/cases/c1/tls-graph");
    expect(res.status).toBe(200);
    expect(res.body.rowsRead).toBe(2);
    expect(res.body.nodes).toHaveLength(1);
    expect(res.body.nodes[0].sensors).toBe(2);
    expect(res.body.nodes[0].uploads).toBe(2);
    expect(res.body.nodes[0].names.listed).toEqual(["a.example.net", "b.example.net"]);
    expect(res.body.nodes[0].crossFacts[0]).toMatch(/^names differ between sensors/);
    expect(res.body.basis).toMatch(/no contact with any observed infrastructure/);
  });
});
