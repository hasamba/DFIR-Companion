// #993 (proxy -> workstation half): GET /cases/:id/proxy-host-identity-matches. Real
// StateStore-backed events, real hostBinding.ts resolution end-to-end.
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
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { InvestigationState, ForensicEvent } from "../../src/analysis/stateTypes.js";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-proxy-host-identity-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const app = createApp(store, { stateStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

async function makeAppWithSuperTimeline() {
  const root = await mkdtemp(join(tmpdir(), "dfir-proxy-host-identity-super-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const app = createApp(store, { stateStore, superTimelineStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, superTimelineStore };
}

function logonEvent(id: string, host: string, client: string, ip: string, ts: string): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: `logon @ ${host}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: host,
    canonical: createCanonicalEvent({
      event: { category: "authentication", type: "logon", outcome: "success" },
      target: { kind: "host", name: host },
      authentication: { logonType: 3 },
      session: { terminal: client },
      network: { source: { address: ip, provenance: "edge-observed" } }, // #1265: the real Zeek/EVTX stamp
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "test", locator: `row:${id}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

function webEvent(id: string, ip: string, ts: string): ForensicEvent {
  return {
    id,
    timestamp: ts,
    description: `GET / from ${ip}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "web-request" },
      network: { source: { address: ip, provenance: "edge-observed" } }, // #1265: the real Zeek/EVTX stamp
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: "zeek-http", locator: `row:${id}` }] },
      producer: { importer: "zeek", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

function stateWith(events: ForensicEvent[]): InvestigationState {
  return { ...emptyState("c1"), forensicTimeline: events, updatedAt: new Date().toISOString() };
}

describe("GET /cases/:id/proxy-host-identity-matches", () => {
  it("returns 501 when the state store is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-proxy-host-identity-bare-"));
    const store = new CaseStore(root);
    const bareApp = createApp(store, {});
    await request(bareApp)
      .post("/cases")
      .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(bareApp).get("/cases/c1/proxy-host-identity-matches");
    expect(res.status).toBe(501);
  });

  it("resolves a proxy request's own source IP to the client host a 4624 logon names", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        logonEvent("l1", "fs-01", "ws-042", "10.0.0.5", "2026-06-10T12:00:00Z"),
        webEvent("w1", "10.0.0.5", "2026-06-10T12:05:00Z"),
      ]),
    );
    const res = await request(app).get("/cases/c1/proxy-host-identity-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches).toHaveLength(1);
    expect(res.body.matches[0]).toMatchObject({ eventId: "w1", outcome: "matched" });
    expect(res.body.matches[0].hosts).toEqual([
      { host: "ws-042", sampleTime: "2026-06-10T12:00:00Z", evidenceEventIds: ["l1"], via: ["address"] },
    ]);
  });

  it("uses the default 6-hour tolerance when none is given, and rejects a match outside it", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        logonEvent("l1", "fs-01", "ws-042", "10.0.0.5", "2026-06-10T00:00:00Z"),
        webEvent("w1", "10.0.0.5", "2026-06-10T12:00:00Z"), // 12h later, outside the 6h default
      ]),
    );
    const res = await request(app).get("/cases/c1/proxy-host-identity-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches[0].outcome).toBe("no-match");
    expect(res.body.matches[0].toleranceMs).toBe(21_600_000);
  });

  it("accepts an overriding ?toleranceMs= query param", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        logonEvent("l1", "fs-01", "ws-042", "10.0.0.5", "2026-06-10T00:00:00Z"),
        webEvent("w1", "10.0.0.5", "2026-06-10T12:00:00Z"),
      ]),
    );
    const res = await request(app).get("/cases/c1/proxy-host-identity-matches?toleranceMs=43200000");
    expect(res.status).toBe(200);
    expect(res.body.matches[0].outcome).toBe("matched");
    expect(res.body.matches[0].toleranceMs).toBe(43_200_000);
  });

  // #1189: toleranceMs=0 is a real, meaningful value (an exact-instant match), not a degenerate
  // one — must be accepted, not 400ed.
  it("accepts toleranceMs=0 as an exact-instant match", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(
      stateWith([
        logonEvent("l1", "fs-01", "ws-042", "10.0.0.5", "2026-06-10T12:00:00Z"),
        webEvent("w1", "10.0.0.5", "2026-06-10T12:00:00Z"),
      ]),
    );
    const res = await request(app).get("/cases/c1/proxy-host-identity-matches?toleranceMs=0");
    expect(res.status).toBe(200);
    expect(res.body.matches[0]).toMatchObject({ outcome: "matched", toleranceMs: 0 });
  });

  it("400s a malformed toleranceMs instead of silently clamping it", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(stateWith([]));
    const res = await request(app).get("/cases/c1/proxy-host-identity-matches?toleranceMs=-5");
    expect(res.status).toBe(400);
    const res2 = await request(app).get("/cases/c1/proxy-host-identity-matches?toleranceMs=notanumber");
    expect(res2.status).toBe(400);
  });

  it("400s a toleranceMs past the documented ceiling instead of silently accepting it", async () => {
    const { app, stateStore } = await makeApp();
    await stateStore.save(stateWith([]));
    const res = await request(app).get("/cases/c1/proxy-host-identity-matches?toleranceMs=9999999999999");
    expect(res.status).toBe(400);
  });

  it("returns an empty match list for a well-formed but nonexistent case, never a 500 (StateStore.load's own real behavior)", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/nonexistent-case/proxy-host-identity-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches).toEqual([]);
  });

  // #1277: dab20efe added the forensic ∪ super-timeline union read (#1243) but neither route's own
  // suite proved it. The web-log row here lives ONLY in the super-timeline (as it would under the
  // severity gate, which routes Info rows there) — if the route ever regressed to reading
  // state.forensicTimeline alone, this event would vanish and the match below would not appear.
  it("resolves a proxy row that lives only in the super-timeline, not the forensic timeline", async () => {
    const { app, stateStore, superTimelineStore } = await makeAppWithSuperTimeline();
    await stateStore.save(
      stateWith([logonEvent("l1", "fs-01", "ws-042", "10.0.0.5", "2026-06-10T12:00:00Z")]),
    );
    await superTimelineStore.append("c1", [webEvent("w1", "10.0.0.5", "2026-06-10T12:05:00Z")]);

    const res = await request(app).get("/cases/c1/proxy-host-identity-matches");
    expect(res.status).toBe(200);
    expect(res.body.matches).toHaveLength(1);
    expect(res.body.matches[0]).toMatchObject({ eventId: "w1", outcome: "matched" });
    expect(res.body.matches[0].hosts).toEqual([
      { host: "ws-042", sampleTime: "2026-06-10T12:00:00Z", evidenceEventIds: ["l1"], via: ["address"] },
    ]);
  });
});
