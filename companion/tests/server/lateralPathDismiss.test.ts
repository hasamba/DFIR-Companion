import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { LateralPathDismissStore, lateralPathKey } from "../../src/analysis/lateralPathDismiss.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

const HASH = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

let store: CaseStore;
let stateStore: StateStore;

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return { timestamp: "", description: "", severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}

// A case whose timeline yields one chain: WS-01 → WS-02, from a tool in a writable location
// (so the vendor-software filter keeps it).
async function seedCaseWithOneChain(caseId: string): Promise<void> {
  await store.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  const state = emptyState(caseId);
  const path = "C:\\Users\\jdoe\\Downloads\\psexec.exe";
  state.forensicTimeline.push(
    ev({ id: "e1", asset: "WS-01", sha256: HASH, path, timestamp: "2026-05-20T09:00:00Z" }),
    ev({ id: "e2", asset: "WS-02", sha256: HASH, path, timestamp: "2026-05-20T10:00:00Z" }),
  );
  await stateStore.save(state);
}

function appWith(dismissStore: LateralPathDismissStore) {
  return createApp(store, {
    reportWriter: new ReportWriter(store, stateStore, { lateralPathDismissals: dismissStore }),
    lateralPathDismissStore: dismissStore,
  });
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-lateral-dismiss-"));
  store = new CaseStore(root);
  stateStore = new StateStore(store);
  setServerLogger(createConsoleLogger("error"));
});

describe("lateral path dismissal", () => {
  it("hides a dismissed chain from the lateral-paths read", async () => {
    await seedCaseWithOneChain("c1");
    const app = appWith(new LateralPathDismissStore(store));

    const before = await request(app).get("/cases/c1/lateral-paths");
    expect(before.status).toBe(200);
    expect(before.body).toHaveLength(1);
    const hostIds = before.body[0].hostIds as string[];

    const dismissed = await request(app).post("/cases/c1/lateral-path-dismissals").send({ hostIds, note: "backup job" });
    expect(dismissed.status).toBe(201);

    const after = await request(app).get("/cases/c1/lateral-paths");
    expect(after.body).toEqual([]);
  });

  it("does NOT touch the underlying evidence — dismissing an inference is not a false positive", async () => {
    await seedCaseWithOneChain("c1");
    const app = appWith(new LateralPathDismissStore(store));
    const paths = await request(app).get("/cases/c1/lateral-paths");
    await request(app).post("/cases/c1/lateral-path-dismissals").send({ hostIds: paths.body[0].hostIds, note: "" });

    // The events that produced the chain are still in the case timeline.
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.map((e) => e.id)).toEqual(["e1", "e2"]);
  });

  it("returns the dismissed chain, flagged, under ?includeDismissed=1 so it can be reviewed and undone", async () => {
    await seedCaseWithOneChain("c1");
    const app = appWith(new LateralPathDismissStore(store));
    const paths = await request(app).get("/cases/c1/lateral-paths");
    await request(app).post("/cases/c1/lateral-path-dismissals").send({ hostIds: paths.body[0].hostIds, note: "backup job" });

    const review = await request(app).get("/cases/c1/lateral-paths?includeDismissed=1");
    expect(review.body).toHaveLength(1);
    expect(review.body[0].dismissed).toBe(true);
    expect(review.body[0].dismissalNote).toBe("backup job");
  });

  it("restores a chain when the dismissal is deleted", async () => {
    await seedCaseWithOneChain("c1");
    const app = appWith(new LateralPathDismissStore(store));
    const paths = await request(app).get("/cases/c1/lateral-paths");
    const hostIds = paths.body[0].hostIds as string[];
    await request(app).post("/cases/c1/lateral-path-dismissals").send({ hostIds, note: "" });
    expect((await request(app).get("/cases/c1/lateral-paths")).body).toEqual([]);

    const del = await request(app).delete(`/cases/c1/lateral-path-dismissals/${encodeURIComponent(lateralPathKey(hostIds))}`);
    expect(del.status).toBe(204);
    expect((await request(app).get("/cases/c1/lateral-paths")).body).toHaveLength(1);
  });

  it("survives re-derivation: the dismissal still applies after the case is re-read", async () => {
    await seedCaseWithOneChain("c1");
    const dismissStore = new LateralPathDismissStore(store);
    const app = appWith(dismissStore);
    const paths = await request(app).get("/cases/c1/lateral-paths");
    await request(app).post("/cases/c1/lateral-path-dismissals").send({ hostIds: paths.body[0].hostIds, note: "" });

    // A brand-new app instance (fresh stores, nothing cached) must honour the persisted dismissal.
    const reopened = appWith(new LateralPathDismissStore(store));
    expect((await request(reopened).get("/cases/c1/lateral-paths")).body).toEqual([]);
  });

  it("lists dismissals and rejects a route that is not a chain", async () => {
    await seedCaseWithOneChain("c1");
    const app = appWith(new LateralPathDismissStore(store));
    await request(app).post("/cases/c1/lateral-path-dismissals").send({ hostIds: ["host:ws-01", "host:ws-02"], note: "n" });

    const list = await request(app).get("/cases/c1/lateral-path-dismissals");
    expect(list.status).toBe(200);
    expect(list.body).toHaveLength(1);
    expect(list.body[0].hostIds).toEqual(["host:ws-01", "host:ws-02"]);

    const bad = await request(app).post("/cases/c1/lateral-path-dismissals").send({ hostIds: ["host:only-one"], note: "" });
    expect(bad.status).toBe(400);
  });

  it("404s when restoring something that was never dismissed", async () => {
    await seedCaseWithOneChain("c1");
    const app = appWith(new LateralPathDismissStore(store));
    const res = await request(app).delete("/cases/c1/lateral-path-dismissals/host%3Anope%3Ehost%3Anope2");
    expect(res.status).toBe(404);
  });

  it("501s when the store isn't configured", async () => {
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const app = createApp(store, {});
    expect((await request(app).get("/cases/c1/lateral-path-dismissals")).status).toBe(501);
  });
});
