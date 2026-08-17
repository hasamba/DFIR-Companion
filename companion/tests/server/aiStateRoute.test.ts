// GET /cases/:id/ai-state — the read that corrects the pill.
//
// The derivation itself is unit-tested in tests/analysis/aiState.test.ts. This suite is about the
// composition: that the route actually reaches each gate's store, so the endpoint reports a hold
// that really exists rather than a default. A derivation that is right about inputs it never
// receives would leave the pill exactly as wrong as it was.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { createApp } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "d",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

let app: ReturnType<typeof createApp>;
let cases: CaseStore;
let presidio: PresidioPendingStore;

async function build(assets: string[], opts: { aiConfigured?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-aistate-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  assets.forEach((a, i) => s.forensicTimeline.push(ev(`e${i}`, a)));
  await stateStore.save(s);
  presidio = new PresidioPendingStore(cases);
  app = createApp(cases, {
    stateStore,
    assetOverridesStore: new AssetOverridesStore(cases),
    hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
    aiConfigured: opts.aiConfigured ?? true,
  });
}

describe("GET /cases/:id/ai-state", () => {
  it("404s for a case that does not exist", async () => {
    await build(["WIN11"]);
    const res = await request(app).get("/cases/nope/ai-state");
    expect(res.status).toBe(404);
  });

  it("reports idle for a quiet, ungated case", async () => {
    await build(["WIN11", "DC01.windomain.local"]);
    const res = await request(app).get("/cases/c1/ai-state");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ state: "idle", holds: [] });
  });

  // The reload bug, end to end: this case is held, and the endpoint must say so to anything that
  // asks — including a browser that has just loaded and has no event history at all.
  it("reports the duplicate-host hold it can actually see", async () => {
    await build(["WIN11", "WIN11.windomain.local"]);
    const res = await request(app).get("/cases/c1/ai-state");
    expect(res.body.state).toBe("blocked");
    expect(res.body.holds).toHaveLength(1);
    expect(res.body.holds[0]).toMatchObject({ kind: "host-duplicates", count: 1 });
  });

  it("reports a pending Presidio approval", async () => {
    await build(["WIN11"]);
    await presidio.save("c1", [{ value: "Jane Doe", category: "PERSON" }]);
    const res = await request(app).get("/cases/c1/ai-state");
    expect(res.body.state).toBe("blocked");
    expect(res.body.holds[0]).toMatchObject({ kind: "presidio", count: 1 });
  });

  it("stops reporting the hold once the pair is merged", async () => {
    await build(["WIN11", "WIN11.windomain.local"]);
    await request(app)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    const res = await request(app).get("/cases/c1/ai-state");
    expect(res.body.state).not.toBe("blocked");
    expect(res.body.holds).toEqual([]);
  });

  it("reports off when no model is configured, without losing the hold", async () => {
    await build(["WIN11", "WIN11.windomain.local"], { aiConfigured: false });
    const res = await request(app).get("/cases/c1/ai-state");
    expect(res.body.state).toBe("off");
    expect(res.body.holds).toHaveLength(1);
  });
});
