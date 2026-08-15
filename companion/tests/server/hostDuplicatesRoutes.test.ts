import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { createApp } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

let app: ReturnType<typeof createApp>;
let assetOverridesStore: AssetOverridesStore;

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

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hostdup-routes-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("a", "WIN11"), ev("b", "WIN11.windomain.local"));
  await stateStore.save(s);
  assetOverridesStore = new AssetOverridesStore(cases);
  app = createApp(cases, {
    stateStore,
    assetOverridesStore,
    hostDuplicateDismissalStore: new HostDuplicateDismissalStore(cases),
  });
});

describe("/cases/:id/host-duplicates", () => {
  it("lists the unresolved pair", async () => {
    const res = await request(app).get("/cases/c1/host-duplicates");
    expect(res.status).toBe(200);
    expect(res.body.pending).toHaveLength(1);
    expect(res.body.pending[0].canonical).toBe("win11.windomain.local");
  });

  it("merging clears the pair", async () => {
    const res = await request(app)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(res.status).toBe(200);
    expect(res.body.pending).toEqual([]);
  });

  it("merges the short name INTO the fqdn, not the reverse", async () => {
    await request(app)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    const overrides = await assetOverridesStore.load("c1");
    // fromId (the duplicate being folded away) -> intoId (the surviving canonical id). A reversed
    // call would instead fold the FQDN into the short name and record the opposite key/value.
    expect(overrides.merges).toEqual({ "host:win11": "host:win11.windomain.local" });
  });

  it("dismissing clears the pair", async () => {
    const res = await request(app)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    expect(res.status).toBe(200);
    expect(res.body.pending).toEqual([]);
  });

  it("a dismissal persists across requests", async () => {
    await request(app)
      .post("/cases/c1/host-duplicates/dismiss")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    const res = await request(app).get("/cases/c1/host-duplicates");
    expect(res.body.pending).toEqual([]);
  });

  it("rejects a request missing a host", async () => {
    const res = await request(app).post("/cases/c1/host-duplicates/merge").send({ canonical: "a.corp" });
    expect(res.status).toBe(400);
  });

  it("rejects a merge of a host into itself", async () => {
    const res = await request(app)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11", other: "win11" });
    expect(res.status).toBe(400);
  });
});
