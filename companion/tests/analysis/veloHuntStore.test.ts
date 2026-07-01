import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { VeloHuntStore, type VeloHuntJob } from "../../src/analysis/veloHuntStore.js";

const JOB: VeloHuntJob = {
  bundleId: "fast-triage",
  bundleName: "Fast Triage",
  artifacts: ["Windows.System.Pslist", "Windows.Network.Netstat"],
  huntId: "H.ABC123",
  guiUrl: "https://velo.example/app/index.html#/hunts/H.ABC123",
  launchedAt: "2026-06-10T10:00:00.000Z",
  waitMinutes: 10,
  collectAt: "2026-06-10T10:10:00.000Z",
  status: "running",
  target: { os: "windows", excludeLabels: ["servers"] },
};

describe("VeloHuntStore", () => {
  let store: VeloHuntStore;
  let cases: CaseStore;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-velohunt-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new VeloHuntStore(cases);
  });

  it("returns an empty list when no jobs exist", async () => {
    expect(await store.list("c1")).toEqual([]);
    expect(await store.get("c1", "H.NONE")).toBeNull();
  });

  it("upserts and reads a job round-trip", async () => {
    await store.upsert("c1", JOB);
    expect(await store.list("c1")).toEqual([JOB]);
    expect(await store.get("c1", JOB.huntId)).toEqual(JOB);
  });

  it("keeps MULTIPLE concurrent jobs (a second run does not drop the first)", async () => {
    const a = { ...JOB, huntId: "H.AAA", bundleName: "A" };
    const b = { ...JOB, huntId: "H.BBB", bundleName: "B" };
    await store.upsert("c1", a);
    await store.upsert("c1", b);
    const ids = (await store.list("c1")).map((j) => j.huntId);
    expect(ids).toContain("H.AAA");
    expect(ids).toContain("H.BBB");
    expect(ids[0]).toBe("H.BBB");   // newest prepended
  });

  it("updates an existing job in place (matched by huntId, order preserved)", async () => {
    const a = { ...JOB, huntId: "H.AAA" };
    const b = { ...JOB, huntId: "H.BBB" };
    await store.upsert("c1", a);
    await store.upsert("c1", b);
    await store.upsert("c1", { ...a, status: "imported", addedEvents: 42 });
    const list = await store.list("c1");
    expect(list.map((j) => j.huntId)).toEqual(["H.BBB", "H.AAA"]);   // order unchanged
    expect((await store.get("c1", "H.AAA"))!.status).toBe("imported");
    expect((await store.get("c1", "H.AAA"))!.addedEvents).toBe(42);
  });

  it("reads a legacy single-object file as a one-element list", async () => {
    // simulate the old format (one job object, not an array)
    await writeFile(join(cases.stateDir("c1"), "velo-hunt.json"), JSON.stringify(JOB, null, 2), "utf8");
    expect(await store.list("c1")).toEqual([JOB]);
  });

  it("round-trips the deleted and unreachable statuses", async () => {
    await store.upsert("c1", { ...JOB, huntId: "H.DEL1", status: "deleted" });
    await store.upsert("c1", { ...JOB, huntId: "H.UNR1", status: "unreachable" });
    expect((await store.get("c1", "H.DEL1"))!.status).toBe("deleted");
    expect((await store.get("c1", "H.UNR1"))!.status).toBe("unreachable");
  });
});
