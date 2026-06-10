import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
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

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-velohunt-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new VeloHuntStore(cases);
  });

  it("returns null when no job exists", async () => {
    expect(await store.load("c1")).toBeNull();
  });

  it("saves and loads a job round-trip", async () => {
    await store.save("c1", JOB);
    expect(await store.load("c1")).toEqual(JOB);
  });

  it("overwrites the previous job (one active job per case)", async () => {
    await store.save("c1", JOB);
    const done: VeloHuntJob = { ...JOB, status: "imported", importedAt: "2026-06-10T10:10:30.000Z", addedEvents: 42, addedIocs: 5 };
    await store.save("c1", done);
    const loaded = await store.load("c1");
    expect(loaded!.status).toBe("imported");
    expect(loaded!.addedEvents).toBe(42);
  });
});
