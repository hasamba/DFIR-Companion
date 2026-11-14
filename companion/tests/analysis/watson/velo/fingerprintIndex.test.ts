import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CaseStore } from "../../../../src/storage/caseStore.js";
import { HuntFingerprintStore } from "../../../../src/analysis/ai/watson/velo/huntFingerprintStore.js";
import {
  withFingerprintIndex,
  loadLaunchFingerprints,
} from "../../../../src/analysis/ai/watson/velo/fingerprintIndex.js";
import { checkLaunch } from "../../../../src/analysis/ai/watson/velo/launchCheck.js";
import { HuntOutcomeStore } from "../../../../src/analysis/huntOutcomeStore.js";
import { recordDeploy, type HuntDeployInput } from "../../../../src/analysis/huntOutcomes.js";
import { matchClient } from "../../../../src/integrations/velociraptor/clientInventory.js";
import { SNAPSHOT_STATE_FILES } from "../../../../src/analysis/investigationStateFiles.js";

let dir: string;
let cases: CaseStore;
let index: HuntFingerprintStore;
let outcomes: HuntOutcomeStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "hunt-fp-"));
  cases = { stateDir: () => dir } as unknown as CaseStore;
  index = new HuntFingerprintStore(cases);
  outcomes = new HuntOutcomeStore(cases);
});

const deployInput = (n: number): HuntDeployInput => ({
  source: "fleet",
  title: `hunt ${n}`,
  vql: `SELECT * FROM pslist() WHERE Pid = ${n}`,
  deployedAt: `2026-11-14T00:00:${String(n % 60).padStart(2, "0")}Z`,
});

// The real recordHuntDeploy: load, recordDeploy capped at 50, save.
const innerRecord = async (caseId: string, input: HuntDeployInput): Promise<void> => {
  await outcomes.save(caseId, recordDeploy(await outcomes.load(caseId), input, 50));
};

describe("HuntFingerprintStore", () => {
  it("is empty for a case that never deployed", async () => {
    expect((await index.load("c1")).size).toBe(0);
  });

  it("appends and never drops", async () => {
    await index.add("c1", ["aa", "bb"]);
    await index.add("c1", ["cc", "aa", ""]);
    expect([...(await index.load("c1"))].sort()).toEqual(["aa", "bb", "cc"]);
  });

  it("refuses to read a corrupt file instead of reporting nothing ran", async () => {
    await writeFile(join(dir, "hunt-fingerprints.json"), "{not json");
    await expect(index.load("c1")).rejects.toThrow();
  });

  it("keeps every entry when two deploys write at once", async () => {
    await Promise.all(Array.from({ length: 20 }, (_, i) => index.add("c1", [`fp${i}`])));
    expect((await index.load("c1")).size).toBe(20);
  });

  it("stays out of backup and restore", () => {
    expect(SNAPSHOT_STATE_FILES as readonly string[]).not.toContain("hunt-fingerprints.json");
  });
});

describe("withFingerprintIndex", () => {
  it("still blocks the first VQL after the 51st distinct launch", async () => {
    const record = withFingerprintIndex(innerRecord, index, () => {});
    for (let n = 1; n <= 51; n++) await record("c1", deployInput(n));
    expect((await outcomes.load("c1")).length).toBe(50);
    const deployed = await loadLaunchFingerprints("c1", index, outcomes);
    const r = checkLaunch(
      { vql: deployInput(1).vql!, mode: "hunt" },
      { inventory: [], deployed, matchClient },
    );
    expect(r).toEqual({ ok: false, reason: "this hunt already ran on the case" });
  });

  it("indexes the deploy even when the outcome recorder fails", async () => {
    const failing = async (): Promise<void> => {
      throw new Error("outcome store down");
    };
    const record = withFingerprintIndex(failing, index, () => {});
    await expect(record("c1", deployInput(7))).rejects.toThrow("outcome store down");
    expect((await index.load("c1")).size).toBeGreaterThan(0);
  });

  it("logs and carries on when the index write fails", async () => {
    const lines: string[] = [];
    const broken = {
      add: async () => Promise.reject(new Error("disk full")),
    } as unknown as HuntFingerprintStore;
    const record = withFingerprintIndex(innerRecord, broken, (l) => lines.push(l));
    await record("c1", deployInput(3));
    expect(lines.join(" ")).toContain("disk full");
    expect((await outcomes.load("c1")).length).toBe(1);
  });

  it("skips bundles, which carry no VQL", async () => {
    const record = withFingerprintIndex(innerRecord, index, () => {});
    await record("c1", { source: "bundle", title: "b", deployedAt: "2026-11-14T00:00:00Z" });
    expect((await index.load("c1")).size).toBe(0);
  });
});

describe("loadLaunchFingerprints", () => {
  it("unions the index with outcomes recorded before the index existed", async () => {
    await innerRecord("c1", deployInput(9));
    const raw = await readFile(join(dir, "hunt-outcomes.json"), "utf8");
    expect(raw).toContain("vqlFingerprint");
    const deployed = await loadLaunchFingerprints("c1", index, outcomes);
    expect(
      checkLaunch({ vql: deployInput(9).vql!, mode: "hunt" }, { inventory: [], deployed, matchClient }).ok,
    ).toBe(false);
  });
});
