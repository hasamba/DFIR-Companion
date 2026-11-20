import { describe, it, expect, afterEach } from "vitest";
import { join } from "node:path";
import { writeFile } from "node:fs/promises";
import { buildZip, huntTree } from "../helpers/huntExportFixture.js";
import { dropLog, exists, listFiles, makeHarness } from "../helpers/dropHuntHarness.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { huntHeldStoreFor } from "../../src/analysis/huntHeldStore.js";

// #2746: a hunt zip's result files over the size limits wait for the analyst; the rest imports.
// perClientJson holds 9 result files (3 clients x 3 artifacts). Synthetic data only.

const PSLIST_A = "WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.json";
const NETSTAT = [
  "WS-ALPHA-C.0000000000000001/results/Windows.Network.Netstat.json",
  "WS-BRAVO-C.0000000000000002/results/Windows.Network.Netstat.json",
  "SRV-CHARLIE-C.0000000000000003/results/Windows.Network.Netstat.json",
];

afterEach(() => {
  delete process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB;
  delete process.env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB;
});

/** The tree with `paths` grown to about `kb` KB each (the same rows repeated). */
function inflated(paths: readonly string[], kb: number): Record<string, string> {
  const tree = huntTree("perClientJson");
  for (const p of paths) tree[p] = tree[p].repeat(Math.ceil((kb * 1024) / tree[p].length));
  return tree;
}

async function dropped(tree: Record<string, string>, jobManager?: JobManager) {
  const h = await makeHarness(jobManager ? { jobManager } : {});
  await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(tree));
  await h.sweep();
  await h.sweep();
  const held = huntHeldStoreFor(h.store);
  return { h, held };
}

describe("drop folder — hunt zip artifacts over the size limits (#2746)", () => {
  it("holds one PC's oversized artifact, imports the rest, and keeps the zip in drop/", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    process.env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB = "0";
    const { h, held } = await dropped(inflated([PSLIST_A], 200));
    expect(h.calls).toHaveLength(8);
    expect(await exists(join(h.dropDir, "hunt.zip"))).toBe(true);
    const [rec] = await held.list("c1");
    expect(rec.waiting).toBe(true);
    expect(rec.entries).toEqual([
      expect.objectContaining({ member: PSLIST_A, reason: "host", host: "WS-ALPHA", limitMb: 0.1 }),
    ]);
    expect(rec.entries[0].bytes).toBeGreaterThan(100 * 1024);
  });

  it("an artifact over the across-PCs limit is held for every PC", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    process.env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB = "0.15";
    const { h, held } = await dropped(inflated(NETSTAT, 60));
    expect(h.calls).toHaveLength(6);
    const [rec] = await held.list("c1");
    expect(rec.entries.map((e) => e.member).sort()).toEqual([...NETSTAT].sort());
    expect(rec.entries.every((e) => e.reason === "total" && e.groupBytes > 0.15 * 1024 * 1024)).toBe(true);
  });

  it("while it waits only for the analyst, later sweeps leave the zip alone (no new Jobs row)", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    const jobs = new JobManager();
    const { h } = await dropped(inflated([PSLIST_A], 200), jobs);
    const rows = jobs.list("c1").length;
    await h.sweep();
    await h.sweep();
    expect(h.calls).toHaveLength(8);
    expect(jobs.list("c1")).toHaveLength(rows);
  });

  it("Import anyway imports it on the next sweep and the zip completes", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    const { h, held } = await dropped(inflated([PSLIST_A], 200));
    const [rec] = await held.list("c1");
    expect(
      await held.decide("c1", [{ archiveId: rec.archiveId, member: PSLIST_A, decision: "import" }]),
    ).toBe(1);
    await h.sweep();
    expect(h.calls).toHaveLength(9);
    expect(await listFiles(h.dropDir)).toContain("_processed/hunt.zip");
    expect(await held.list("c1")).toEqual([]);
  });

  it("Skip sets it aside with a SKIPPED line; the zip completes as imported", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    const { h, held } = await dropped(inflated([PSLIST_A], 200));
    const [rec] = await held.list("c1");
    await held.decide("c1", [{ archiveId: rec.archiveId, member: PSLIST_A, decision: "skip" }]);
    await h.sweep();
    expect(h.calls).toHaveLength(8);
    expect(await listFiles(h.dropDir)).toContain("_processed/hunt.zip");
    const log = await dropLog(h.dropDir);
    expect(log).toMatch(/SKIPPED\s+hunt\.zip!WS-ALPHA.*Pslist\.json\s+— over the hunt artifact size limit/);
    expect(log).toMatch(/IMPORTED\s+hunt\.zip/);
    expect(await held.list("c1")).toEqual([]);
  });

  it("a decision for an archive that is not held is ignored", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    const { held } = await dropped(inflated([PSLIST_A], 200));
    const n = await held.decide("c1", [{ archiveId: "0".repeat(32), member: PSLIST_A, decision: "import" }]);
    expect(n).toBe(0);
  });

  it("0 turns the limits off: everything imports", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0";
    process.env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB = "0";
    const { h, held } = await dropped(inflated([PSLIST_A], 200));
    expect(h.calls).toHaveLength(9);
    expect(await held.list("c1")).toEqual([]);
  });

  it("a restart mid-zip keeps the holds and the decisions", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(inflated([PSLIST_A], 200)));
    await h.sweep();
    h.hangAfter = 3;
    await h.sweepUntilHang();
    h.restart();
    await h.sweep();
    await h.sweep();
    expect(h.calls).toHaveLength(8); // nothing imported twice, the held file not at all
    const held = huntHeldStoreFor(h.store);
    const [rec] = await held.list("c1");
    expect(rec.entries.map((e) => e.member)).toEqual([PSLIST_A]);
  });

  it("a decision made while the rest imports is applied on the next sweep, not lost", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    const h = await makeHarness();
    const held = huntHeldStoreFor(h.store);
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(inflated([PSLIST_A], 200)));
    h.onIngest = async (n) => {
      if (n !== 2) return;
      const [rec] = await held.list("c1");
      await held.decide("c1", [{ archiveId: rec.archiveId, member: PSLIST_A, decision: "import" }]);
    };
    await h.sweep();
    await h.sweep();
    expect(h.calls).toHaveLength(8);
    expect(await exists(join(h.dropDir, "hunt.zip"))).toBe(true); // not filed as complete
    h.onIngest = null;
    await h.sweep();
    expect(h.calls).toHaveLength(9);
    expect(await listFiles(h.dropDir)).toContain("_processed/hunt.zip");
  });
});
