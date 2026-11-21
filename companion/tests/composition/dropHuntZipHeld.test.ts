import { describe, it, expect, afterEach } from "vitest";
import { join } from "node:path";
import { mkdir, rename, writeFile } from "node:fs/promises";
import { buildZip, huntTree } from "../helpers/huntExportFixture.js";
import { dropLog, exists, listFiles, makeHarness, type Harness } from "../helpers/dropHuntHarness.js";
import { huntHeldStoreFor } from "../../src/analysis/huntHeldStore.js";
import { decideHeldFile } from "../../src/analysis/dropHeldFiles.js";

// #2746 / #2755: a hunt result over the size limits waits as a file in drop/_held/; Import anyway moves
// it back into drop/ (it imports), Skip moves it to drop/_skipped/ (moving it back imports it).
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

async function settle(h: Harness): Promise<void> {
  await h.sweep();
  await h.sweep();
}

const decide = (h: Harness, rel: string, decision: "import" | "skip") =>
  decideHeldFile(huntHeldStoreFor(h.store), "c1", h.dropDir, rel, decision);

describe("drop folder — hunt zip results over the size limits (#2755)", () => {
  it("extracts the oversized member to _held/, imports the rest, and the zip completes", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    process.env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB = "0";
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(inflated([PSLIST_A], 200)));
    await settle(h);
    expect(h.calls).toHaveLength(8);
    const files = await listFiles(h.dropDir);
    expect(files).toContain("_processed/hunt.zip");
    expect(files).toContain(`_held/hunt/${PSLIST_A}`);
    const [info] = (await huntHeldStoreFor(h.store).load("c1")).held;
    expect(info).toMatchObject({
      rel: `_held/hunt/${PSLIST_A}`,
      origin: "zip",
      reason: "host",
      host: "WS-ALPHA",
    });
    expect(await dropLog(h.dropDir)).toMatch(
      /IMPORTED\s+hunt\.zip\s+— 1 result file\(s\) held over the size limit/,
    );
  });

  it("#2805: one artifact is never summed across PCs — small per-PC files all import", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    process.env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB = "0.15";
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(inflated(NETSTAT, 60)));
    await settle(h);
    expect(h.calls).toHaveLength(9);
    expect((await listFiles(h.dropDir)).some((f) => f.startsWith("_held/"))).toBe(false);
  });

  it("#2805: a file held by the old across-PCs sum is released by the next sweep and imports", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    const h = await makeHarness();
    const small = NETSTAT[0];
    const heldRel = `_held/hunt/${small}`;
    await mkdir(join(h.dropDir, "_held/hunt", small, ".."), { recursive: true });
    await writeFile(join(h.dropDir, heldRel), inflated([small], 1)[small]);
    await huntHeldStoreFor(h.store).putHeld("c1", {
      ...{ rel: heldRel, origin: "zip", source: "hunt.zip", artifact: "Windows.Network.Netstat" },
      ...{ host: "WS-ALPHA", bytes: 1024, groupBytes: 900 * 1024 * 1024, reason: "total", limitMb: 200 },
    });
    await settle(h); // released back into drop/
    await settle(h); // settled and imported
    expect((await listFiles(h.dropDir)).some((f) => f.startsWith("_held/"))).toBe(false);
    expect(h.calls.map((c) => c.name)).toContain("Windows.Network.Netstat.json");
  });

  it("Import anyway moves it back into drop/ and the next sweep imports it, with its PC's host", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(inflated([PSLIST_A], 200)));
    await settle(h);
    const r = await decide(h, `_held/hunt/${PSLIST_A}`, "import");
    expect(r.to).toBe(`hunt/${PSLIST_A}`);
    await settle(h);
    expect(h.calls).toHaveLength(9);
    expect(h.calls[8]).toMatchObject({ name: "Windows.System.Pslist.json", host: "WS-ALPHA" });
    expect((await listFiles(h.dropDir)).some((f) => f.startsWith("_held/"))).toBe(false);
  });

  it("Skip moves it to _skipped/; moving it back into drop/ imports it", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(inflated([PSLIST_A], 200)));
    await settle(h);
    const r = await decide(h, `_held/hunt/${PSLIST_A}`, "skip");
    expect(r.to).toBe(`_skipped/hunt/${PSLIST_A}`);
    await settle(h);
    expect(h.calls).toHaveLength(8); // skipped: not imported
    const back = join(h.dropDir, "hunt", ...PSLIST_A.split("/"));
    await mkdir(join(back, ".."), { recursive: true });
    await rename(join(h.dropDir, "_skipped", "hunt", ...PSLIST_A.split("/")), back);
    await settle(h);
    expect(h.calls).toHaveLength(9); // approved: not held again
  });

  it("0 turns the limits off: everything imports", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0";
    process.env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB = "0";
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(inflated([PSLIST_A], 200)));
    await settle(h);
    expect(h.calls).toHaveLength(9);
    expect(await exists(join(h.dropDir, "_held"))).toBe(false);
  });

  it("a restart mid-zip does not extract or import anything twice", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(inflated([PSLIST_A], 200)));
    await h.sweep();
    h.hangAfter = 3;
    await h.sweepUntilHang();
    h.restart();
    await settle(h);
    expect(h.calls).toHaveLength(8);
    expect((await listFiles(h.dropDir)).filter((f) => f.startsWith("_held/"))).toEqual([
      `_held/hunt/${PSLIST_A}`,
    ]);
  });
});

describe("drop folder — manually dropped Velociraptor results over the size limits (#2755)", () => {
  it("a single Velociraptor result file over the per-PC limit waits in _held/; Import anyway imports it", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    const h = await makeHarness();
    const big = inflated([PSLIST_A], 200)[PSLIST_A];
    await writeFile(join(h.dropDir, "Windows.System.Pslist.json"), big);
    await settle(h);
    expect(h.calls).toHaveLength(0);
    expect(await listFiles(h.dropDir)).toContain("_held/Windows.System.Pslist.json");
    await decide(h, "_held/Windows.System.Pslist.json", "import");
    await settle(h);
    expect(h.calls).toHaveLength(1);
  });

  it("#2805: a dropped file with several PCs' results has the several-PCs limit", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    process.env.DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB = "0.5";
    const h = await makeHarness();
    const rows = (client: string) =>
      Array.from({ length: 900 }, (_, i) =>
        JSON.stringify({ ClientId: client, Fqdn: `${client}.example.test`, Name: `proc${i}.exe`, Pid: i }),
      ).join("\n");
    const several = `${rows("C.0000000000000001")}\n${rows("C.0000000000000002")}\n`; // ~0.17 MB: over the per-PC limit, under the several-PCs one
    await writeFile(join(h.dropDir, "Windows.System.Pslist.json"), several);
    await settle(h);
    expect(await exists(join(h.dropDir, "_held"))).toBe(false);
    expect(h.calls).toHaveLength(1);
  });

  it("a large file that is not Velociraptor results imports as today", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.01";
    const h = await makeHarness();
    const thor = JSON.stringify({
      level: "Warning",
      module: "Filescan",
      message: "x".repeat(20000),
      time: "2026-05-02T10:00:00Z",
      file: "C:\\Temp\\a.exe",
    });
    await writeFile(join(h.dropDir, "thor.json"), thor);
    await settle(h);
    expect(await exists(join(h.dropDir, "_held"))).toBe(false);
  });

  it("an unzipped hunt folder holds its oversized imports and releases the rest", async () => {
    process.env.DFIR_HUNT_ARTIFACT_HOST_MAX_MB = "0.1";
    const h = await makeHarness();
    for (const [p, text] of Object.entries(inflated([PSLIST_A], 200))) {
      const full = join(h.dropDir, "hunt", ...p.split("/"));
      await mkdir(join(full, ".."), { recursive: true });
      await writeFile(full, text);
    }
    await settle(h);
    expect(h.calls).toHaveLength(8);
    expect(await listFiles(h.dropDir)).toContain(`_held/hunt/${PSLIST_A}`);
    const state = await huntHeldStoreFor(h.store).load("c1");
    expect(state.pending).toEqual([]); // carried out
    expect(state.held[0]).toMatchObject({ origin: "folder", host: "WS-ALPHA" });
  });
});
