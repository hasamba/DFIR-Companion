import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { writeFile, mkdir } from "node:fs/promises";
import { expectedRowKeys, huntTree, writeTree, type HuntLayout } from "../helpers/huntExportFixture.js";
import { dropLog, exists, listFiles, makeHarness } from "../helpers/dropHuntHarness.js";

// #2714: an unzipped Velociraptor hunt export in the drop folder imports every row exactly once,
// with the client folder's host, and sets every other copy and the metadata aside in _skipped/.

async function dropHunt(layout: HuntLayout) {
  const h = await makeHarness();
  const tree = huntTree(layout, "Hunt1");
  await writeTree(h.dropDir, tree);
  await h.sweep(); // first sight
  await h.sweep(); // settled → handled
  return { h, tree };
}

describe("drop folder — unzipped Velociraptor hunt export (#2714)", () => {
  for (const layout of ["full", "perClientJson", "huntWide", "csvOnlyUsers"] as const) {
    it(`${layout}: every row imported exactly once, with the right host`, async () => {
      const { h, tree } = await dropHunt(layout);
      expect(h.rowKeys()).toEqual(expectedRowKeys(layout));
      // Nothing is left in drop/ and nothing is deleted: imports under _processed/, the rest under _skipped/.
      const after = await listFiles(h.dropDir);
      const kept = after.filter((p) => p.startsWith("_processed/") || p.startsWith("_skipped/"));
      expect(kept.map((p) => p.replace(/^_(processed|skipped)\//, "")).sort()).toEqual(
        Object.keys(tree).sort(),
      );
      expect(after.filter((p) => p.startsWith("Hunt1/"))).toEqual([]);
    });
  }

  it("per-client copies carry the client folder's host; JSON goes to the Velociraptor importer", async () => {
    const { h } = await dropHunt("full");
    const pslist = h.calls.filter((c) => c.name === "Windows.System.Pslist.json");
    expect(pslist.map((c) => c.host).sort()).toEqual(["SRV-CHARLIE", "WS-ALPHA", "WS-BRAVO"]);
    expect(h.calls.every((c) => c.kind === "velociraptor")).toBe(true);
  });

  it("hunt-wide copies take the host from each row (no declared host)", async () => {
    const { h } = await dropHunt("huntWide");
    expect(h.calls.map((c) => c.name).sort()).toEqual([
      "All Windows.Network.Netstat.json",
      "All Windows.Sys.Users%2FUsers.json",
      "All Windows.System.Pslist.json",
    ]);
    expect(h.calls.every((c) => c.host === undefined)).toBe(true);
  });

  it("moves the skipped files with their full relative path and logs one SKIPPED line per hunt", async () => {
    const { h } = await dropHunt("full");
    expect(await exists(join(h.dropDir, "_skipped/Hunt1/hunt_info.json"))).toBe(true);
    expect(await exists(join(h.dropDir, "_skipped/Hunt1/results/All Windows.System.Pslist.json"))).toBe(true);
    expect(
      await exists(
        join(h.dropDir, "_skipped/Hunt1/WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.csv"),
      ),
    ).toBe(true);
    const skipped = (await dropLog(h.dropDir)).split("\n").filter((l) => l.includes("SKIPPED"));
    expect(skipped).toHaveLength(1);
    expect(skipped[0]).toContain("Hunt1/");
    expect(skipped[0]).toContain("28 moved to _skipped/");
  });

  it("waits while any member of the hunt has not settled", async () => {
    const h2 = await makeHarness();
    await writeTree(h2.dropDir, huntTree("full", "Hunt1"));
    await h2.sweep();
    await mkdir(join(h2.dropDir, "Hunt1/WS-ALPHA-C.0000000000000001/results"), { recursive: true });
    await writeFile(join(h2.dropDir, "Hunt1/WS-ALPHA-C.0000000000000001/results/Late.json"), '{"Pid":1}\n');
    await h2.sweep(); // Late.json is new: the whole hunt waits
    expect(h2.calls).toEqual([]);
    expect(await exists(join(h2.dropDir, "Hunt1/results/All Windows.System.Pslist.json"))).toBe(true);
    await h2.sweep();
    expect(h2.calls.length).toBe(10);
  });

  it("leaves non-member files beside a hunt to the ordinary drop path", async () => {
    const h = await makeHarness();
    await writeTree(h.dropDir, huntTree("perClientJson", "Hunt1"));
    const evtxLike = "Hunt1/WS-ALPHA-C.0000000000000001/uploads/notes.json";
    await mkdir(join(h.dropDir, "Hunt1/WS-ALPHA-C.0000000000000001/uploads"), { recursive: true });
    await writeFile(join(h.dropDir, evtxLike), JSON.stringify([{ a: 1 }]));
    await h.sweep();
    await h.sweep();
    expect(await exists(join(h.dropDir, "_skipped", evtxLike))).toBe(false);
    expect(await exists(join(h.dropDir, evtxLike))).toBe(false); // handled as an ordinary file
  });

  it("a crash after the copies moved, then a restart, imports every row exactly once", async () => {
    const h = await makeHarness();
    await writeTree(h.dropDir, huntTree("full", "Hunt1"));
    await h.sweep();
    h.hangAfter = 2; // copies + metadata moved; the third import never returns
    await h.sweepUntilHang();
    h.restart(); // fresh in-memory state over the same case dir
    await h.sweep();
    await h.sweep();
    expect(h.rowKeys()).toEqual(expectedRowKeys("full"));
  });
});
