import { describe, it, expect, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { prepareHuntDrops } from "../../src/composition/dropHuntFolder.js";
import type { DropFileStat, StuckDropFile } from "../../src/analysis/dropScan.js";
import { huntTree } from "../helpers/huntExportFixture.js";

// #2714: the sweep-side gate for an unzipped hunt, without the filesystem walk.

const stat = (relpath: string): DropFileStat => ({ relpath, size: 1, mtimeMs: 1 });

async function run(
  listing: string[],
  opts: { ready?: string[]; stuck?: string[]; failMove?: (r: string) => boolean } = {},
) {
  const dropDir = await mkdtemp(join(tmpdir(), "dfir-hunt-plan-"));
  const files = listing.map(stat);
  const skipMove = vi.fn(async (rel: string) => {
    if (opts.failMove?.(rel)) throw new Error("locked");
  });
  const stuck = new Map<string, StuckDropFile>(
    (opts.stuck ?? []).map((r) => [r, { size: 1, mtimeMs: 1, ok: true }]),
  );
  const ready = await prepareHuntDrops({
    dropDir,
    listing: files,
    ready: files.filter((f) => (opts.ready ?? listing).includes(f.relpath) && !stuck.has(f.relpath)),
    stuck,
    skipMove,
  });
  return { ready: ready.map((f) => f.relpath), moved: skipMove.mock.calls.map((c) => c[0]) };
}

describe("prepareHuntDrops (#2714)", () => {
  it("reads a backslash (Windows) listing and hands back native relpaths", async () => {
    const listing = Object.keys(huntTree("full", "Hunt1")).map((p) => p.replace(/\//g, "\\"));
    const { ready, moved } = await run(listing);
    expect(ready).toHaveLength(3); // #2810: one hunt-wide copy per artifact
    expect(ready.every((r) => r.includes("\\results\\All ") && r.endsWith(".json"))).toBe(true);
    expect(moved).toContain("Hunt1\\hunt_info.json");
  });

  it("moves copies before metadata", async () => {
    const { moved } = await run(Object.keys(huntTree("full")));
    const firstMeta = moved.findIndex((m) => m.endsWith("hunt_info.json") || m.endsWith("client_info.json"));
    const lastCopy = moved.map((m) => /\.csv$|All /.test(m)).lastIndexOf(true);
    expect(lastCopy).toBeLessThan(firstMeta);
  });

  it("holds the whole hunt when a copy cannot be moved", async () => {
    const { ready, moved } = await run(Object.keys(huntTree("full")), {
      failMove: (r) => r === "WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.json",
    });
    expect(ready).toEqual([]);
    expect(moved.some((m) => m.endsWith("hunt_info.json"))).toBe(false); // metadata stays, so it is still a hunt
  });

  it("a stuck member neither holds the hunt nor imports again, and still counts for the choice", async () => {
    const listing = Object.keys(huntTree("full"));
    const stuckOne = "results/All Windows.System.Pslist.json";
    const { ready, moved } = await run(listing, { stuck: [stuckOne] });
    expect(ready).toHaveLength(2);
    expect(ready).not.toContain(stuckOne);
    expect(moved).toContain("WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.json");
  });

  it("keeps every member back while one is unsettled, and leaves other files alone", async () => {
    const listing = [...Object.keys(huntTree("full", "Hunt1")), "other/chainsaw.json"];
    const { ready, moved } = await run(listing, {
      ready: listing.filter((p) => !p.endsWith("All Windows.System.Pslist.csv")),
    });
    expect(ready).toEqual(["other/chainsaw.json"]);
    expect(moved).toEqual([]);
  });
});
