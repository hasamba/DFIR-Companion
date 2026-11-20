import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HuntHeldStore, HUNT_HELD_FILE, isApproved } from "../../src/analysis/huntHeldStore.js";

// #2755: what the held-file store remembers. Synthetic values only.

const meta = {
  ...{ origin: "zip" as const, source: "hunt.zip", artifact: "Hayabusa", host: "WS-A" },
  ...{ bytes: 9, groupBytes: 9, reason: "host" as const, limitMb: 50 },
};

async function store() {
  const dir = await mkdtemp(join(tmpdir(), "dfir-held-"));
  return { s: new HuntHeldStore(() => dir), dir };
}

describe("hunt held store (#2755)", () => {
  it("drops entries naming unsafe paths on load", async () => {
    const { s, dir } = await store();
    await writeFile(
      join(dir, HUNT_HELD_FILE),
      JSON.stringify({
        held: [
          { ...meta, rel: "../escape.json" },
          { ...meta, rel: "not-held/x.json" },
          { ...meta, rel: "_held/ok.json" },
        ],
        approved: [{ relpath: "../x", size: 1, mtimeMs: 1 }],
      }),
    );
    const st = await s.load("c1");
    expect(st.held.map((h) => h.rel)).toEqual(["_held/ok.json"]);
    expect(st.approved).toEqual([]);
  });

  it("an approval matches the exact file: path, size and modification time", async () => {
    const { s } = await store();
    await s.putHeld("c1", { ...meta, rel: "_held/a/x.json" });
    await s.approve("c1", { relpath: "a/x.json", size: 10, mtimeMs: 1000 }, "_held/a/x.json");
    const st = await s.load("c1");
    expect(st.held).toEqual([]);
    expect(isApproved(st, { relpath: "a/x.json", size: 10, mtimeMs: 1000 })).toBe(true);
    expect(isApproved(st, { relpath: "a/x.json", size: 11, mtimeMs: 1000 })).toBe(false);
    expect(isApproved(st, { relpath: "a/x.json", size: 10, mtimeMs: 5000 })).toBe(false);
  });

  it("pending holds are added and cleared; hunt decisions accumulate", async () => {
    const { s } = await store();
    await s.setPending("c1", [{ relpath: "h/c/results/A.json", meta }]);
    expect((await s.load("c1")).pending).toHaveLength(1);
    await s.setPending("c1", [], ["h/c/results/A.json"]);
    expect((await s.load("c1")).pending).toEqual([]);
    await s.decideHunt("c1", "H.X1", "A", "import");
    await s.decideHunt("c1", "H.X1", "B", "skip");
    expect(await s.huntDecisions("c1", "H.X1")).toEqual({ A: "import", B: "skip" });
  });

  it("forgets the details of held files that are gone", async () => {
    const { s } = await store();
    await s.putHeld("c1", { ...meta, rel: "_held/a.json" });
    await s.putHeld("c1", { ...meta, rel: "_held/b.json" });
    await s.forgetMissing("c1", new Set(["_held/b.json"]));
    expect((await s.load("c1")).held.map((h) => h.rel)).toEqual(["_held/b.json"]);
  });

  it("carries over bundle-hunt decisions stored by #2753's format", async () => {
    const { s, dir } = await store();
    await writeFile(
      join(dir, HUNT_HELD_FILE),
      JSON.stringify({
        hunts: [
          {
            huntId: "H.OLD1",
            entries: [
              { artifact: "A", decision: "import" },
              { artifact: "B", decision: "skip" },
              { artifact: "C" },
            ],
          },
        ],
      }),
    );
    expect(await s.huntDecisions("c1", "H.OLD1")).toEqual({ A: "import", B: "skip" });
  });
});
