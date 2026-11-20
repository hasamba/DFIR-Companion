import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HuntHeldStore, HUNT_HELD_FILE, type HeldArchive } from "../../src/analysis/huntHeldStore.js";

// #2746: the held-file record per archive. Synthetic values only.

const ID = "a".repeat(32);
const entry = (member: string) => ({
  ...{ member, artifact: "Hayabusa", host: "WS-A", bytes: 9, groupBytes: 9 },
  ...{ reason: "host" as const, limitMb: 50 },
});
const archive = (over: Partial<HeldArchive> = {}): HeldArchive => ({
  ...{ archiveId: ID, relpath: "hunt.zip", size: 10, mtimeMs: 1, waiting: true },
  entries: [entry("WS-A-C.1/results/H.json"), entry("WS-B-C.2/results/H.json")],
  ...over,
});

async function store() {
  const dir = await mkdtemp(join(tmpdir(), "dfir-held-"));
  return { s: new HuntHeldStore(() => dir), dir };
}

describe("hunt held store (#2746)", () => {
  it("drops entries naming unsafe paths on load", async () => {
    const { s, dir } = await store();
    const bad = { ...archive(), relpath: "../escape.zip" };
    const badMember = archive({
      archiveId: "b".repeat(32),
      entries: [entry("../../etc/x"), entry("ok/results/H.json")],
    });
    await writeFile(join(dir, HUNT_HELD_FILE), JSON.stringify({ archives: [bad, badMember] }));
    const list = await s.list("c1");
    expect(list).toHaveLength(1);
    expect(list[0].entries.map((e) => e.member)).toEqual(["ok/results/H.json"]);
  });

  it("decides only existing entries and clears waiting", async () => {
    const { s } = await store();
    await s.put("c1", archive());
    const n = await s.decide("c1", [
      { archiveId: ID, member: "WS-A-C.1/results/H.json", decision: "skip" },
      { archiveId: ID, member: "nope/results/H.json", decision: "import" },
    ]);
    expect(n).toBe(1);
    const [rec] = await s.list("c1");
    expect(rec.waiting).toBe(false);
    expect(rec.entries.find((e) => e.member.startsWith("WS-A"))?.decision).toBe("skip");
  });

  it("leaves out a ready zip only while it waits for the analyst and has not changed", async () => {
    const { s } = await store();
    await s.put("c1", archive());
    const zip = { relpath: "hunt.zip", size: 10, mtimeMs: 1 };
    expect(await s.excludeAwaiting("c1", [zip])).toEqual([]);
    expect(await s.excludeAwaiting("c1", [{ ...zip, size: 11 }])).toHaveLength(1); // a changed file runs
    await s.decide("c1", [{ archiveId: ID, member: "WS-A-C.1/results/H.json", decision: "import" }]);
    expect(await s.excludeAwaiting("c1", [zip])).toHaveLength(1); // a decision arrived
  });

  it("update keeps a decision made meanwhile; prune drops zips gone from drop/", async () => {
    const { s } = await store();
    await s.put("c1", archive());
    await s.decide("c1", [{ archiveId: ID, member: "WS-B-C.2/results/H.json", decision: "import" }]);
    await s.update("c1", ID, (cur) => ({ ...cur, waiting: false }));
    expect((await s.get("c1", ID))?.entries.find((e) => e.member.startsWith("WS-B"))?.decision).toBe(
      "import",
    );
    await s.prune("c1", []);
    expect(await s.list("c1")).toEqual([]);
  });
});
