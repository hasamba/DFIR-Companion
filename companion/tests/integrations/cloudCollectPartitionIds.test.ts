import { describe, it, expect } from "vitest";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import { applySplit, decideSplit } from "../../src/integrations/cloudCollect/collectSplit.js";
import type { CollectFs } from "../../src/integrations/cloudCollect/collectFs.js";
import type {
  CloudCollectSession,
  SubWindowStatus,
} from "../../src/integrations/cloudCollect/collectTypes.js";
import { faultFs, kill, pipelineImporter, tempCase, type TempCase } from "../helpers/cloudCollectFakes.js";
import { denseSession, denseSource, fakeClock, type DenseRecord } from "../helpers/cloudCollectDense.js";

// #2312 review: partition child ids must never collide — not when two values sanitise to the same
// text ("projects/a" vs "projects_a"), not when they share a long prefix. A collision let one
// partition's result mark the other done without querying it: "complete" with a coverage hole.

const WINDOW = { start: "2026-10-01T10:00:00.000Z", end: "2026-10-01T10:00:01.000Z" };
const T0 = Date.parse(WINDOW.start);
const PREFIX = "projects/lab-project/logs/".padEnd(80, "x");
const VALUES = ["projects/a", "projects_a", `${PREFIX}/one`, `${PREFIX}/two`];
let tick = 0;
const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();

/** 16 records in one second, 4 per partition value: capped at 10, each partition fits. */
const records = (): DenseRecord[] =>
  Array.from({ length: 16 }, (_, i) => ({ at: T0 + i * 50, region: VALUES[i % 4] }));

const source = denseSource({ minWindowMs: 1000, partition: { key: "logName" } });

async function start(t: TempCase, fs: CollectFs, session: CloudCollectSession) {
  await createCollection(
    fs,
    session,
    {
      dir: t.dir,
      collectionId: "cc-test-abc123",
      caseId: "c1",
      accountId: "acct1",
      accountName: "lab",
      provider: "gcp",
      sources: ["ct"],
      window: WINDOW,
      filters: {},
      companionVersion: "0.0.0-test",
    },
    now,
  );
}

const run = (t: TempCase, fs: CollectFs, session: CloudCollectSession, resume = false) =>
  runCollection(
    { fs, session, importer: pipelineImporter(t), sources: [source], now, clock: fakeClock() },
    t.dir,
    { resume },
  );

/** The fake filters on `partition.region`; map the logName partition onto it. */
function session(cap: number) {
  const inner = denseSession({ records: records(), cap, partitionValues: VALUES });
  return {
    ...inner,
    fetchPage: (req: Parameters<typeof inner.fetchPage>[0]) =>
      inner.fetchPage({ ...req, ...(req.partition ? { partition: { region: req.partition.logName } } : {}) }),
  };
}

const events = async (t: TempCase) => (await t.stateStore.load("c1")).forensicTimeline.length;

describe("partition child ids (#2312 review)", () => {
  const capped: SubWindowStatus = {
    id: "ct:0",
    source: "ct",
    window: WINDOW,
    state: "capped",
    pages: 1,
    records: 10,
    restarts: 0,
  };

  it("are unique for values that sanitise alike or share a long prefix", () => {
    const d = decideSplit(capped, source, VALUES, 1);
    expect(d.mode).toBe("partition");
    expect(new Set(d.children.map((c) => c.id)).size).toBe(VALUES.length);
    expect(d.children.map((c) => c.partition?.logName)).toEqual(VALUES);
  });

  it("a split whose child id already exists is refused, never merged", () => {
    const d = decideSplit(capped, source, VALUES, 1);
    const tree = applySplit([capped], d);
    const clash = {
      subWindowId: tree[1].id,
      mode: "time" as const,
      children: [{ id: tree[2].id, window: WINDOW }],
    };
    expect(() => applySplit(tree, clash)).toThrow(/duplicate sub-window id/);
  });

  it("collection and replay fetch every partition; counts equal an uncapped run", async () => {
    const base = await tempCase();
    const baseFs = faultFs();
    const uncapped = session(1000);
    await start(base, baseFs, uncapped);
    expect((await run(base, baseFs, uncapped)).status).toBe("complete");
    const want = await events(base);

    const t = await tempCase();
    const fs = faultFs();
    const s = session(10);
    await start(t, fs, s);
    const cp = await run(t, fs, s);
    expect(cp.status).toBe("complete");
    const asked = new Set(s.calls.map((c) => c.partition?.region).filter(Boolean));
    expect([...asked].sort()).toEqual([...VALUES].sort());
    expect(await events(t)).toBe(want);

    // A crash after the partition split line (append 3: capped page, split, first child page).
    const r = await tempCase();
    const rfs = faultFs();
    const rs = session(10);
    await start(r, rfs, rs);
    let count = 0;
    rfs.inject("appendSync", (p) => p.endsWith("manifest.jsonl") && ++count === 4, kill);
    await expect(run(r, rfs, rs)).rejects.toThrow(/simulated kill/);
    rfs.clear();
    const resumed = await run(r, rfs, rs, true);
    expect(resumed.status).toBe("complete");
    const leafIds = resumed.subWindows.filter((x) => x.partition).map((x) => x.partition?.logName);
    expect(leafIds.sort()).toEqual([...VALUES].sort());
    expect(resumed.subWindows.filter((x) => x.partition).every((x) => x.state === "done")).toBe(true);
    expect(await events(r)).toBe(want);
  }, 30_000);
});
