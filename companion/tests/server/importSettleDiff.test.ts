import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent, type Severity } from "../../src/analysis/stateTypes.js";
import { captureImportBaseline, releaseImportBaseline } from "../../src/analysis/importBaseline.js";
import { outlineEvents } from "../../src/analysis/forensicRows.js";
import { diffTimeline } from "../../src/analysis/timelineDiff.js";
import { refreshRowFacts } from "../../src/analysis/rowFacts.js";
import { ImportJournalLostError, settleTimelineDiff } from "../../src/routes/importSettleDiff.js";

// #1874: the settle's timeline diff reads keys only for the rows the import changed. It must equal
// diffTimeline over the whole timeline before and after — membership, displayed row, order.

let dir: string;
let store: StateStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-settle-diff-"));
  const cases = new CaseStore(dir);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new StateStore(cases);
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Few distinct times and texts, with case/whitespace variants and empty fields, so keys collide.
const TIMES = [
  "2026-01-01T00:00:00Z",
  "2026-01-01t00:00:00z",
  " 2026-01-02T00:00:00Z",
  "",
  "2026-01-03T00:00:00Z",
];
const TEXTS = ["svchost started", "SVCHOST  started", "cmd.exe /c whoami", "", "net user x /add", "dup"];
const SEVERITIES: Severity[] = ["Info", "Low", "Medium", "High"];

let serial = 0;
function randomEvent(r: () => number, id?: string): ForensicEvent {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
  return {
    id: id ?? `x${serial++}`,
    timestamp: pick(TIMES),
    description: pick(TEXTS),
    severity: pick(SEVERITIES),
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

async function mutate(r: () => number, steps: number): Promise<void> {
  for (let s = 0; s < steps; s++) {
    const op = r();
    const state = await store.load("c1");
    const rows = state.forensicTimeline;
    if (op < 0.3) {
      await store.appendForensicEvents("c1", [randomEvent(r), randomEvent(r)]);
    } else if (op < 0.45 && rows.length) {
      // Rewrite a row's text (same id and time: a targeted row update).
      const [row] = await store.forensicRowsById("c1", [rows[Math.floor(r() * rows.length)].id]);
      if (row) {
        const other = randomEvent(r);
        await store.updateForensicRows("c1", [
          { ...row, event: { ...row.event, description: other.description, severity: other.severity } },
        ]);
      }
    } else if (op < 0.6 && rows.length) {
      // Delete the newest rows — their row ids are the ones SQLite hands out again.
      const outline = await store.forensicOutline("c1", false);
      const top = [...outline.rowIds].sort((a, b) => b - a).slice(0, 1 + Math.floor(r() * 2));
      await store.deleteForensicRows("c1", top);
    } else {
      // A full save: rows change time or text, some go, some arrive, the order is re-sorted.
      const next = rows.filter(() => r() > 0.1).map((e) => (r() < 0.2 ? { ...randomEvent(r, e.id) } : e));
      next.push(randomEvent(r));
      next.sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));
      await store.save({ ...state, forensicTimeline: next });
    }
  }
}

async function checkOne(seed: number, refreshBefore: boolean): Promise<void> {
  const r = rng(seed);
  await store.save({
    ...emptyState("c1"),
    forensicTimeline: Array.from({ length: 12 }, () => randomEvent(r)),
  });
  await mutate(r, 2);
  if (refreshBefore) await refreshRowFacts(store, "c1");
  await mutate(r, Math.floor(r() * 2)); // rows written after the refresh: unknown facts at capture
  const baseline = await captureImportBaseline(store, "c1");
  const before = await store.forensicOutline("c1", true);
  try {
    await mutate(r, 1 + Math.floor(r() * 4));
    const after = await store.forensicOutline("c1", true);
    const expected = diffTimeline(outlineEvents(before), outlineEvents(after));
    const got = await settleTimelineDiff(store, "c1", baseline);
    expect(got.timelineDiff, `seed ${seed}`).toStrictEqual(expected);
    expect(got.forensicCount).toBe(after.ids.length);
  } finally {
    await releaseImportBaseline(store, baseline);
  }
}

describe("settleTimelineDiff (#1874)", () => {
  it("equals diffTimeline over the whole timeline, with facts known at capture", async () => {
    for (let seed = 1; seed <= 40; seed++) {
      await rm(store.databasePath("c1"), { force: true });
      await rm(`${store.databasePath("c1")}-wal`, { force: true });
      await rm(`${store.databasePath("c1")}-shm`, { force: true });
      await checkOne(seed, true);
    }
  }, 120_000);

  it("equals diffTimeline when no facts were ever computed (every row read)", async () => {
    for (let seed = 101; seed <= 115; seed++) {
      await rm(store.databasePath("c1"), { force: true });
      await rm(`${store.databasePath("c1")}-wal`, { force: true });
      await rm(`${store.databasePath("c1")}-shm`, { force: true });
      await checkOne(seed, false);
    }
  }, 120_000);

  it("reports an import into an empty case like the full diff", async () => {
    const baseline = await captureImportBaseline(store, "c1");
    expect(baseline.empty).toBe(true);
    const r = rng(7);
    await store.save({
      ...emptyState("c1"),
      forensicTimeline: Array.from({ length: 9 }, () => randomEvent(r)),
    });
    const after = await store.forensicOutline("c1", true);
    const got = await settleTimelineDiff(store, "c1", baseline);
    expect(got.timelineDiff).toStrictEqual(diffTimeline([], outlineEvents(after)));
  });

  it("re-importing rows the case already holds adds nothing", async () => {
    const r = rng(9);
    const rows = Array.from({ length: 10 }, () => randomEvent(r));
    await store.save({ ...emptyState("c1"), forensicTimeline: rows });
    await refreshRowFacts(store, "c1");
    const baseline = await captureImportBaseline(store, "c1");
    await store.appendForensicEvents(
      "c1",
      rows.map((e) => ({ ...e, id: `${e.id}-again` })),
    );
    const got = await settleTimelineDiff(store, "c1", baseline);
    await releaseImportBaseline(store, baseline);
    expect(got.timelineDiff).toStrictEqual({ added: [], removed: [] });
  });

  it("fails, rather than report a partial diff, when the journal is gone", async () => {
    await store.save({
      ...emptyState("c1"),
      forensicTimeline: [randomEvent(rng(1), "a"), randomEvent(rng(2), "b")],
    });
    await refreshRowFacts(store, "c1");
    const baseline = await captureImportBaseline(store, "c1");
    await releaseImportBaseline(store, baseline); // the journal goes (a replaced database, in life)
    await store.appendForensicEvents("c1", [randomEvent(rng(3), "c")]);
    await expect(settleTimelineDiff(store, "c1", baseline)).rejects.toBeInstanceOf(ImportJournalLostError);
  });

  it("reads back only pre-import rows from the journal: rows the import inserted stay out", async () => {
    await store.save({
      ...emptyState("c1"),
      forensicTimeline: [randomEvent(rng(1), "a"), randomEvent(rng(2), "b")],
    });
    const baseline = await captureImportBaseline(store, "c1");
    await store.appendForensicEvents("c1", [randomEvent(rng(3), "new")]);
    const rows = await store.forensicRowsById("c1", ["a", "new"]);
    await store.updateForensicRows(
      "c1",
      rows.map((r) => ({ ...r, event: { ...r.event, severity: "Critical" as const } })),
    );
    const all = await store.readImportJournal("c1", baseline.journalToken!);
    const fenced = await store.readImportJournal("c1", baseline.journalToken!, baseline.journalFence);
    await releaseImportBaseline(store, baseline);
    expect(all!.map((j) => j.event.id).sort()).toEqual(["a", "new"]);
    expect(fenced!.map((j) => j.event.id)).toEqual(["a"]);
  });
});
