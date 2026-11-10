import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { deltaSchema, type AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { mergeDelta, type WindowContext } from "../../src/analysis/stateMerge.js";
import { mergeIntoCase } from "../../src/analysis/caseMerge.js";
import { MERGE_FLAG_TRIGGER, mergeIndexEntry, mergeTrigger } from "../../src/analysis/mergeIndex.js";
import {
  COVERAGE_EVENT_ID,
  METADATA_MARKER,
  metadataCoverageEvent,
} from "../../src/analysis/cloudMetadataAccess.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// #2504: a case holding cloud audit logs and no host telemetry carries the "Cloud coverage gap" row,
// placed at the earliest cloud-audit record. That row used to send every later import down the full
// merge (it read as a correlation trigger, and its time is a case-wide aggregate), so each page of a
// live cloud collection loaded and re-saved the whole case. The incremental merge now places the row
// itself; every test runs the same imports into "full" (load → mergeDelta → save) and "inc"
// (mergeIntoCase) and compares what a load of each returns after every step.

type Ev = Partial<ForensicEvent> & { id: string; timestamp: string };

function event(e: Ev): Record<string, unknown> {
  return {
    description: `AWS CreateAccessKey by ops-${e.id} (iam.amazonaws.com)`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    asset: "123456789012",
    sources: ["AWS CloudTrail"],
    ...e,
  };
}

function delta(events: Ev[]): AnalysisDelta {
  return deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    forensicEvents: events.map(event),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: `import of ${events.length} event(s)`,
    summary: "",
  });
}

let root: string;
let store: StateStore;
let step = 0;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-inccov-"));
  const cases = new CaseStore(root);
  for (const caseId of ["full", "inc"])
    await cases.createCase({ caseId, name: caseId, investigator: "i", aiProvider: null });
  store = new StateStore(cases);
  step = 0;
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function windowCtx(): WindowContext {
  step++;
  return {
    windowSequence: -1,
    timestamp: `2026-10-30T10:${String(step).padStart(2, "0")}:00.000Z`,
    sourceScreenshots: [`page-${step}.json`],
  };
}

/** One import into both cases; returns whether the incremental side took the fast path. */
async function importBoth(d: AnalysisDelta): Promise<boolean> {
  const ctx = windowCtx();
  await store.save(mergeDelta(await store.load("full"), d, ctx));
  const out = await mergeIntoCase(store, "inc", d, ctx, (s) => mergeDelta(s, d, ctx));
  return !out.complete;
}

async function both(write: (caseId: string) => Promise<void>): Promise<void> {
  await write("full");
  await write("inc");
}

async function expectSame(): Promise<InvestigationState> {
  const full = await store.load("full");
  const inc = await store.load("inc");
  expect({ ...inc, caseId: "x" }).toEqual({ ...full, caseId: "x" });
  return full;
}

const coverageOf = (s: InvestigationState) => s.forensicTimeline.find((e) => e.id === COVERAGE_EVENT_ID);
const at = (d: number, h = 10, m = 0) =>
  `2026-10-${String(d).padStart(2, "0")}T${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:00Z`;

/** A page of CloudTrail rows, `n` of them, one minute apart from `start` on day `d`. */
function page(prefix: string, d: number, n = 10, start = 0): Ev[] {
  return Array.from({ length: n }, (_, i) => ({ id: `${prefix}e${i + 1}`, timestamp: at(d, 10, start + i) }));
}

describe("cloud coverage row — the incremental merge places it as the full merge does (#2504)", () => {
  it("takes the fast path page after page, and the row follows the earliest record as pages go back in time", async () => {
    expect(await importBoth(delta(page("p1", 20)))).toBe(false); // an empty case: the full merge indexes it
    let s = await expectSame();
    expect(coverageOf(s)?.timestamp).toBe(at(20, 10, 0));
    // CloudTrail LookupEvents pages run newest first: every page is earlier than the last.
    for (let k = 2; k <= 6; k++) {
      expect(await importBoth(delta(page(`p${k}`, 21 - k)))).toBe(true);
      s = await expectSame();
      expect(coverageOf(s)?.timestamp).toBe(at(21 - k, 10, 0));
    }
    // A later page leaves the row where it is.
    expect(await importBoth(delta(page("late", 28)))).toBe(true);
    s = await expectSame();
    expect(coverageOf(s)?.timestamp).toBe(at(15, 10, 0));
    expect(s.forensicTimeline.filter((e) => e.id === COVERAGE_EVENT_ID)).toHaveLength(1);
  });

  it("sorts the row after a record at the same instant, a new one or a stored one, in either string form", async () => {
    await importBoth(delta(page("a", 10)));
    // A new record at exactly the earliest instant, written another way (+00:00 vs Z).
    expect(
      await importBoth(delta([{ id: "tie", timestamp: "2026-10-10T10:00:00.000+00:00" }, ...page("b", 12)])),
    ).toBe(true);
    let s = await expectSame();
    // earliestEventTime keeps the first record at the earliest instant: the stored one.
    expect(coverageOf(s)?.timestamp).toBe(at(10, 10, 0));
    const ids = s.forensicTimeline.map((e) => e.id);
    expect(ids.indexOf(COVERAGE_EVENT_ID)).toBeGreaterThan(ids.indexOf("tie"));
    expect(ids.indexOf(COVERAGE_EVENT_ID)).toBeGreaterThan(ids.indexOf("ae1"));
    // A new record earlier than all of them: the row takes its time string.
    expect(await importBoth(delta([{ id: "early", timestamp: "2026-10-09T08:00:00+00:00" }]))).toBe(true);
    s = await expectSame();
    expect(coverageOf(s)?.timestamp).toBe("2026-10-09T08:00:00.000Z"); // the importer's normal form
  });

  it("moves the row later when another writer deletes (as demote does) or rewrites the earliest record", async () => {
    await importBoth(delta(page("a", 10)));
    expect(await importBoth(delta(page("b", 12)))).toBe(true);
    await expectSame();
    // Demote removes the earliest record; the next merge must find the next earliest one.
    await both(async (c) => {
      const gone = await store.forensicRowsById(c, ["ae1"]);
      await store.deleteForensicRows(
        c,
        gone.map((g) => g.rowId),
      );
    });
    expect(await importBoth(delta(page("c", 14)))).toBe(true);
    let s = await expectSame();
    expect(coverageOf(s)?.timestamp).toBe(at(10, 10, 1));
    // Another writer rewrites the (new) earliest record so it is no audit record: a stale row, read in
    // full, whose classification changed.
    await both(async (c) => {
      const [r] = await store.forensicRowsById(c, ["ae2"]);
      const res = await store.updateForensicRows(c, [
        { ...r, event: { ...r.event, description: "Edited by the analyst: not an audit record" } },
      ]);
      expect(res.updated).toBe(1);
    });
    expect(await importBoth(delta(page("d", 16)))).toBe(true);
    s = await expectSame();
    expect(coverageOf(s)?.timestamp).toBe(at(10, 10, 2));
  });

  it("re-adds the row when it was demoted, and replaces a stored row whatever another writer did to it", async () => {
    await importBoth(delta(page("a", 10)));
    await importBoth(delta(page("b", 11)));
    // A High gate demotes the Medium coverage row.
    await both(async (c) => {
      const rows = await store.forensicRowsById(c, [COVERAGE_EVENT_ID]);
      await store.deleteForensicRows(
        c,
        rows.map((r) => r.rowId),
      );
    });
    expect(await importBoth(delta(page("c", 12)))).toBe(true);
    let s = await expectSame();
    expect(coverageOf(s)?.timestamp).toBe(at(10, 10, 0));
    // Another writer re-grades the stored row; the next merge replaces it with a fresh one.
    await both(async (c) => {
      const [r] = await store.forensicRowsById(c, [COVERAGE_EVENT_ID]);
      const res = await store.updateForensicRows(c, [{ ...r, event: { ...r.event, severity: "High" } }]);
      expect(res.updated).toBe(1);
    });
    expect(await importBoth(delta(page("d", 13)))).toBe(true);
    s = await expectSame();
    expect(coverageOf(s)?.severity).toBe("Medium");
  });

  it("keeps the stored row, unchanged, once host telemetry arrives — and stays on the fast path", async () => {
    await importBoth(delta(page("a", 10)));
    await importBoth(delta(page("b", 11)));
    const host: Ev = {
      id: "proc1",
      timestamp: at(9, 8, 0),
      description: "Process created: powershell.exe",
      processName: "powershell.exe",
      asset: "WEB-1",
      sources: ["Sysmon"],
    };
    await importBoth(delta([host]));
    let s = await expectSame();
    expect(coverageOf(s)?.timestamp).toBe(at(10, 10, 0));
    for (let k = 0; k < 3; k++) {
      expect(await importBoth(delta(page(`h${k}`, 5 + k)))).toBe(true);
      s = await expectSame();
      expect(coverageOf(s)?.timestamp).toBe(at(10, 10, 0)); // no longer recomputed, as in the full merge
    }
  });

  it("skips a stored record with an unreadable time when finding the earliest one", async () => {
    await importBoth(delta([{ id: "bad", timestamp: "not a time" }, ...page("a", 10)]));
    await expectSame();
    expect(await importBoth(delta(page("b", 12)))).toBe(true);
    const s = await expectSame();
    expect(coverageOf(s)?.timestamp).toBe(at(10, 10, 0));
  });

  it("re-anchors a guessed year first, so the earliest record is judged on the clamped time", async () => {
    await importBoth(delta(page("a", 10, 12)));
    // A guessed-year record far in the past: the clamp moves it onto the dominant year.
    expect(
      await importBoth(delta([{ id: "guess", timestamp: "2019-10-05T10:00:00Z", yearInferred: true }])),
    ).toBe(true);
    const s = await expectSame();
    expect(coverageOf(s)?.timestamp).toBe("2026-10-05T10:00:00.000Z");
  });

  it("re-indexes a case indexed before the change once, then takes the fast path", async () => {
    await importBoth(delta(page("a", 10)));
    await importBoth(delta(page("b", 11)));
    // As the previous build left it: the coverage row indexed as a trigger, under the old stamp.
    const state = await store.load("inc");
    const position = state.forensicTimeline.findIndex((e) => e.id === COVERAGE_EVENT_ID);
    const row = state.forensicTimeline[position];
    const snap = await store.mergeSnapshot("inc");
    await store.mergeIndexWrite(
      "inc",
      snap!.generation,
      [{ position, index: { ...mergeIndexEntry(row), flags: MERGE_FLAG_TRIGGER, clean: true } }],
      { stamp: "1:previous-build", stable: true },
    );
    expect(await importBoth(delta(page("c", 9)))).toBe(false); // the full merge rebuilds the index
    await expectSame();
    expect(await importBoth(delta(page("d", 8)))).toBe(true);
    const s = await expectSame();
    expect(coverageOf(s)?.timestamp).toBe(at(8, 10, 0));
  });

  it("falls back to the full merge when no cloud record has a readable time", async () => {
    await importBoth(delta([{ id: "bad1", timestamp: "not a time" }]));
    expect(await importBoth(delta([{ id: "bad2", timestamp: "also not a time" }]))).toBe(false);
  });
});

describe("cloud coverage row — merge index trigger (#2504)", () => {
  const cloud = {
    id: "c1",
    timestamp: at(1),
    description: "AWS CreateAccessKey by ops",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  } as ForensicEvent;

  it("the generated coverage row is not a trigger", () => {
    const row = metadataCoverageEvent([cloud])!;
    expect(row.id).toBe(COVERAGE_EVENT_ID);
    expect(mergeTrigger(row)).toBeNull();
  });

  it("a coverage-id row that carries something else is judged on it", () => {
    const row = metadataCoverageEvent([cloud])!;
    expect(mergeTrigger({ ...row, sources: ["Email"] })).toBe("email delivery");
    expect(mergeTrigger({ ...row, description: `${row.description} certutil -urlcache` })).not.toBeNull();
  });

  // #2539: the metadata passes are per-row rewrites and never strip or re-read the note, so a marked
  // row is inert — it used to be a trigger, which sent every later import down the full merge.
  it("any other row carrying the metadata note is inert (#2539)", () => {
    expect(mergeTrigger({ ...cloud, description: `GET / ${METADATA_MARKER} something]` })).toBeNull();
  });
});
