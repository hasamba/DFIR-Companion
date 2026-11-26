// #2909: the grade-mark follow-ups of #2891. Real stores (state, super-timeline, forensic gate, demote).
//   1. rows an importer merged but never stamped (it threw, the process died) carry the mark from their
//      insert, so no demote moves them ungraded;
//   2. the mark survives a same-id re-merge (the Sigma re-grade path);
//   3. a Watson paste's rows are marked "held" and only a held tagger ever grades them;
//   4. a re-grade runs the settle's caps;
//   5. rows held after a tagger failure are graded at the NEXT import's settle, not only at start-up;
//   6. the recovery tag paths remove the mark and never copy it into the super-timeline;
//   7. no export carries the mark.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { captureImportBaseline, releaseImportBaseline } from "../../src/analysis/importBaseline.js";
import { beginImportSection } from "../../src/routes/importSection.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import { settleForensicImport, type SettleDeps } from "../../src/routes/importSettle.js";
import { regradePendingRows } from "../../src/composition/ungradedRecovery.js";
import { forensicGradePendingIds, type TagOutcome } from "../../src/analysis/gradeMark.js";
import { gradeStampedRows, recoveryDepsFromSettle } from "../../src/routes/importRowRecovery.js";
import { resetSweepBackoff } from "../../src/routes/importRegrade.js";
import { carryAndStampPaged } from "../../src/routes/importSettlePaged.js";
import { gradeMarkUnion } from "../../src/analysis/promotionMerge.js";
import { upsertForensicEvents } from "../../src/analysis/stateMerge.js";
import { deltaSchema } from "../../src/analysis/responseSchema.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { toTimesketchJsonl } from "../../src/integrations/timesketch/timesketchMap.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const MINE = "0011_upload.json";
const OTHER = "0012_upload.json";

const ev = (
  id: string,
  severity: ForensicEvent["severity"],
  description = `row ${id}`,
  source = MINE,
): ForensicEvent => ({
  id,
  timestamp: "2026-05-02T10:00:00Z",
  description,
  severity,
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [source],
  sources: ["Sysmon"],
});

let root: string;
let cases: CaseStore;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let options: AppOptions;
let lock: StateLock;
const runExclusive = <T>(caseId: string, fn: () => Promise<T>): Promise<T> => lock.runExclusive(caseId, fn);

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-grade-2909-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  lock = new StateLock();
  options = {
    stateStore,
    superTimelineStore: superStore,
    forensicGateControlStore: new ForensicGateControlStore(cases),
  };
  resetSweepBackoff();
  vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
  vi.spyOn(getServerLogger(), "info").mockImplementation(() => {});
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(root, { recursive: true, force: true });
});

type Tagger = (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;

/** The tagger stand-in raises "marker" rows to High, as a one-rule ruleset would. */
const raiseMarkers: Tagger = async (caseId, added) => {
  await runExclusive(caseId, async () => {
    const state = await stateStore.load(caseId);
    const raise = (e: ForensicEvent) =>
      added.some((a) => a.id === e.id) && e.description.includes("marker")
        ? { ...e, severity: "High" as const }
        : e;
    await stateStore.save({ ...state, forensicTimeline: state.forensicTimeline.map(raise) });
  });
  return { ungraded: [] };
};
const failAll: Tagger = async (_c, added) => ({ ungraded: added.map((e) => e.id) });

function deps(tag: Tagger, offered: string[] = [], extra: Partial<SettleDeps> = {}) {
  const demote = createImportDemote({ options, runStateExclusive: runExclusive });
  const d: SettleDeps = {
    stateStore,
    runStateExclusive: runExclusive,
    superTimelineStore: superStore,
    autoTagImported: async (caseId, added) => {
      offered.push(...added.map((e) => e.id));
      return tag(caseId, added);
    },
    demoteForensic: demote.demoteForensic,
    ...extra,
  };
  return { d, demote };
}

async function addRows(rows: ForensicEvent[], caseId = "c1"): Promise<void> {
  await runExclusive(caseId, async () => {
    const state = await stateStore.load(caseId);
    await stateStore.save({ ...state, forensicTimeline: [...state.forensicTimeline, ...rows] });
  });
}

/** An import whose importer merges `rows` and then throws: no settle runs (the section is released). */
async function importThatThrows(rows: ForensicEvent[], markGrade: true | "held" = true): Promise<void> {
  const baseline = await captureImportBaseline(stateStore, "c1", { markGrade });
  try {
    await addRows(rows);
  } finally {
    await releaseImportBaseline(stateStore, baseline);
  }
}

async function importRows(d: SettleDeps, rows: ForensicEvent[], markGrade: true | "held" | undefined = true) {
  const baseline = await captureImportBaseline(stateStore, "c1", { markGrade });
  await addRows(rows);
  try {
    return await settleForensicImport(d, "c1", baseline, MINE);
  } finally {
    await releaseImportBaseline(stateStore, baseline);
  }
}

const forensic = async () => new Map((await stateStore.load("c1")).forensicTimeline.map((e) => [e.id, e]));
async function superRows(): Promise<ForensicEvent[]> {
  const rows: ForensicEvent[] = [];
  for await (const b of superStore.eventBatches("c1")) rows.push(...b);
  return rows;
}
const pending = async () => [...(await forensicGradePendingIds(stateStore, "c1"))].sort();

describe("item 1 — rows merged but never stamped carry the mark from their insert", () => {
  it("an importer that throws after its merge: the rows are marked, no demote moves them, the next import grades them", async () => {
    await addRows([ev("seed", "High")]); // the case has a database
    await importThatThrows([
      ev("lost-marker", "Info", "ntds marker", OTHER),
      ev("lost-plain", "Info", "p", OTHER),
    ]);
    expect(await pending()).toEqual(["lost-marker", "lost-plain"]);
    const { d, demote } = deps(raiseMarkers);
    expect(await demote.demoteForensic("c1")).toEqual([]); // held, not demoted ungraded

    const offered: string[] = [];
    await importRows(deps(raiseMarkers, offered).d, [ev("new-1", "High")]);
    const after = await forensic();
    expect(after.get("lost-marker")).toMatchObject({ severity: "High" });
    expect(after.get("lost-marker")?.importBatchId).toBeTruthy(); // stamped by the re-grade
    expect(after.get("lost-marker")?.gradePending).toBeUndefined();
    expect(after.has("lost-plain")).toBe(false); // graded, then demoted into the super-timeline
    expect((await superRows()).map((e) => e.id)).toContain("lost-plain");
    expect(offered.sort()).toEqual(["lost-marker", "lost-plain", "new-1"]);
    expect(await pending()).toEqual([]);
    void d;
  });

  it("the first import into a brand-new case is armed too (the case had no database)", async () => {
    await importThatThrows([ev("first-1", "Info", "ntds marker")]);
    expect(await pending()).toEqual(["first-1"]);
    expect(await deps(raiseMarkers).demote.demoteForensic("c1")).toEqual([]);
  });

  it("a brand-new case's first import that throws: releasing the section drops the arm", async () => {
    const importLock = new ImportLock();
    const section = await beginImportSection(importLock, "c1", stateStore, 1, true);
    expect(section.baseline?.empty).toBe(true);
    await addRows([ev("first-1", "Info")]);
    section.release(); // the importer threw: no settle
    (await importLock.acquire("c1"))(); // the release is done once the lock is free again
    await addRows([ev("later-1", "Info", "an analyst's row", OTHER)]);
    expect(await pending()).toEqual(["first-1"]);
  });

  it("an unarmed section marks nothing, and the settle drops the arm before its own inserts", async () => {
    await addRows([ev("seed", "High")]);
    const unarmed = await captureImportBaseline(stateStore, "c1"); // a section that never settles
    await addRows([ev("plain", "Info")]);
    await releaseImportBaseline(stateStore, unarmed);
    expect(await pending()).toEqual([]);

    const baseline = await captureImportBaseline(stateStore, "c1", { markGrade: true });
    try {
      await addRows([ev("own", "High")]);
      await settleForensicImport(deps(raiseMarkers).d, "c1", baseline, MINE);
      await addRows([ev("after-settle", "Info")]); // e.g. a hunt summary row the settle writes
      expect(await pending()).toEqual([]);
    } finally {
      await releaseImportBaseline(stateStore, baseline);
    }
  });

  it("a mark a fold carries onto an old row: the row is tagged and unmarked, but keeps its stamp", async () => {
    await addRows([
      {
        ...ev("old-marker", "Info", "old marker"),
        importBatchId: "b-old",
        importedAt: "2026-01-01T00:00:00Z",
      },
    ]);
    const unstampedOld = ev("legacy-marker", "Info", "legacy marker");
    await addRows([unstampedOld]);
    const baseline = await captureImportBaseline(stateStore, "c1", { markGrade: true });
    try {
      // The importer's merge folds a new marked row into both old rows (correlation unions the mark).
      await runExclusive("c1", async () => {
        const state = await stateStore.load("c1");
        await stateStore.save({
          ...state,
          forensicTimeline: [
            ...state.forensicTimeline.map((e) => ({ ...e, gradePending: true as const })),
            ev("new-1", "High"),
          ],
        });
      });
      await settleForensicImport(deps(raiseMarkers).d, "c1", baseline, MINE);
    } finally {
      await releaseImportBaseline(stateStore, baseline);
    }
    const after = await forensic();
    expect(after.get("old-marker")).toMatchObject({ severity: "High", importBatchId: "b-old" });
    expect(after.get("old-marker")?.importedAt).toBe("2026-01-01T00:00:00Z");
    expect(after.get("legacy-marker")?.importBatchId).toBeUndefined(); // never stamped as this import's
    expect(after.get("legacy-marker")?.severity).toBe("High");
    expect(await pending()).toEqual([]);
  });

  it("the marked-ids query walks the partial index (only marked rows), not every forensic row", async () => {
    await addRows([ev("seed", "High")]);
    const db = new (loadDatabaseSync())(stateStore.databasePath("c1"));
    try {
      const plan = db
        .prepare(
          "EXPLAIN QUERY PLAN SELECT entity_id FROM entities INDEXED BY entities_grade_pending_idx " +
            "WHERE kind='forensicTimeline' AND json_extract(payload, '$.gradePending') IS NOT NULL",
        )
        .all()
        .map((r) => String((r as { detail: string }).detail))
        .join(" ");
      expect(plan).toMatch(/USING (COVERING )?INDEX entities_grade_pending_idx/);
    } finally {
      db.close();
    }
  });

  it("start-up drops a grade arm a crash left, so a later non-import insert is not marked", async () => {
    await addRows([ev("seed", "High")]);
    await captureImportBaseline(stateStore, "c1", { markGrade: true }); // never released: the crash
    await regradePendingRows(recoveryDepsFromSettle(deps(raiseMarkers).d), "c1");
    await addRows([ev("analyst-later", "Info")]);
    expect(await pending()).toEqual([]);
  });
});

describe("item 5 — rows held after a tagger failure are graded at the next import", () => {
  it("the next import's settle grades them; no restart needed", async () => {
    await importRows(deps(failAll).d, [ev("a-marker", "Info", "ntds marker"), ev("a-plain", "Info")]);
    expect(await pending()).toEqual(["a-marker", "a-plain"]);
    await importRows(deps(raiseMarkers).d, [ev("b-1", "High", "b row", OTHER)]);
    const after = await forensic();
    expect(after.get("a-marker")?.severity).toBe("High");
    expect(after.has("a-plain")).toBe(false);
    expect(await pending()).toEqual([]);
  });

  it("is skipped when this import's own tagger pass fails too (a broken tags file)", async () => {
    await importRows(deps(failAll).d, [ev("a-plain", "Info")]);
    const offered: string[] = [];
    await importRows(deps(failAll, offered).d, [ev("b-plain", "Info", "b", OTHER)]);
    expect(offered).toEqual(["b-plain"]); // the held row was not offered again
    expect(await pending()).toEqual(["a-plain", "b-plain"]);
  });

  it("an import that added nothing (a monitor poll) still sweeps, then backs off after a sweep that graded nothing", async () => {
    await importRows(deps(failAll).d, [ev("a-plain", "Info")]);
    const offered: string[] = [];
    await importRows(deps(failAll, offered).d, []);
    await importRows(deps(failAll, offered).d, []);
    expect(offered).toEqual(["a-plain"]); // once, then the back-off
    expect(await pending()).toEqual(["a-plain"]);
  });
});

describe("item 2 — a same-id re-merge keeps the mark", () => {
  it("the stored row is updated in place, so the mark survives (pinned)", async () => {
    await addRows([{ ...ev("x", "Info"), gradePending: true }]);
    const state = await stateStore.load("c1");
    const timeline = state.forensicTimeline.map((e) => ({ ...e }));
    upsertForensicEvents(
      timeline,
      // Through the delta schema, as mergeSigmaRegrade builds it: the schema drops unknown fields.
      deltaSchema.parse({
        findings: [],
        iocs: [],
        mitreTechniques: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "",
        summary: "",
        forensicEvents: [{ ...ev("x", "High"), description: "re-graded" }],
      }),
      {
        sourceScreenshots: ["Sigma re-grade"],
        timestamp: "2026-05-03T00:00:00Z",
      },
    );
    await stateStore.save({ ...state, forensicTimeline: timeline });
    expect((await forensic()).get("x")).toMatchObject({ description: "re-graded", gradePending: true });
  });
});

describe("item 2 — through the pipeline's real merge (Sigma re-grade, promotion)", () => {
  const pipeline = () =>
    new AnalysisPipeline({
      stateStore,
      superTimelineStore: superStore,
      stateLock: lock,
      imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    });

  it("a Sigma re-grade of a marked row keeps the mark (already preserved, now pinned)", async () => {
    await addRows([{ ...ev("x", "Info"), importBatchId: "b1", gradePending: true }, ev("y", "High")]);
    await pipeline().mergeSigmaRegrade("c1", [{ ...ev("x", "High"), description: "re-graded" }], {
      label: "Sigma re-grade (test)",
      at: "2026-05-03T00:00:00Z",
      note: "Sigma re-grade",
    });
    expect((await forensic()).get("x")).toMatchObject({ severity: "High", gradePending: true });
  });

  it("a promotion of a marked row keeps the mark, and the row is exempt: a re-grade only unmarks it", async () => {
    await addRows([{ ...ev("x", "Info"), importBatchId: "b1", gradePending: true }]);
    await pipeline().promoteSuperTimeline("c1", [ev("x", "Info")], {
      importedAt: "2026-05-03T00:00:00Z",
      intent: "manual",
    });
    const promoted = (await forensic()).get("x");
    expect(promoted?.promotedAt).toBeTruthy();
    expect(promoted?.gradePending).toBe(true);
    const offered: string[] = [];
    await regradePendingRows(recoveryDepsFromSettle(deps(raiseMarkers, offered).d), "c1");
    expect(offered).toEqual([]);
    expect((await forensic()).get("x")).toMatchObject({ severity: "Info" });
    expect(await pending()).toEqual([]);
  });
});

describe("item 3 — a Watson paste's rows are marked held; only a held tagger grades them", () => {
  it("held wins in a fold and in a stamp", async () => {
    expect(gradeMarkUnion([{ gradePending: true }, { gradePending: "held" }] as ForensicEvent[])).toEqual({
      gradePending: "held",
    });
    expect(gradeMarkUnion([{ gradePending: true }, {}] as ForensicEvent[])).toEqual({ gradePending: true });
    expect(gradeMarkUnion([{}, {}] as ForensicEvent[])).toEqual({});
    await addRows([{ ...ev("p", "Info"), gradePending: "held" }]);
    const ledger = await stateStore.loadOverview("c1");
    const scope = { addedIds: ["p"], touchedRowIds: [], touchedKnown: true, mergedCount: 0 };
    await carryAndStampPaged(stateStore, "c1", ledger, scope, false, {
      capturedAt: undefined,
      downgrade: true,
      gradePending: true,
    });
    expect((await forensic()).get("p")?.gradePending).toBe("held");
  });

  it("a held tagger failure keeps the paste's rows marked held; the next import hands them to the held tagger only", async () => {
    const heldOffered: string[] = [];
    const pasteDeps = deps(raiseMarkers, [], {
      markGradePending: "held",
      tagHeld: async (_c, added) => {
        heldOffered.push(...added.map((e) => e.id));
        return { ungraded: added.map((e) => e.id) }; // the held tagger failed
      },
    });
    await importRows(pasteDeps.d, [ev("paste-marker", "Info", "ntds marker")], "held");
    expect((await forensic()).get("paste-marker")?.gradePending).toBe("held");

    const plainOffered: string[] = [];
    const later = deps(raiseMarkers, plainOffered, {
      tagHeld: async (_c, added) => {
        heldOffered.push(...added.map((e) => e.id));
        return { ungraded: [] }; // tags only: no raise applied
      },
    });
    await importRows(later.d, [ev("b-1", "High", "b row", OTHER)]);
    expect(plainOffered).toEqual(["b-1"]); // never the plain tagger: no unapproved raise
    expect(heldOffered).toEqual(["paste-marker", "paste-marker"]);
    const after = await forensic();
    expect(after.has("paste-marker")).toBe(false); // Info, demoted to the super-timeline like any held row
    expect(await pending()).toEqual([]);
  });

  it("with no held tagger wired, a held row is never offered to the plain tagger and stays marked", async () => {
    await importThatThrows([ev("paste-1", "Info", "ntds marker")], "held");
    const offered: string[] = [];
    await importRows(deps(raiseMarkers, offered).d, [ev("b-1", "High", "b", OTHER)]);
    expect(offered).toEqual(["b-1"]);
    expect(await pending()).toEqual(["paste-1"]);
  });
});

describe("item 4 — a re-grade runs the settle's caps", () => {
  it("start-up re-grade caps a lab-setup row the tagger raised, as a full settle would", async () => {
    const lab = {
      ...ev("lab-marker", "Info", "dropped marker"),
      path: "C:\\Users\\a\\AppData\\Local\\Temp\\vmware-a\\VMwareDnD\\488a9d64\\tool.exe",
    };
    await importRows(deps(failAll).d, [lab]);
    expect(await pending()).toEqual(["lab-marker"]);
    await regradePendingRows(recoveryDepsFromSettle(deps(raiseMarkers).d), "c1");
    expect((await forensic()).get("lab-marker")?.severity).toBe("Medium");
  });

  it("the next import's sweep caps it too", async () => {
    const lab = {
      ...ev("lab-marker", "Info", "dropped marker"),
      path: "C:\\Users\\a\\AppData\\Local\\Temp\\vmware-a\\VMwareDnD\\488a9d64\\tool.exe",
    };
    await importRows(deps(failAll).d, [lab]);
    await importRows(deps(raiseMarkers).d, [ev("b-1", "High", "b", OTHER)]);
    expect((await forensic()).get("lab-marker")?.severity).toBe("Medium");
  });
});

describe("item 6 — recovery tag paths remove the mark and keep it out of the super-timeline", () => {
  it("gradeStampedRows (drop-batch recovery, a landed cloud page) unmarks what it graded", async () => {
    await addRows([
      { ...ev("m", "Info", "ntds marker"), importBatchId: "b1", gradePending: true },
      { ...ev("p", "Info"), importBatchId: "b1", gradePending: true },
    ]);
    await gradeStampedRows(recoveryDepsFromSettle(deps(raiseMarkers).d), "c1", ["m", "p"]);
    const after = await forensic();
    expect(after.get("m")).toMatchObject({ severity: "High" });
    expect(after.get("m")?.gradePending).toBeUndefined();
    expect(after.has("p")).toBe(false);
    expect(await pending()).toEqual([]);
    const raw = await superRows();
    expect(raw.map((e) => e.id).sort()).toEqual(["m", "p"]);
    expect(raw.every((e) => e.gradePending === undefined)).toBe(true);
  });
});

describe("item 6 + 4 — a recovery tag path runs the caps before it unmarks", () => {
  it("gradeStampedRows with no candidates handed in still caps a lab-setup row the tagger raised", async () => {
    const lab = {
      ...ev("lab-marker", "Info", "dropped marker"),
      path: "C:\\Users\\a\\AppData\\Local\\Temp\\vmware-a\\VMwareDnD\\488a9d64\\tool.exe",
      importBatchId: "b1",
      gradePending: true as const,
    };
    await addRows([lab]);
    await gradeStampedRows(recoveryDepsFromSettle(deps(raiseMarkers).d), "c1", ["lab-marker"]);
    expect((await forensic()).get("lab-marker")).toMatchObject({ severity: "Medium" });
    expect(await pending()).toEqual([]);
  });
});

describe("item 7 — no export carries the mark", () => {
  it("every report file, the filtered state and the Timesketch export are free of it", async () => {
    await addRows([
      { ...ev("held-1", "High", "a held row"), gradePending: true },
      { ...ev("held-2", "Medium", "a paste row"), gradePending: "held" },
    ]);
    const writer = new ReportWriter(cases, stateStore, {});
    const filtered = await writer.filteredState("c1");
    expect(filtered.forensicTimeline).toHaveLength(2);
    expect(JSON.stringify(filtered)).not.toContain("gradePending");
    expect(toTimesketchJsonl(filtered)).not.toContain("gradePending");
    await writer.writeAll("c1");
    const dir = cases.reportsDir("c1");
    for (const name of await readdir(dir)) {
      const text = await readFile(join(dir, name), "utf8").catch(() => "");
      expect(text, name).not.toContain("gradePending");
    }
  });
});
