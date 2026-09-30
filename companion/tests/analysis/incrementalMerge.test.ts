import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { deltaSchema, type AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { mergeDelta, type WindowContext } from "../../src/analysis/stateMerge.js";
import { mergeIntoCase, mergeIndexStamp } from "../../src/analysis/caseMerge.js";
import { mergeIncrementally } from "../../src/analysis/incrementalMerge.js";
import { MERGE_SCAN_PAGE } from "../../src/analysis/caseSqliteWorkerMerge.js";
import { captureImportBaseline } from "../../src/analysis/importBaseline.js";
import { baselineCheckpoint } from "../../src/analysis/importUndoRows.js";
import { applyUndoDelta } from "../../src/analysis/importUndoDelta.js";
import { diffTimeline } from "../../src/analysis/timelineDiff.js";
import { outlineEvents } from "../../src/analysis/forensicRows.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// #1874: the incremental importer merge must leave exactly the state today's full merge leaves —
// forensic timeline order and content, IOCs, findings, metadata — on every step of a sequence of
// imports, whatever else wrote to the case in between. Every test runs the same steps into two cases:
// "full" through load → mergeDelta → save, "inc" through mergeIntoCase, and compares what a load of
// each returns after every step.

type Ev = Partial<ForensicEvent> & { id: string; timestamp: string };

function event(e: Ev): Record<string, unknown> {
  return {
    description: `event ${e.id}`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    asset: "HOST-1",
    sources: ["SIEM import"],
    ...e,
  };
}

function delta(events: Ev[], extra: Record<string, unknown> = {}): AnalysisDelta {
  return deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    forensicEvents: events.map(event),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: `import of ${events.length} event(s)`,
    summary: "",
    ...extra,
  });
}

let root: string;
let store: StateStore;
let step = 0;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-incmerge-"));
  const cases = new CaseStore(root);
  for (const caseId of ["full", "inc"])
    await cases.createCase({ caseId, name: caseId, investigator: "i", aiProvider: null });
  store = new StateStore(cases);
  step = 0;
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function windowCtx(extra: Partial<WindowContext> = {}): WindowContext {
  step++;
  return {
    windowSequence: -1,
    timestamp: `2026-09-30T10:${String(step).padStart(2, "0")}:00.000Z`,
    sourceScreenshots: [`import-${step}.json`],
    ...extra,
  };
}

/** One import into both cases; returns whether the incremental side took the fast path. */
async function importBoth(d: AnalysisDelta, extra: Partial<WindowContext> = {}): Promise<boolean> {
  const ctx = windowCtx(extra);
  await store.save(mergeDelta(await store.load("full"), d, ctx));
  const out = await mergeIntoCase(store, "inc", d, ctx, (s) => mergeDelta(s, d, ctx));
  return !out.complete;
}

/** The same outside write on both cases. */
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

const day = (d: number, h = 10, m = 0, s = 0) =>
  `2026-07-${String(d).padStart(2, "0")}T${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}.000Z`;

function batch(prefix: string, n: number, extra: (i: number) => Partial<Ev> = () => ({})): Ev[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `${prefix}e${i + 1}`,
    timestamp: day(1 + (i % 28), 10, i % 60),
    description: `Service installed ${prefix}-${i}`,
    path: `C:\\Windows\\Temp\\${prefix}-${i}.exe`,
    ...extra(i),
  }));
}

describe("incremental importer merge — same result as the full merge", () => {
  it("takes the fast path after the first import and matches on every step, with other writers between", async () => {
    expect(await importBoth(delta(batch("a", 60)))).toBe(false); // an empty case: the full merge indexes it
    await expectSame();
    for (let k = 2; k <= 8; k++) {
      const d = delta(batch(`p${k}`, 60), {
        iocs: [{ id: `p${k}i1`, type: "file", value: `C:\\Windows\\Temp\\p${k}-0.exe` }],
      });
      expect(await importBoth(d)).toBe(true);
      const state = await expectSame();
      // What settle does: stamp the new rows (fields the merge never reads).
      const added = state.forensicTimeline.filter((e) => e.id.startsWith(`p${k}e`)).map((e) => e.id);
      await both(async (c) => {
        const rows = await store.forensicRowsById(c, added);
        await store.updateForensicRows(
          c,
          rows.map((r) => ({ ...r, event: { ...r.event, importedAt: `t${k}`, importBatchId: `b${k}` } })),
        );
      });
      // Another writer grades a row (a field the merge reads), and deletes two.
      await both(async (c) => {
        const [r] = await store.forensicRowsById(c, [added[5]]);
        await store.updateForensicRows(c, [{ ...r, event: { ...r.event, severity: "High" } }]);
        const gone = await store.forensicRowsById(c, added.slice(0, 2));
        await store.deleteForensicRows(
          c,
          gone.map((g) => g.rowId),
        );
      });
      await expectSame();
    }
    // An analyst edit through a full save, then rows appended out of time order (the bulk path).
    await both(async (c) => {
      const s = await store.load(c);
      s.forensicTimeline[3] = { ...s.forensicTimeline[3], description: "edited by the analyst" };
      await store.save(s);
      await store.appendForensicEvents(c, [
        event({ id: "late1", timestamp: day(2, 1), sourceScreenshots: [] }) as unknown as ForensicEvent,
        event({ id: "late2", timestamp: day(20, 23), sourceScreenshots: [] }) as unknown as ForensicEvent,
      ] as ForensicEvent[]);
    });
    expect(await importBoth(delta(batch("z", 30)))).toBe(true);
    await expectSame();
  });

  it("folds a re-import of the same rows under new ids onto the stored rows", async () => {
    await importBoth(delta(batch("a", 40)));
    expect(await importBoth(delta(batch("b", 40)))).toBe(true);
    const state = await expectSame();
    // Same time, text and host: the re-import is the same observation.
    expect(state.forensicTimeline.length).toBe(80);
    expect(await importBoth(delta(batch("a", 40).map((e) => ({ ...e, id: `r-${e.id}` }))))).toBe(true);
    expect((await expectSame()).forensicTimeline.length).toBe(80);
  });

  it("folds a new row onto a stored one by hash, and every citation follows the survivor", async () => {
    const sha = "a".repeat(64);
    await importBoth(
      delta([{ id: "old", timestamp: day(3), description: "file written", sha256: sha, severity: "Low" }], {
        iocs: [{ id: "x1", type: "hash", value: sha, extractedFrom: ["old"] }],
      }),
    );
    await importBoth(delta(batch("n", 10)));
    expect(
      await importBoth(
        delta(
          [
            {
              id: "new",
              timestamp: day(3, 11),
              description: "malware found",
              sha256: sha,
              severity: "High",
              sources: ["THOR"],
            },
          ],
          {
            iocs: [{ id: "y1", type: "hash", value: sha.toUpperCase(), extractedFrom: ["new"] }],
          },
        ),
      ),
    ).toBe(true);
    const state = await expectSame();
    expect(state.forensicTimeline.filter((e) => e.sha256 === sha)).toHaveLength(1);
    expect(state.eventAliases).toBeDefined();
  });

  it("re-anchors guessed outlier years on the case's dominant year, and again when it moves", async () => {
    await importBoth(delta(batch("a", 30)));
    const guessed = (id: string, year: number): Ev => ({
      id,
      timestamp: `${year}-07-05T08:00:00.000Z`,
      description: `syslog line ${id}`,
      yearInferred: true,
    });
    expect(await importBoth(delta([guessed("g1", 2023), guessed("g2", 2031)]))).toBe(true);
    const state = await expectSame();
    expect(state.forensicTimeline.filter((e) => e.yearClampedFrom)).toHaveLength(2);
    // Enough 2025 evidence that 2025 becomes the dominant year: the clamped rows move again.
    const later = Array.from({ length: 400 }, (_, i) => ({
      id: `y${i}`,
      timestamp: `2025-03-${String(1 + (i % 28)).padStart(2, "0")}T10:${String(i % 60).padStart(2, "0")}:00.000Z`,
      description: `older evidence ${i}`,
    }));
    await importBoth(delta(later));
    const moved = await expectSame();
    expect(moved.forensicTimeline.find((e) => e.id === "g1")?.timestamp.startsWith("2025")).toBe(true);
  });

  it("merges IOCs case-insensitively, through aliases, past exclusions, continuing the id sequence", async () => {
    await importBoth(
      delta(batch("a", 5), {
        iocs: [
          { id: "q1", type: "domain", value: "Evil.Example.com" },
          { id: "q2", type: "ip", value: "10.1.1.1" },
        ],
      }),
    );
    await both(async (c) => {
      const s = await store.load(c);
      await store.save({
        ...s,
        iocExcludeRules: [
          { id: "x1", match: "suffix", pattern: ".lan", addedAt: "2026-09-30T00:00:00.000Z" },
        ],
      });
    });
    const aliases = { "evil-alias.example.com": "i002" };
    expect(
      await importBoth(
        delta(batch("b", 5), {
          iocs: [
            { id: "b1", type: "domain", value: "EVIL.example.COM" },
            { id: "b2", type: "domain", value: "evil-alias.example.com" },
            { id: "b3", type: "domain", value: "printer.lan" },
            { id: "b4", type: "ip", value: "10.2.2.2 (DC01)" },
          ],
        }),
        { iocAliases: aliases },
      ),
    ).toBe(true);
    const state = await expectSame();
    expect(state.iocs.some((i) => i.value === "printer.lan")).toBe(false);
    expect(state.iocs.find((i) => i.id === "i002")?.aliasValues).toEqual(["evil-alias.example.com"]);
  });

  it("carries the host rename ledger and collector names", async () => {
    await importBoth(delta(batch("a", 5)));
    const renames = [{ formerName: "OLD-PC", currentName: "HOST-1", until: day(2), basis: "6011" as const }];
    expect(
      await importBoth(delta(batch("b", 5), { hostRenames: renames, collectorHostnames: ["COLLECTOR"] })),
    ).toBe(true);
    await expectSame();
  });

  it("reads every ransomware-precursor row on every merge, so the cluster forms as in the full merge", async () => {
    await importBoth(delta(batch("a", 20)));
    const pre = (id: string, m: number, technique: string): Ev => ({
      id,
      timestamp: day(9, 3, m),
      description: `precursor ${id}`,
      mitreTechniques: [technique],
      asset: "HOST-9",
    });
    expect(await importBoth(delta([pre("r1", 1, "T1490"), pre("r2", 5, "T1562.001")]))).toBe(true);
    await expectSame();
    expect(await importBoth(delta([pre("r3", 9, "T1070.001")]))).toBe(true);
    const state = await expectSame();
    expect(state.forensicTimeline.find((e) => e.id === "r1")?.description).toContain(
      "[ransomware precursors:",
    );
    expect(await importBoth(delta(batch("c", 10)))).toBe(true);
    await expectSame();
  });

  it("keeps order when every new row sorts before every stored one (the timeline is respaced)", async () => {
    await importBoth(delta(batch("a", 30)));
    for (let k = 0; k < 4; k++) {
      const early = Array.from({ length: 30 }, (_, i) => ({
        id: `early${k}-${i}`,
        timestamp: `2026-06-${String(20 - k).padStart(2, "0")}T0${i % 10}:00:00.000Z`,
        description: `earlier ${k}/${i}`,
      }));
      expect(await importBoth(delta(early))).toBe(true);
      await expectSame();
    }
  });

  it("records that stored rows would fold on the next merge, and the next merge takes the full path", async () => {
    const path = "C:\\Tools\\drop.exe";
    // X and R share a structured path but are 2.5 s apart: no fold.
    await importBoth(
      delta([
        {
          id: "x",
          timestamp: day(4, 12, 0, 10),
          description: "write",
          path,
          sources: ["A"],
          sha256: "b".repeat(64),
        },
        { id: "r", timestamp: day(4, 12, 0, 7), description: "seen", path, sources: ["B"] },
      ]),
    );
    await importBoth(delta(batch("n", 5)));
    // Y shares X's hash and sits 4 s before it: X and Y fold, and the survivor takes Y's earlier time,
    // which is inside R's window — a fold today's merge makes only on the NEXT merge.
    const y = {
      id: "y",
      timestamp: day(4, 12, 0, 6),
      description: "hash hit",
      sha256: "b".repeat(64),
      sources: ["C"],
    };
    await importBoth(delta([y]));
    await expectSame();
    expect((await store.mergeSnapshot("inc"))?.meta?.stable).toBe(false);
    expect(await importBoth(delta(batch("m", 3)))).toBe(false);
    const state = await expectSame();
    expect(state.forensicTimeline.filter((e) => e.path === path)).toHaveLength(1);
    // The full merge recorded the case as stable again: the one after it is incremental.
    expect(await importBoth(delta(batch("k", 3)))).toBe(true);
    await expectSame();
  });
});

describe("incremental importer merge — refusals", () => {
  const ctx = (): WindowContext => windowCtx();

  it("refuses when a correlation pass has work, and names it", async () => {
    await importBoth(delta(batch("a", 5)));
    const d = delta([
      { id: "mail", timestamp: day(5), description: "Phish linking evil.example.com", sources: ["Email"] },
    ]);
    const out = await mergeIncrementally(store, "inc", d, ctx(), mergeIndexStamp());
    expect(out).toEqual({ ok: false, reason: "a correlation pass has work: email delivery" });
  });

  it("refuses a case indexed by another build", async () => {
    await importBoth(delta(batch("a", 5)));
    const out = await mergeIncrementally(store, "inc", delta(batch("b", 5)), ctx(), "0:other-build");
    expect(out).toEqual({ ok: false, reason: "the merge index is missing or from another build" });
  });

  it("falls back to the full merge when a write lands while it computes, and loses no write", async () => {
    await importBoth(delta(batch("a", 10)));
    const d = delta(batch("b", 10));
    const c = windowCtx();
    // The same outside write, before the merge on "full" and in the middle of it on "inc".
    const write = async (caseId: string) => {
      const [r] = await store.forensicRowsById(caseId, ["ae3"]);
      await store.updateForensicRows(caseId, [{ ...r, event: { ...r.event, severity: "Critical" } }]);
    };
    await write("full");
    await store.save(mergeDelta(await store.load("full"), d, c));
    const original = store.loadMergeOverview.bind(store);
    store.loadMergeOverview = async (caseId: string) => {
      const out = await original(caseId);
      await write(caseId);
      return out;
    };
    const out = await mergeIntoCase(store, "inc", d, c, (s) => mergeDelta(s, d, c));
    store.loadMergeOverview = original;
    expect(out.complete).toBe(true);
    await expectSame();
  });

  it("never indexes a row from the merge's copy when another write landed after its full save", async () => {
    const d = delta(batch("a", 10));
    const c = windowCtx();
    // The outside write turns an ordinary row into an email delivery (a pass anchor).
    const write = async (caseId: string) => {
      const [r] = await store.forensicRowsById(caseId, ["ae1"]);
      await store.updateForensicRows(caseId, [
        { ...r, event: { ...r.event, sources: ["Email"], description: "Phish linking evil.example.com" } },
      ]);
    };
    await store.save(mergeDelta(await store.load("full"), d, c));
    await write("full");
    const original = store.mergeStalePositions.bind(store);
    store.mergeStalePositions = async (caseId: string, stamp: string) => {
      await write(caseId);
      return original(caseId, stamp);
    };
    await mergeIntoCase(store, "inc", d, c, (s) => mergeDelta(s, d, c));
    store.mergeStalePositions = original;
    await expectSame();
    const next = delta([{ id: "contact", timestamp: day(20), description: "connected to evil.example.com" }]);
    expect(await importBoth(next)).toBe(false);
    await expectSame();
  });

  it("fails the import, and merges nothing twice, when an apply fails after it may have committed", async () => {
    await importBoth(delta(batch("a", 10)));
    const d = delta(batch("b", 10));
    const c = windowCtx();
    await store.save(mergeDelta(await store.load("full"), d, c));
    const original = store.mergeApply.bind(store);
    store.mergeApply = async (caseId, plan) => {
      await original(caseId, plan);
      throw new Error("the worker's reply was lost");
    };
    await expect(mergeIntoCase(store, "inc", d, c, (s) => mergeDelta(s, d, c))).rejects.toThrow(
      "the worker's reply was lost",
    );
    store.mergeApply = original;
    await expectSame();
  });

  it("falls back when another writer stored the timeline out of time order", async () => {
    await importBoth(delta(batch("a", 10)));
    await importBoth(delta(batch("b", 10)));
    await both(async (caseId) => {
      const s = await store.load(caseId);
      const t = [...s.forensicTimeline];
      [t[0], t[5]] = [t[5], t[0]];
      await store.save({ ...s, forensicTimeline: t });
    });
    expect(await importBoth(delta(batch("c", 10)))).toBe(false);
    await expectSame();
  });
});

describe("incremental importer merge — a timeline longer than one scan page (#1887)", () => {
  // The placement scan reads the timeline MERGE_SCAN_PAGE rows at a time; the order check and the
  // placement must see one continuous timeline across the page edges.
  const big = 2 * MERGE_SCAN_PAGE + 5;

  it("places new rows across page edges exactly as the full merge does", async () => {
    await importBoth(delta(batch("a", big)));
    for (const k of ["b", "c"]) {
      expect(
        await importBoth(
          delta(batch(k, 90, (i) => ({ timestamp: day(1 + (i % 28), 9 + (i % 5), i % 60, 30) }))),
        ),
      ).toBe(true);
      await expectSame();
    }
  }, 60_000);

  it("refuses a timeline that is out of order exactly at a page edge", async () => {
    await importBoth(delta(batch("a", big)));
    await importBoth(delta(batch("b", 10)));
    await both(async (caseId) => {
      const s = await store.load(caseId);
      const t = [...s.forensicTimeline];
      // The last row of the first page takes the latest time, so the order breaks between the
      // last row of page one and the first row of page two.
      const edge = MERGE_SCAN_PAGE - 1;
      [t[edge], t[t.length - 1]] = [t[t.length - 1], t[edge]];
      expect(Date.parse(t[edge].timestamp)).toBeGreaterThan(Date.parse(t[edge + 1].timestamp));
      await store.save({ ...s, forensicTimeline: t });
    });
    expect(await importBoth(delta(batch("c", 10)))).toBe(false);
    await expectSame();
  }, 60_000);
});

describe("incremental importer merge — undo and import counts", () => {
  it("undoes to the pre-import state, and counts the same added rows as the full merge", async () => {
    await importBoth(delta(batch("a", 30)));
    await importBoth(delta(batch("b", 30)));
    const before = { full: await store.load("full"), inc: await store.load("inc") };
    const baseline = {
      full: await captureImportBaseline(store, "full"),
      inc: await captureImportBaseline(store, "inc"),
    };
    const sha = "c".repeat(64);
    const d = delta(
      [
        ...batch("c", 30),
        {
          id: "dup",
          timestamp: day(2, 10, 1),
          description: "Service installed a-1",
          path: "C:\\Windows\\Temp\\a-1.exe",
          sha256: sha,
        },
      ],
      {
        iocs: [{ id: "c1", type: "hash", value: sha, extractedFrom: ["dup"] }],
      },
    );
    expect(await importBoth(d)).toBe(true);
    await expectSame();
    for (const c of ["full", "inc"] as const) {
      const checkpoint = await baselineCheckpoint(store, baseline[c], "import", "2026-09-30T12:00:00.000Z");
      expect(checkpoint).not.toBeNull();
      const restored = applyUndoDelta(await store.load(c), checkpoint!.delta!);
      expect({ ...restored, caseId: "x" }).toEqual({ ...before[c], caseId: "x" });
    }
    const counts = async (c: "full" | "inc") =>
      diffTimeline(outlineEvents(baseline[c].outline), outlineEvents(await store.forensicOutline(c)));
    expect(await counts("inc")).toEqual(await counts("full"));
  });
});
