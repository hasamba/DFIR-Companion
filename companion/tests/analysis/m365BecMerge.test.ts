// #2570: the M365 BEC pairings (#2550) across separate uploads, in the merge chain. Each upload goes
// into "full" (load → mergeDelta → save) and "inc" (mergeIntoCase); a load of each must be equal
// after every step, with the default demote (Info out) simulated between imports on both. The grades
// must equal a whole-file import of the same records ("whole").
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { deltaSchema, type AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { mergeDelta, type WindowContext } from "../../src/analysis/stateMerge.js";
import { mergeIntoCase } from "../../src/analysis/caseMerge.js";
import { MERGE_FLAG_LOAD, MERGE_FLAG_TRIGGER, mergeIndexEntry } from "../../src/analysis/mergeIndex.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { BEC_PAIRING_MARKER, raiseCaseBecPairs } from "../../src/analysis/m365BecMerge.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import { addUser, deleter, ex, forwardOut, grantAdmin, pairRole } from "./fixtures/m365BecRecords.js";

type Rec = Record<string, unknown>;

let root: string;
let store: StateStore;
let step = 0;
let incrementalRuns = 0;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-bec-merge-"));
  const cases = new CaseStore(root);
  for (const caseId of ["full", "inc", "whole"])
    await cases.createCase({ caseId, name: caseId, investigator: "i", aiProvider: null });
  store = new StateStore(cases);
  step = 0;
  incrementalRuns = 0;
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function upload(records: readonly Rec[], aggregate = false): ForensicEvent[] {
  step++;
  const rows = parseM365Audit(JSON.stringify(records), { aggregate }).events;
  return rows.map((e, i) => ({
    ...e,
    id: `f${step}e${i + 1}`,
    relatedFindingIds: [],
    sourceScreenshots: [],
  }));
}

function delta(events: ForensicEvent[]): AnalysisDelta {
  return deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    forensicEvents: events,
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: `import of ${events.length} event(s)`,
    summary: "",
  });
}

const windowCtx = (): WindowContext => ({
  windowSequence: -1,
  timestamp: `2026-11-11T10:${String(step).padStart(2, "0")}:00.000Z`,
  sourceScreenshots: [`file-${step}.json`],
});

async function demote(caseId: string): Promise<void> {
  const info = await store.forensicRowsOutsideSeverities(caseId, ["Critical", "High", "Medium", "Low"]);
  if (info.length)
    await store.deleteForensicRows(
      caseId,
      info.map((r) => r.rowId),
    );
}

/** One upload into "full" and "inc", the demote on both, then a check that both read the same. */
async function importBoth(records: readonly Rec[], aggregate = false): Promise<InvestigationState> {
  const d = delta(upload(records, aggregate));
  const ctx = windowCtx();
  await store.save(mergeDelta(await store.load("full"), d, ctx));
  const { complete } = await mergeIntoCase(store, "inc", d, ctx, (s) => mergeDelta(s, d, ctx));
  if (!complete) incrementalRuns++;
  for (const c of ["full", "inc"]) await demote(c);
  const full = await store.load("full");
  const inc = await store.load("inc");
  expect({ ...inc, caseId: "x" }).toEqual({ ...full, caseId: "x" });
  return full;
}

/** The same records as ONE upload into "whole". */
async function importWhole(records: readonly Rec[], aggregate = false): Promise<InvestigationState> {
  const d = delta(upload(records, aggregate));
  await store.save(mergeDelta(await store.load("whole"), d, windowCtx()));
  await demote("whole");
  return store.load("whole");
}

/** Pairing role → severity, sorted, for comparing a split import with a whole one. */
const grades = (s: InvestigationState): string[] =>
  s.forensicTimeline
    .map((e) => `${pairRole(e.description)}:${e.severity}`)
    .filter((x) => !x.startsWith(":"))
    .sort();
const row = (s: InvestigationState, role: ReturnType<typeof pairRole>): ForensicEvent => {
  const r = s.forensicTimeline.find((e) => pairRole(e.description) === role);
  if (!r) throw new Error(`no ${role} row`);
  return r;
};

/** Import `parts` one upload each, then the whole set once; returns the split state. */
async function splitVsWhole(parts: Rec[][], aggregate = false): Promise<InvestigationState> {
  let s: InvestigationState | undefined;
  for (const p of parts) s = await importBoth(p, aggregate);
  const whole = await importWhole(parts.flat(), aggregate);
  expect(grades(s!)).toEqual(grades(whole));
  return s!;
}

describe("hiding rule + forward-out rule across uploads (#2570)", () => {
  it("forward first, hide in a later upload: the hide row is Critical, 'in this case'", async () => {
    const s = await splitVsWhole([[forwardOut(0)], [deleter(2)]]);
    expect(row(s, "hide").severity).toBe("Critical");
    expect(row(s, "hide").description).toContain(`${BEC_PAIRING_MARKER} hides mail`);
    expect(row(s, "hide").description).toMatch(/within 10 minutes in this case/);
    expect(row(s, "forward").severity).toBe("High");
    expect(incrementalRuns).toBeGreaterThan(0);
  });
  it("hide stored first, the forward arrives later: the stored hide row is raised", async () => {
    const s = await splitVsWhole([[deleter(0)], [forwardOut(5)]]);
    expect(row(s, "hide").severity).toBe("Critical");
    expect(row(s, "hide").description.split(BEC_PAIRING_MARKER)).toHaveLength(2);
    expect(incrementalRuns).toBeGreaterThan(0);
  });
  it("exactly 10 minutes apart pairs; one second more does not", async () => {
    expect(row(await splitVsWhole([[forwardOut(0)], [deleter(10)]]), "hide").severity).toBe("Critical");
  });
  it("10 minutes and one second apart stays High", async () => {
    const s = await splitVsWhole([[forwardOut(0)], [deleter(10 + 1 / 60)]]);
    expect(row(s, "hide").severity).toBe("High");
  });
  it("a different mailbox domain or tenant is no pair, though the local name matches", async () => {
    const other = { ObjectId: "alice@other.invalid\\Fin", UserId: "alice@tenant.invalid" };
    const a = await splitVsWhole([
      [forwardOut(0, other)],
      [deleter(2, { ObjectId: "alice@tenant.invalid\\" })],
    ]);
    expect(row(a, "hide").severity).toBe("High");
  });
  it("a different tenant is no pair", async () => {
    const s = await splitVsWhole([[forwardOut(0, { OrganizationId: "tenant-2" })], [deleter(2)]]);
    expect(row(s, "hide").severity).toBe("High");
  });
  it("one rule that both forwards out and deletes is never paired with itself", async () => {
    const both = ex(
      "New-InboxRule",
      { Name: "", ForwardTo: "drop@outside.invalid", DeleteMessage: "True" },
      0,
    );
    const s = await splitVsWhole([[both]]);
    expect(s.forensicTimeline.some((e) => e.severity === "Critical")).toBe(false);
  });
  it("a re-upload of the hide record adds no second note", async () => {
    await importBoth([forwardOut(0)]);
    const hide = deleter(2);
    await importBoth([hide]);
    const s = await importBoth([hide]);
    const hides = s.forensicTimeline.filter((e) => pairRole(e.description) === "hide");
    for (const h of hides) expect(h.description.split(BEC_PAIRING_MARKER).length).toBeLessThanOrEqual(2);
    expect(hides.every((h) => h.severity === "Critical")).toBe(true);
  });
});

describe("folded rows join only on a known occurrence time", () => {
  it("forward rules folded at 0 and 120 minutes do not pair with a hide at 60", async () => {
    const s = await splitVsWhole([[forwardOut(0), forwardOut(120)], [deleter(60)]], true);
    expect(row(s, "forward").count).toBe(2);
    expect(row(s, "hide").severity).toBe("High");
  });
  it("a folded row joins on the time of the record it shows, never on its span", async () => {
    // The stored folded row shows the record at 0; the one at 120 is only a count, so a hide uploaded
    // later at 125 is not paired (a documented loss: the whole-file parse pairs before it folds).
    await importBoth([forwardOut(0), forwardOut(120)], true);
    expect(row(await importBoth([deleter(125)], true), "hide").severity).toBe("High");
  });
  it("the folded row still pairs on the time it shows", async () => {
    const s = await splitVsWhole([[forwardOut(0), forwardOut(120)], [deleter(5)]], true);
    expect(row(s, "hide").severity).toBe("Critical");
  });
  it("a budget aggregate of two users' creations never lends one user's time to the other", () => {
    // User A created at 10:00 and user B at 11:00, folded into one row that kept A's block; a grant to
    // A the next day at 11:00 is 25 h after A's creation (#2570 review).
    const [created, grant] = parseM365Audit(JSON.stringify([addUser(0), grantAdmin(25 * 60)]), {
      aggregate: false,
    }).events.map((e, i) => ({ ...e, id: `b${i}`, relatedFindingIds: [], sourceScreenshots: [] }));
    const folded = {
      ...created,
      count: 2,
      endTimestamp: new Date(Date.parse(created.timestamp) + 3_600_000).toISOString(),
    };
    const out = raiseCaseBecPairs([folded, grant]);
    expect(out.find((e) => e.id === grant.id)?.severity).toBe("Medium");
  });
});

describe("privileged role granted to a newly created user, across uploads (#2570)", () => {
  it("creation first, grant in a later upload: the grant is High, the creation stays Medium", async () => {
    const s = await splitVsWhole([[addUser(0)], [grantAdmin(60)]]);
    expect(row(s, "grant").severity).toBe("High");
    expect(row(s, "grant").description).toMatch(/created within 24 hours in this case/);
    expect(row(s, "created").severity).toBe("Medium");
    expect(incrementalRuns).toBeGreaterThan(0);
  });
  it("grant stored first, the earlier creation arrives later: the stored grant is raised", async () => {
    const s = await splitVsWhole([[grantAdmin(60)], [addUser(0)]]);
    expect(row(s, "grant").severity).toBe("High");
  });
  it("exactly 24 hours pairs; a grant before the creation or later than 24 h does not", async () => {
    expect(row(await splitVsWhole([[addUser(0)], [grantAdmin(24 * 60)]]), "grant").severity).toBe("High");
  });
  it("a grant 24 h and one second after, or before the creation, stays Medium", async () => {
    const late = await splitVsWhole([[addUser(0)], [grantAdmin(24 * 60 + 1 / 60)]]);
    expect(row(late, "grant").severity).toBe("Medium");
  });
  it("a grant before the creation stays Medium", async () => {
    const s = await splitVsWhole([[grantAdmin(0)], [addUser(5)]]);
    expect(row(s, "grant").severity).toBe("Medium");
  });
  it("a different tenant is no pair", async () => {
    const s = await splitVsWhole([[addUser(0, { OrganizationId: "tenant-2" })], [grantAdmin(1)]]);
    expect(row(s, "grant").severity).toBe("Medium");
  });
});

describe("the pass and its merge index", () => {
  const rows = (recs: Rec[]): ForensicEvent[] =>
    parseM365Audit(JSON.stringify(recs), { aggregate: false }).events.map((e, i) => ({
      ...e,
      id: `p${i}`,
      relatedFindingIds: [],
      sourceScreenshots: [],
    }));

  it("stamps the join block on every pairing row at import", () => {
    const r = rows([forwardOut(0), deleter(30), addUser(0), grantAdmin(1)]);
    for (const role of ["hide", "forward", "grant", "created"] as const)
      expect(r.find((e) => pairRole(e.description) === role)?.canonical?.m365Bec).toBeDefined();
  });
  it("is idempotent, and the import-time raise plus the pass write one note", () => {
    const once = raiseCaseBecPairs(rows([forwardOut(0), deleter(2)]));
    const twice = raiseCaseBecPairs(once);
    expect(twice).toEqual(once);
    const hide = twice.find((e) => pairRole(e.description) === "hide")!;
    expect(hide.severity).toBe("Critical");
    expect(hide.description.split(BEC_PAIRING_MARKER)).toHaveLength(2);
  });
  it("raises a noted row again when its grade was reset, without a second note", () => {
    const raised = raiseCaseBecPairs(rows([forwardOut(0), deleter(2)]));
    const reset = raised.map((e) =>
      pairRole(e.description) === "hide" ? { ...e, severity: "High" as const } : e,
    );
    const hide = raiseCaseBecPairs(reset).find((e) => pairRole(e.description) === "hide")!;
    expect(hide.severity).toBe("Critical");
    expect(hide.description.split(BEC_PAIRING_MARKER)).toHaveLength(2);
  });
  it("joins nothing for rows without the block (imported before #2570)", () => {
    const bare = rows([forwardOut(0), deleter(30)]).map((e) => {
      const { m365Bec: _drop, ...canonical } = e.canonical!;
      void _drop;
      return { ...e, canonical };
    });
    const moved = bare.map((e) =>
      pairRole(e.description) === "hide" ? { ...e, timestamp: forwardOut(2).CreationTime as string } : e,
    );
    expect(raiseCaseBecPairs(moved).some((e) => e.severity === "Critical")).toBe(false);
  });
  it("marks every pairing row LOAD, never TRIGGER", () => {
    for (const e of rows([forwardOut(0), deleter(30), addUser(0), grantAdmin(1)])) {
      if (!pairRole(e.description)) continue;
      const { flags } = mergeIndexEntry(e);
      expect(flags & MERGE_FLAG_LOAD).toBe(MERGE_FLAG_LOAD);
      expect(flags & MERGE_FLAG_TRIGGER).toBe(0);
    }
  });
});
