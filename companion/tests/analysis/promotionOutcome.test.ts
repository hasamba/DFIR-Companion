import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1761: a promotion used to report success by asking, afterwards, which requested ids were in the
// forensic timeline. That cannot tell a new row from one that was already there, from one the
// correlation merge folded into an existing event, or from one that took an existing event's place.
// The missed-evidence review then told the analyst it had promoted 202 rows when 3 landed, and called
// the other 199 "refused by the promotion seam". The seam now reports what happened to each row.

const ev = (id: string, over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: "2026-05-12T08:00:00Z",
  description: `row ${id}`,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WS-01",
  ...over,
});

/** Same second, same text, same host: the correlation merge folds these into one event. */
const twin = (id: string, of: string, over: Partial<ForensicEvent> = {}) =>
  ev(id, { description: `row ${of}`, ...over });

const AT = "2026-09-28T10:00:00.000Z";

let stateStore: StateStore;
let pipeline: AnalysisPipeline;

beforeEach(async () => {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-promote-outcome-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  pipeline = new AnalysisPipeline({
    stateStore,
    superTimelineStore: new SuperTimelineStore(cases),
    stateLock: new StateLock(),
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
});

const seed = (forensicTimeline: ForensicEvent[], eventAliases?: Record<string, string>) =>
  stateStore.save({ ...emptyState("c1"), forensicTimeline, ...(eventAliases ? { eventAliases } : {}) });

describe("a missed-evidence promotion refuses a row the case already holds under another id", () => {
  it("reports a lineage-mapped row as a duplicate and leaves the event it maps to untouched", async () => {
    // The route checks this too, against the state it loaded before the grade and archive reads. The
    // seam checks again under the state lock, so an import that folds the row in between cannot
    // slip it through.
    await seed([ev("e1", { severity: "High" })], { r1: "e1" });

    const { state, outcome } = await pipeline.promoteSuperTimelineWithOutcome(
      "c1",
      [ev("r1", { description: "hayabusa copy", severity: "Critical" })],
      { importedAt: AT, intent: "missed-evidence", tagById: { r1: ["[missed-evidence: Critical]"] } },
    );

    expect(outcome.duplicates).toEqual([{ id: "r1", of: "e1" }]);
    expect(outcome.added).toEqual([]);
    expect(state.forensicTimeline.map((e) => e.id)).toEqual(["e1"]);
    expect(state.forensicTimeline[0].severity).toBe("High");
    expect(state.forensicTimeline[0].provenance ?? []).toEqual([]);
  });

  it("leaves an event with the same id untouched, rather than restating it at the model's grade", async () => {
    // The route read its state before the grade and archive lookups; an import that added the same
    // row in between is only visible here. A same-id merge overwrites text and severity, so letting
    // the archive copy through would rewrite the event at the model's grade — here, a lower one.
    await seed([ev("r1", { severity: "High", description: "as imported" })]);

    const { state, outcome } = await pipeline.promoteSuperTimelineWithOutcome(
      "c1",
      [ev("r1", { description: "archive copy", severity: "Medium" })],
      { importedAt: AT, intent: "missed-evidence", tagById: { r1: ["[missed-evidence: Medium]"] } },
    );

    expect(outcome.alreadyPresent).toEqual(["r1"]);
    expect(outcome.added).toEqual([]);
    const [row] = state.forensicTimeline;
    expect(row).toMatchObject({ id: "r1", severity: "High", description: "as imported" });
    expect(row.provenance ?? []).toEqual([]);
    expect(row.promotedAt).toBeUndefined();
    expect((await stateStore.load("c1")).forensicTimeline[0].severity).toBe("High");
  });

  it("keeps today's behaviour for the other intents", async () => {
    await seed([ev("e1", { severity: "High" })], { r1: "e1" });

    const { outcome } = await pipeline.promoteSuperTimelineWithOutcome(
      "c1",
      [ev("r1", { description: "hayabusa copy" })],
      { importedAt: AT, intent: "manual" },
    );

    expect(outcome.added).toEqual(["r1"]);
  });
});

describe("what happened to each requested row", () => {
  it("tells a new row from one already there, a duplicate, a twin in the same selection and a replacement", async () => {
    await seed([
      ev("p1"),
      ev("e1", { severity: "High" }),
      ev("e2", { severity: "Low" }),
    ]);

    const { state, outcome } = await pipeline.promoteSuperTimelineWithOutcome(
      "c1",
      [
        ev("p1"),
        ev("n1", { severity: "High" }),
        twin("d1", "e1", { severity: "Medium" }),
        ev("s1", { description: "one event, two rows", severity: "Medium" }),
        ev("s2", { description: "one event, two rows", severity: "Low" }),
        twin("x1", "e2", { severity: "High" }),
        ev("lab1", { origin: "lab" }),
      ],
      {
        importedAt: AT,
        intent: "missed-evidence",
        tagById: { d1: ["[missed-evidence: Medium]"], x1: ["[missed-evidence: High]"] },
      },
    );

    expect(outcome.alreadyPresent).toEqual(["p1"]);
    expect([...outcome.added].sort()).toEqual(["n1", "s1", "x1"]);
    expect(outcome.duplicates).toEqual([{ id: "d1", of: "e1" }]);
    expect(outcome.mergedIntoSelected).toEqual([{ id: "s2", of: "s1" }]);
    // The one path where a model's grade reaches an event the case already held. It keeps its tag,
    // and the outcome names it so the route can say so.
    expect(outcome.replaced).toEqual([{ id: "x1", of: "e2" }]);
    expect(outcome.refused).toEqual(["lab1"]);

    const byId = new Map(state.forensicTimeline.map((e) => [e.id, e]));
    // A folded-away row cannot raise the event that kept its id, and its tag has nowhere to land.
    expect(byId.get("e1")?.severity).toBe("High");
    expect((byId.get("e1")?.provenance ?? []).join(" ")).not.toContain("missed-evidence");
    expect(byId.get("x1")?.provenance).toContain("[missed-evidence: High]");
    expect(byId.has("e2")).toBe(false);
  });

  it("counts each requested id once", async () => {
    await seed([]);
    const { outcome } = await pipeline.promoteSuperTimelineWithOutcome("c1", [ev("n1"), ev("n1")], {
      importedAt: AT,
      intent: "manual",
    });
    expect(outcome.added).toEqual(["n1"]);
  });
});

describe("the case timeline note", () => {
  it("counts only the rows this promotion added when the note is a function", async () => {
    await seed([ev("e1", { severity: "High" })]);

    const { state } = await pipeline.promoteSuperTimelineWithOutcome(
      "c1",
      [ev("n1"), twin("d1", "e1")],
      { importedAt: AT, intent: "missed-evidence", note: (o) => `promoted ${o.added.length}` },
    );

    expect(state.timeline.map((t) => t.description)).toEqual(["promoted 1"]);
    expect(state.timeline[0]).toEqual({
      timestamp: AT,
      windowSequence: -1,
      description: "promoted 1",
      sourceScreenshots: [],
    });
    expect((await stateStore.load("c1")).timeline.map((t) => t.description)).toEqual(["promoted 1"]);
  });

  it("writes no note when the function returns nothing", async () => {
    await seed([ev("e1", { severity: "High" })]);

    const { state } = await pipeline.promoteSuperTimelineWithOutcome("c1", [twin("d1", "e1")], {
      importedAt: AT,
      intent: "missed-evidence",
      note: (o) => (o.added.length ? `promoted ${o.added.length}` : ""),
    });

    expect(state.timeline).toEqual([]);
  });

  it("writes a string note as before, and the plain promotion still answers with the state", async () => {
    await seed([]);

    const state = await pipeline.promoteSuperTimeline("c1", [ev("n1")], {
      importedAt: AT,
      intent: "manual",
      note: "attached as remediation evidence for b1",
    });

    expect(state.timeline.map((t) => t.description)).toEqual(["attached as remediation evidence for b1"]);
    expect(state.forensicTimeline.map((e) => e.id)).toEqual(["n1"]);
  });
});
