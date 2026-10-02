import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState, type ForensicEvent, type Severity } from "../../src/analysis/stateTypes.js";
import { JevGradeStore } from "../../src/analysis/ai/jev/jevGradeRecord.js";
import type { JevGradeSignals } from "../../src/analysis/ai/jev/jevGrader.js";

// The WRITE half of the missed-evidence review (#1568).
//
// The grading pass promotes nothing; this route is the only way its findings reach the forensic
// timeline, and it moves only what the analyst ticked. What is worth pinning at the route is what
// an analyst would be unable to see afterwards: that the severity on a promoted row is the one the
// model gave, that a promotion can only ever RAISE it, that the row says a model chose it, and that
// the three "nothing to do" cases report themselves instead of failing the batch.
//
// THE GRADE IS THE SERVER'S, NOT THE BROWSER'S (#1578). The route writes the severity and the tag
// from the server's own record of what the review graded. So each test seeds that record the way a
// review would, and the browser sends only row ids.

const raw = (id: string, p: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: `row ${id}`,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...p,
});

const tick = (id: string, grade: Severity, confidence = 0.86, score = 3.4) => ({
  id,
  grade,
  confidence,
  score,
});

type Tick = ReturnType<typeof tick> & { signals?: JevGradeSignals };

async function harness(
  opts: {
    archive?: ForensicEvent[];
    forensic?: ForensicEvent[];
    withSuperStore?: boolean;
    /** What the review graded, as the server recorded it. */
    reviewed?: Tick[];
    model?: string;
    /** The case lineage (#1715): absorbed id -> the id of the event that kept it. */
    aliases?: Record<string, string>;
  } = {},
) {
  const root = await mkdtemp(join(tmpdir(), "dfir-jev-promote-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save({
    ...emptyState("c1"),
    forensicTimeline: opts.forensic ?? [],
    ...(opts.aliases ? { eventAliases: opts.aliases } : {}),
  });
  // A deterministic runtime pipeline with no AI provider: promotion is a merge, not a model call.
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const superTimelineStore = opts.withSuperStore === false ? undefined : new SuperTimelineStore(store);
  if (superTimelineStore && opts.archive?.length) await superTimelineStore.append("c1", opts.archive);
  if (opts.reviewed?.length) {
    await new JevGradeStore(store).record("c1", opts.model ?? "typesafe/jev-1.13", opts.reviewed);
  }
  const activity: string[] = [];
  const app = createApp(store, {
    pipeline,
    stateStore,
    ...(superTimelineStore ? { superTimelineStore } : {}),
    activityLogStore: {
      add: async (_caseId: string, entry: { detail?: string }) => void activity.push(entry.detail ?? ""),
    } as never,
  });
  return { app, stateStore, store, activity };
}

const promote = (app: Awaited<ReturnType<typeof harness>>["app"], body: unknown) =>
  request(app)
    .post("/cases/c1/jev/promote")
    .send(body as object);

/** The body the panel sends: row ids, and nothing the server should have to trust. */
const ids = (...list: string[]) => ({ rows: list.map((id) => ({ id })) });

describe("promoting what the missed-evidence review found", () => {
  it("lands the ticked rows at the grade the model gave them", async () => {
    const { app, stateStore } = await harness({
      archive: [raw("r1"), raw("r2"), raw("r3")],
      reviewed: [tick("r1", "High"), tick("r2", "Medium", 0.42, 2.1), tick("r3", "High")],
    });

    const res = await promote(app, ids("r1", "r2"));

    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(2);
    expect(res.body.skipped).toBe(0);
    expect(res.body.state.forensicEvents).toBe(2);

    const after = await stateStore.load("c1");
    const byId = new Map(after.forensicTimeline.map((e) => [e.id, e]));
    expect(byId.get("r1")?.severity).toBe("High");
    expect(byId.get("r2")?.severity).toBe("Medium");
    // r3 was not ticked, so it is still archive-only. A review that promoted what it read rather
    // than what the analyst picked would fail here and nowhere else.
    expect(byId.has("r3")).toBe(false);
  });

  it("adds the rule version to the tag when the grade came from the decomposed questions (#1924)", async () => {
    const signals = {
      shape: "decomposed" as const,
      rule: "d1",
      malicious: 0.92,
      explained: null,
      strength: 2.6,
      strengthConfidence: 0.8,
      impact: 2.7,
      decision: "graded" as const,
    };
    const { app, stateStore } = await harness({
      archive: [raw("r1"), raw("r2")],
      reviewed: [{ ...tick("r1", "Critical", 0.8), signals }, tick("r2", "High", 0.7)],
    });

    await promote(app, ids("r1", "r2"));

    const byId = new Map((await stateStore.load("c1")).forensicTimeline.map((e) => [e.id, e]));
    const decomposed = (byId.get("r1")?.provenance ?? []).join(" ");
    expect(decomposed).toMatch(/\[missed-evidence: Critical conf 0\.80 by typesafe\/jev-1\.13 · d1\]/);
    // A single-question grade keeps today's tag, unchanged.
    expect((byId.get("r2")?.provenance ?? []).join(" ")).toMatch(
      /\[missed-evidence: High conf 0\.70 by typesafe\/jev-1\.13\]/,
    );
  });

  it("records the review, the grade, the confidence and the model on the promoted row", async () => {
    const { app, stateStore } = await harness({
      archive: [raw("r1")],
      reviewed: [tick("r1", "High", 0.86)],
      model: "typesafe/jev-1.13",
    });

    await promote(app, ids("r1"));

    const [row] = (await stateStore.load("c1")).forensicTimeline;
    const tag = (row.provenance ?? []).join(" ");
    expect(tag).toContain("missed-evidence");
    expect(tag).toContain("High");
    expect(tag).toContain("0.86");
    expect(tag).toContain("typesafe/jev-1.13");
    // Not a human's own call, and not the deterministic tagger's: "[promoted]" means an analyst
    // graded it themselves, and this severity came from a model.
    expect(row.provenance ?? []).not.toContain("[promoted]");
    expect(row.promotedAt).toBeTruthy();
  });

  it("raises a severity but never lowers one", async () => {
    const { app, stateStore } = await harness({
      archive: [raw("hot", { severity: "High" }), raw("cold")],
      reviewed: [tick("hot", "Low", 0.3, 1), tick("cold", "Critical", 0.9, 4)],
    });

    const res = await promote(app, ids("hot", "cold"));

    expect(res.body.promoted).toBe(2);
    const byId = new Map((await stateStore.load("c1")).forensicTimeline.map((e) => [e.id, e]));
    expect(byId.get("hot")?.severity).toBe("High");
    expect(byId.get("cold")?.severity).toBe("Critical");
  });

  it("skips a row that is already in the forensic timeline instead of failing the batch", async () => {
    const already = raw("r1", { severity: "High" });
    const { app, stateStore } = await harness({
      archive: [already, raw("r2")],
      forensic: [already],
      reviewed: [tick("r1", "Critical"), tick("r2", "High")],
    });

    const res = await promote(app, ids("r1", "r2"));

    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(1);
    expect(res.body.skipped).toBe(1);
    expect(res.body.reasons.join(" ")).toMatch(/already in the forensic timeline/i);
    const byId = new Map((await stateStore.load("c1")).forensicTimeline.map((e) => [e.id, e]));
    // A no-op, in both directions: the row that was there keeps the severity it had.
    expect(byId.get("r1")?.severity).toBe("High");
    expect(byId.get("r2")?.severity).toBe("High");
  });

  it("refuses a sandbox-produced row and says so", async () => {
    const { app, stateStore } = await harness({
      archive: [raw("lab1", { origin: "lab" }), raw("r2")],
      reviewed: [tick("lab1", "High"), tick("r2", "Medium")],
    });

    const res = await promote(app, ids("lab1", "r2"));

    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(1);
    expect(res.body.skipped).toBe(1);
    expect(res.body.reasons.join(" ")).toMatch(/sandbox/i);
    const landed = (await stateStore.load("c1")).forensicTimeline.map((e) => e.id);
    expect(landed).toEqual(["r2"]);
  });

  it("reports a row the archive no longer holds rather than 404-ing the whole selection", async () => {
    const { app } = await harness({
      archive: [raw("r1")],
      reviewed: [tick("r1", "High"), tick("gone", "High")],
    });

    const res = await promote(app, ids("r1", "gone"));

    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(1);
    expect(res.body.skipped).toBe(1);
    expect(res.body.reasons.join(" ")).toMatch(/no longer in the archive/i);
  });

  it("warns that a row promoted at Info reaches synthesis only once (#1586)", async () => {
    const { app } = await harness({ archive: [raw("r1")], reviewed: [tick("r1", "Info", 0.2, 0.1)] });

    const res = await promote(app, ids("r1"));

    expect(res.body.promoted).toBe(1);
    const text = res.body.reasons.join(" ");
    expect(text).toMatch(/stayed Info/);
    expect(text).toMatch(/next synthesis reads them once as newly promoted evidence/);
    expect(text).not.toMatch(/will not read them/);
  });
});

describe("the grade on a promoted row is the one the server recorded (#1578)", () => {
  it("ignores a grade, confidence, score and model the browser sends", async () => {
    // An older dashboard tab still sends all four, and a tampered body sends whatever it likes. The
    // row must land at the recorded grade, tagged with the recorded confidence and model.
    const { app, stateStore } = await harness({
      archive: [raw("r1")],
      reviewed: [tick("r1", "Low", 0.31, 1.2)],
      model: "typesafe/jev-1.13",
    });

    const res = await promote(app, {
      rows: [{ id: "r1", grade: "Critical", confidence: 0.99, score: 4 }],
      model: "[promoted]",
    });

    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(1);
    const [row] = (await stateStore.load("c1")).forensicTimeline;
    expect(row.severity).toBe("Low");
    const tag = (row.provenance ?? []).join(" ");
    expect(tag).toContain("Low conf 0.31");
    expect(tag).toContain("typesafe/jev-1.13");
    expect(tag).not.toContain("Critical");
    expect(tag).not.toContain("0.99");
    expect(tag).not.toContain("[promoted]");
  });

  it("does not promote a row no review in this case graded, and says so", async () => {
    const { app, stateStore } = await harness({
      archive: [raw("r1"), raw("unreviewed")],
      reviewed: [tick("r1", "High")],
    });

    const res = await promote(app, ids("r1", "unreviewed"));

    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(1);
    expect(res.body.skipped).toBe(1);
    expect(res.body.reasons.join(" ")).toMatch(/not graded by a review in this case/i);
    expect((await stateStore.load("c1")).forensicTimeline.map((e) => e.id)).toEqual(["r1"]);
  });

  it("skips every row, rather than failing, when the case has never been reviewed", async () => {
    const { app, stateStore } = await harness({ archive: [raw("r1"), raw("r2")] });

    const res = await promote(app, ids("r1", "r2"));

    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(0);
    expect(res.body.skipped).toBe(2);
    expect(res.body.reasons.join(" ")).toMatch(/2 row\(s\) were not graded by a review in this case/i);
    expect((await stateStore.load("c1")).forensicTimeline).toEqual([]);
  });
});

describe("a ticked row whose event the forensic timeline already holds (#1761)", () => {
  // Two tools, one event: Chainsaw and Hayabusa both read the same Sysmon log. The case keeps the
  // Chainsaw event and records the Hayabusa row as its duplicate (the lineage, #1715). The review
  // used to offer those rows as missed evidence and the route promoted them, calling the rows the
  // merge folded away "refused by the promotion seam" and writing the requested count into the note.
  const chainsaw = raw("e1", { severity: "High", description: "toolkit written to C:\\Users\\Public" });
  const notes = async (stateStore: Awaited<ReturnType<typeof harness>>["stateStore"]) =>
    (await stateStore.load("c1")).timeline.map((t) => t.description);

  it("reports a recorded duplicate by the event it duplicates, not as refused, and changes nothing", async () => {
    const { app, stateStore, activity } = await harness({
      forensic: [chainsaw],
      aliases: { r1: "e1", r2: "e1" },
      archive: [raw("r1", { description: "hayabusa copy" }), raw("r2", { description: "second copy" })],
      // r2 was never graded: a duplicate is reported as one whatever the grade record says.
      reviewed: [tick("r1", "Critical")],
    });

    const res = await promote(app, ids("r1", "r2"));

    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(0);
    expect(res.body.skipped).toBe(2);
    const text = res.body.reasons.join(" ");
    expect(text).toMatch(/2 row\(s\) were already in the forensic timeline as a duplicate of an event there/);
    expect(text).toContain("r1 (duplicate of e1)");
    expect(text).not.toMatch(/refused/);
    expect(text).not.toMatch(/not graded/);
    const after = await stateStore.load("c1");
    expect(after.forensicTimeline.map((e) => e.id)).toEqual(["e1"]);
    expect(after.forensicTimeline[0].severity).toBe("High");
    expect(after.forensicTimeline[0].provenance ?? []).toEqual([]);
    // Nothing was promoted, so the case timeline gains no "promoted" note.
    expect(await notes(stateStore)).toEqual([]);
    expect(activity.join(" ")).toMatch(/promoted 0 archive row/);
  });

  it("reports a row the merge folds into an existing event as a duplicate, and the note counts what landed", async () => {
    const { app, stateStore, activity } = await harness({
      forensic: [chainsaw],
      archive: [raw("d1", { description: chainsaw.description }), raw("n1")],
      reviewed: [tick("d1", "Medium"), tick("n1", "High")],
    });

    const res = await promote(app, ids("d1", "n1"));

    expect(res.body.promoted).toBe(1);
    expect(res.body.skipped).toBe(1);
    const text = res.body.reasons.join(" ");
    expect(text).toContain("d1 (duplicate of e1)");
    expect(text).not.toMatch(/refused/);
    expect(await notes(stateStore)).toEqual([
      "Missed-evidence review: promoted 1 archive row(s) at the grade a decision model gave them",
    ]);
    expect(activity.join(" ")).toMatch(/promoted 1 archive row/);
    const byId = new Map((await stateStore.load("c1")).forensicTimeline.map((e) => [e.id, e]));
    expect(byId.get("e1")?.severity).toBe("High");
    expect((byId.get("e1")?.provenance ?? []).join(" ")).not.toContain("missed-evidence");
  });

  it("does not warn about Info, or name the model, for a row that folded away", async () => {
    const { app, store, activity } = await harness({
      forensic: [chainsaw],
      archive: [raw("d1", { description: chainsaw.description }), raw("n1")],
      reviewed: [tick("d1", "Info", 0.2, 0.1)],
      model: "model-that-graded-the-duplicate",
    });
    await new JevGradeStore(store).record("c1", "model-that-graded-the-new-row", [tick("n1", "High")]);

    const res = await promote(app, ids("d1", "n1"));

    expect(res.body.promoted).toBe(1);
    expect(res.body.reasons.join(" ")).not.toMatch(/stayed Info/);
    const log = activity.join(" ");
    expect(log).toContain("model-that-graded-the-new-row");
    expect(log).not.toContain("model-that-graded-the-duplicate");
  });

  it("says two ticked rows describing one event were merged, not that they were already there", async () => {
    // Two tools' rows for one file: different text, one hash. (Identical text would never reach the
    // archive twice — the super-timeline keeps one copy of an exact duplicate.)
    const sha256 = "ab".repeat(32);
    const { app } = await harness({
      archive: [
        raw("s1", { description: "file written (chainsaw)", sha256 }),
        raw("s2", { description: "file written (hayabusa)", sha256 }),
      ],
      reviewed: [tick("s1", "High"), tick("s2", "Medium")],
    });

    const res = await promote(app, ids("s1", "s2"));

    expect(res.body.promoted).toBe(1);
    const text = res.body.reasons.join(" ");
    expect(text).toContain("s2 (merged into s1)");
    expect(text).not.toMatch(/already in the forensic timeline/);
  });

  it("says so when a promoted row took the place of an event the case already held", async () => {
    const { app, stateStore } = await harness({
      forensic: [raw("e2", { severity: "Low", description: "same fact" })],
      archive: [raw("x1", { description: "same fact" })],
      reviewed: [tick("x1", "High")],
    });

    const res = await promote(app, ids("x1"));

    expect(res.body.promoted).toBe(1);
    expect(res.body.reasons.join(" ")).toContain("x1 (in place of e2)");
    const [row] = (await stateStore.load("c1")).forensicTimeline;
    expect(row.id).toBe("x1");
    expect((row.provenance ?? []).join(" ")).toContain("missed-evidence");
  });

  it("names at most three examples and counts the rest", async () => {
    const rows = ["a", "b", "c", "d", "e"].map((id) => raw(id, { description: `copy ${id}` }));
    const { app } = await harness({
      forensic: [chainsaw],
      aliases: Object.fromEntries(rows.map((r) => [r.id, "e1"])),
      archive: rows,
    });

    const res = await promote(app, ids(...rows.map((r) => r.id)));

    const line = res.body.reasons.find((r: string) => r.includes("duplicate"));
    expect(line).toContain("a (duplicate of e1), b (duplicate of e1), c (duplicate of e1) and 2 more");
  });
});

describe("what the promote route refuses", () => {
  it("400s an empty selection", async () => {
    const { app, stateStore } = await harness({ archive: [raw("r1")] });
    for (const body of [{}, { rows: [] }, { rows: "r1" }]) {
      const res = await promote(app, body);
      expect(res.status).toBe(400);
      expect(String(res.body.error)).toMatch(/\S/);
    }
    expect((await stateStore.load("c1")).forensicTimeline).toEqual([]);
  });

  it("400s a malformed selection whole, rather than promoting the valid half", async () => {
    const { app, stateStore } = await harness({
      archive: [raw("r1"), raw("r2")],
      reviewed: [tick("r1", "High"), tick("r2", "High")],
    });

    for (const bad of [{ id: "  " }, { id: 42 }, null, "r2"]) {
      const res = await promote(app, { rows: [{ id: "r1" }, bad] });
      expect(res.status).toBe(400);
    }
    expect((await stateStore.load("c1")).forensicTimeline).toEqual([]);
  });

  it("501s when the super-timeline is not configured", async () => {
    const { app } = await harness({ withSuperStore: false });
    const res = await promote(app, ids("r1"));
    expect(res.status).toBe(501);
    expect(String(res.body.error)).toMatch(/\S/);
  });

  it("404s an unknown case", async () => {
    const { app } = await harness({ archive: [raw("r1")] });
    const res = await request(app).post("/cases/nope/jev/promote").send(ids("r1"));
    expect(res.status).toBe(404);
  });
});
