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

type Tick = ReturnType<typeof tick>;

async function harness(
  opts: {
    archive?: ForensicEvent[];
    forensic?: ForensicEvent[];
    withSuperStore?: boolean;
    /** What the review graded, as the server recorded it. */
    reviewed?: Tick[];
    model?: string;
  } = {},
) {
  const root = await mkdtemp(join(tmpdir(), "dfir-jev-promote-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save({ ...emptyState("c1"), forensicTimeline: opts.forensic ?? [] });
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
  const app = createApp(store, {
    pipeline,
    stateStore,
    ...(superTimelineStore ? { superTimelineStore } : {}),
  });
  return { app, stateStore };
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
