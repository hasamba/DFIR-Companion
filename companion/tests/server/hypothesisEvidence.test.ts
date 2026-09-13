import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { HypothesisStore } from "../../src/analysis/hypothesisStore.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #933 item 22 — the hypothesis GET carries the evidence assessment; an analyst exclusion is an
// audit-trailed, per-hypothesis act that deletes nothing.

function ev(id: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-01-02T03:04:05Z",
    description: `event ${id}`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Velociraptor"],
    ...extra,
  };
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-hyp-evidence-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const hypothesisStore = new HypothesisStore(store);
  const app = createApp(store, { pipeline, stateStore, aiConfigured: false, hypothesisStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const state = await stateStore.load("c1");
  await stateStore.save({
    ...state,
    forensicTimeline: [ev("e1", { yearInferred: true }), ev("e2"), ev("e3")],
  });
  return { app, store, stateStore, hypothesisStore };
}

async function twoHypotheses(app: ReturnType<typeof createApp>) {
  const a = (
    await request(app)
      .post("/cases/c1/hypotheses")
      .send({
        title: "Initial access was phishing",
        status: "supported",
        relatedEventIds: ["e1", "e2", "ghost"],
      })
  ).body;
  const b = (
    await request(app)
      .post("/cases/c1/hypotheses")
      .send({ title: "Initial access was VPN", relatedEventIds: ["e2"] })
  ).body;
  // The analyst says e1 argues against VPN — the PATCH route does not take contradictingEventIds,
  // so it goes through the store, as synthesis would write it.
  return { a, b };
}

describe("GET /cases/:id/hypotheses carries the assessment", () => {
  it("attaches the reading, the qualifier, and the resolved evidence rows", async () => {
    const { app, hypothesisStore } = await makeApp();
    const { a, b } = await twoHypotheses(app);
    await hypothesisStore.update("c1", b.id, { contradictingEventIds: ["e1"] });
    const list = (await request(app).get("/cases/c1/hypotheses")).body;
    const phish = list.find((h: { id: string }) => h.id === a.id);
    expect(phish.assessment.support.distinguishing).toEqual([
      { eventId: "e1", separatesFrom: [{ id: b.id, title: "Initial access was VPN", status: "open" }] },
    ]);
    expect(phish.assessment.support.consistentWithAlternatives).toEqual([
      { eventId: "e2", assessedBy: 2, notAssessedBy: 0 },
    ]);
    expect(phish.assessment.notCounted).toEqual([{ eventId: "ghost", reason: "not in the timeline" }]);
    expect(phish.assessment.restsOnSingleObservation).toBe(true);
    expect(phish.qualifier).toBe("");
    const e1 = phish.evidence.find((r: { eventId: string }) => r.eventId === "e1");
    expect(e1).toEqual({
      eventId: "e1",
      present: true,
      timestamp: "2026-01-02T03:04:05Z",
      description: "event e1",
      uncertainty: ["year inferred, not read from the record"],
    });
    expect(phish.evidence.find((r: { eventId: string }) => r.eventId === "ghost").present).toBe(false);
    // Never a number that reads as a probability.
    expect(JSON.stringify(phish.assessment)).not.toMatch(/%|probab|likel|confiden|score/i);
  });

  it("a false-positive mark takes the observation out of every count", async () => {
    const { app, hypothesisStore } = await makeApp();
    const { a, b } = await twoHypotheses(app);
    await hypothesisStore.update("c1", b.id, { contradictingEventIds: ["e1"] });
    await request(app)
      .post("/cases/c1/false-positive")
      .send({ kind: "event", ref: "e1", reason: "benign", note: "authorized" });
    const list = (await request(app).get("/cases/c1/hypotheses")).body;
    const phish = list.find((h: { id: string }) => h.id === a.id);
    expect(phish.assessment.notCounted).toContainEqual({ eventId: "e1", reason: "marked false positive" });
    expect(phish.assessment.support.distinguishing).toEqual([]);
    expect(phish.qualifier).toContain("no observation separates it from an alternative");
  });
});

describe("exclusions — an audit trail, never a deletion", () => {
  it("excludes with a reason, keeps the link and the event, restores with history", async () => {
    const { app, stateStore } = await makeApp();
    const { a, b } = await twoHypotheses(app);
    const ex = await request(app)
      .post(`/cases/c1/hypotheses/${a.id}/exclusions`)
      .send({ eventId: "e2", reason: "fits both", by: "alice" });
    expect(ex.status).toBe(200);
    expect(ex.body.excludedEvidence).toEqual([
      { eventId: "e2", reason: "fits both", by: "alice", excludedAt: expect.any(String) },
    ]);
    expect(ex.body.relatedEventIds).toEqual(["e1", "e2", "ghost"]);
    expect(ex.body.analystTouched).toBe(true); // born analyst-authored; an exclusion did not change that
    expect((await stateStore.load("c1")).forensicTimeline.map((e) => e.id)).toEqual(["e1", "e2", "e3"]);
    const list = (await request(app).get("/cases/c1/hypotheses")).body;
    const phish = list.find((h: { id: string }) => h.id === a.id);
    expect(phish.assessment.excluded).toEqual([
      { eventId: "e2", reason: "fits both", by: "alice", excludedAt: expect.any(String) },
    ]);
    expect(phish.assessment.support.consistentWithAlternatives).toEqual([]);
    // The other hypothesis still reads e2 as its own support, now unassessed by phishing.
    const vpn = list.find((h: { id: string }) => h.id === b.id);
    expect(vpn.assessment.support.notAssessedElsewhere).toEqual(["e2"]);

    const restored = await request(app).delete(`/cases/c1/hypotheses/${a.id}/exclusions/e2?by=bob`);
    expect(restored.status).toBe(200);
    expect(restored.body.excludedEvidence[0]).toMatchObject({
      eventId: "e2",
      restoredAt: expect.any(String),
      restoredBy: "bob",
    });
    expect((await request(app).delete(`/cases/c1/hypotheses/${a.id}/exclusions/e2`)).status).toBe(404);
  });

  it("rejects a missing reason, an unlinked observation, and an unknown hypothesis", async () => {
    const { app } = await makeApp();
    const { a } = await twoHypotheses(app);
    expect(
      (await request(app).post(`/cases/c1/hypotheses/${a.id}/exclusions`).send({ eventId: "e2" })).status,
    ).toBe(400);
    expect(
      (
        await request(app)
          .post(`/cases/c1/hypotheses/${a.id}/exclusions`)
          .send({ eventId: "e3", reason: "r" })
      ).status,
    ).toBe(400);
    expect(
      (await request(app).post(`/cases/c1/hypotheses/nope/exclusions`).send({ eventId: "e2", reason: "r" }))
        .status,
    ).toBe(404);
  });

  it("a PATCH that unlinks an excluded observation closes the exclusion; acknowledgeReview clears the flag", async () => {
    const { app, hypothesisStore } = await makeApp();
    const { a } = await twoHypotheses(app);
    await request(app)
      .post(`/cases/c1/hypotheses/${a.id}/exclusions`)
      .send({ eventId: "e2", reason: "fits both" });
    const patched = await request(app)
      .patch(`/cases/c1/hypotheses/${a.id}`)
      .send({ relatedEventIds: ["e1"] });
    expect(patched.body.excludedEvidence[0]).toMatchObject({ eventId: "e2", restoredBy: "unlinked" });
    await request(app)
      .patch(`/cases/c1/hypotheses/${a.id}`)
      .send({ alternativeIds: ["x", a.id] });
    expect((await hypothesisStore.load("c1")).find((h) => h.id === a.id)!.alternativeIds).toEqual(["x"]);
    await request(app)
      .post("/cases/c1/false-positive")
      .send({ kind: "event", ref: "e1", reason: "benign", note: "authorized" });
    const flagged = (await hypothesisStore.load("c1")).find((h) => h.id === a.id)!;
    expect(flagged.needsReview).toBe(true);
    expect(flagged.reviewReason).toContain("false positive");
    const noted = await request(app).patch(`/cases/c1/hypotheses/${a.id}`).send({ notes: "checking" });
    expect(noted.body.needsReview).toBe(true); // a note is not a review
    const acked = await request(app).patch(`/cases/c1/hypotheses/${a.id}`).send({ acknowledgeReview: true });
    expect(acked.body).toMatchObject({ needsReview: false, reviewReason: "" });
  });
});
