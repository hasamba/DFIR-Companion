import { describe, expect, it } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { RemediationStore, RECEIPTS_PER_BOUNDARY_MAX } from "../../src/analysis/remediationBoundary.js";
import { createApp } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { loadFilteredState } from "../../src/reports/filteredState.js";
import { normalizeReportTemplate, REPORT_SECTION_DEFS } from "../../src/reports/reportTemplate.js";

// #969 routes: declare → verify (a receipt, nothing else written) → status against the receipt →
// attach (a super-timeline row enters by PROMOTION with its intent) → the report renders the
// analyst's status and the receipt's facts. And the forensic / super-timeline boundary, literally:
// the receipt holds ids and counts, never a raw row's text.

const T = "2026-06-01T00:00:00.000Z";
const at = (h: number) => new Date(Date.parse(T) + h * 3_600_000).toISOString();
const PATH = "C:\\Users\\a\\Downloads\\evil.exe";
const ev = (over: Partial<ForensicEvent>): ForensicEvent => ({
  id: "e",
  timestamp: at(1),
  description: "d",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WS-042",
  sources: ["Sysmon"],
  path: PATH,
  processName: "evil.exe",
  ...over,
});

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-remediation-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const remediationStore = new RemediationStore(store);
  const state = emptyState("c1");
  state.forensicTimeline = [
    ev({ id: "f1", severity: "Low", description: "Process create: evil.exe (forensic)" }),
  ];
  await stateStore.save(state);
  await superTimelineStore.append("c1", [
    ev({ id: "r1", timestamp: at(30), description: "RAW ROW TEXT evil.exe started again" }),
    ev({
      id: "r2",
      timestamp: at(31),
      path: "C:\\Windows\\notepad.exe",
      processName: "notepad.exe",
      description: "notepad",
    }),
  ]);
  const pipeline = new AnalysisPipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    superTimelineStore,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  const app = createApp(store, { stateStore, superTimelineStore, remediationStore, pipeline });
  return { app, store, stateStore, superTimelineStore, remediationStore, root };
}

describe("remediation routes", () => {
  it("declare → verify → status → attach by promotion → report; 400/404/409 where the analyst is wrong", async () => {
    const { app, store, stateStore, superTimelineStore, remediationStore } = await harness();
    // Declare.
    const bad = await request(app)
      .post("/cases/c1/remediation")
      .send({ host: "ws-042", artifact: { kind: "hash", value: "nope" }, remediatedAt: T });
    expect(bad.status).toBe(400);
    expect(bad.body.error).toContain("artifact.value");
    expect(
      (
        await request(app)
          .post("/cases/nope/remediation")
          .send({ host: "h", artifact: { kind: "path", value: "x" }, remediatedAt: T })
      ).status,
    ).toBe(404);
    const declared = await request(app)
      .post("/cases/c1/remediation")
      .send({
        host: "ws-042",
        artifact: { kind: "path", value: PATH },
        remediatedAt: T,
        windowHours: 168,
        note: "quarantined by hand",
      });
    expect(declared.status).toBe(201);
    const bid = declared.body.boundary.id as string;
    expect(declared.body.boundary.status).toBe("unreviewed");

    // Verify: facts, a receipt, and NOTHING else written — the super-timeline is untouched.
    const metaBefore = await superTimelineStore.meta("c1");
    const verified = await request(app).post(`/cases/c1/remediation/${bid}/verify`).send({});
    expect(verified.status).toBe(200);
    expect(verified.body.spellings).toEqual(["WS-042"]);
    expect(verified.body.hits.map((h: { id: string; store: string }) => [h.id, h.store])).toEqual([
      ["f1", "forensic"],
      ["r1", "super"],
    ]);
    // The rows carry no importer envelope: the legacy upgrade reads them as process/observation.
    expect(verified.body.hits[1].cls).toBe("activity");
    expect(verified.body.hits[1].classNote).toContain("observation of a process");
    expect(verified.body.sentence).toContain("Only you can say");
    expect(await superTimelineStore.meta("c1")).toEqual(metaBefore);
    expect((await stateStore.load("c1")).forensicTimeline.map((e) => e.id)).toEqual(["f1"]);
    const receiptId = verified.body.receipt.id as string;
    const stored = (await remediationStore.load("c1"))[0];
    expect(stored.receipts.map((r) => r.id)).toEqual([receiptId]);
    // The receipt holds ids and counts, never a raw row's text (the boundary rule).
    const onDisk = await readFile(join(store.stateDir("c1"), "remediation-boundaries.json"), "utf8");
    expect(onDisk).not.toContain("RAW ROW TEXT");
    // Forensic ids only; the raw hit is a count until attached.
    expect(onDisk).toContain('"f1"');
    expect(onDisk).not.toContain('"r1"');
    expect(verified.body.receipt.superHitTotal).toBe(1);

    // Status: needs a receipt; checked-not-observed against a gapped receipt needs an override.
    expect(
      (await request(app).patch(`/cases/c1/remediation/${bid}/status`).send({ status: "bogus" })).status,
    ).toBe(400);
    expect(
      (
        await request(app)
          .patch(`/cases/c1/remediation/${bid}/status`)
          .send({ status: "recurrence-observed" })
      ).status,
    ).toBe(400);
    expect(
      (
        await request(app)
          .patch(`/cases/c1/remediation/${bid}/status`)
          .send({ status: "recurrence-observed", receiptId: "rr-nope" })
      ).status,
    ).toBe(404);
    const refused = await request(app)
      .patch(`/cases/c1/remediation/${bid}/status`)
      .send({ status: "checked-not-observed", receiptId });
    expect(refused.status).toBe(409);
    expect(refused.body.reasons).toContain("a relevant telemetry family is not covered");
    const overridden = await request(app).patch(`/cases/c1/remediation/${bid}/status`).send({
      status: "checked-not-observed",
      receiptId,
      note: "reviewed",
      override: "EDR confirms no execution in the window",
    });
    expect(overridden.status).toBe(200);
    expect(overridden.body.boundary).toMatchObject({
      status: "checked-not-observed",
      statusReceiptId: receiptId,
      statusOverrideNote: "EDR confirms no execution in the window",
    });
    const recorded = await request(app)
      .patch(`/cases/c1/remediation/${bid}/status`)
      .send({ status: "recurrence-observed", receiptId, note: "it came back" });
    expect(recorded.status).toBe(200);
    expect(recorded.body.boundary.receipts[0].stale).toBe(false);
    // The override belonged to the checked-not-observed statement: another status clears it.
    expect(recorded.body.boundary.statusOverrideNote).toBeUndefined();

    // Attach: the super row is promoted with the remediation-check intent, then attached by id.
    const attached = await request(app)
      .post(`/cases/c1/remediation/${bid}/attach`)
      .send({ eventIds: ["r1", "f1"] });
    expect(attached.body, JSON.stringify(attached.body)).toMatchObject({ promoted: 1 });
    expect(attached.status).toBe(200);
    expect(attached.body.boundary.evidence).toEqual(["r1", "f1"]);
    const after = await stateStore.load("c1");
    const promoted = after.forensicTimeline.find((e) => e.id === "r1")!;
    expect(promoted).toBeDefined();
    expect(
      after.timeline.some((t) => t.description.includes(`attached as remediation evidence for ${bid}`)),
    ).toBe(true);
    expect(
      (
        await request(app)
          .post(`/cases/c1/remediation/${bid}/attach`)
          .send({ eventIds: ["ghost"] })
      ).status,
    ).toBe(404);
    // The promotion moved the forensic store: the receipt is now stale on read.
    const listed = await request(app).get("/cases/c1/remediation");
    expect(listed.body.boundaries[0].receipts[0].stale).toBe(true);

    // Report: the analyst's status, the receipt it names, the attached rows; off unless opted in.
    const filtered = await loadFilteredState({ state: stateStore, cases: store }, "c1");
    expect(filtered.remediationBoundaries).toHaveLength(1);
    const only = normalizeReportTemplate({
      sections: REPORT_SECTION_DEFS.map((d) => ({ key: d.key, enabled: d.key === "remediationChecks" })),
    });
    const render = (t = only) =>
      renderMarkdownReport(filtered, undefined, undefined, undefined, undefined, undefined, t);
    const md = render();
    expect(md).toContain("## Remediation checks");
    expect(md).toContain("**recurrence-observed**");
    expect(md).toContain("it came back");
    expect(md).toContain("recorded against older data");
    expect(md).toContain("| process | yes |");
    expect(render(normalizeReportTemplate({}))).not.toContain("## Remediation checks");

    // Delete.
    expect((await request(app).delete(`/cases/c1/remediation/${bid}`)).status).toBe(204);
    expect((await request(app).delete(`/cases/c1/remediation/${bid}`)).status).toBe(404);
  });

  it("a full boundary refuses the attach before anything is promoted; a deleted boundary refuses the receipt", async () => {
    const { app, stateStore, remediationStore } = await harness();
    const bid = (
      await request(app)
        .post("/cases/c1/remediation")
        .send({ host: "ws-042", artifact: { kind: "path", value: PATH }, remediatedAt: T })
    ).body.boundary.id;
    await remediationStore.attach(
      "c1",
      bid,
      Array.from({ length: 200 }, (_, i) => `x${i}`),
    );
    const refused = await request(app)
      .post(`/cases/c1/remediation/${bid}/attach`)
      .send({ eventIds: ["r1"] });
    expect(refused.status).toBe(400);
    expect((await stateStore.load("c1")).forensicTimeline.map((e) => e.id)).toEqual(["f1"]);
    await request(app).delete(`/cases/c1/remediation/${bid}`);
    expect((await request(app).post(`/cases/c1/remediation/${bid}/verify`).send({})).status).toBe(404);
  });

  it("the receipt a status names is pinned outside the rolling bound", async () => {
    const { app, remediationStore } = await harness();
    const bid = (
      await request(app)
        .post("/cases/c1/remediation")
        .send({ host: "ws-042", artifact: { kind: "path", value: PATH }, remediatedAt: T })
    ).body.boundary.id;
    const first = (await request(app).post(`/cases/c1/remediation/${bid}/verify`).send({})).body.receipt.id;
    await request(app)
      .patch(`/cases/c1/remediation/${bid}/status`)
      .send({ status: "recurrence-observed", receiptId: first });
    for (let i = 0; i < RECEIPTS_PER_BOUNDARY_MAX + 3; i += 1)
      await request(app).post(`/cases/c1/remediation/${bid}/verify`).send({});
    const b = (await remediationStore.load("c1"))[0];
    expect(b.receipts).toHaveLength(RECEIPTS_PER_BOUNDARY_MAX + 1);
    expect(b.receipts.some((r) => r.id === first)).toBe(true);
  });
});
