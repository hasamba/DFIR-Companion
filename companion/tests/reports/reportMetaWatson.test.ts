import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import type { ActivityLogStore, NewActivityEntry } from "../../src/analysis/activityLog.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import {
  applyWatsonProposal,
  WatsonProposalConflict,
  type WriterDeps,
} from "../../src/analysis/ai/watson/proposals.js";
import type { WatsonReportTextProposal } from "../../src/analysis/ai/watson/types.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { ReportMetaStore } from "../../src/reports/reportMeta.js";
import { reportMetaHash } from "../../src/reports/reportTextDiff.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// Watson's report text goes through the one serialized report-meta write path. The analyst's form
// sends the version it opened (baseUpdatedAt); a save over a newer version is refused (409), and an
// analyst edit to a Watson-written field takes the Watson mark off it.

const CASE = "c1";
const STALE = "Report details changed since you opened them — reload";

const proposal = (over: Partial<WatsonReportTextProposal> = {}): WatsonReportTextProposal => ({
  id: "wp-r",
  turnId: "t1",
  kind: "report_text",
  targetId: "conclusions",
  field: "conclusions",
  before: "",
  after: "The phishing mail led to encoded PowerShell on wkstn-blue.",
  status: "pending",
  ...over,
});

describe("Watson report text and the report-meta version check", () => {
  let cases: CaseStore;
  let meta: ReportMetaStore;
  let chatStore: WatsonChatStore;
  let deps: WriterDeps;
  let app: ReturnType<typeof createApp>;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-report-meta-watson-"));
    cases = new CaseStore(root);
    const stateStore = new StateStore(cases);
    meta = new ReportMetaStore(cases);
    app = createApp(cases, { stateStore, reportMetaStore: meta });
    await request(app).post("/cases").send({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(emptyState(CASE));
    chatStore = new WatsonChatStore(cases);
    await chatStore.update(CASE, (c) => ({ ...c, proposals: [proposal()] }));
    const activity = {
      add: async (_c: string, e: NewActivityEntry) => ({ ...e, id: "a", at: "t", actor: e.actor ?? "x" }),
    } as unknown as ActivityLogStore;
    deps = {
      stateStore,
      stateLock: new StateLock(),
      chatStore,
      activity,
      cases,
      markConclusionsOutOfDate: async () => undefined,
      reportText: meta,
    };
  });

  it("apply writes the field with the Watson mark; a PUT with the pre-apply version → 409", async () => {
    const opened = (await request(app).get(`/cases/${CASE}/report-meta`)).body;
    expect(opened.updatedAt).toBeUndefined();
    await applyWatsonProposal(deps, CASE, "wp-r", "apply", "ana");
    const stored = await meta.load(CASE);
    expect(stored.conclusions).toBe(proposal().after);
    expect(stored.watsonFields?.conclusions).toMatchObject({ proposalId: "wp-r" });
    expect(stored.updatedAt).toEqual(expect.any(String));

    const put = await request(app)
      .put(`/cases/${CASE}/report-meta`)
      .send({ ...opened, conclusions: "analyst text", baseUpdatedAt: opened.updatedAt ?? "" });
    expect(put.status).toBe(409);
    expect(put.body.error).toBe(STALE);
    expect((await meta.load(CASE)).conclusions).toBe(proposal().after);
  });

  it("a PUT that changes a Watson-marked field drops its mark; one that leaves it keeps it", async () => {
    await applyWatsonProposal(deps, CASE, "wp-r", "apply");
    const cur = (await request(app).get(`/cases/${CASE}/report-meta`)).body;
    const keep = await request(app)
      .put(`/cases/${CASE}/report-meta`)
      .send({ ...cur, organization: "ExampleCorp", baseUpdatedAt: cur.updatedAt });
    expect(keep.status).toBe(200);
    expect(keep.body.watsonFields?.conclusions).toMatchObject({ proposalId: "wp-r" });
    expect(keep.body.updatedAt > cur.updatedAt).toBe(true);

    const change = await request(app)
      .put(`/cases/${CASE}/report-meta`)
      .send({ ...keep.body, conclusions: "Now the analyst's words.", baseUpdatedAt: keep.body.updatedAt });
    expect(change.status).toBe(200);
    expect(change.body.conclusions).toBe("Now the analyst's words.");
    expect(change.body.watsonFields?.conclusions).toBeUndefined();
  });

  it("a PUT without baseUpdatedAt is allowed and still drops the mark of a changed field", async () => {
    await applyWatsonProposal(deps, CASE, "wp-r", "apply");
    const put = await request(app).put(`/cases/${CASE}/report-meta`).send({ conclusions: "API client text" });
    expect(put.status).toBe(200);
    expect(put.body.watsonFields?.conclusions).toBeUndefined();
  });

  it("a PUT body cannot forge a Watson mark or a version", async () => {
    const put = await request(app)
      .put(`/cases/${CASE}/report-meta`)
      .send({
        conclusions: "x",
        updatedAt: "2099-01-01T00:00:00.000Z",
        watsonFields: { conclusions: { proposalId: "forged", at: "t" } },
      });
    expect(put.status).toBe(200);
    expect(put.body.watsonFields?.conclusions).toBeUndefined();
    expect(put.body.updatedAt).not.toBe("2099-01-01T00:00:00.000Z");
  });

  it("two overlapping saves from the same version: one lands, the other gets 409", async () => {
    const base = (await request(app).put(`/cases/${CASE}/report-meta`).send({ organization: "a" })).body
      .updatedAt as string;
    const [a, b] = await Promise.all([
      request(app).put(`/cases/${CASE}/report-meta`).send({ conclusions: "first", baseUpdatedAt: base }),
      request(app).put(`/cases/${CASE}/report-meta`).send({ conclusions: "second", baseUpdatedAt: base }),
    ]);
    expect([a.status, b.status].sort()).toEqual([200, 409]);
  });

  it("every save stamps a strictly newer version, even within one millisecond", async () => {
    const stamps: string[] = [];
    for (let i = 0; i < 5; i++)
      stamps.push((await meta.save(CASE, { organization: `o${i}` })).updatedAt ?? "");
    for (let i = 1; i < stamps.length; i++) expect(stamps[i] > stamps[i - 1]).toBe(true);
  });

  it("a failed update does not block the next save", async () => {
    await expect(
      meta.update(CASE, () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect((await meta.save(CASE, { organization: "after" })).organization).toBe("after");
  });

  it("apply refuses when the field changed since the proposal; undo restores and clears the mark", async () => {
    await meta.save(CASE, { conclusions: "analyst moved on" });
    await expect(applyWatsonProposal(deps, CASE, "wp-r", "apply")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    await meta.save(CASE, { conclusions: "" });
    await applyWatsonProposal(deps, CASE, "wp-r", "apply");
    await applyWatsonProposal(deps, CASE, "wp-r", "undo");
    const after = await meta.load(CASE);
    expect(after.conclusions).toBe("");
    expect(after.watsonFields?.conclusions).toBeUndefined();
  });

  it("undo refuses when the analyst rewrote the field", async () => {
    await applyWatsonProposal(deps, CASE, "wp-r", "apply");
    await meta.save(CASE, { conclusions: "rewritten" });
    await expect(applyWatsonProposal(deps, CASE, "wp-r", "undo")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    expect((await meta.load(CASE)).conclusions).toBe("rewritten");
  });

  it("the version stamp and marks do not change the version-dedupe hash", async () => {
    const a = await meta.save(CASE, { organization: "same" });
    const b = await meta.save(CASE, { organization: "same" });
    expect(a.updatedAt).not.toBe(b.updatedAt);
    expect(reportMetaHash(a)).toBe(reportMetaHash(b));
  });
});
