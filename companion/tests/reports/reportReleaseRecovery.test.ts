import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import type { AnalysisRunManifest } from "../../src/analysis/analysisRunTypes.js";
import type { Finding } from "../../src/analysis/stateTypes.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import { ReportReleaseStore } from "../../src/reports/reportReleaseStore.js";
import { ReportVersionStore } from "../../src/reports/reportVersionStore.js";
import type { ReportActor } from "../../src/reports/reportWorkflowTypes.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// Issue #2405: one release per approved version, even when two requests race or an earlier release
// was interrupted between writing the release record and marking the workflow released. And only the
// people in the review can resolve a reviewer's blocking note.

const HASH = "a".repeat(64);
const investigator: ReportActor = { id: "inv-1", displayName: "Investigator", kind: "local" };
const reviewer: ReportActor = { id: "rev-1", displayName: "Reviewer", kind: "local" };
const outsider: ReportActor = { id: "out-1", displayName: "Someone Else", kind: "local" };
const service: ReportActor = { id: "svc-1", displayName: "Automation", kind: "service" };
const soloAuthor: ReportActor = { id: "solo", displayName: "Solo investigator", kind: "solo" };

function analysisRun(): AnalysisRunManifest {
  return {
    id: "run-1",
    caseId: "c1",
    schemaVersion: 1,
    sequence: 1,
    kind: "report",
    status: "completed",
    parentRunId: null,
    startedAt: "2026-07-31T00:00:00.000Z",
    finishedAt: "2026-07-31T00:00:01.000Z",
    durationMs: 1000,
    versions: { application: "test" },
    input: { artifacts: [], eventIds: [], entityIds: [] },
    execution: { retries: 0, warnings: [] },
    output: { entityIds: [], hashes: [], claims: [] },
    previousManifestHash: null,
    manifestHash: HASH,
  };
}

const releaseInput = (actor: ReportActor, supersedesReleaseId?: string) => ({
  actor,
  ...(supersedesReleaseId ? { supersedesReleaseId } : {}),
  analysisRuns: [analysisRun()],
  analysisIntegrity: { ok: true, manifests: 1, problems: [], foreignManifests: 0 },
  custody: { head: { records: 0, headSeq: null, headHash: "" }, chainBreaks: [], mismatches: [] },
});

let cases: CaseStore;
let versions: ReportVersionStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-report-release-recovery-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  versions = new ReportVersionStore(cases);
});

async function approvedVersion(markdown: string): Promise<string> {
  const summary = await versions.snapshot("c1", {
    markdown,
    meta: emptyReportMeta(),
    state: { findings: [], iocs: [], forensicTimeline: [] },
    analysisRunIds: ["run-1"],
  });
  await versions.selfApprove("c1", summary.id, investigator, "checked");
  return summary.id;
}

/** Simulate an interrupted release: the record is committed to the release ledger, but the workflow
 *  was never marked released (the second write failed or the process died). */
async function interruptedRelease(versionId: string, supersedesReleaseId?: string): Promise<string> {
  const version = (await versions.get("c1", versionId))!;
  const workflow = (await versions.workflow("c1", versionId))!;
  const record = await new ReportReleaseStore(cases).create("c1", {
    ...releaseInput(investigator, supersedesReleaseId),
    version,
    workflow,
  });
  expect((await versions.workflow("c1", versionId))!.status).toBe("approved");
  return record.id;
}

const releaseDir = () => join(cases.stateDir("c1"), "report-releases");

describe("ReportVersionStore.release — one release per version (#2405)", () => {
  it("lets exactly one of two concurrent releases through", async () => {
    const id = await approvedVersion("# report");
    const results = await Promise.allSettled([
      versions.release("c1", id, releaseInput(investigator)),
      versions.release("c1", id, releaseInput(investigator)),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
    expect(String(rejected.reason)).toMatch(/already released/);
    expect(await versions.listReleases("c1")).toHaveLength(1);
    const workflow = (await versions.workflow("c1", id))!;
    expect(workflow.status).toBe("released");
    expect(workflow.history.filter((e) => e.action === "released")).toHaveLength(1);
  });

  it("completes an interrupted release instead of stranding it, without a second record", async () => {
    const id = await approvedVersion("# report");
    const releaseId = await interruptedRelease(id);
    const record = await versions.release("c1", id, releaseInput(investigator));
    expect(record.id).toBe(releaseId);
    expect(await versions.listReleases("c1")).toHaveLength(1);
    const workflow = (await versions.workflow("c1", id))!;
    expect(workflow.status).toBe("released");
    expect(workflow.releaseId).toBe(releaseId);
    expect(workflow.history.filter((e) => e.action === "released")).toHaveLength(1);
    // And a further retry is now an ordinary duplicate.
    await expect(versions.release("c1", id, releaseInput(investigator))).rejects.toThrow(/already released/);
  });

  it("completes an interrupted release even after a later release superseded it", async () => {
    const first = await approvedVersion("# report one");
    const firstRelease = await interruptedRelease(first);
    const second = await approvedVersion("# report two");
    await versions.release("c1", second, releaseInput(investigator, firstRelease));
    const record = await versions.release("c1", first, releaseInput(investigator));
    expect(record.id).toBe(firstRelease);
    expect((await versions.workflow("c1", first))!.status).toBe("released");
    expect(await versions.listReleases("c1")).toHaveLength(2);
  });

  it("refuses to complete an interrupted release when the record was altered", async () => {
    const id = await approvedVersion("# report");
    const releaseId = await interruptedRelease(id);
    const path = join(releaseDir(), `${releaseId}.json`);
    const record = JSON.parse(await readFile(path, "utf8")) as { packs: { technical: string } };
    record.packs.technical = "# tampered";
    await writeFile(path, JSON.stringify(record));
    await expect(versions.release("c1", id, releaseInput(investigator))).rejects.toThrow(
      /release ledger integrity failed.*manifest hash mismatch/,
    );
    expect((await versions.workflow("c1", id))!.status).toBe("approved");
  });

  it("refuses to complete an interrupted release when the ledger head is missing", async () => {
    const id = await approvedVersion("# report");
    await interruptedRelease(id);
    await rm(join(releaseDir(), "head.json"));
    await expect(versions.release("c1", id, releaseInput(investigator))).rejects.toThrow(/head is missing/);
    expect((await versions.workflow("c1", id))!.status).toBe("approved");
  });
});

describe("resolving a reviewer's note — only the people in the review (#2405)", () => {
  const finding = {
    id: "f1",
    severity: "High",
    title: "Malware execution",
    description: "d",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    relatedEventIds: [],
    firstSeen: "2026-07-30T00:00:00.000Z",
    lastUpdated: "2026-07-30T00:00:00.000Z",
    status: "confirmed",
  } as unknown as Finding;

  async function inReviewWithNote(): Promise<{ versionId: string; noteId: () => Promise<string> }> {
    const summary = await versions.snapshot("c1", {
      markdown: "# review me",
      meta: emptyReportMeta(),
      state: { findings: [finding], iocs: [], forensicTimeline: [] },
    });
    // The snapshot was written by the solo author; a different investigator opens the review.
    await versions.submitForReview("c1", summary.id, investigator, reviewer);
    const noteId = async (): Promise<string> => {
      const wf = await versions.addReviewAnnotation("c1", summary.id, reviewer, {
        targetType: "finding",
        targetId: "f1",
        category: "uncertainty",
        impact: "high",
        message: "is this really malware?",
      });
      return wf.annotations.at(-1)!.id;
    };
    return { versionId: summary.id, noteId };
  }

  it("refuses someone outside the review, and a service identity", async () => {
    const { versionId, noteId } = await inReviewWithNote();
    const id = await noteId();
    await expect(versions.resolveReviewAnnotation("c1", versionId, id, outsider, "done")).rejects.toThrow(
      /only the report's investigator, the assigned reviewer, or the note's author/,
    );
    await expect(versions.resolveReviewAnnotation("c1", versionId, id, service, "done")).rejects.toThrow(
      /service identity/,
    );
    await expect(versions.approve("c1", versionId, reviewer, "ok")).rejects.toThrow(
      /uncertainty blocks approval/,
    );
  });

  it("lets the investigator who opened the review, the snapshot author and the reviewer resolve", async () => {
    const { versionId, noteId } = await inReviewWithNote();
    for (const who of [investigator, soloAuthor, reviewer]) {
      const id = await noteId();
      const wf = await versions.resolveReviewAnnotation("c1", versionId, id, who, "linked evidence");
      expect(wf.annotations.find((a) => a.id === id)!.resolvedById).toBe(who.id);
    }
  });
});
