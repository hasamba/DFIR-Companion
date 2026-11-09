import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { AuthObservationStore } from "../../src/analysis/authObservationStore.js";
import { CloudCoverageStore } from "../../src/analysis/cloudCoverage.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { MEDIUM_FAILED_READS_PER_ACTOR } from "../../src/analysis/cloudStreamLimits.js";

// #2481 — a CSPM scanner role denied across dozens of read actions, end to end through the streamed
// CloudTrail import: its first failed reads stay individual, the rest become ONE counted Medium event
// that lists the actions, every folded call is still in the super-timeline (analyst search only), a
// failed write is never folded, and the disclosure says so.

const ACCOUNT = "123456789012";
const SCANNER = `arn:aws:sts::${ACCOUNT}:assumed-role/CSPMScanner/scan-session`;

async function setup() {
  const root = await mkdtemp(join(tmpdir(), "dfir-failedreads-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const superTimelineStore = new SuperTimelineStore(cases);
  const cloudCoverageStore = new CloudCoverageStore(cases);
  const pipeline = new AnalysisPipeline({
    stateStore: new StateStore(cases),
    superTimelineStore,
    cloudRecordStore: new CloudRecordStore(cases),
    cloudCoverageStore,
    authObservationStore: new AuthObservationStore(cases, 168),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const path = join(root, "ct.json");
  return { pipeline, superTimelineStore, cloudCoverageStore, path };
}

let seq = 0;
function call(name: string, source: string, readOnly: boolean, arn = SCANNER, errorCode = "AccessDenied") {
  seq++;
  return {
    eventVersion: "1.09",
    eventID: `00000000-0000-4000-b000-${String(seq).padStart(12, "0")}`,
    eventTime: `2026-11-09T10:${String(Math.floor(seq / 60) % 60).padStart(2, "0")}:${String(seq % 60).padStart(2, "0")}Z`,
    eventSource: source,
    eventName: name,
    awsRegion: "us-east-1",
    sourceIPAddress: "198.51.100.20",
    userAgent: "scanner/1.0",
    readOnly,
    userIdentity: {
      type: "AssumedRole",
      arn,
      principalId: "AROAEXAMPLEID:scan-session",
      accountId: ACCOUNT,
      sessionContext: { sessionIssuer: { type: "Role", userName: "CSPMScanner" } },
    },
    ...(errorCode ? { errorCode, errorMessage: "User is not authorized" } : {}),
  };
}

const ACTIONS = Array.from({ length: 40 }, (_, i) => ({
  name: `GetProbeTarget${i}`,
  source: `probe${i % 5}.amazonaws.com`,
}));

describe("streamed CloudTrail import folds a principal's failed reads (#2481)", () => {
  it("keeps the first N, folds the rest into one listed group, writes every folded call to the super-timeline", async () => {
    const { pipeline, superTimelineStore, cloudCoverageStore, path } = await setup();
    const records = [
      // Three scan runs over 40 read actions, every one denied.
      ...[0, 1, 2].flatMap(() => ACTIONS.map((a) => call(a.name, a.source, true))),
      // A denied write by the same role, and one denied read by someone else.
      call("PutBucketPolicy", "s3.amazonaws.com", false),
      call("GetBucketCors", "s3.amazonaws.com", true, `arn:aws:iam::${ACCOUNT}:user/alice`),
    ];
    await writeFile(path, JSON.stringify({ Records: records }));
    const { state, disclosure } = await pipeline.importCloudFile("c1", "aws", path, {
      label: "ct.json",
      idPrefix: "f1",
      importedAt: "2026-11-09T12:00:00Z",
      batchRecords: 25,
    });

    const scannerRows = state.forensicTimeline.filter((e) => e.description.includes("GetProbeTarget"));
    const groups = scannerRows.filter((e) => e.description.includes("failed read-only call(s)"));
    expect(groups).toHaveLength(1);
    const g = groups[0];
    expect(g.severity).toBe("Medium");
    const folded = (ACTIONS.length - MEDIUM_FAILED_READS_PER_ACTOR) * 3;
    expect(g.description).toContain(`${folded} failed read-only call(s) across 30 action(s)`);
    expect(g.description).toContain("GetProbeTarget10 ×3");
    // The first N distinct actions stay individual (their repeats merge into them, #2502).
    expect(scannerRows.filter((e) => e !== g)).toHaveLength(MEDIUM_FAILED_READS_PER_ACTOR);
    // The failed write and the other principal's single failed read stay exactly as they were.
    expect(state.forensicTimeline.filter((e) => /PutBucketPolicy/.test(e.description))).toHaveLength(1);
    const alice = state.forensicTimeline.filter((e) => /GetBucketCors/.test(e.description));
    expect(alice).toHaveLength(1);
    expect(alice[0].severity).toBe("Medium");
    expect(alice[0].description).not.toContain("failed read-only call(s)");

    // Every folded call is in the super-timeline, never in the forensic timeline.
    const sup = await superTimelineStore.query("c1", { limit: 500 });
    const superFolded = sup.events.filter((e) => e.id.startsWith("f1s") && e.severity === "Medium");
    expect(superFolded).toHaveLength(folded);
    expect(state.forensicTimeline.some((e) => e.id.startsWith("f1s"))).toBe(false);

    expect(disclosure.mediumOverflow.failedReadBudget).toBe(folded);
    expect(disclosure.failedReads).toEqual({ folded, toSuper: folded });
    const clauses = (await cloudCoverageStore.load("c1"))[0].importDisclosure?.join(" | ") ?? "";
    expect(clauses).toContain(
      `${folded} failed read-only Medium call(s) past the budget of ${MEDIUM_FAILED_READS_PER_ACTOR} per actor`,
    );
    expect(clauses).toContain(`${folded} of them sent to the super-timeline individually`);
    expect(clauses).toContain("Low/Info and folded Medium row(s) written to the super-timeline");
  });

  it("an import with no failed reads discloses exactly what it did before", async () => {
    const { pipeline, cloudCoverageStore, path } = await setup();
    await writeFile(
      path,
      JSON.stringify({ Records: [call("ListBuckets", "s3.amazonaws.com", true, SCANNER, "")] }),
    );
    const { disclosure } = await pipeline.importCloudFile("c1", "aws", path, {
      label: "ct.json",
      idPrefix: "f2",
      importedAt: "2026-11-09T12:00:00Z",
    });
    expect(disclosure.failedReads).toEqual({ folded: 0, toSuper: 0 });
    const clauses = (await cloudCoverageStore.load("c1"))[0].importDisclosure?.join(" | ") ?? "";
    expect(clauses).not.toContain("failed read-only");
    expect(clauses).not.toContain("folded Medium");
  });
});
