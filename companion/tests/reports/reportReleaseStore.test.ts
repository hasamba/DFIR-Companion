import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import type { AnalysisRunManifest } from "../../src/analysis/analysisRunTypes.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { defaultReportTemplate } from "../../src/reports/reportTemplate.js";
import { ReportReleaseStore } from "../../src/reports/reportReleaseStore.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import type { ReportVersionRecord } from "../../src/reports/reportVersionStore.js";
import type { ReportWorkflow } from "../../src/reports/reportWorkflowTypes.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const actor = { id: "investigator-1", displayName: "Investigator One", kind: "local" as const };
const HASH = "a".repeat(64);

function workflow(versionId = "version-1"): ReportWorkflow {
  return {
    versionId,
    status: "approved",
    createdBy: actor,
    assignedReviewer: undefined,
    annotations: [],
    approvals: [
      {
        actorId: actor.id,
        actorDisplayName: actor.displayName,
        actorKind: actor.kind,
        at: "2026-07-31T00:00:00.000Z",
        independent: false,
        note: "self-review",
      },
    ],
    history: [],
  };
}

function version(markdown = "# Approved report", id = "version-1"): ReportVersionRecord {
  const state = emptyState("c1");
  state.forensicTimeline.push({
    id: "e1",
    timestamp: "2026-07-30T00:00:00.000Z",
    severity: "High",
    description: "Malware executed",
    mitreTechniques: ["T1204"],
    relatedFindingIds: ["f1"],
    sourceScreenshots: [],
  });
  state.findings.push({
    id: "f1",
    severity: "High",
    title: "Malware execution",
    description: "Malware executed on the host.",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: ["T1204"],
    relatedEventIds: ["e1"],
    firstSeen: "2026-07-30T00:00:00.000Z",
    lastUpdated: "2026-07-30T00:00:00.000Z",
    status: "confirmed",
  });
  return {
    id,
    createdAt: "2026-07-31T00:00:00.000Z",
    version: id === "version-1" ? "v1" : "v2",
    manualVersion: "",
    contentHash: HASH,
    findingsCount: 1,
    iocsCount: 0,
    eventsCount: 1,
    analysisRunIds: ["run-1"],
    markdown,
    meta: emptyReportMeta(),
    state: {
      findings: state.findings,
      iocs: state.iocs,
      forensicTimeline: state.forensicTimeline,
      uncertainties: state.uncertainties,
    },
    template: defaultReportTemplate(),
  };
}

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
    input: { artifacts: [], eventIds: ["e1"], entityIds: ["f1"] },
    execution: { retries: 0, warnings: [] },
    output: { entityIds: ["f1"], hashes: [], claims: [] },
    previousManifestHash: null,
    manifestHash: HASH,
  };
}

let cases: CaseStore;
let releases: ReportReleaseStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-report-release-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  releases = new ReportReleaseStore(cases);
});

describe("ReportReleaseStore", () => {
  it("creates a hash-pinned immutable snapshot and four packs", async () => {
    const released = await releases.create("c1", {
      version: version(),
      workflow: workflow(),
      actor,
      analysisRuns: [analysisRun()],
      analysisIntegrity: { ok: true, manifests: 1, problems: [] },
      custody: {
        head: { records: 0, headSeq: null, headHash: "" },
        chainBreaks: [],
        mismatches: [],
      },
    });

    expect(released.sequence).toBe(1);
    expect(released.manifestHash).toMatch(/^[a-f0-9]{64}$/);
    expect(released.snapshot.markdown).toBe("# Approved report");
    expect(released.analysisRuns).toEqual([{ id: "run-1", manifestHash: HASH }]);
    expect(Object.keys(released.packs).sort()).toEqual(["executive", "ioc", "legal", "technical"]);
    expect(released.packs.ioc).toContain("id,type,value");
    expect((await releases.verify("c1")).ok).toBe(true);
  });

  it("blocks release when a material finding has no valid evidence link", async () => {
    const ungrounded = version();
    ungrounded.state.findings[0] = { ...ungrounded.state.findings[0], relatedEventIds: ["missing"] };

    await expect(
      releases.create("c1", {
        version: ungrounded,
        workflow: workflow(),
        actor,
        analysisRuns: [analysisRun()],
        analysisIntegrity: { ok: true, manifests: 1, problems: [] },
        custody: {
          head: { records: 0, headSeq: null, headHash: "" },
          chainBreaks: [],
          mismatches: [],
        },
      }),
    ).rejects.toThrow("missing evidence");
  });

  it("blocks broken custody, missing artifacts, and damaged analysis ledgers", async () => {
    const base = {
      version: version(),
      workflow: workflow(),
      actor,
      analysisRuns: [analysisRun()],
      analysisIntegrity: { ok: true, manifests: 1, problems: [] },
      custody: {
        head: { records: 1, headSeq: 1, headHash: HASH },
        chainBreaks: [{ line: 1, seq: 1, reason: "prev-hash-mismatch" as const }],
        mismatches: [],
      },
    };
    await expect(releases.create("c1", base)).rejects.toThrow("custody chain");
    await expect(
      releases.create("c1", {
        ...base,
        custody: {
          ...base.custody,
          chainBreaks: [],
          mismatches: [
            {
              artifactPath: "/missing/image.E01",
              recordedSha256: HASH,
              actualSha256: null,
              reason: "missing" as const,
            },
          ],
        },
      }),
    ).rejects.toThrow("missing artifact");
    await expect(
      releases.create("c1", {
        ...base,
        analysisIntegrity: { ok: false, manifests: 1, problems: ["head mismatch"] },
        custody: { ...base.custody, chainBreaks: [] },
      }),
    ).rejects.toThrow("analysis run ledger");
  });

  it("requires explicit supersession and preserves the prior release", async () => {
    const common = {
      actor,
      analysisRuns: [analysisRun()],
      analysisIntegrity: { ok: true, manifests: 1, problems: [] },
      custody: {
        head: { records: 0, headSeq: null, headHash: "" },
        chainBreaks: [],
        mismatches: [],
      },
    };
    const first = await releases.create("c1", { ...common, version: version(), workflow: workflow() });
    const secondVersion = version("# Corrected report", "version-2");

    await expect(
      releases.create("c1", {
        ...common,
        version: secondVersion,
        workflow: workflow("version-2"),
      }),
    ).rejects.toThrow("supersede");

    const second = await releases.create("c1", {
      ...common,
      version: secondVersion,
      workflow: workflow("version-2"),
      supersedesReleaseId: first.id,
    });
    expect(second.supersedesReleaseId).toBe(first.id);
    expect((await releases.get("c1", first.id))?.snapshot.markdown).toBe("# Approved report");
    expect(await releases.list("c1")).toEqual([
      expect.objectContaining({ id: second.id, supersedesReleaseId: first.id }),
      expect.objectContaining({ id: first.id }),
    ]);
  });

  it("detects post-release snapshot tampering", async () => {
    const released = await releases.create("c1", {
      version: version(),
      workflow: workflow(),
      actor,
      analysisRuns: [analysisRun()],
      analysisIntegrity: { ok: true, manifests: 1, problems: [] },
      custody: {
        head: { records: 0, headSeq: null, headHash: "" },
        chainBreaks: [],
        mismatches: [],
      },
    });
    const path = join(cases.stateDir("c1"), "report-releases", `${released.id}.json`);
    const altered = { ...released, snapshot: { ...released.snapshot, markdown: "tampered" } };
    await writeFile(path, JSON.stringify(altered), "utf8");

    expect(await releases.verify("c1")).toMatchObject({
      ok: false,
      problems: [expect.stringContaining("manifest hash mismatch")],
    });
  });
});
