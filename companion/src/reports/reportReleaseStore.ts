import { randomUUID } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CustodyChainBreak, CustodyChainHead, CustodyMismatch } from "../analysis/custody.js";
import { hashManifestValue } from "../analysis/analysisRunHash.js";
import type { AnalysisRunIntegrity, AnalysisRunManifest } from "../analysis/analysisRunTypes.js";
import { StateLock } from "../analysis/stateLock.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import { defaultReportTemplate, orderedEnabledSections } from "./reportTemplate.js";
import type { ReportVersionRecord } from "./reportVersionStore.js";
import type { ReportActor, ReportWorkflow } from "./reportWorkflowTypes.js";

export const REPORT_PACK_TYPES = ["executive", "technical", "legal", "ioc"] as const;
export type ReportPackType = (typeof REPORT_PACK_TYPES)[number];

export interface ReportReleaseSummary {
  id: string;
  sequence: number;
  reportVersionId: string;
  reportVersion: string;
  releasedAt: string;
  releasedBy: ReportActor;
  supersedesReleaseId?: string;
  manifestHash: string;
}

export interface ReportReleaseRecord extends ReportReleaseSummary {
  schemaVersion: 1;
  caseId: string;
  previousManifestHash: string | null;
  approval: ReportWorkflow["approvals"];
  analysisRuns: Array<{ id: string; manifestHash: string }>;
  custody: { head: CustodyChainHead };
  snapshot: ReportVersionRecord;
  packs: Record<ReportPackType, string>;
  packHashes: Record<ReportPackType, string>;
}

export interface ReportReleaseIntegrity {
  ok: boolean;
  releases: number;
  problems: string[];
}

interface ReportReleaseHead {
  sequence: number;
  manifestHash: string;
}

export interface ReportReleaseInput {
  version: ReportVersionRecord;
  workflow: ReportWorkflow;
  actor: ReportActor;
  supersedesReleaseId?: string;
  analysisRuns: AnalysisRunManifest[];
  analysisIntegrity: AnalysisRunIntegrity;
  custody: {
    head: CustodyChainHead;
    chainBreaks: CustodyChainBreak[];
    mismatches: CustodyMismatch[];
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isActor(value: unknown): value is ReportActor {
  if (!isObject(value)) return false;
  return (
    typeof value.id === "string" &&
    typeof value.displayName === "string" &&
    (value.kind === "local" || value.kind === "oidc" || value.kind === "service" || value.kind === "solo")
  );
}

function isReleaseSummary(value: unknown): value is ReportReleaseSummary {
  if (!isObject(value)) return false;
  return (
    typeof value.id === "string" &&
    typeof value.sequence === "number" &&
    typeof value.reportVersionId === "string" &&
    typeof value.reportVersion === "string" &&
    typeof value.releasedAt === "string" &&
    isActor(value.releasedBy) &&
    (value.supersedesReleaseId === undefined || typeof value.supersedesReleaseId === "string") &&
    typeof value.manifestHash === "string"
  );
}

function isReleaseRecord(value: unknown): value is ReportReleaseRecord {
  if (!isReleaseSummary(value) || !isObject(value)) return false;
  const snapshot = value.snapshot;
  const packs = value.packs;
  const packHashes = value.packHashes;
  const custody = value.custody;
  return (
    value.schemaVersion === 1 &&
    typeof value.caseId === "string" &&
    (value.previousManifestHash === null || typeof value.previousManifestHash === "string") &&
    Array.isArray(value.approval) &&
    Array.isArray(value.analysisRuns) &&
    isObject(custody) &&
    isObject(custody.head) &&
    isObject(snapshot) &&
    typeof snapshot.id === "string" &&
    typeof snapshot.markdown === "string" &&
    isObject(snapshot.state) &&
    Array.isArray(snapshot.state.findings) &&
    Array.isArray(snapshot.state.iocs) &&
    Array.isArray(snapshot.state.forensicTimeline) &&
    isObject(packs) &&
    REPORT_PACK_TYPES.every((type) => typeof packs[type] === "string") &&
    isObject(packHashes) &&
    REPORT_PACK_TYPES.every((type) => typeof packHashes[type] === "string")
  );
}

function validId(value: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(value);
}

function csvCell(value: string): string {
  const guarded = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${guarded.replace(/"/g, '""')}"`;
}

function iocPack(version: ReportVersionRecord): string {
  const rows = version.state.iocs.map((ioc) =>
    [ioc.id, ioc.type, ioc.value, ioc.firstSeen, ioc.note ?? ""].map(csvCell).join(","),
  );
  return ["id,type,value,firstSeen,note", ...rows].join("\n") + "\n";
}

function executivePack(version: ReportVersionRecord): string {
  const findings = version.state.findings
    .filter((finding) => finding.status !== "dismissed")
    .filter((finding) => finding.severity === "Critical" || finding.severity === "High")
    .map((finding) => `- **${finding.severity}: ${finding.title}** — ${finding.description}`);
  return [
    "# Executive Incident Brief",
    "",
    version.meta.executiveSummary || "No separate executive summary was recorded.",
    "",
    "## Material findings",
    "",
    ...(findings.length > 0 ? findings : ["No Critical or High findings were in the approved evidence set."]),
    "",
  ].join("\n");
}

function legalPack(version: ReportVersionRecord, workflow: ReportWorkflow): string {
  const approvals = workflow.approvals.map(
    (approval) =>
      `- ${approval.actorDisplayName} — ${approval.independent ? "independent peer review" : "self-review"} at ${approval.at}`,
  );
  const uncertainties = (version.state.uncertainties ?? []).map(
    (item) =>
      `- **${item.topic} (${item.status})** — ${item.basis || "No basis recorded"}; gap: ${item.gap || "none recorded"}`,
  );
  return [
    "# Legal / Insurance Incident Pack",
    "",
    `Organization: ${version.meta.organization || "not recorded"}`,
    `Incident ID: ${version.meta.incidentId || "not recorded"}`,
    `Restrictions: ${version.meta.restrictions || "not recorded"}`,
    "",
    "## Approval record",
    "",
    ...approvals,
    "",
    "## Investigation limitations",
    "",
    version.meta.investigationLimitations || "No limitations were recorded.",
    "",
    "## Analytical uncertainty",
    "",
    ...(uncertainties.length > 0 ? uncertainties : ["No structured uncertainties were recorded."]),
    "",
  ].join("\n");
}

function buildPacks(version: ReportVersionRecord, workflow: ReportWorkflow): Record<ReportPackType, string> {
  return {
    executive: executivePack(version),
    technical: version.markdown,
    legal: legalPack(version, workflow),
    ioc: iocPack(version),
  };
}

function evidenceProblems(version: ReportVersionRecord): string[] {
  const eventIds = new Set(version.state.forensicTimeline.map((event) => event.id));
  const requireAll = version.template?.releaseRequirements.requireEvidenceLinks ?? false;
  return version.state.findings.flatMap((finding) => {
    const material = finding.severity === "Critical" || finding.severity === "High";
    if (finding.status === "dismissed" || (!material && !requireAll)) return [];
    const links = finding.relatedEventIds ?? [];
    const invalid = links.filter((id) => !eventIds.has(id));
    return links.length === 0 || invalid.length > 0
      ? [`${finding.id} (${finding.title}) is missing evidence links`]
      : [];
  });
}

function releaseProblems(input: ReportReleaseInput): string[] {
  const problems: string[] = [];
  if (input.actor.kind === "service") problems.push("a service identity cannot release a report");
  if (input.workflow.status !== "approved") problems.push("report workflow is not approved");
  if (input.workflow.approvals.length === 0) problems.push("report has no structured approval");
  if (
    input.version.template?.releaseRequirements.requireIndependentReview &&
    !input.workflow.approvals.some((approval) => approval.independent)
  ) {
    problems.push("report template requires independent review");
  }
  const enabled = new Set(orderedEnabledSections(input.version.template ?? defaultReportTemplate()));
  for (const key of input.version.template?.releaseRequirements.requiredSections ?? []) {
    if (!enabled.has(key)) problems.push(`report template requires section ${key}`);
  }
  problems.push(...evidenceProblems(input.version));
  if (
    input.workflow.annotations.some(
      (item) => item.category === "uncertainty" && item.impact === "high" && !item.resolvedAt,
    )
  ) {
    problems.push("unresolved high-impact uncertainty remains");
  }
  if (!input.analysisIntegrity.ok) problems.push("analysis run ledger integrity failed");
  const runIds = new Set(input.analysisRuns.map((run) => run.id));
  if ((input.version.analysisRunIds ?? []).length === 0) problems.push("report has no pinned analysis runs");
  for (const id of input.version.analysisRunIds ?? []) {
    if (!runIds.has(id)) problems.push(`pinned analysis run ${id} is missing`);
  }
  if (input.custody.chainBreaks.length > 0) problems.push("custody chain is broken");
  if (input.custody.mismatches.some((item) => item.reason === "missing")) {
    problems.push("missing artifact recorded in custody");
  }
  if (input.custody.mismatches.some((item) => item.reason === "hash-mismatch")) {
    problems.push("artifact hash does not match custody record");
  }
  return problems;
}

export class ReportReleaseStore {
  private readonly lock = new StateLock();

  constructor(private readonly cases: CaseStore) {}

  private dir(caseId: string): string {
    return join(this.cases.stateDir(caseId), "report-releases");
  }

  private indexPath(caseId: string): string {
    return join(this.dir(caseId), "index.json");
  }

  private headPath(caseId: string): string {
    return join(this.dir(caseId), "head.json");
  }

  private recordPath(caseId: string, releaseId: string): string {
    if (!validId(releaseId)) throw new Error("invalid report release id");
    return join(this.dir(caseId), `${releaseId}.json`);
  }

  async list(caseId: string): Promise<ReportReleaseSummary[]> {
    try {
      const value = JSON.parse(await readFile(this.indexPath(caseId), "utf8")) as unknown;
      if (!Array.isArray(value) || !value.every(isReleaseSummary)) {
        throw new Error("report release index is invalid");
      }
      return value;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async get(caseId: string, releaseId: string): Promise<ReportReleaseRecord | null> {
    if (!validId(releaseId)) return null;
    try {
      const value = JSON.parse(await readFile(this.recordPath(caseId, releaseId), "utf8")) as unknown;
      if (!isReleaseRecord(value)) throw new Error("report release record is invalid");
      return value;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  private async readHead(caseId: string): Promise<ReportReleaseHead | null> {
    try {
      const value = JSON.parse(await readFile(this.headPath(caseId), "utf8")) as unknown;
      if (!isObject(value) || typeof value.sequence !== "number" || typeof value.manifestHash !== "string") {
        throw new Error("report release head is invalid");
      }
      return { sequence: value.sequence, manifestHash: value.manifestHash };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  create(caseId: string, input: ReportReleaseInput): Promise<ReportReleaseRecord> {
    return this.lock.runExclusive(caseId, async () => {
      const problems = releaseProblems(input);
      if (problems.length > 0) throw new Error(`release blocked: ${problems.join("; ")}`);
      const existing = await this.list(caseId);
      if (existing.some((release) => release.reportVersionId === input.version.id)) {
        throw new Error("this report version is already released");
      }
      const latest = existing[0];
      if (latest && input.supersedesReleaseId !== latest.id) {
        throw new Error(`a prior release exists; explicitly supersede ${latest.id}`);
      }
      if (!latest && input.supersedesReleaseId) throw new Error("there is no prior release to supersede");
      const sequence = (latest?.sequence ?? 0) + 1;
      const releasedAt = new Date().toISOString();
      const id = `r${sequence}-${randomUUID().slice(0, 8)}`;
      const packs = buildPacks(input.version, input.workflow);
      const packHashes = Object.fromEntries(
        REPORT_PACK_TYPES.map((type) => [type, hashManifestValue(packs[type])]),
      ) as Record<ReportPackType, string>;
      const analysisRuns = (input.version.analysisRunIds ?? []).map((id) => {
        const run = input.analysisRuns.find((candidate) => candidate.id === id);
        if (!run) throw new Error(`release blocked: pinned analysis run ${id} is missing`);
        return { id, manifestHash: run.manifestHash };
      });
      const unhashed: Omit<ReportReleaseRecord, "manifestHash"> = {
        id,
        schemaVersion: 1,
        sequence,
        caseId,
        reportVersionId: input.version.id,
        reportVersion: input.version.version,
        releasedAt,
        releasedBy: input.actor,
        ...(latest ? { supersedesReleaseId: latest.id } : {}),
        previousManifestHash: latest?.manifestHash ?? null,
        approval: input.workflow.approvals,
        analysisRuns,
        custody: { head: input.custody.head },
        snapshot: input.version,
        packs,
        packHashes,
      };
      const record: ReportReleaseRecord = {
        ...unhashed,
        manifestHash: hashManifestValue(unhashed),
      };
      const summary: ReportReleaseSummary = {
        id: record.id,
        sequence: record.sequence,
        reportVersionId: record.reportVersionId,
        reportVersion: record.reportVersion,
        releasedAt: record.releasedAt,
        releasedBy: record.releasedBy,
        ...(record.supersedesReleaseId ? { supersedesReleaseId: record.supersedesReleaseId } : {}),
        manifestHash: record.manifestHash,
      };
      await mkdir(this.dir(caseId), { recursive: true });
      await atomicWrite(this.recordPath(caseId, id), JSON.stringify(record, null, 2));
      await atomicWrite(this.indexPath(caseId), JSON.stringify([summary, ...existing], null, 2));
      await atomicWrite(
        this.headPath(caseId),
        JSON.stringify({ sequence: record.sequence, manifestHash: record.manifestHash }, null, 2),
      );
      return record;
    });
  }

  async verify(caseId: string): Promise<ReportReleaseIntegrity> {
    let summaries: ReportReleaseSummary[];
    try {
      summaries = [...(await this.list(caseId))].sort((left, right) => left.sequence - right.sequence);
    } catch (err) {
      return { ok: false, releases: 0, problems: [(err as Error).message] };
    }
    const problems: string[] = [];
    let head: ReportReleaseHead | null;
    try {
      head = await this.readHead(caseId);
    } catch (err) {
      return {
        ok: false,
        releases: summaries.length,
        problems: [(err as Error).message],
      };
    }
    let previous: string | null = null;
    for (const [index, summary] of summaries.entries()) {
      let release: ReportReleaseRecord | null;
      try {
        release = await this.get(caseId, summary.id);
      } catch (err) {
        problems.push(`${summary.id}: ${(err as Error).message}`);
        continue;
      }
      if (!release) {
        problems.push(`${summary.id}: release record is missing`);
        continue;
      }
      const { manifestHash, ...unhashed } = release;
      if (hashManifestValue(unhashed) !== manifestHash) {
        problems.push(`${summary.id}: manifest hash mismatch`);
      }
      if (release.sequence !== index + 1) problems.push(`${summary.id}: sequence mismatch`);
      if (release.previousManifestHash !== previous) {
        problems.push(`${summary.id}: previous manifest hash mismatch`);
      }
      if (summary.manifestHash !== release.manifestHash) {
        problems.push(`${summary.id}: release index hash mismatch`);
      }
      previous = release.manifestHash;
    }
    const latest = summaries.at(-1);
    if (latest && !head) problems.push("report release head is missing");
    if (!latest && head) problems.push("report release head exists without releases");
    if (latest && head && (latest.sequence !== head.sequence || latest.manifestHash !== head.manifestHash)) {
      problems.push("report release head mismatch");
    }
    return { ok: problems.length === 0, releases: summaries.length, problems };
  }
}
