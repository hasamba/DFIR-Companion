import { readFile, unlink, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID, createHash } from "node:crypto";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { Finding, IOC, ForensicEvent } from "../analysis/stateTypes.js";
import type { Uncertainty } from "../analysis/stateTypes.js";
import { authenticatedActorFields } from "../auth/identityContext.js";
import type { ReportMeta } from "./reportMeta.js";
import type { ReportTemplate } from "./reportTemplate.js";
import {
  ReportReleaseStore,
  type ReportReleaseInput,
  type ReportReleaseIntegrity,
  type ReportReleaseRecord,
  type ReportReleaseSummary,
} from "./reportReleaseStore.js";
import { ReportWorkflowStore } from "./reportWorkflowStore.js";
import type { ReportActor, ReportAnnotationInput, ReportWorkflow } from "./reportWorkflowTypes.js";

// Report versioning (#77): every `writeAll()` (report generation) snapshots the rendered markdown +
// the human-authored report-meta + the diff-relevant slice of state (findings/IOCs/forensic timeline)
// into a side file under state/report-versions/, so an analyst can see what changed between two
// generated reports (reusing findingsDiff/iocsDiff/timelineDiff) and roll back to a prior version's
// editable meta. Like HuntOutcomeStore, a side file NOT part of InvestigationState — re-synthesis
// never touches it. Writes go through atomicWrite (Dropbox/OneDrive-safe temp-rename).
//
// Two files per case: a lightweight `index.json` (summaries, read for listing) and one `<id>.json`
// per version (the heavier markdown + meta + diff state, read only on demand for a diff or restore).
// This mirrors the report itself (which is regenerable) rather than InvestigationState: the version
// store is an audit trail, not a source of truth, so a corrupt/missing entry degrades to "fewer
// versions available" rather than breaking anything.

export interface ReportVersionDiffState {
  findings: Finding[];
  iocs: IOC[];
  forensicTimeline: ForensicEvent[];
  uncertainties?: Uncertainty[];
}

export interface ReportVersionSummary {
  id: string;
  createdAt: string; // ISO timestamp
  version: string; // auto-numbered "v1", "v2", ... (display label)
  manualVersion: string; // the human-authored revisions[] latest entry's version string, if any ("" if none)
  contentHash: string; // sha256 of the rendered markdown — lets snapshot() dedupe unchanged regenerations
  findingsCount: number;
  iocsCount: number;
  eventsCount: number;
  /** Exact analysis/import/enrichment/report runs this released snapshot was derived from (#377). */
  analysisRunIds?: string[];
  createdBy?: ReportActor;
}

export interface ReportVersionRecord extends ReportVersionSummary {
  markdown: string;
  meta: ReportMeta;
  state: ReportVersionDiffState;
  template?: ReportTemplate;
}

// Cap the number of retained versions per case (oldest pruned first) so state/report-versions/ can't
// grow unbounded on a long-running case that regenerates the report often. Override via env.
const DEFAULT_MAX_VERSIONS = 50;

function maxVersions(): number {
  const n = Number(process.env.DFIR_REPORT_VERSION_MAX);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_MAX_VERSIONS;
}

// Version ids are generated internally as `${iso-timestamp}-${uuid8}` (see snapshot()), so they only
// ever contain [A-Za-z0-9-]. The diff/restore routes accept the id straight from user-controlled
// query/path params, so anything outside this shape (a path separator, `..`, a null byte) must be
// rejected before it reaches join()/readFile — otherwise `from=../../../../etc/hostname` would escape
// the report-versions directory and read an arbitrary .json off disk (path traversal).
const VALID_VERSION_ID = /^[A-Za-z0-9_-]+$/;

function isValidVersionId(id: string): boolean {
  return VALID_VERSION_ID.test(id);
}

// The next auto-numbered display label. Derived from the newest retained summary's own label rather
// than from the list length: once the history hits the retention cap (maxVersions) the list stops
// growing, so `v${list.length + 1}` would hand out the SAME label to every subsequent version (with a
// cap of 2 you get v3, v3, v3…). Counting up from the newest label keeps them monotonic and unique.
function nextVersionLabel(existing: readonly ReportVersionSummary[]): string {
  const latest = existing[0];
  const n = latest ? /^v(\d+)$/.exec(latest.version)?.[1] : undefined;
  return `v${n ? Number(n) + 1 : existing.length + 1}`;
}

export class ReportVersionStore {
  private readonly workflows: ReportWorkflowStore;
  private readonly releases: ReportReleaseStore;

  constructor(private readonly cases: CaseStore) {
    this.workflows = new ReportWorkflowStore(cases);
    this.releases = new ReportReleaseStore(cases);
  }

  private dir(caseId: string): string {
    return join(this.cases.stateDir(caseId), "report-versions");
  }

  private indexPath(caseId: string): string {
    return join(this.dir(caseId), "index.json");
  }

  private recordPath(caseId: string, id: string): string {
    // Defence in depth — snapshot() only ever passes a freshly generated id, but never build a path
    // from an id that could contain traversal sequences.
    if (!isValidVersionId(id)) throw new Error(`invalid report version id: ${id}`);
    return join(this.dir(caseId), `${id}.json`);
  }

  // The case's version summaries, newest first. [] when absent or malformed — a corrupt index must
  // never break report generation or the dashboard.
  async list(caseId: string): Promise<ReportVersionSummary[]> {
    try {
      const parsed = JSON.parse(await readFile(this.indexPath(caseId), "utf8")) as unknown;
      return Array.isArray(parsed) ? (parsed as ReportVersionSummary[]) : [];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      if (err instanceof SyntaxError) return [];
      throw err;
    }
  }

  private async saveIndex(caseId: string, summaries: readonly ReportVersionSummary[]): Promise<void> {
    await atomicWrite(this.indexPath(caseId), JSON.stringify(summaries, null, 2));
  }

  // The full snapshot (markdown + meta + diff state) for one version id, or null if it doesn't exist
  // (already pruned, or never existed).
  async get(caseId: string, id: string): Promise<ReportVersionRecord | null> {
    // The diff/restore routes pass this id straight from user input. A malformed id can't correspond
    // to a real version, so treat it as "not found" (404) rather than risk a traversal in recordPath.
    if (!isValidVersionId(id)) return null;
    try {
      return JSON.parse(await readFile(this.recordPath(caseId, id), "utf8")) as ReportVersionRecord;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      if (err instanceof SyntaxError) return null;
      throw err;
    }
  }

  async workflow(caseId: string, versionId: string): Promise<ReportWorkflow | null> {
    const version = await this.get(caseId, versionId);
    if (!version) return null;
    return this.workflows.load(caseId, versionId, version.createdBy);
  }

  async submitForReview(
    caseId: string,
    versionId: string,
    actor: ReportActor,
    reviewer: ReportActor,
  ): Promise<ReportWorkflow> {
    if (!(await this.get(caseId, versionId))) throw new Error("report version not found");
    return this.workflows.submit(caseId, versionId, actor, reviewer);
  }

  async addReviewAnnotation(
    caseId: string,
    versionId: string,
    actor: ReportActor,
    input: ReportAnnotationInput,
  ): Promise<ReportWorkflow> {
    const version = await this.get(caseId, versionId);
    if (!version) throw new Error("report version not found");
    const validTarget =
      input.targetType === "evidence"
        ? version.state.forensicTimeline.some((event) => event.id === input.targetId)
        : version.state.findings.some((finding) => finding.id === input.targetId);
    if (!validTarget) throw new Error(`${input.targetType} target not found in this report version`);
    return this.workflows.addAnnotation(caseId, versionId, actor, input);
  }

  resolveReviewAnnotation(
    caseId: string,
    versionId: string,
    annotationId: string,
    actor: ReportActor,
    resolution: string,
  ): Promise<ReportWorkflow> {
    return this.workflows.resolveAnnotation(caseId, versionId, annotationId, actor, resolution);
  }

  requestReportChanges(
    caseId: string,
    versionId: string,
    actor: ReportActor,
    reason: string,
  ): Promise<ReportWorkflow> {
    return this.workflows.requestChanges(caseId, versionId, actor, reason);
  }

  approve(caseId: string, versionId: string, actor: ReportActor, note: string): Promise<ReportWorkflow> {
    return this.workflows.approve(caseId, versionId, actor, note);
  }

  selfApprove(caseId: string, versionId: string, actor: ReportActor, note: string): Promise<ReportWorkflow> {
    return this.workflows.selfApprove(caseId, versionId, actor, note);
  }

  async release(
    caseId: string,
    versionId: string,
    input: Omit<ReportReleaseInput, "version" | "workflow">,
  ): Promise<ReportReleaseRecord> {
    const version = await this.get(caseId, versionId);
    if (!version) throw new Error("report version not found");
    const workflow = await this.workflows.load(caseId, versionId, version.createdBy);
    const release = await this.releases.create(caseId, { ...input, version, workflow });
    await this.workflows.markReleased(caseId, versionId, input.actor, release.id);
    return release;
  }

  listReleases(caseId: string): Promise<ReportReleaseSummary[]> {
    return this.releases.list(caseId);
  }

  getRelease(caseId: string, releaseId: string): Promise<ReportReleaseRecord | null> {
    return this.releases.get(caseId, releaseId);
  }

  verifyReleases(caseId: string): Promise<ReportReleaseIntegrity> {
    return this.releases.verify(caseId);
  }

  // Persist a version snapshot after a report regeneration. Skips writing a new version (returns the
  // existing latest summary instead) when the rendered markdown is byte-identical to the most recent
  // version — a re-generation with nothing changed shouldn't grow the history. Best-effort: callers
  // (ReportWriter.writeAll) should swallow errors from this so a version-store failure never breaks
  // report generation itself.
  async snapshot(
    caseId: string,
    input: {
      markdown: string;
      meta: ReportMeta;
      state: ReportVersionDiffState;
      analysisRunIds?: string[];
      template?: ReportTemplate;
    },
  ): Promise<ReportVersionSummary> {
    const contentHash = createHash("sha256").update(input.markdown).digest("hex");
    const existing = await this.list(caseId);
    const latest = existing[0];
    const analysisRunIds = input.analysisRunIds ?? [];
    if (
      latest &&
      latest.contentHash === contentHash &&
      JSON.stringify(latest.analysisRunIds ?? []) === JSON.stringify(analysisRunIds)
    )
      return latest;

    const createdAt = new Date().toISOString();
    const id = `${createdAt.replace(/[:.]/g, "-")}-${randomUUID().slice(0, 8)}`;
    const manualVersion = input.meta.revisions.length
      ? input.meta.revisions[input.meta.revisions.length - 1].version
      : "";
    const summary: ReportVersionSummary = {
      id,
      createdAt,
      version: nextVersionLabel(existing),
      manualVersion,
      contentHash,
      findingsCount: input.state.findings.length,
      iocsCount: input.state.iocs.length,
      eventsCount: input.state.forensicTimeline.length,
      analysisRunIds,
      createdBy: (() => {
        const authenticated = authenticatedActorFields();
        return authenticated
          ? {
              id: authenticated.actorId,
              displayName: authenticated.actorDisplayName,
              kind: authenticated.actorKind,
            }
          : { id: "solo", displayName: "Solo investigator", kind: "solo" };
      })(),
    };
    const record: ReportVersionRecord = {
      ...summary,
      markdown: input.markdown,
      meta: input.meta,
      state: input.state,
      ...(input.template ? { template: input.template } : {}),
    };

    await mkdir(this.dir(caseId), { recursive: true });
    await atomicWrite(this.recordPath(caseId, id), JSON.stringify(record));
    const updated = [summary, ...existing];
    const cap = maxVersions();
    const protectedIds = new Set(
      (await this.releases.list(caseId)).map((release) => release.reportVersionId),
    );
    const retainedWorking = new Set(
      updated
        .filter((item) => !protectedIds.has(item.id))
        .slice(0, cap)
        .map((item) => item.id),
    );
    const kept = updated.filter((item) => protectedIds.has(item.id) || retainedWorking.has(item.id));
    const pruned = updated.filter((item) => !kept.includes(item));
    await this.saveIndex(caseId, kept);
    await Promise.all(pruned.map((p) => unlink(this.recordPath(caseId, p.id)).catch(() => {})));
    return summary;
  }
}
