import { readFile, unlink, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID, createHash } from "node:crypto";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { Finding, IOC, ForensicEvent } from "../analysis/stateTypes.js";
import type { ReportMeta } from "./reportMeta.js";

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
}

export interface ReportVersionSummary {
  id: string;
  createdAt: string;   // ISO timestamp
  version: string;     // auto-numbered "v1", "v2", ... (display label)
  manualVersion: string; // the human-authored revisions[] latest entry's version string, if any ("" if none)
  contentHash: string; // sha256 of the rendered markdown — lets snapshot() dedupe unchanged regenerations
  findingsCount: number;
  iocsCount: number;
  eventsCount: number;
}

export interface ReportVersionRecord extends ReportVersionSummary {
  markdown: string;
  meta: ReportMeta;
  state: ReportVersionDiffState;
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

export class ReportVersionStore {
  constructor(private readonly cases: CaseStore) {}

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

  // Persist a version snapshot after a report regeneration. Skips writing a new version (returns the
  // existing latest summary instead) when the rendered markdown is byte-identical to the most recent
  // version — a re-generation with nothing changed shouldn't grow the history. Best-effort: callers
  // (ReportWriter.writeAll) should swallow errors from this so a version-store failure never breaks
  // report generation itself.
  async snapshot(
    caseId: string,
    input: { markdown: string; meta: ReportMeta; state: ReportVersionDiffState },
  ): Promise<ReportVersionSummary> {
    const contentHash = createHash("sha256").update(input.markdown).digest("hex");
    const existing = await this.list(caseId);
    const latest = existing[0];
    if (latest && latest.contentHash === contentHash) return latest;

    const createdAt = new Date().toISOString();
    const id = `${createdAt.replace(/[:.]/g, "-")}-${randomUUID().slice(0, 8)}`;
    const manualVersion = input.meta.revisions.length
      ? input.meta.revisions[input.meta.revisions.length - 1].version
      : "";
    const summary: ReportVersionSummary = {
      id,
      createdAt,
      version: `v${existing.length + 1}`,
      manualVersion,
      contentHash,
      findingsCount: input.state.findings.length,
      iocsCount: input.state.iocs.length,
      eventsCount: input.state.forensicTimeline.length,
    };
    const record: ReportVersionRecord = { ...summary, markdown: input.markdown, meta: input.meta, state: input.state };

    await mkdir(this.dir(caseId), { recursive: true });
    await atomicWrite(this.recordPath(caseId, id), JSON.stringify(record));
    const updated = [summary, ...existing];
    const cap = maxVersions();
    const kept = updated.slice(0, cap);
    const pruned = updated.slice(cap);
    await this.saveIndex(caseId, kept);
    await Promise.all(pruned.map((p) => unlink(this.recordPath(caseId, p.id)).catch(() => {})));
    return summary;
  }
}
