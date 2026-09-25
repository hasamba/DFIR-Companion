// The per-artifact loop behind POST /cases/:id/velociraptor/import-external, for both the hunt and
// the flow branch (#1428).
//
// The external import used to be a bare request: no job, no slot, no progress. The dashboard showed
// "importing…" for as long as the request ran — minutes on a big flow — with no bar, no jobs chip,
// nothing in the log, and no way to tell a slow import from a stuck one. It is an import like any
// other now: it takes the case's import slot (it writes the same timeline the dashboard's own imports
// write to, so two writers at once would corrupt each other's "+N events" and undo checkpoints), and
// reports every artifact to that job — count, name, rows — which the job engine turns into a rate and
// an ETA and the Background jobs popover draws as a bar.
//
// Unlike the bundle collect, the reads happen INSIDE the slot: this loop streams one artifact at a
// time (read, ingest, release) so a large hunt is never resident in full, and that interleaving is
// what keeps the heap flat. The cost is that a big external import holds the case's slot for the
// duration of its reads too. The analyst started it on purpose; the wait shows in the popover.

import type { JobManager } from "../analysis/jobManager.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { formatImportCancelled, formatImportFailed } from "../logging/importLog.js";
import { redactedErrorMessage } from "../analysis/redactPaths.js";
import type { TruncatedArtifact, UnreadArtifact } from "../analysis/veloHuntStore.js";
import type { SkippedArtifact } from "../integrations/velociraptor/velociraptorApi.js";

// The slice of the server's AiStatusEvent this loop emits, spelled out here: routes may not import
// composition types (check:boundaries), and the server's own callback accepts this subset.
export interface ExternalImportStatus {
  status: "analyzing" | "idle" | "error";
  phase?: "extracting";
  at: string;
  detail?: string;
}

export interface ExternalImportDeps {
  jobManager?: JobManager;
  onAiStatus?: (caseId: string, event: ExternalImportStatus) => void;
  logLine: (msg: string) => void;
  /** The diagnostics ring, which logs the FAILED line itself (#1438); without it the loop logs one. */
  recordImportFailure?: (caseId: string, kind: string, filename: string, err: unknown) => void;
}

export interface ArtifactIngestResult {
  addedEvents: number;
  addedIocs: number;
}

/**
 * One artifact's read. `sourcesUnknown` (#1635) means its source list could not be looked up, so rows
 * it keeps under named sources were never read; `truncated` means the read hit the row cap.
 */
export interface ExternalArtifactRead {
  rows: unknown[];
  truncated?: boolean;
  total?: number;
  sourcesUnknown?: true;
}

/**
 * What the loop did, per artifact. The three gap lists use the collect's own shapes (#1645), so the
 * external import says "not read in full", "cut short" and "failed" the way a collect's hunt card does.
 * None of them settles anything: this path records no hunt job and no per-artifact outcome.
 */
export interface ExternalImportOutcome {
  imported: string[];
  addedEvents: number;
  addedIocs: number;
  failed: SkippedArtifact[];
  truncated: TruncatedArtifact[];
  unread: UnreadArtifact[];
}

/**
 * Read and ingest `artifacts` one at a time under one import job. `what` names the source the way
 * the log reads it ("hunt H.X (external import)"); the job row gets the collect's "velociraptor: "
 * prefix in front of it. A read that fails
 * is logged and skipped, exactly as before — the rest of the hunt still imports. An ingest that fails
 * is a local persistence bug, a different class of problem: it fails the job and propagates.
 */
export async function importArtifactsUnderJob(
  deps: ExternalImportDeps,
  caseId: string,
  what: string,
  artifacts: string[],
  readRows: (artifact: string) => Promise<ExternalArtifactRead>,
  // `partlyRead` (#1651): the read had no source list, so the ingest stamps every row it makes.
  ingest: (artifact: string, rows: unknown[], read: { partlyRead: boolean }) => Promise<ArtifactIngestResult>,
): Promise<ExternalImportOutcome> {
  const label = `velociraptor: ${what}`;
  const startedAt = performance.now();
  const job = deps.jobManager?.register({
    caseId,
    kind: "import",
    label,
    detail: label,
    resumable: false,
    cancellable: true, // the popover's ✕ Cancel; honoured between artifacts below
  });
  if (job) {
    await job.durable;
    await job.ready; // the case's import slot — see the file header
  }
  const total = artifacts.length;
  const report = (done: number, detail: string): void => {
    if (job) deps.jobManager?.progress(job.jobId, done, total, detail);
  };
  const imported: string[] = [];
  const failed: SkippedArtifact[] = [];
  const truncated: TruncatedArtifact[] = [];
  const unread: UnreadArtifact[] = [];
  let addedEvents = 0;
  let addedIocs = 0;
  try {
    for (const [index, artifact] of artifacts.entries()) {
      // The popover's ✕ Cancel. Checked between artifacts — the one in flight finishes, so the
      // timeline never holds half an artifact — and surfaced as the request's error.
      if (job?.signal?.aborted)
        throw Object.assign(new Error("import cancelled by the analyst"), { name: "AbortError" });
      let read: ExternalArtifactRead;
      try {
        read = await readRows(artifact);
      } catch (e) {
        deps.logLine(`[velociraptor] ${what}: artifact ${artifact} read failed: ${(e as Error).message}`);
        failed.push({ name: artifact, error: (e as Error).message });
        continue;
      }
      let rows = read.rows;
      // Logged as the read returns, not after the loop, so a later cancel or failed ingest keeps it.
      if (read.sourcesUnknown) {
        unread.push({ name: artifact, rows: rows.length });
        deps.logLine(unreadLogLine(what, artifact, rows.length));
      }
      if (read.truncated) {
        truncated.push({ name: artifact, kept: rows.length, total: Number(read.total) || rows.length });
        deps.logLine(
          `[velociraptor] ${what}: artifact ${artifact} cut short at the row cap (kept ${rows.length}); ` +
            `raise DFIR_VELOCIRAPTOR_COLLECT_MAX_ROWS and import again.`,
        );
      }
      if (!rows.length) continue;
      const step = `artifact ${index + 1}/${total} · ${artifact} (${rows.length} rows)`;
      report(index, step);
      deps.logLine(`[velociraptor] ${what}: importing ${step}`);
      deps.onAiStatus?.(caseId, {
        status: "analyzing",
        phase: "extracting",
        at: new Date().toISOString(),
        detail: `importing ${what} — ${step}`,
      });
      const one = await ingest(artifact, rows, { partlyRead: !!read.sourcesUnknown });
      rows = []; // release before the next artifact is read
      imported.push(artifact);
      addedEvents += one.addedEvents;
      addedIocs += one.addedIocs;
    }
    report(total, `${imported.length}/${total} artifact(s) imported`);
    if (job) await deps.jobManager?.finish(job.jobId);
    deps.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
  } catch (err) {
    // A cancel is the analyst's decision, not a failure: one "cancelled" line, no ring entry.
    if ((err as Error).name === "AbortError")
      getServerLogger().info(formatImportCancelled(caseId, what, performance.now() - startedAt), { caseId });
    else if (deps.recordImportFailure) deps.recordImportFailure(caseId, "velociraptor-external", what, err);
    else
      getServerLogger().warn(
        formatImportFailed({
          caseId,
          label: what,
          kind: "velociraptor-external",
          message: redactedErrorMessage(err),
        }),
        { caseId },
      );
    if (job) await deps.jobManager?.fail(job.jobId, err);
    deps.onAiStatus?.(caseId, {
      status: "error",
      at: new Date().toISOString(),
      detail: `Velociraptor external import failed: ${(err as Error).message}`,
    });
    throw err;
  }
  return { imported, addedEvents, addedIocs, failed, truncated, unread };
}

function unreadLogLine(what: string, artifact: string, rows: number): string {
  return (
    `[velociraptor] ${what}: artifact ${artifact} not read in full — the artifact catalog did not give ` +
    `its source list, so rows under named sources were never read (${rows} row(s) from its default ` +
    `source). Import again once the server answers.`
  );
}

export interface ExternalImportFields {
  artifacts: string[]; // the IMPORTED artifacts — never the requested list, which the UI would count
  requestedArtifacts: string[];
  failedArtifacts?: SkippedArtifact[];
  truncatedArtifacts?: TruncatedArtifact[];
  unreadArtifacts?: UnreadArtifact[];
  note?: string;
}

/**
 * The per-artifact half of the import-external response (#1645). `noRowsNote` ("the hunt returned no
 * rows yet") is said only when nothing imported AND every read was complete: an artifact not read in
 * full, or a read that failed, is not evidence the hunt found nothing.
 */
export function externalImportFields(
  out: ExternalImportOutcome,
  requested: string[],
  noRowsNote: string,
): ExternalImportFields {
  const fields: ExternalImportFields = { artifacts: out.imported, requestedArtifacts: requested };
  if (out.failed.length) fields.failedArtifacts = out.failed;
  if (out.truncated.length) fields.truncatedArtifacts = out.truncated;
  if (out.unread.length) fields.unreadArtifacts = out.unread;
  if (out.imported.length) return fields;
  const gaps = [
    out.unread.length ? `${out.unread.length} artifact(s) not read in full (source list unknown)` : "",
    out.failed.length ? `${out.failed.length} artifact(s) failed to read` : "",
  ].filter(Boolean);
  fields.note = gaps.length
    ? `no rows imported — ${gaps.join(", ")}; this is not evidence that nothing was found`
    : noRowsNote;
  return fields;
}
