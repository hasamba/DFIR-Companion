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
}

export interface ArtifactIngestResult {
  addedEvents: number;
  addedIocs: number;
}

export interface ExternalImportOutcome {
  imported: string[];
  addedEvents: number;
  addedIocs: number;
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
  readRows: (artifact: string) => Promise<unknown[]>,
  ingest: (artifact: string, rows: unknown[]) => Promise<ArtifactIngestResult>,
): Promise<ExternalImportOutcome> {
  const label = `velociraptor: ${what}`;
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
  let addedEvents = 0;
  let addedIocs = 0;
  try {
    for (const [index, artifact] of artifacts.entries()) {
      // The popover's ✕ Cancel. Checked between artifacts — the one in flight finishes, so the
      // timeline never holds half an artifact — and surfaced as the request's error.
      if (job?.signal?.aborted) throw new Error("import cancelled by the analyst");
      let rows: unknown[];
      try {
        rows = await readRows(artifact);
      } catch (e) {
        deps.logLine(`[velociraptor] ${what}: artifact ${artifact} read failed: ${(e as Error).message}`);
        continue;
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
      const one = await ingest(artifact, rows);
      rows = []; // release before the next artifact is read
      imported.push(artifact);
      addedEvents += one.addedEvents;
      addedIocs += one.addedIocs;
    }
    report(total, `${imported.length}/${total} artifact(s) imported`);
    if (job) await deps.jobManager?.finish(job.jobId);
    deps.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
  } catch (err) {
    if (job) await deps.jobManager?.fail(job.jobId, err);
    deps.onAiStatus?.(caseId, {
      status: "error",
      at: new Date().toISOString(),
      detail: `Velociraptor external import failed: ${(err as Error).message}`,
    });
    throw err;
  }
  return { imported, addedEvents, addedIocs };
}
