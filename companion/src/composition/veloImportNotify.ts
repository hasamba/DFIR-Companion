import {
  artifactGaps,
  notifyImport,
  type ImportCounts,
  type ImportFailedItem,
} from "../analysis/importNotification.js";
import { createCaseNotifier, type CaseNotifierDeps } from "./caseNotifier.js";
import type { NotificationEvent } from "../analysis/notifications.js";
import type { VeloUploadsOutcome } from "../routes/veloUploadFields.js";
import { logLine } from "../logging/serverLogger.js";

// "Import finished" messages (#2978) for the Velociraptor imports that are not one file: an
// uploads-only import (the GUI's "Uploaded Files" URL) and a multi-artifact external import. Kept out
// of the ingest and route files, which are at their size ceiling.

const SKIPPED_REASON = "not imported (unsupported format, AI off for this case, or the import failed)";

/**
 * Pass an uploads-only import's result through, sending its message when it settles or fails. A
 * skipped file was unsupported, held back with AI off, or failed to store or parse — the ingest keeps
 * no per-file reason — and when every file was skipped the import as a whole failed.
 */
export async function notifyUploadsImport(
  dispatch: ((event: NotificationEvent) => void) | undefined,
  caseId: string,
  label: string,
  run: Promise<VeloUploadsOutcome>,
): Promise<VeloUploadsOutcome> {
  const source = `velociraptor: ${label}`;
  try {
    const out = await run;
    const failed: ImportFailedItem[] = out.skipped.map((name) => ({ name, reason: SKIPPED_REASON }));
    const ok = out.imported.length > 0 || failed.length === 0;
    notifyImport(
      dispatch,
      {
        caseId,
        source,
        ok,
        files: out.imported.length + out.skipped.length,
        ...(out.counts ? { counts: out.counts } : {}),
        ...(failed.length ? { failed } : {}),
        ...(ok ? {} : { reason: "no uploaded file could be imported" }),
      },
      logLine,
    );
    return out;
  } catch (err) {
    notifyImport(dispatch, { caseId, source, ok: false, reason: (err as Error).message }, logLine);
    throw err;
  }
}

/** The collect as its hunt card names it: the bundle, else the hunt id. */
function huntSource(job: { bundleName?: string; huntId: string }): string {
  return `velociraptor: ${job.bundleName || `hunt ${job.huntId}`}`;
}

/**
 * A hunt collect that reached its settle. A collect that failed partway still imported what came
 * before the failure, so it reads "finished, N failed" — unless nothing settled at all.
 */
export function notifyHuntCollect(
  notifierDeps: CaseNotifierDeps,
  caseId: string,
  job: {
    bundleName?: string;
    huntId: string;
    artifacts?: readonly string[];
    error?: string;
    settleWarning?: string;
    skippedArtifacts?: readonly { name: string; error: string }[];
    truncatedArtifacts?: readonly { name: string }[];
    unreadArtifacts?: readonly { name: string }[];
  },
  settled: { counts?: ImportCounts; error?: string },
): void {
  const skipped = job.skippedArtifacts ?? [];
  const gaps = artifactGaps({
    failed: skipped,
    truncated: job.truncatedArtifacts ?? [],
    unread: job.unreadArtifacts ?? [],
  });
  // A settle that failed (and what its recovery managed) is part of the outcome, not a footnote.
  const settleProblem = job.settleWarning ?? settled.error;
  if (settleProblem) gaps.push({ name: "forensic timeline settle", reason: settleProblem });
  const landed = (settled.counts?.added ?? 0) + (settled.counts?.superAdded ?? 0) > 0;
  // Every artifact failed to download or import: nothing was read, so the collect failed.
  const allFailed = !!job.artifacts?.length && skipped.length >= job.artifacts.length && !landed;
  const ok = (!job.error || landed) && !allFailed;
  const reason = job.error ?? (allFailed ? "no artifact could be read" : undefined);
  notifyImport(
    createCaseNotifier(notifierDeps),
    {
      caseId,
      source: huntSource(job),
      ok,
      ...(job.artifacts?.length ? { files: job.artifacts.length } : {}),
      ...(settled.counts ? { counts: settled.counts } : {}),
      ...(gaps.length ? { failed: gaps } : {}),
      ...(ok || !reason ? {} : { reason }),
    },
    logLine,
  );
}

/** A collect that failed as a whole, before anything of it settled. */
export function notifyHuntFailed(
  dispatch: ((event: NotificationEvent) => void) | undefined,
  caseId: string,
  huntId: string,
  reason: string,
): void {
  notifyImport(dispatch, { caseId, source: huntSource({ huntId }), ok: false, reason }, logLine);
}
