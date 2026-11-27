import { extname } from "node:path";
import { notifyImport } from "../analysis/importNotification.js";
import type { NotificationEvent } from "../analysis/notifications.js";
import { IMAGE_EXTS } from "../analysis/dropScan.js";
import { logLine } from "../logging/serverLogger.js";
import type { SweepTally } from "./dropBatch.js";

// A drop-folder sweep's "import finished" message (#2978). It replaces the failure-only milestone the
// sweep used to send, and moves it under the channel's imports toggle.
//
// ONLY COMPLETED EVIDENCE IMPORTS COUNT. A dropped image is a screenshot capture (left out, as
// extension screenshots are); an HTTP tool's file was only submitted, its verdict comes later; a
// pending or deferred file runs again on a later sweep. None of those finished an import, so a sweep
// that holds only them sends nothing.
//
// The sweep imports each file through its own settle and keeps no per-file diff, so a drop message
// says its event counts are not available rather than reporting zero.

const SOURCE = "drop folder";

const isImage = (relpath: string): boolean => IMAGE_EXTS.has(extname(relpath).toLowerCase());

export function notifyDropSweep(
  dispatch: ((event: NotificationEvent) => void) | undefined,
  caseId: string,
  tally: Pick<SweepTally, "imported" | "failed">,
): void {
  const evidence = tally.imported.filter((relpath) => !isImage(relpath));
  const failed = tally.failed.map((f) => ({ name: f.relpath, reason: f.reason }));
  if (!evidence.length && !failed.length) return;
  const ok = evidence.length > 0;
  notifyImport(
    dispatch,
    {
      caseId,
      source: `${SOURCE} (${evidence.length + failed.length} file${evidence.length + failed.length === 1 ? "" : "s"})`,
      ok,
      files: evidence.length + failed.length,
      ...(failed.length ? { failed } : {}),
      ...(ok ? {} : { reason: "no dropped file could be imported" }),
    },
    logLine,
  );
}

/** The sweep itself failed (listing, metadata or store I/O): nothing of it is known to have imported. */
export function notifyDropSweepFailed(
  dispatch: ((event: NotificationEvent) => void) | undefined,
  caseId: string,
  err: unknown,
): void {
  notifyImport(dispatch, { caseId, source: SOURCE, ok: false, reason: (err as Error).message }, logLine);
}
