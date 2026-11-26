import { stat, type FileHandle } from "node:fs/promises";
import type { InvestigationState } from "../analysis/stateTypes.js";
import { CLOUD_STREAM_MIN_BYTES } from "../analysis/cloudStreamLimits.js";
import type { ImportAdmissionHint } from "../analysis/importMemoryGuard.js";
import type { WindowsLogStreamKind } from "../analysis/ingest/windowsLogFileImport.js";
import { probeSiemJsonLinesHead } from "../analysis/siemJsonLinesFile.js";
import { hasUtf16Bom } from "../analysis/streamedTextFile.js";
import { formatImportCancelled, formatImportMerged, formatImportStart } from "../logging/importLog.js";
import type { ImportBase } from "./context.js";
import type { SettleContext } from "./routeSettleDeps.js";
import { emitImportDebug } from "./importDebugEmit.js";

/**
 * A large SIEM / EDR JSON Lines export or Windows Event XML export, read from the stored evidence file
 * in parts instead of as one string (#2823) — the twin of importVeloFileLogged. These two whole-text
 * importers measured a peak that followed the FILE: about 0.9 GB above the idle server for a 100 MB
 * SIEM file kept at 2,000 rows (#2814).
 *
 * A file streams when it can without changing what is imported: 32 MB or more (the cloud exports'
 * threshold; the drop folder passes its own cap when that is lower, since there the alternative is a
 * refusal), not gzip, not UTF-16, and for SIEM a JSON Lines head (probeSiemJsonLinesHead). Anything else
 * of these two kinds is still read whole — and its caller charges the guard for the file's size
 * (`windowsLogWholeReadHint`). Every other kind is untouched.
 */

const STREAM_KINDS: ReadonlySet<string> = new Set<WindowsLogStreamKind>(["siem", "evtxxml"]);

export function isWindowsLogStreamKind(kind: string): kind is WindowsLogStreamKind {
  return STREAM_KINDS.has(kind);
}

/** Whether a stored upload of `kind` streams from disk, decided on the handle the path guard judged. */
export async function decideWindowsLogDiskStream(
  a: { kind: string; handle: FileHandle; size: number; gzip: boolean },
  threshold = CLOUD_STREAM_MIN_BYTES,
): Promise<boolean> {
  if (!isWindowsLogStreamKind(a.kind) || a.gzip || a.size < threshold) return false;
  if (await hasUtf16Bom(a.handle)) return false;
  return a.kind === "evtxxml" || (await probeSiemJsonLinesHead(a.handle));
}

/**
 * The guard's hint for a file that is read whole: for these two kinds the file's size is charged too
 * (analysis/importMemoryGuard.ts), since their memory follows the file. Every other kind: the size alone.
 */
export function windowsLogWholeReadHint(kind: string, bytes: number): ImportAdmissionHint {
  return isWindowsLogStreamKind(kind) ? { incomingBytes: bytes, wholeRead: true } : { incomingBytes: bytes };
}

export async function importWindowsLogFileLogged(
  ctx: SettleContext,
  caseId: string,
  kind: WindowsLogStreamKind,
  storedPath: string,
  storedName: string,
  base: ImportBase,
): Promise<InvestigationState> {
  const { serverLogger: log, options } = ctx;
  if (!options.pipeline) throw new Error("pipeline is not configured");
  const bytes = await stat(storedPath)
    .then((s) => s.size)
    .catch(() => undefined);
  log.info(formatImportStart({ caseId, label: storedName, kind, bytes }), { caseId });
  const startedAt = Date.now();
  try {
    const state = await options.pipeline.importWindowsLogFile(caseId, kind, storedPath, {
      label: base.label,
      idPrefix: base.idPrefix,
      importedAt: base.importedAt,
      minSeverity: base.minSeverity,
      debug: base.debug,
      signal: base.signal,
      onProgress: base.onProgress,
      onParseProgress: base.onParseProgress,
      startBatch: base.startBatch,
    });
    log.info(formatImportMerged(caseId, storedName, Date.now() - startedAt), { caseId });
    emitImportDebug(caseId, base.debug, "parsed"); // as dispatchImport: the caller still settles
    return state;
  } catch (err) {
    if ((err as Error).name === "AbortError") {
      log.info(formatImportCancelled(caseId, storedName, Date.now() - startedAt), { caseId });
      emitImportDebug(caseId, base.debug, "cancelled");
    }
    throw err;
  }
}
