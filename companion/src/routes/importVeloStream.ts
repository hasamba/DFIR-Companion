import { stat, type FileHandle } from "node:fs/promises";
import type { InvestigationState } from "../analysis/stateTypes.js";
import { maxImportFileBytes } from "../analysis/ingest/importFileCap.js";
import { probeNdjsonFileHead, UTF16_REFUSAL } from "../analysis/velociraptorFileRowStream.js";
import { formatImportCancelled, formatImportMerged, formatImportStart } from "../logging/importLog.js";
import type { ImportBase } from "./context.js";
import type { SettleContext } from "./routeSettleDeps.js";
import { emitImportDebug } from "./importDebugEmit.js";

/**
 * A large Velociraptor JSON Lines export, streamed from disk (#2705) — the Velociraptor twin of
 * importPlasoFileLogged. Below the threshold nothing changes: the file is read whole and takes the
 * whole-string path (bulk past 8 MB). Above it, a JSON Lines file is read from the stored copy a
 * record at a time, so a file past V8's ~512 MB string ceiling imports at all.
 *
 * The threshold is the smaller of DFIR_MAX_IMPORT_FILE_MB and a fixed 256 MB, so raising the cap
 * can never bring back the string-length failure. The decision is taken BEFORE the 202, on the
 * handle the path guard judged: a file that is not JSON Lines keeps the 413 it always got, a UTF-16
 * file is refused with what to do about it, and a server without the batched importer's stores
 * keeps today's 413 rather than accepting a job that would fail.
 */

const MB = 1024 * 1024;
/** Well under V8's ~512 MB string ceiling: above this a Velociraptor export is never one string. */
export const VELO_DISK_STREAM_BYTES = 256 * MB;

export function veloDiskStreamThreshold(env: NodeJS.ProcessEnv = process.env): number {
  return Math.min(maxImportFileBytes(env), VELO_DISK_STREAM_BYTES);
}

export interface VeloDiskDecision {
  streams: boolean;
  /** Set when the file must be refused before any evidence copy: the 413 sentence. */
  refuse?: string;
}

/**
 * Whether a Velociraptor upload streams from disk. `threshold` defaults to veloDiskStreamThreshold();
 * the drop folder passes a lower one (its own cap), since there the alternative is a refusal.
 */
export async function decideVeloDiskStream(
  a: { kind: string; handle: FileHandle; size: number; gzip: boolean; sinkWired: boolean },
  threshold = veloDiskStreamThreshold(),
): Promise<VeloDiskDecision> {
  if (a.kind !== "velociraptor" || a.gzip || !a.sinkWired || a.size <= threshold) return { streams: false };
  const verdict = await probeNdjsonFileHead(a.handle);
  if (verdict === "utf16") return { streams: false, refuse: UTF16_REFUSAL };
  return { streams: verdict === "ndjson" };
}

export async function importVeloFileLogged(
  ctx: SettleContext,
  caseId: string,
  storedPath: string,
  storedName: string,
  base: ImportBase,
): Promise<InvestigationState> {
  const { serverLogger: log, options } = ctx;
  if (!options.pipeline) throw new Error("pipeline is not configured");
  const bytes = await stat(storedPath)
    .then((s) => s.size)
    .catch(() => undefined);
  log.info(formatImportStart({ caseId, label: storedName, kind: "velociraptor", bytes }), { caseId });
  const startedAt = Date.now();
  try {
    const state = await options.pipeline.importVelociraptorFile(caseId, storedPath, {
      label: base.label,
      idPrefix: base.idPrefix,
      importedAt: base.importedAt,
      minSeverity: base.minSeverity,
      debug: base.debug,
      signal: base.signal,
      // The analyst-declared host, as the in-memory dispatch passes it (#1496).
      ...(base.assetHost
        ? { velociraptor: { hostFallback: base.assetHost, hostFallbackBasis: "analyst" as const } }
        : {}),
      onProgress: (done, total) => void base.onProgress?.(done, total), // as the in-memory dispatch reports it
    });
    log.info(formatImportMerged(caseId, storedName, Date.now() - startedAt), { caseId });
    emitImportDebug(caseId, base.debug, "succeeded");
    return state;
  } catch (err) {
    if ((err as Error).name === "AbortError") {
      log.info(formatImportCancelled(caseId, storedName, Date.now() - startedAt), { caseId });
      emitImportDebug(caseId, base.debug, "cancelled");
    }
    throw err;
  }
}
