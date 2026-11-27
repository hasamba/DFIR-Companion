/**
 * The drop folder's streamed branch (#2336), kept beside composition/dropFolder.ts so that file
 * stays under its size limit. A gzip file, or a file over DFIR_DROP_MAX_BYTES, is sniffed through
 * an O_NOFOLLOW descriptor verified by fstat (storage/noFollowRead.ts), gzip-aware as Import-from-
 * path sniffs, and a cloud audit export or Plaso super-timeline is streamed from that same
 * descriptor instead of being read whole or refused. A cloud kind streams whenever the alternative
 * is a refusal — gzip, or over the drop cap — not only past the routes' 32 MB threshold. A gzip of
 * any other kind gets the routes' own GZIP_ONLY_CLOUD refusal. A Velociraptor JSON Lines export over
 * the drop cap streams the same way (#2705); any other Velociraptor shape keeps the oversize refusal.
 */
import { basename } from "node:path";
import { createImportDebugRecorder, type ImportDebugRecorder } from "../analysis/importDebug.js";
import type { FileHandle } from "node:fs/promises";
import { isGzipMagic } from "../analysis/cloudStreamReader.js";
import { isStreamKind } from "../analysis/ingest/cloudStreamProviders.js";
import { assetHostFromDropRelpath } from "../analysis/assetHost.js";
import { openNoFollow } from "../storage/noFollowRead.js";
import { sniffImportFileHeadDetail } from "../routes/importFileHead.js";
import { GZIP_ONLY_CLOUD, readsFromDisk } from "../routes/importCloudStream.js";
import { decideVeloDiskStream, veloDiskStreamThreshold } from "../routes/importVeloStream.js";
import { decideWindowsLogDiskStream } from "../routes/importWindowsLogStream.js";
import { CLOUD_STREAM_MIN_BYTES } from "../analysis/cloudStreamLimits.js";
import { logSiemFallback } from "../routes/importDebugEmit.js";
import { siemFallbackWarning } from "../routes/importNotes.js";
import type { IngestDiskFile } from "./importIngestDisk.js";
import type { ImportCounts } from "../analysis/importNotification.js";

export { isGzipMagic };

/** At or above this size an under-cap drop file is offered to the streamer first (#2823). */
export const WINLOG_MIN = CLOUD_STREAM_MIN_BYTES;

export interface StreamedDropResult {
  ok: boolean;
  reason?: string;
  warning?: string;
  /** The import's settled counts (#2982); absent when unknown. */
  counts?: ImportCounts;
}

export interface DropStreamerDeps {
  resolveImportKind: (filename: string, text: string, debug?: ImportDebugRecorder) => string;
  ingestDiskFile: IngestDiskFile;
  dropMaxBytes: number;
  /** Whether the batched Velociraptor importer's stores are wired — a large JSON Lines export streams only then (#2705). */
  veloSinkWired?: () => boolean;
}

/** Null: not a kind that streams (and not gzip) — the caller takes its usual path. */
export type StreamDropFile = (
  caseId: string,
  fullPath: string,
  relpath: string,
  debug: ImportDebugRecorder,
  /** An under-cap file (#2823): only a SIEM JSON Lines / Windows Event XML export streams; else null. */
  windowsLogOnly?: boolean,
) => Promise<StreamedDropResult | null>;

export function createDropStreamer(deps: DropStreamerDeps): StreamDropFile {
  const { resolveImportKind, ingestDiskFile, dropMaxBytes } = deps;
  const veloSinkWired = deps.veloSinkWired ?? (() => false);
  const winlogThreshold = Math.min(CLOUD_STREAM_MIN_BYTES, dropMaxBytes);
  async function ingest(
    caseId: string,
    a: { kind: string; handle: FileHandle; name: string; relpath: string; debug: ImportDebugRecorder },
  ): Promise<StreamedDropResult> {
    const assetHost = assetHostFromDropRelpath(a.relpath) || undefined;
    const r = await ingestDiskFile(caseId, a.kind, a.handle, a.name, assetHost, a.debug);
    logSiemFallback(caseId, a.relpath, a.kind, a.debug); // a guessed SIEM import, as the text path names it (#1824)
    const warning = [...r.disclosure, siemFallbackWarning(a.kind, a.debug).warning ?? ""].filter(Boolean);
    const counts = r.counts ? { counts: r.counts } : {};
    return { ok: true, ...counts, ...(warning.length ? { warning: warning.join(" ") } : {}) };
  }
  return async (caseId, fullPath, relpath, debug, windowsLogOnly = false) => {
    const name = basename(relpath);
    const handle = await openNoFollow(fullPath);
    try {
      const { sample, gzip } = await sniffImportFileHeadDetail(handle);
      const bare = name.replace(/\.gz$/i, "");
      // An under-cap file only asks whether it streams: the whole read detects it again if not.
      const kind = resolveImportKind(bare, sample, windowsLogOnly ? createImportDebugRecorder() : debug);
      const { size } = await handle.stat();
      // A large SIEM JSON Lines / Windows Event XML export reads in parts, not whole (#2823).
      const winlog = await decideWindowsLogDiskStream({ kind, handle, size, gzip }, winlogThreshold);
      if (windowsLogOnly) {
        if (!winlog) return null; // the under-cap whole read stays as it was
        resolveImportKind(bare, sample, debug); // this attempt's detection decision
        return await ingest(caseId, { kind, handle, name, relpath, debug });
      }
      // A Velociraptor JSON Lines file streams whenever the alternative is a refusal at the drop cap (#2705).
      const veloThreshold = Math.min(veloDiskStreamThreshold(), dropMaxBytes);
      const velo = await decideVeloDiskStream(
        { kind, handle, size, gzip, sinkWired: veloSinkWired() },
        veloThreshold,
      );
      if (velo.refuse) return { ok: false, reason: velo.refuse };
      const streams =
        velo.streams ||
        winlog ||
        readsFromDisk(kind, size, gzip) ||
        (isStreamKind(kind) && size > dropMaxBytes);
      if (!streams) return gzip ? { ok: false, reason: GZIP_ONLY_CLOUD } : null;
      return await ingest(caseId, { kind, handle, name, relpath, debug });
    } finally {
      await handle.close().catch(() => undefined);
    }
  };
}

/** The gzip-head case: always answered here, never handed to a tool as a raw binary. */
export async function streamGzipDropFile(
  stream: StreamDropFile,
  ...args: Parameters<StreamDropFile>
): Promise<StreamedDropResult> {
  return (await stream(...args)) ?? { ok: false, reason: GZIP_ONLY_CLOUD };
}
