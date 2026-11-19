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
import type { ImportDebugRecorder } from "../analysis/importDebug.js";
import { isGzipMagic } from "../analysis/cloudStreamReader.js";
import { isStreamKind } from "../analysis/ingest/cloudStreamProviders.js";
import { assetHostFromDropRelpath } from "../analysis/assetHost.js";
import { openNoFollow } from "../storage/noFollowRead.js";
import { sniffImportFileHeadDetail } from "../routes/importFileHead.js";
import { GZIP_ONLY_CLOUD, readsFromDisk } from "../routes/importCloudStream.js";
import { decideVeloDiskStream, veloDiskStreamThreshold } from "../routes/importVeloStream.js";
import type { IngestDiskFile } from "./importIngestDisk.js";

export { isGzipMagic };

export interface StreamedDropResult {
  ok: boolean;
  reason?: string;
  warning?: string;
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
) => Promise<StreamedDropResult | null>;

export function createDropStreamer(deps: DropStreamerDeps): StreamDropFile {
  const { resolveImportKind, ingestDiskFile, dropMaxBytes } = deps;
  const veloSinkWired = deps.veloSinkWired ?? (() => false);
  return async (caseId, fullPath, relpath, debug) => {
    const name = basename(relpath);
    const handle = await openNoFollow(fullPath);
    try {
      const { sample, gzip } = await sniffImportFileHeadDetail(handle);
      const kind = resolveImportKind(name.replace(/\.gz$/i, ""), sample, debug);
      const { size } = await handle.stat();
      // A Velociraptor JSON Lines file streams whenever the alternative is a refusal at the drop cap (#2705).
      const veloThreshold = Math.min(veloDiskStreamThreshold(), dropMaxBytes);
      const velo = await decideVeloDiskStream(
        { kind, handle, size, gzip, sinkWired: veloSinkWired() },
        veloThreshold,
      );
      if (velo.refuse) return { ok: false, reason: velo.refuse };
      const streams =
        velo.streams || readsFromDisk(kind, size, gzip) || (isStreamKind(kind) && size > dropMaxBytes);
      if (!streams) return gzip ? { ok: false, reason: GZIP_ONLY_CLOUD } : null;
      const assetHost = assetHostFromDropRelpath(relpath) || undefined;
      const r = await ingestDiskFile(caseId, kind, handle, name, assetHost, debug);
      return { ok: true, ...(r.disclosure.length ? { warning: r.disclosure.join(" ") } : {}) };
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
