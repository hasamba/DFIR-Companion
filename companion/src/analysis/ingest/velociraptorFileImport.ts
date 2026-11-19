import { open } from "node:fs/promises";
import type { InvestigationState, Severity } from "../stateTypes.js";
import type { VelociraptorImportOptions } from "../velociraptorImport.js";
import type { ImportDebugRecorder } from "../importDebug.js";
import {
  openVelociraptorFileRowStream,
  probeNdjsonFileHead,
  UTF16_REFUSAL,
} from "../velociraptorFileRowStream.js";
import { importVelociraptorBulk, type BulkRowSource } from "./velociraptorBulk.js";
import { knownHostIdentity } from "./importState.js";
import type { ImportContext } from "./importContext.js";

/**
 * A Velociraptor JSON Lines export imported from the stored file (#2705), never read into one
 * string: the bulk driver reads it a record at a time, twice (evidence pass, then mapping pass). The
 * routes send a file here only when it is over the in-memory threshold AND its head is JSON Lines;
 * the checks below are the backstop for a caller that did not ask first.
 */

/** Rows often carry no _Source: the Velociraptor-named file label stands in as the artifact name. */
export function veloArtifactFromLabel(label: string): string {
  // A hunt export's hunt-wide copy is `All <Artifact>.json` (#2714): the artifact is the rest.
  const raw = label
    .replace(/^\d+_/, "")
    .replace(/\.(json|jsonl|ndjson|csv)$/i, "")
    .replace(/^All[ _](?=[A-Za-z][\w-]*\.)/, "");
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw; // malformed %xx — keep the raw label
  }
}

/** The bulk driver's source for a JSON Lines file of `bytes` bytes. */
export function fileRowSource(
  path: string,
  bytes: number,
  opts: { maxRecordBytes?: number; signal?: AbortSignal } = {},
): BulkRowSource {
  return { bytes, open: () => openVelociraptorFileRowStream(path, opts) };
}

export interface VelociraptorFileOptions {
  label: string;
  idPrefix: string;
  importedAt: string;
  velociraptor?: VelociraptorImportOptions;
  minSeverity?: Severity;
  veloUrl?: string;
  onProgress?: (done: number, total: number) => void;
  debug?: ImportDebugRecorder;
  signal?: AbortSignal;
}

async function checkHead(storedPath: string): Promise<number> {
  const fh = await open(storedPath, "r");
  try {
    const verdict = await probeNdjsonFileHead(fh);
    if (verdict === "utf16") throw new Error(UTF16_REFUSAL);
    if (verdict !== "ndjson")
      throw new Error(
        "this Velociraptor file is too large to read whole and is not JSON Lines — only JSON Lines streams from disk; export it as JSON Lines or split it",
      );
    return (await fh.stat()).size;
  } finally {
    await fh.close();
  }
}

export async function importVelociraptorFile(
  ctx: ImportContext,
  caseId: string,
  storedPath: string,
  opts: VelociraptorFileOptions,
): Promise<InvestigationState> {
  const sink = ctx.opts.bulkImportSink;
  if (!sink)
    throw new Error(
      "this Velociraptor file is too large to read whole, and the batched importer that streams it is not available on this server",
    );
  const bytes = await checkHead(storedPath);
  const known = await knownHostIdentity(ctx, caseId); // the case's rename ledger seeds the parse (#1495)
  const artifact = veloArtifactFromLabel(opts.label);
  const state = await importVelociraptorBulk(
    ctx,
    sink,
    caseId,
    fileRowSource(storedPath, bytes, opts.signal ? { signal: opts.signal } : {}),
    {
      label: opts.label,
      idPrefix: opts.idPrefix,
      importedAt: opts.importedAt,
      velociraptor: { artifact, ...known, ...opts.velociraptor, debug: opts.debug },
      minSeverity: opts.minSeverity,
      veloUrl: opts.veloUrl,
      onProgress: opts.onProgress,
      ...(opts.signal ? { signal: opts.signal } : {}),
    },
  );
  if (!state) throw new Error("the Velociraptor file could not be read as JSON Lines"); // a file source always opens
  return state;
}
