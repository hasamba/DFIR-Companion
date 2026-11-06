/**
 * The drop folder's streamed import (#2336): a cloud audit export or a Plaso super-timeline that is
 * gzip, or too large to read as one string, imported the way Import-from-path imports it — by
 * streaming from the stored evidence copy, never from a decoded string.
 *
 * The stored copy is written from the handle the sweep opened with O_NOFOLLOW and verified by fstat
 * (storage/noFollowRead.ts), so the link guard and the custody hash cover the very bytes imported;
 * the drop path is never opened a second time. The run is the routes' own runDiskImport, so a
 * streamed drop file and a streamed upload share their importer, log lines, pre-grading and
 * disclosure. The rest mirrors ingestStreamed (composition/importIngest.ts): one import writer per
 * case, the settle seam, the known-good auto-marks and a background re-synthesis — minus the AI-off
 * gate, which no streamed kind needs (none of them makes a model call).
 */
import type { FileHandle } from "node:fs/promises";
import { statusFromStore, withIngestAdmission } from "../analysis/caseIngestAdmission.js";
import { createImportDebugRecorder, type ImportDebugRecorder } from "../analysis/importDebug.js";
import {
  captureImportBaseline,
  releaseImportBaseline,
  type ImportBaseline,
} from "../analysis/importBaseline.js";
import type { ImportLock } from "../analysis/importLock.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import { getServerLogger } from "../logging/serverLogger.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { ImportBase } from "../routes/context.js";
import { runDiskImport, streamedImportMeta } from "../routes/importCloudStream.js";
import type { AppOptions } from "./appOptions.js";
import { settleStreamedImport, type StreamedSettleDeps } from "./importIngestSettle.js";

export interface DiskIngestDeps {
  store: CaseStore;
  options: AppOptions;
  importLock: ImportLock;
  runStateExclusive: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
  demoteForensic: (caseId: string) => Promise<ForensicEvent[]>;
  settleDeps: StreamedSettleDeps;
  /** The whitelist / NSRL / deobfuscation auto-marks and the background re-synthesis. */
  afterImport: (caseId: string) => Promise<void>;
}

export interface DiskIngestResult {
  storedName: string;
  addedEvents: number;
  addedIocs: number;
  /** The streamed import's disclosure sentences (budgets reached, gzip read), for drop-log.txt. */
  disclosure: string[];
}

export type IngestDiskFile = (
  caseId: string,
  kind: string,
  handle: FileHandle,
  originalName: string,
  assetHost?: string,
  debug?: ImportDebugRecorder,
) => Promise<DiskIngestResult>;

export function createDiskIngest(deps: DiskIngestDeps): IngestDiskFile {
  const { store, options, importLock } = deps;
  const statusOf = statusFromStore(store);
  const diskCtx = {
    options,
    runStateExclusive: deps.runStateExclusive,
    serverLogger: getServerLogger(),
    demoteForensic: deps.demoteForensic,
  };
  const baselineOf = async (caseId: string): Promise<ImportBaseline | null> =>
    options.stateStore ? captureImportBaseline(options.stateStore, caseId).catch(() => null) : null;

  async function admitted(
    caseId: string,
    kind: string,
    handle: FileHandle,
    originalName: string,
    assetHost?: string,
    debug: ImportDebugRecorder = createImportDebugRecorder(),
  ): Promise<DiskIngestResult> {
    if (!options.pipeline) throw new Error("AI pipeline not configured");
    options.onImport?.(caseId);
    const seq = await store.nextImportSeq(caseId);
    const safe = originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.dat";
    const storedName = `${String(seq).padStart(4, "0")}_${safe}`;
    const importedAt = new Date().toISOString();
    const saved = await store.saveImportFromHandle(caseId, storedName, handle);
    await store.appendImport(caseId, {
      caseId,
      sequenceNumber: seq,
      importedAt,
      filename: storedName,
      originalName,
      rows: 0,
      bytes: saved.bytes,
    });
    const status = (detail: string): void =>
      options.onAiStatus?.(caseId, {
        status: "analyzing",
        phase: "extracting",
        at: new Date().toISOString(),
        detail,
      });
    status(`importing (${kind}) by streaming`);
    const base: ImportBase = {
      label: storedName,
      idPrefix: `${seq}`,
      importedAt,
      debug,
      onProgress: (done, total) => status(`${kind} import — ${done}/${total}`),
      ...(assetHost ? { assetHost } : {}),
    };
    let disclosure: string[] = [];
    const counts = await importLock.runSized(caseId, { incomingBytes: saved.bytes }, async () => {
      const baseline = await baselineOf(caseId);
      try {
        await runDiskImport(diskCtx, kind, caseId, saved.path, storedName, base);
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
        const streamMeta = streamedImportMeta(caseId, storedName);
        disclosure = streamMeta.streamDisclosure ?? [];
        return await settleStreamedImport(deps.settleDeps, {
          caseId,
          kind,
          storedName,
          baseline,
          streamMeta,
        });
      } finally {
        if (options.stateStore) await releaseImportBaseline(options.stateStore, baseline);
      }
    });
    await deps.afterImport(caseId);
    return { storedName, ...counts, disclosure };
  }

  // #1920: reserve the case against an archive before the first evidence write, as ingestStreamed does.
  return (caseId, ...rest) =>
    withIngestAdmission(store.casesRoot, caseId, () => admitted(caseId, ...rest), statusOf);
}
