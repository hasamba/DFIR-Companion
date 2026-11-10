import type { Request, Response } from "express";
import type { FileHandle } from "node:fs/promises";
import { IMPORT_FILE_UNKNOWN_MESSAGE, unknownImportResponse } from "../analysis/importKindHints.js";
import { createImportDebugRecorder } from "../analysis/importDebug.js";
import { aiExtractionFromDebug } from "../analysis/importMeta.js";
import { FalsePositiveStore } from "../analysis/falsePositive.js";
import { matchFpPropagation } from "../analysis/fpPropagation.js";
import type { ImportBaseline } from "../analysis/importBaseline.js";
import type { Severity } from "../analysis/stateTypes.js";
import { isStringTooLongError } from "../storage/boundedRead.js";
import type { RouteContext } from "./context.js";
import { buildImportBase, importJobParameters } from "./importBase.js";
import { cloudStream } from "./importCloudStream.js";
import { sniffImportFileHeadDetail, readImportFileBounded } from "./importFileHead.js";
import { cancellableByParse, isAiDependent, refuseAiOffImport, refuseDetectedImport } from "./importKinds.js";
import { siemFallbackWarning } from "./importNotes.js";
import { settleForensicImport } from "./importSettle.js";
import { routeSettleDeps } from "./routeSettleDeps.js";
import { logImportActivity } from "./importActivity.js";
import { recordImportRun } from "./importRunRecorder.js";
import { createImportJobTracking, IMPORT_JOB_PENDING_DETAIL } from "./importJobTracking.js";
import { beginImportSection, type ImportSection } from "./importSection.js";
import { sendPipelineError } from "./presidioApproval.js";

/**
 * Import a file the server already holds open, from the head sniff onward: the one flow shared by
 * POST /cases/:id/import-file (a judged server path, #1834) and POST /cases/:id/import-upload (a
 * spooled request body, #2336). Lifted out of routes/import.ts so the upload route reuses it rather
 * than copying it: gzip-aware sniff, kind detection and its refusals, the streamed-or-whole-file
 * decision (Plaso and large/gzip cloud exports read from disk, #2303), the evidence-first stored
 * copy, job registration with the parse-cancellable predicate (#2337), and the settle tail.
 *
 * The caller owns the handle and the custody receipt; `save` copies the handle into the case's
 * imports dir and returns null when it has already answered (a 409 for bytes changed since their
 * receipt). Every path through here ends in a response; nothing reads the handle after the 202.
 */
export interface ImportFromHandleInput {
  caseId: string;
  handle: FileHandle;
  /** The file's base name, already sanitized by the caller: never a path the client chose. */
  originalName: string;
  minSeverity: Severity | undefined;
  /** How the bytes arrived, for the status line: "from path" or "uploaded". */
  via: string;
  save: (storedName: string) => Promise<{ bytes: number } | null>;
}

export async function importFromHandle(
  ctx: RouteContext,
  req: Request,
  res: Response,
  input: ImportFromHandleInput,
): Promise<unknown> {
  const { caseId, handle, originalName, minSeverity, via, save } = input;
  const {
    store,
    options,
    importLock,
    recordImportFailure,
    recordAiError,
    getControl,
    pushImportCheckpoint,
    dispatchImport,
    resynthesizeInBackground,
    applyWhitelistToCase,
    applyNsrlToCase,
    applyDeobfuscationToCase,
  } = ctx;
  const aiEnabled = async (id: string): Promise<boolean> => (await getControl(id)).enabled;
  const onAiStatus: typeof options.onAiStatus = (id, event) => options.onAiStatus?.(id, event);
  const settleDeps = routeSettleDeps(ctx);

  // Detect the import kind from a bounded HEAD sample — never read the whole file just to sniff
  // it. A Plaso super-timeline can exceed V8's ~512 MB max string length (readFile(utf8) throws
  // "Invalid string length"), so a sample-based sniff is the only way to even classify it.
  let sample: string, gzip: boolean; // a gzip upload is sniffed from its decompressed head (#2303)
  try {
    ({ sample, gzip } = await sniffImportFileHeadDetail(handle));
  } catch (err) {
    return res.status(400).json({ error: `cannot read file: ${(err as Error).message}` });
  }
  if (!sample.trim()) return res.status(400).json({ error: "file is empty" });

  const debug = createImportDebugRecorder(); // this attempt's, detection first (#1736)
  const kind = ctx.resolveImportKind()(originalName.replace(/\.gz$/i, ""), sample, debug);
  // best-effort unknown hint: a truncated head gives no capa hint; then no provider / AI budget.
  const unknown = () => unknownImportResponse(originalName, sample, IMPORT_FILE_UNKNOWN_MESSAGE);
  const hasSynthesisProvider = options.pipeline?.hasSynthesisProvider() === true;
  if (refuseDetectedImport({ kind, caseId, res, hasSynthesisProvider, unknown, debug })) return;

  // Plaso and large/gzip cloud exports stream (#2303); else one string, capped by DFIR_MAX_IMPORT_FILE_MB (#921).
  const streaming = cloudStream.readsFromDisk(kind, (await handle.stat()).size, gzip);
  if (gzip && !streaming) return res.status(415).json({ error: cloudStream.GZIP_ONLY_CLOUD });
  let text = "";
  if (!streaming) {
    try {
      const read = await readImportFileBounded(handle, kind);
      if (read.tooLarge !== undefined) return res.status(413).json({ error: read.tooLarge });
      text = read.text;
    } catch (err) {
      const m = (err as Error).message;
      if (isStringTooLongError(err)) {
        return res.status(413).json({
          error: `file is too large to import as ${kind} (exceeds the ~512 MB in-memory limit); only Plaso super-timelines support streaming import — split or convert the file`,
        });
      }
      return res.status(400).json({ error: `cannot read file: ${m}` });
    }
    if (!text.trim()) return res.status(400).json({ error: "file is empty" });
  }

  options.onImport?.(caseId);

  try {
    const seq = await store.nextImportSeq(caseId);
    const safeName = originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.dat";
    const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
    const importedAt = new Date().toISOString();
    // Evidence-first: copy the raw bytes (a >512 MB file is never string-decoded), then audit-log it. From
    // the caller's handle (#1834), exclusive (#214), custody-recorded (#2055); the caller's save sends
    // its own 409 when the bytes changed since their receipt, and returns null.
    const saved = await save(storedName);
    if (!saved) return;
    await store.appendImport(caseId, {
      caseId,
      sequenceNumber: seq,
      importedAt,
      filename: storedName,
      originalName,
      rows: 0,
      bytes: saved.bytes,
    });

    // Same AI-off gate as /import above — rationale on isAiDependent().
    const aiDependent = isAiDependent(kind);
    const body = { file: storedName, minSeverity, ...siemFallbackWarning(kind, debug) }; // #1795
    if (await refuseAiOffImport({ kind, caseId, res, aiEnabled, onAiStatus, debug, body })) return;

    const job = options.jobManager?.register({
      caseId,
      kind: "import",
      label: `${kind}: ${storedName}`,
      detail: IMPORT_JOB_PENDING_DETAIL,
      cancellable: aiDependent || cancellableByParse(kind, streaming), // Plaso streams, never cancels
      resumable: true,
      maxRetries: 2,
      parameters: importJobParameters({ kind, storedName, seq, importedAt, minSeverity, streaming, req }),
    });
    await job?.durable;
    res.status(202).json({ accepted: true, kind, ...body });
    const tracking = createImportJobTracking(options.jobManager, job, kind, (done, total) =>
      options.onAiStatus?.(caseId, {
        status: "analyzing",
        phase: "extracting",
        at: new Date().toISOString(),
        detail: `${kind} import — ${done}/${total}`,
      }),
    );
    const base = buildImportBase({
      storedName,
      seq,
      importedAt,
      kind,
      minSeverity,
      tracking,
      job,
      req,
      debug,
    });
    options.onAiStatus?.(caseId, {
      status: "analyzing",
      phase: "extracting",
      at: importedAt,
      detail: `importing (${kind}) ${via}${minSeverity ? ` — min severity ${minSeverity}` : ""}`,
    });

    // Held through the diff below; released in the `.finally`. See routes/importSection.ts.
    let baseline: ImportBaseline | null = null;
    let section: ImportSection | null = null;
    // Plaso streams from disk; everything else dispatches the in-memory string.
    const run = async (): Promise<unknown> => {
      await tracking.start();
      section = await beginImportSection(importLock, caseId, options.stateStore, saved.bytes);
      baseline = section.baseline;
      return streaming
        ? cloudStream.runStoredFile(ctx, { kind, caseId, storedName, base })
        : dispatchImport(kind, caseId, text, base);
    };

    run()
      .then(async () => {
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
        if (settleDeps && baseline) {
          try {
            // The seam every import crosses (routes/importSettle.ts): dual-write → tag → demote,
            // diffs from the POST-demote state so "+N events" counts only graded signal.
            const settled = await settleForensicImport(settleDeps, caseId, baseline, storedName);
            const { superTimelineAddedCount, superTimelineEvicted } = settled;
            const { timelineDiff: tDiff, iocsDiff: iDiff } = settled;
            // Proactive FP-pattern propagation (#15b): does this import re-arrive with events matching a
            // known false-positive pattern? Match the NEW forensic events against the FP markers'
            // fingerprints and surface a one-click bulk-mark suggestion on the banner (never auto-mark).
            let fpPropagation: Awaited<ReturnType<typeof matchFpPropagation>> = [];
            try {
              // #1874: this import's rows are read only when there is a marker to match them against.
              const markers = await new FalsePositiveStore(store).load(caseId);
              if (markers.length) fpPropagation = matchFpPropagation(await settled.addedEvents(), markers);
            } catch {
              /* non-fatal — propagation is a suggestion, never blocks the import */
            }
            if (options.importMetaStore) {
              // Cap-hit truncation (#10 trigger b): consume the log-aggregation truncation the import
              // method stashed (log path only; null otherwise) and stamp it onto import-meta.
              const truncation = options.pipeline?.consumeImportTruncation?.(caseId) ?? null;
              await options.importMetaStore.record(caseId, {
                kind,
                file: storedName,
                diff: tDiff,
                superTimelineAddedCount,
                superTimelineEvicted,
                iocsDiff: iDiff,
                linesIn: text.split(/\r?\n/).length,
                ...cloudStream.importMeta(caseId, storedName),
                path: aiDependent ? "ai" : "deterministic",
                fpPropagation,
                truncation,
                aiExtraction: aiExtractionFromDebug(aiDependent ? "ai" : "deterministic", debug), // #2460
              });
              options.onImportMeta?.(caseId);
            }
            logImportActivity(options, caseId, `${kind} (${storedName})`, { timeline: tDiff, iocs: iDiff });
            if (
              tDiff.added.length ||
              tDiff.removed.length ||
              iDiff.added.length ||
              iDiff.removed.length ||
              settled.principalNamesChanged // #2490: names an Undo must be able to take back
            ) {
              await pushImportCheckpoint(caseId, baseline, `${kind} (${storedName})`);
            }
          } catch {
            /* non-fatal */
          }
        }
        await recordImportRun(ctx, {
          caseId,
          kind,
          storedName,
          startedAt: importedAt,
          baseline,
          minSeverity,
          assetHost: base.assetHost,
          path: aiDependent ? "ai" : "deterministic",
        });
        try {
          const wl = await applyWhitelistToCase(caseId);
          if (wl.added > 0)
            ctx.serverLogger.info(`[whitelist] ${caseId} auto-marked ${wl.added} imported IOC(s) legitimate`);
        } catch {
          /* non-fatal */
        }
        try {
          const ns = await applyNsrlToCase(caseId);
          if (ns.added > 0)
            ctx.serverLogger.info(
              `[nsrl] ${caseId} auto-marked ${ns.added} imported known-good item(s) legitimate`,
            );
        } catch {
          /* non-fatal */
        }
        try {
          const deob = await applyDeobfuscationToCase(caseId);
          if (deob.deobfuscated > 0)
            ctx.serverLogger.info(
              `[deobfuscate] ${caseId} decoded ${deob.deobfuscated} event(s), +${deob.newIocs} new IOC(s)`,
            );
        } catch {
          /* non-fatal */
        }
        if (job) await options.jobManager?.finish(job.jobId);
        resynthesizeInBackground(caseId);
      })
      .catch(async (err) => {
        if ((err as Error).name === "AbortError") {
          options.onAiStatus?.(caseId, {
            status: "idle",
            at: new Date().toISOString(),
            detail: "import processing cancelled; stored evidence retained",
          });
          if (job) await options.jobManager?.fail(job.jobId, err); // a case delete's abort: settles the job (#1831)
          return;
        }
        if (job) await options.jobManager?.fail(job.jobId, err, { code: "import_failed", retryable: true });
        recordImportFailure(caseId, kind, storedName, err, debug);
        recordAiError(caseId, "import", err);
        options.onAiStatus?.(caseId, {
          status: "error",
          at: new Date().toISOString(),
          detail: (err as Error).message,
        });
      })
      .finally(() => {
        // Unconditional: a section left held would wedge every later import for this case.
        section?.release();
        section = null;
      });
    return;
  } catch (err) {
    recordImportFailure(caseId, kind, originalName, err, debug);
    return sendPipelineError(res, err);
  }
}
