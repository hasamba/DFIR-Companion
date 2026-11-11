import { stat } from "node:fs/promises";
import { join } from "node:path";
import type { InvestigationState } from "../analysis/stateTypes.js";
import { formatImportCancelled, formatImportMerged, formatImportStart } from "../logging/importLog.js";
import { isStreamKind, type StreamKind } from "../analysis/ingest/cloudStreamProviders.js";
import { CLOUD_STREAM_MIN_BYTES } from "../analysis/cloudStreamLimits.js";
import {
  describeCloudStreamDisclosure,
  type CloudStreamDisclosure,
} from "../analysis/cloudStreamDisclosure.js";
import { readTaggerSettings } from "../analysis/taggerRun.js";
import type { CompiledRuleset } from "../analysis/taggerRules.js";
import type { ImportBase, RouteContext } from "./context.js";
import { emitImportDebug } from "./importDebugEmit.js";
import { importPlasoFileLogged } from "./importPlasoStream.js";
import { routeSettleDeps, type SettleContext } from "./routeSettleDeps.js";

/**
 * The streamed cloud import seen from the routes (#2303). `/import-file`, `/import` and the job
 * resume handler decide here whether a stored upload streams, and run it through one function with
 * its log lines — the cloud twin of importPlasoFileLogged, which every streamed kind shares.
 *
 * A cloud upload streams when it is gzip (it cannot be decoded as one string at all) or at least
 * CLOUD_STREAM_MIN_BYTES; a smaller one keeps the whole-file path, whose output is unchanged. The
 * import's disclosure is kept per case until the route's import-meta write consumes it, so the
 * "last import" record carries the same sentences as the import note and the coverage panel.
 */

/** The refusal for a gzip upload of a kind that does not stream. */
export const GZIP_ONLY_CLOUD =
  "gzip uploads are read only for cloud audit exports (M365 / Entra, AWS CloudTrail, GCP / Azure Activity, AWS GuardDuty findings) — decompress the file and import it again";

/** Whether a stored upload of `kind` takes the streaming path. */
export function streamsCloudImport(kind: string, bytes: number, gzip: boolean): kind is StreamKind {
  return isStreamKind(kind) && (gzip || bytes >= CLOUD_STREAM_MIN_BYTES);
}

/** Whether `kind` reads from disk rather than from one string: Plaso always, a cloud kind when it streams. */
export function readsFromDisk(kind: string, bytes: number, gzip: boolean): boolean {
  return kind === "plaso" || streamsCloudImport(kind, bytes, gzip);
}

// Keyed by the import's stored file, never by case alone: a streamed import whose disclosure no
// route consumes (a resumed job) must not lend it to the next, unrelated import of the case (#1063).
const disclosures = new Map<string, CloudStreamDisclosure>();
const keyOf = (caseId: string, storedName: string): string => `${caseId}\n${storedName}`;

function stashDisclosure(caseId: string, storedName: string, d: CloudStreamDisclosure): void {
  for (const k of disclosures.keys()) if (k.startsWith(`${caseId}\n`)) disclosures.delete(k);
  disclosures.set(keyOf(caseId, storedName), d);
}

/** That import's disclosure, once; null when it did not stream. */
export function consumeCloudStreamDisclosure(
  caseId: string,
  storedName: string,
): CloudStreamDisclosure | null {
  const d = disclosures.get(keyOf(caseId, storedName)) ?? null;
  disclosures.delete(keyOf(caseId, storedName));
  return d;
}

/** The import-meta fields a streamed import supplies: its record count and its disclosure. */
export function streamedImportMeta(
  caseId: string,
  storedName: string,
): { linesIn?: number; streamDisclosure?: string[] } {
  const d = consumeCloudStreamDisclosure(caseId, storedName);
  return d ? { linesIn: d.records, streamDisclosure: describeCloudStreamDisclosure(d) } : {};
}

/** The tagger's ruleset when its severity rules may raise a forensic grade (TAGGER_AUTO on, scope not super-only). */
async function preGradeRules(ctx: SettleContext): Promise<CompiledRuleset | null> {
  const settings = readTaggerSettings();
  if (!settings.auto || settings.scope === "super" || !ctx.options.taggerStore) return null;
  try {
    return await ctx.options.taggerStore.load();
  } catch {
    return null; // an invalid hand-edited ruleset: the settle tagger skips it too
  }
}

async function importCloudFileLogged(
  ctx: SettleContext,
  caseId: string,
  kind: StreamKind,
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
  const settle = routeSettleDeps(ctx);
  try {
    const { state, disclosure } = await options.pipeline.importCloudFile(caseId, kind, storedPath, {
      label: base.label,
      idPrefix: base.idPrefix,
      importedAt: base.importedAt,
      minSeverity: base.minSeverity,
      debug: base.debug,
      signal: base.signal,
      ...(base.skipSummaries ? { skipSummaries: true } : {}),
      ...(base.coverageGroup ? { coverageGroup: base.coverageGroup } : {}),
      ...(base.cloudBatch ? { batch: base.cloudBatch } : {}), // a drop-folder batch (#2540)
      onProgress: (done, total) =>
        void (
          base.onParseProgress?.(done, total, `reading ${kind} records`) ?? base.onProgress?.(done, total)
        ),
      preGradeRules: await preGradeRules(ctx),
      onSuperRows:
        base.cloudBatch?.superRows ?? (settle ? (rows) => settle.autoTagImported(caseId, rows) : undefined),
    });
    stashDisclosure(caseId, storedName, disclosure);
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

/** Run a stored upload that reads from disk: a Plaso super-timeline, or a streamed cloud export. */
export function runDiskImport(
  ctx: SettleContext,
  kind: string,
  caseId: string,
  storedPath: string,
  storedName: string,
  base: ImportBase,
): Promise<InvestigationState> {
  return isStreamKind(kind)
    ? importCloudFileLogged(ctx, caseId, kind, storedPath, storedName, base)
    : importPlasoFileLogged(ctx, caseId, storedPath, storedName, base);
}

/**
 * `/import`'s run: the body text is already stored as the evidence file, so a large cloud export is
 * re-read from it in batches; anything else goes to the in-memory importer it always did.
 */
function runStored(
  ctx: RouteContext,
  a: { kind: string; caseId: string; storedName: string; text: string; base: ImportBase },
  dispatch: (kind: string, caseId: string, text: string, base: ImportBase) => Promise<unknown>,
): Promise<unknown> {
  if (!streamsCloudImport(a.kind, a.text.length, false)) return dispatch(a.kind, a.caseId, a.text, a.base);
  const storedPath = join(ctx.store.importsDir(a.caseId), a.storedName);
  return runDiskImport(ctx, a.kind, a.caseId, storedPath, a.storedName, a.base);
}

/** `/import-file`'s run for a kind that reads from disk: the stored evidence file is the input. */
function runStoredFile(
  ctx: RouteContext,
  a: { kind: string; caseId: string; storedName: string; base: ImportBase },
): Promise<InvestigationState> {
  const storedPath = join(ctx.store.importsDir(a.caseId), a.storedName);
  return runDiskImport(ctx, a.kind, a.caseId, storedPath, a.storedName, a.base);
}

/** One import name for routes/import.ts, which sits at its file-size ledger. */
export const cloudStream = {
  GZIP_ONLY_CLOUD,
  streams: streamsCloudImport,
  readsFromDisk,
  runStored,
  runStoredFile,
  importMeta: streamedImportMeta,
};
