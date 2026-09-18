import { parseBulkExtractorUrl, type BulkExtractorUrlOptions } from "../bulkExtractorUrlImport.js";
import { parseBulkExtractorCarved, type BulkExtractorCarvedOptions } from "../bulkExtractorCarvedImport.js";
import { parseSqliteRowStateCsv, type SqliteRowStateOptions } from "../sqliteRowStateImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { resolveExtractedFrom } from "../siemImport.js";
import { type InvestigationState, type Severity } from "../stateTypes.js";
import { noteEmptyImport } from "./importState.js";
import type { ImportContext } from "./importContext.js";

/**
 * External carving/recovery-tool reports (#932 items 4, 8): what a tool that already ran against
 * an image says it found, never a re-implementation of carving itself. `bulk_extractor`'s url.txt
 * feature file, its carved-object feature files (#1116) and sqlite-dissect's per-table
 * commit-history CSV are the formats read so far; see RECOMMENDATION-4.md / RECOMMENDATION-8.md /
 * RECOMMENDATION-1116.md for the deliberately deferred formats.
 */

// Import a bulk_extractor url.txt feature file. Deterministic (no AI call).
export async function importBulkExtractorUrl(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    bulkExtractorUrl?: BulkExtractorUrlOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseBulkExtractorUrl(text, opts.bulkExtractorUrl);
  if (!parsedRaw) throw new Error("not a bulk_extractor url.txt feature file");
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) {
    const gapDetail = [
      parsed.malformedRows ? `${parsed.malformedRows} malformed row(s)` : "",
      parsed.notCitedValues ? `${parsed.notCitedValues} distinct value(s) over the per-upload cap` : "",
      parsed.truncatedScan ? "row scan stopped at the upload size cap" : "",
    ]
      .filter(Boolean)
      .join(", ");
    return noteEmptyImport(ctx, caseId, opts, "bulk_extractor url.txt", parsed.total, gapDetail || undefined);
  }

  const eventIdByAggKey = new Map<string, string>();
  const forensicEvents = parsed.events.map((e, i) => {
    const { aggKey, ...rest } = e;
    const id = `${opts.idPrefix}e${i + 1}`;
    if (aggKey) eventIdByAggKey.set(aggKey, id);
    return { ...rest, id, sources: rest.sources?.length ? rest.sources : ["bulk_extractor"] };
  });

  const raw = {
    findings: [],
    iocs: resolveExtractedFrom(parsed.iocs, eventIdByAggKey).map((c, i) => ({
      id: `${opts.idPrefix}i${i + 1}`,
      type: c.type,
      value: c.value,
      ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
    })),
    mitreTechniques: [],
    forensicEvents,
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `bulk_extractor url.txt import: ${parsed.kept} recovered URL fragment(s) from ${parsed.total} row(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      (parsed.malformedRows ? `, ${parsed.malformedRows} malformed row(s)` : "") +
      (parsed.notCitedValues
        ? `, ${parsed.notCitedValues} distinct value(s) beyond the per-upload cap`
        : "") +
      (parsed.truncatedScan ? ", row scan stopped at the upload size cap" : "") +
      `, ${parsed.iocs.length} IOC(s)`,
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return ctx.withStateLock(caseId, async () => {
    let state = await ctx.opts.stateStore.load(caseId);
    state = await ctx.mergeWithAliases(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await ctx.opts.stateStore.save(state);
    ctx.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  });
}

// Import a bulk_extractor carved-object feature file (jpeg.txt, zip_carved.txt, winpe_carved.txt,
// ntfs*_carved.txt, …). Deterministic (no AI call). The intact-file half of #932 item 4 (#1116).
export async function importBulkExtractorCarved(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    bulkExtractorCarved?: BulkExtractorCarvedOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseBulkExtractorCarved(text, opts.bulkExtractorCarved);
  if (!parsedRaw) throw new Error("not a bulk_extractor carved-object feature file");
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) {
    const gapDetail = [
      parsed.malformedRows ? `${parsed.malformedRows} malformed row(s)` : "",
      parsed.notCitedValues ? `${parsed.notCitedValues} distinct digest(s) over the per-upload cap` : "",
      parsed.truncatedScan ? "row scan stopped at the upload size cap" : "",
    ]
      .filter(Boolean)
      .join(", ");
    return noteEmptyImport(
      ctx,
      caseId,
      opts,
      `bulk_extractor ${parsed.recorder} carved objects`,
      parsed.total,
      gapDetail || undefined,
    );
  }

  const eventIdByAggKey = new Map<string, string>();
  const forensicEvents = parsed.events.map((e, i) => {
    const { aggKey, ...rest } = e;
    const id = `${opts.idPrefix}e${i + 1}`;
    if (aggKey) eventIdByAggKey.set(aggKey, id);
    return { ...rest, id, sources: rest.sources?.length ? rest.sources : ["bulk_extractor"] };
  });

  const raw = {
    findings: [],
    iocs: resolveExtractedFrom(parsed.iocs, eventIdByAggKey).map((c, i) => ({
      id: `${opts.idPrefix}i${i + 1}`,
      type: c.type,
      value: c.value,
      ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
    })),
    mitreTechniques: [],
    forensicEvents,
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `bulk_extractor ${parsed.recorder} carved-object import: ${parsed.kept} carved file(s) from ${parsed.total} row(s)` +
      (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
      (parsed.malformedRows ? `, ${parsed.malformedRows} malformed row(s)` : "") +
      (parsed.notCitedValues
        ? `, ${parsed.notCitedValues} distinct digest(s) beyond the per-upload cap`
        : "") +
      (parsed.unpromotedValues
        ? `, ${parsed.unpromotedValues} digest(s) kept but not promoted to an IOC`
        : "") +
      (parsed.truncatedScan ? ", row scan stopped at the upload size cap" : "") +
      `, ${parsed.iocs.length} hash IOC(s)`,
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return ctx.withStateLock(caseId, async () => {
    let state = await ctx.opts.stateStore.load(caseId);
    state = await ctx.mergeWithAliases(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await ctx.opts.stateStore.save(state);
    ctx.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  });
}

// Import sqlite-dissect's per-table commit-history CSV (Added/Updated/Deleted/Carved row
// operations). Deterministic (no AI call).
export async function importSqliteRowState(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    sqliteRowState?: SqliteRowStateOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseSqliteRowStateCsv(text, { ...opts.sqliteRowState, sourceLabel: opts.label });
  if (!parsedRaw) throw new Error("not a sqlite-dissect commit-history CSV");
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) {
    const gapDetail = [
      parsed.malformedRows ? `${parsed.malformedRows} malformed row(s)` : "",
      parsed.rowsTruncated ? "row scan stopped at the upload size cap" : "",
      parsed.tableNameSource === "unavailable" ? "table name could not be derived from the filename" : "",
    ]
      .filter(Boolean)
      .join(", ");
    return noteEmptyImport(
      ctx,
      caseId,
      opts,
      "sqlite-dissect row state",
      parsed.total,
      gapDetail || undefined,
    );
  }

  const eventIdByAggKey = new Map<string, string>();
  const forensicEvents = parsed.events.map((e, i) => {
    const { aggKey, ...rest } = e;
    const id = `${opts.idPrefix}e${i + 1}`;
    if (aggKey) eventIdByAggKey.set(aggKey, id);
    return { ...rest, id, sources: rest.sources?.length ? rest.sources : ["sqlite-dissect"] };
  });

  const raw = {
    findings: [],
    iocs: resolveExtractedFrom(parsed.iocs, eventIdByAggKey).map((c, i) => ({
      id: `${opts.idPrefix}i${i + 1}`,
      type: c.type,
      value: c.value,
      ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
    })),
    mitreTechniques: [],
    forensicEvents,
    threadsOpened: [],
    threadsClosed: [],
    timelineNote:
      `sqlite-dissect row-state import: ${parsed.kept} row(s) from ${parsed.total} scanned` +
      (parsed.malformedRows ? `, ${parsed.malformedRows} malformed row(s)` : "") +
      (parsed.rowsTruncated ? ", row scan stopped at the upload size cap" : "") +
      (parsed.tableNameSource === "unavailable" ? ", table name could not be derived from the filename" : ""),
    summary: "",
  };
  const delta = deltaSchema.parse(raw);

  return ctx.withStateLock(caseId, async () => {
    let state = await ctx.opts.stateStore.load(caseId);
    state = await ctx.mergeWithAliases(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await ctx.opts.stateStore.save(state);
    ctx.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  });
}
