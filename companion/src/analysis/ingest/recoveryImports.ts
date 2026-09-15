import { parseBulkExtractorUrl, type BulkExtractorUrlOptions } from "../bulkExtractorUrlImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { resolveExtractedFrom } from "../siemImport.js";
import { type InvestigationState, type Severity } from "../stateTypes.js";
import { noteEmptyImport } from "./importState.js";
import type { ImportContext } from "./importContext.js";

/**
 * External carving/recovery-tool reports (#932 item 4): what a tool that already ran against an
 * image says it found, never a re-implementation of carving itself. `bulk_extractor`'s url.txt
 * feature file is the only format read so far; see RECOMMENDATION-4.md for the deliberately
 * deferred formats (email/domain/ip feature files, and any intact-file carving report).
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
