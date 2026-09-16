import { parseMacFsEventTsv, type MacFsEventOptions } from "../macFsEventImport.js";
import { parseMacSpotlightUsageCsv, type MacSpotlightUsageOptions } from "../macSpotlightUsageImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { resolveExtractedFrom } from "../siemImport.js";
import { type InvestigationState, type Severity } from "../stateTypes.js";
import { noteEmptyImport } from "./importState.js";
import type { ImportContext } from "./importContext.js";

/**
 * macOS file-activity corroboration importers (#933 items 9, 10): FSEventsParser's own
 * All_FSEVENTS.tsv and mac_apt's own Spotlight store-item CSV, both consumed as the shaped output
 * of a named real tool, never a re-implementation of the underlying binary format. See
 * RECOMMENDATION-11.md for the full research trail.
 */

// Import FSEventsParser's All_FSEVENTS.tsv. Deterministic (no AI call).
export async function importMacFsEvent(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    macFsEvent?: MacFsEventOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseMacFsEventTsv(text, opts.macFsEvent);
  if (!parsedRaw) throw new Error("not an FSEventsParser All_FSEVENTS.tsv report");
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) {
    const gapDetail = [
      parsed.malformedRows ? `${parsed.malformedRows} malformed row(s)` : "",
      parsed.rowsTruncated ? "row scan stopped at the upload size cap" : "",
    ]
      .filter(Boolean)
      .join(", ");
    return noteEmptyImport(ctx, caseId, opts, "FSEvents", parsed.total, gapDetail || undefined);
  }

  const eventIdByAggKey = new Map<string, string>();
  const forensicEvents = parsed.events.map((e, i) => {
    const { aggKey, ...rest } = e;
    const id = `${opts.idPrefix}e${i + 1}`;
    if (aggKey) eventIdByAggKey.set(aggKey, id);
    return { ...rest, id, sources: rest.sources?.length ? rest.sources : ["fseventsparser"] };
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
      `FSEvents import: ${parsed.kept} record(s) from ${parsed.total} scanned` +
      (parsed.malformedRows ? `, ${parsed.malformedRows} malformed row(s)` : "") +
      (parsed.rowsTruncated ? ", row scan stopped at the upload size cap" : ""),
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

// Import mac_apt's Spotlight store-item CSV, filtered to usage/download-bearing rows.
// Deterministic (no AI call).
export async function importMacSpotlightUsage(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    macSpotlightUsage?: MacSpotlightUsageOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseMacSpotlightUsageCsv(text, { ...opts.macSpotlightUsage, sourceLabel: opts.label });
  if (!parsedRaw) throw new Error("not a mac_apt Spotlight store-item CSV");
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) {
    const gapDetail = [
      parsed.malformedRows ? `${parsed.malformedRows} malformed row(s)` : "",
      parsed.filteredNoSignalRows
        ? `${parsed.filteredNoSignalRows} row(s) with no usage/download signal`
        : "",
      parsed.rowsTruncated ? "row scan stopped at the upload size cap" : "",
    ]
      .filter(Boolean)
      .join(", ");
    return noteEmptyImport(ctx, caseId, opts, "Spotlight usage", parsed.total, gapDetail || undefined);
  }

  const eventIdByAggKey = new Map<string, string>();
  const forensicEvents = parsed.events.map((e, i) => {
    const { aggKey, ...rest } = e;
    const id = `${opts.idPrefix}e${i + 1}`;
    if (aggKey) eventIdByAggKey.set(aggKey, id);
    return { ...rest, id, sources: rest.sources?.length ? rest.sources : ["mac_apt-spotlight"] };
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
      `Spotlight usage import: ${parsed.kept} item(s) from ${parsed.total} scanned` +
      (parsed.malformedRows ? `, ${parsed.malformedRows} malformed row(s)` : "") +
      (parsed.filteredNoSignalRows
        ? `, ${parsed.filteredNoSignalRows} row(s) with no usage/download signal`
        : "") +
      (parsed.rowsTruncated ? ", row scan stopped at the upload size cap" : ""),
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
