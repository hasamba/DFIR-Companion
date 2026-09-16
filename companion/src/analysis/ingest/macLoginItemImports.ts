import { parseMacLoginItemBtm, type MacLoginItemOptions } from "../macLoginItemImport.js";
import { deltaSchema } from "../responseSchema.js";
import { applySeverityFloor } from "../severityFloor.js";
import { resolveExtractedFrom } from "../siemImport.js";
import { type InvestigationState, type Severity } from "../stateTypes.js";
import { noteEmptyImport } from "./importState.js";
import type { ImportContext } from "./importContext.js";

/**
 * macOS Background Task Management login-item parser (#933 item 8, importer half, #1013). Byte-
 * native — takes `bytes: Buffer`, never `text: string` (a binary keyed-archive bplist corrupts if
 * read as text) — so this is NOT dispatched through composition/importIngest.ts's text-based
 * `dispatchImport`; routes/importMacLoginItem.ts calls it directly, the same way the Plaso
 * streaming path bypasses the generic text dispatch for its own different reason.
 */
export async function importMacLoginItem(
  ctx: ImportContext,
  caseId: string,
  bytes: Buffer,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    macLoginItem?: MacLoginItemOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<InvestigationState> {
  const parsedRaw = parseMacLoginItemBtm(bytes, opts.macLoginItem);
  if (!parsedRaw) throw new Error("not a recognized macOS Background Task Management file");
  const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
  if (parsed.events.length === 0) {
    const gapDetail = parsed.malformedItems ? `${parsed.malformedItems} malformed item(s)` : undefined;
    return noteEmptyImport(ctx, caseId, opts, "macOS login item", parsed.total, gapDetail);
  }

  const eventIdByAggKey = new Map<string, string>();
  const forensicEvents = parsed.events.map((e, i) => {
    const { aggKey, ...rest } = e;
    const id = `${opts.idPrefix}e${i + 1}`;
    if (aggKey) eventIdByAggKey.set(aggKey, id);
    return { ...rest, id, sources: rest.sources?.length ? rest.sources : ["bookmark-decoder"] };
  });

  const raw = {
    findings: [],
    iocs: resolveExtractedFrom([], eventIdByAggKey).map((c, i) => ({
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
      `macOS login item import (${parsed.sourceFormat}): ${parsed.kept} item(s) from ${parsed.total} scanned` +
      (parsed.malformedItems ? `, ${parsed.malformedItems} malformed item(s)` : ""),
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
