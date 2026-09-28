import {
  parsePlasoCsv,
  parsePlasoFromLines,
  type PlasoImportOptions,
  type PlasoParseResult,
} from "../plasoImport.js";
import { deltaSchema } from "../responseSchema.js";

import { type ForensicEvent, type InvestigationState, type Severity } from "../stateTypes.js";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import { persistPlasoParsed } from "./importState.js";
import type { ImportContext } from "./importContext.js";
import type { ImportDebugRecorder } from "../importDebug.js";
import { applySeverityFloor } from "../severityFloor.js";
import { recordParsedImport } from "./parsedDebug.js";

// The Plaso decisions for the import debug record (#1736). persistPlasoParsed applies the floor
// itself (importState.ts); the same floor is applied here to count what it removes. Counts only.
function recordPlasoParse(
  debug: ImportDebugRecorder | undefined,
  parsed: PlasoParseResult,
  min?: Severity,
): void {
  if (!debug) return;
  const post = applySeverityFloor(parsed.events, min).length;
  recordParsedImport(debug, parsed, parsed.events.length, post);
}
import { isLabProduced, PROMOTED_MARKER } from "../labIntel.js";
import { stateEventResolver } from "../eventAliasLookup.js";
import { promotionOutcome, type PromotionOutcome } from "./promotionOutcome.js";

/**
 * Whole-timeline sources. Plaso arrives already normalised into timeline rows, and
 * promoteSuperTimeline moves rows that are ALREADY in the case from the raw record into the
 * forensic timeline — the promotion seam the forensic/super-timeline boundary is built on.
 *
 * Moved from AnalysisPipeline (#384). Each of these was a method; each is now a free function
 * taking an ImportContext, which is the small set of collaborators an importer is allowed to use.
 * The pipeline keeps a one-line delegation per importer, so callers are unchanged.
 */

// Import a Plaso / log2timeline super-timeline (psort CSV — dynamic or l2tcsv). Deterministic
// (no AI call): each row is an Info evidence event read at its own time, with IOCs scraped
// from the message (hashes/URLs/IPs) and the source file path. Tagged Plaso.
export async function importPlaso(
  ctx: ImportContext,
  caseId: string,
  text: string,
  opts: {
    label: string;
    idPrefix: string; // unique per import (e.g. "p3") so ids never collide
    importedAt: string;
    plaso?: PlasoImportOptions;
    minSeverity?: Severity; // gate-aware import floor (unified Import button) — see applySeverityFloor
    onProgress?: (done: number, total: number) => void;
    debug?: ImportDebugRecorder; // this attempt's decision recorder (#1736)
  },
): Promise<InvestigationState> {
  const parsedRaw = parsePlasoCsv(text, { ...opts.plaso, debug: opts.debug });
  recordPlasoParse(opts.debug, parsedRaw, opts.minSeverity);
  return persistPlasoParsed(ctx, caseId, parsedRaw, opts);
}

// Streaming-from-disk Plaso import: for super-timelines too large to hold as one JS string (a
// 555 MB export EXCEEDS V8's ~512 MB max string length, so readFile(utf8) throws "Invalid string
// length"). Reads the file line-by-line via node:readline and feeds parsePlasoFromLines, which
// keeps memory bounded by the distinct-key set, not the row count. Same downstream merge as
// importPlaso. The route persists the evidence file separately (by copy, not as a string).
export async function importPlasoFile(
  ctx: ImportContext,
  caseId: string,
  filePath: string,
  opts: {
    label: string;
    idPrefix: string;
    importedAt: string;
    plaso?: PlasoImportOptions;
    minSeverity?: Severity;
    onProgress?: (done: number, total: number) => void;
    debug?: ImportDebugRecorder; // this attempt's decision recorder (#1736)
  },
): Promise<InvestigationState> {
  const rl = createInterface({
    input: createReadStream(filePath, { encoding: "utf8", highWaterMark: 1 << 20 }),
    crlfDelay: Infinity,
  });
  let parsedRaw: PlasoParseResult;
  try {
    parsedRaw = await parsePlasoFromLines(rl, { ...opts.plaso, debug: opts.debug });
  } finally {
    rl.close();
  }
  recordPlasoParse(opts.debug, parsedRaw, opts.minSeverity);
  return persistPlasoParsed(ctx, caseId, parsedRaw, opts);
}

// "Promote" copies already-imported super-timeline events UP into the forensic timeline so AI
// synthesis runs over them. The raw super-timeline is a complete record (incl. host-triage artifacts
// routed there exclusively) that is never synthesized; this is how the analyst pulls the events that
// matter into the analyzed timeline. Reuses mergeDelta (dedups forensic events by id) — a stored super
// event keeps its id, so a double-promote is a no-op. No AI here; the caller re-synthesizes.
// Who is promoting, and therefore what a lab row is allowed to become (#932 item 5 part B). Four
// callers share this function; "manually promoted" had no executable meaning until this enum.
//   manual      — the analyst chose these rows in the super-timeline. A lab row is normalised
//                 (origin lab, Info) and stamped PROMOTED_MARKER: their decision is respected and
//                 remembered.
//   explain     — "explain this event" on a raw row promotes it so it can be explained. Incidental:
//                 normalised, NOT marked. It stays a pending lab row.
//   starred-report — a report over the rows the analyst starred promotes them first (§7: the model
//                 reads the forensic timeline, never the raw record). Same as explain: the analyst
//                 asked for a report, not for a lab row to become incident evidence.
//   second-look — the automated loop. A lab row is REFUSED here outright, marker or not: the loop
//                 must never move sandbox behaviour into the incident chronology on its own.
//   missed-evidence — the analyst ticked rows in the missed-evidence review (#1568), and each row
//                 arrives carrying a severity a MODEL chose. A lab row is REFUSED, like the loop's:
//                 the analyst picked the row, but not the grade, and a model's Medium on sandbox
//                 behaviour is exactly the write that refusal exists to stop.
// `remediation-check` (#969): a super-timeline row attached as evidence to a remediation boundary
// enters the case by promotion like any analyst promotion, and is marked like a manual one.
export type PromotionIntent =
  "manual" | "explain" | "starred-report" | "second-look" | "remediation-check" | "missed-evidence";

/** The intents for which a sandbox-produced row is DROPPED rather than normalised. See above. */
const LAB_REFUSING_INTENTS: ReadonlySet<PromotionIntent> = new Set<PromotionIntent>([
  "second-look",
  "missed-evidence",
]);

/**
 * The intents that may only ADD a row the forensic timeline does not hold under any id (#1761). A
 * missed-evidence row is by definition absent from it, so one that is there is DROPPED here:
 *   - under its own id: mergeDelta treats a same-id row as an update and overwrites the event's text
 *     and severity, so a stale archive row would restate the event at the model's grade — lower, too,
 *     since "raise only" was judged against the archive row, not the event;
 *   - under another id, through the case lineage (#1715) — a second tool's copy of the event: it
 *     folds away, or, graded above that event, takes the event's place.
 * The route checks both, but against the state it read before its grade and archive lookups. This
 * runs under the state lock, on the state the merge will use, so an import in between changes nothing.
 */
const NEW_ROWS_ONLY_INTENTS: ReadonlySet<PromotionIntent> = new Set<PromotionIntent>(["missed-evidence"]);

export interface PromotionOptions {
  importedAt: string;
  intent: PromotionIntent;
  tagById?: Record<string, string[]>;
  /**
   * The case timeline note. A string is written as given. A function is called after the merge with
   * what the promotion did, so a count in it is what landed rather than what was asked for (#1761);
   * an empty answer writes no note.
   */
  note?: string | ((outcome: PromotionOutcome) => string);
}

export async function promoteSuperTimeline(
  ctx: ImportContext,
  caseId: string,
  requested: ForensicEvent[],
  opts: PromotionOptions,
): Promise<InvestigationState> {
  return (await promoteSuperTimelineWithOutcome(ctx, caseId, requested, opts)).state;
}

/** promoteSuperTimeline, plus what it did to each requested row (#1761, promotionOutcome.ts). */
export async function promoteSuperTimelineWithOutcome(
  ctx: ImportContext,
  caseId: string,
  requested: ForensicEvent[],
  opts: PromotionOptions,
): Promise<{ state: InvestigationState; outcome: PromotionOutcome }> {
  const requestedIds = requested.map((e) => e.id);
  const events = requested
    .filter((e) => !(LAB_REFUSING_INTENTS.has(opts.intent) && isLabProduced(e)))
    .map((e) => (isLabProduced(e) ? { ...e, origin: "lab" as const, severity: "Info" as const } : e));
  const marked: Record<string, string[]> = { ...(opts.tagById ?? {}) };
  if (opts.intent === "manual" || opts.intent === "remediation-check")
    for (const e of events) marked[e.id] = [...new Set([...(marked[e.id] ?? []), PROMOTED_MARKER])];
  return ctx.withStateLock(caseId, async () => {
    const before = await ctx.opts.stateStore.load(caseId);
    const live = new Set(before.forensicTimeline.map((e) => e.id));
    const canonical = stateEventResolver(before);
    const toMerge = NEW_ROWS_ONLY_INTENTS.has(opts.intent)
      ? events.filter((e) => !live.has(canonical(e.id)))
      : events;
    if (!toMerge.length) return { state: before, outcome: promotionOutcome(before, before, requestedIds) };
    const delta = deltaSchema.parse({
      findings: [],
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      // A function note waits for the outcome below; mergeDelta writes no entry for an empty note.
      timelineNote:
        typeof opts.note === "function"
          ? ""
          : (opts.note ?? `Promoted ${toMerge.length} event(s) from the super-timeline`),
      summary: "",
      forensicEvents: toMerge.map((e) => ({ ...e })),
    });
    const merged = await ctx.mergeWithAliases(before, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [],
    });
    const stamped = stampPromoted(merged, toMerge, marked, opts.importedAt);
    const outcome = promotionOutcome(before, stamped, requestedIds);
    const state = withOutcomeNote(stamped, opts, outcome);
    await ctx.opts.stateStore.save(state);
    ctx.opts.onState?.(state);
    return { state, outcome };
  });
}

function stampPromoted(
  merged: InvestigationState,
  events: readonly ForensicEvent[],
  marked: Record<string, string[]>,
  importedAt: string,
): InvestigationState {
  // Stamp promotedAt so the forensic gate keeps these rows past the next demote pass (#1432).
  // The delta schema strips unknown keys, so the stamp cannot ride through mergeWithAliases;
  // apply it by id afterwards, like the provenance markers below. An earlier stamp is kept.
  const promotedIds = new Set(events.map((e) => e.id));
  let state: InvestigationState = {
    ...merged,
    forensicTimeline: merged.forensicTimeline.map((e) =>
      promotedIds.has(e.id) && !e.promotedAt ? { ...e, promotedAt: importedAt } : e,
    ),
  };
  // Stamp provenance markers on the promoted rows (second-look #11) — mergeDelta carries no
  // provenance through the delta schema, so apply them here by id (union with any existing). Lets the
  // forensic timeline show WHY a raw row was pulled up ("[second-look: h2]").
  if (Object.keys(marked).length) {
    const tagged = new Set(Object.keys(marked));
    state = {
      ...state,
      forensicTimeline: state.forensicTimeline.map((e) =>
        tagged.has(e.id) ? { ...e, provenance: [...new Set([...(e.provenance ?? []), ...marked[e.id]])] } : e,
      ),
    };
  }
  return state;
}

/** The entry mergeDelta would have pushed for this promotion's ctx, written once the outcome is known. */
function withOutcomeNote(
  state: InvestigationState,
  opts: PromotionOptions,
  outcome: PromotionOutcome,
): InvestigationState {
  if (typeof opts.note !== "function") return state;
  const description = opts.note(outcome).trim();
  if (!description) return state;
  return {
    ...state,
    timeline: [
      ...state.timeline,
      { timestamp: opts.importedAt, windowSequence: -1, description, sourceScreenshots: [] },
    ],
  };
}
