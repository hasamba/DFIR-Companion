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
import { isLabProduced, PROMOTED_MARKER } from "../labIntel.js";

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
  },
): Promise<InvestigationState> {
  const parsedRaw = parsePlasoCsv(text, opts.plaso);
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
  },
): Promise<InvestigationState> {
  const rl = createInterface({
    input: createReadStream(filePath, { encoding: "utf8", highWaterMark: 1 << 20 }),
    crlfDelay: Infinity,
  });
  let parsedRaw: PlasoParseResult;
  try {
    parsedRaw = await parsePlasoFromLines(rl, opts.plaso);
  } finally {
    rl.close();
  }
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
export type PromotionIntent = "manual" | "explain" | "starred-report" | "second-look";

export async function promoteSuperTimeline(
  ctx: ImportContext,
  caseId: string,
  requested: ForensicEvent[],
  opts: { importedAt: string; intent: PromotionIntent; tagById?: Record<string, string[]>; note?: string },
): Promise<InvestigationState> {
  const events = requested
    .filter((e) => !(opts.intent === "second-look" && isLabProduced(e)))
    .map((e) => (isLabProduced(e) ? { ...e, origin: "lab" as const, severity: "Info" as const } : e));
  const marked: Record<string, string[]> = { ...(opts.tagById ?? {}) };
  if (opts.intent === "manual")
    for (const e of events) marked[e.id] = [...new Set([...(marked[e.id] ?? []), PROMOTED_MARKER])];
  return ctx.withStateLock(caseId, async () => {
    let state = await ctx.opts.stateStore.load(caseId);
    if (!events.length) return state;
    const delta = deltaSchema.parse({
      findings: [],
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: opts.note ?? `Promoted ${events.length} event(s) from the super-timeline`,
      summary: "",
      forensicEvents: events.map((e) => ({ ...e })),
    });
    state = await ctx.mergeWithAliases(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [],
    });
    // Stamp provenance markers on the promoted rows (second-look #11) — mergeDelta carries no
    // provenance through the delta schema, so apply them here by id (union with any existing). Lets the
    // forensic timeline show WHY a raw row was pulled up ("[second-look: h2]").
    if (Object.keys(marked).length) {
      const tagged = new Set(Object.keys(marked));
      state = {
        ...state,
        forensicTimeline: state.forensicTimeline.map((e) =>
          tagged.has(e.id)
            ? { ...e, provenance: [...new Set([...(e.provenance ?? []), ...marked[e.id]])] }
            : e,
        ),
      };
    }
    await ctx.opts.stateStore.save(state);
    ctx.opts.onState?.(state);
    return state;
  });
}
