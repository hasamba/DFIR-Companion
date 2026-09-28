import { resolveCitedEventId, type AnalysisDelta } from "../responseSchema.js";

/**
 * AI findings that cite no event (#1754).
 *
 * On INC-2026-022 one Opus synthesis stored 13 findings and left relatedEventIds empty on every one.
 * The High backfill reads coverage from those links only, so it raised 82 auto findings — some on rows
 * a dismissed finding had just called sample data. The model did name ids, but in its prose: f12
 * named 29e20, 29e21 and 29e33, and f10 named 4e378 and 12e54. The app dropped nothing; the model's
 * structured field was empty.
 *
 * Three pure helpers, used by the synthesis call and the fold:
 * - `uncitedFindingIds` / `needsCitationRetry`: which findings cite nothing, and whether that is
 *   bad enough to ask the model once more (synthesisCall.ts).
 * - `recoverProseCitations`: an uncited finding gets the ids its own text names, when the prompt
 *   printed them. Conservative on purpose — a link to a dismissed finding silences the backfill for
 *   that row, so a sentence that contrasts or negates the event gives no id.
 * - `citationRunWarnings`: what the run record says, so "completed, no warnings" is not the record
 *   of a run whose findings cite nothing.
 */

/** Below this many uncited findings the answer is not retried: a lone negative finding cites nothing. */
const MIN_UNCITED_FOR_RETRY = 2;

// A sentence that sets an event apart from the finding ("unlike 29e20", "29e21 does not support
// this", "…, but 12e54 is not") is not a citation of it. Case-insensitive, whole words.
const CONTRAST =
  /\b(?:unlike|not|no|never|except|excluding|whereas|however|but|rather|instead|unrelated)\b|n't\b/i;

// A sentence ends at . ! ? ; followed by space, or at a line break. A dot inside a file name
// (shadow.bat) is not followed by space, so it does not split.
const SENTENCE_END = /(?<=[.!?;])\s+|\n+/;

// Characters an event id is built from. An id is read only where neither neighbour is one of these,
// so 4e37 is never read inside 4e378.
const ID_CHAR = "A-Za-z0-9_\\-";

const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function citesKnownEvent(ids: readonly string[] | undefined, known: ReadonlySet<string>): boolean {
  return (ids ?? []).some((id) => known.has(resolveCitedEventId(id, known)));
}

/** Ids of the findings with no citation that resolves to a known event, in answer order. */
export function uncitedFindingIds(delta: AnalysisDelta, known: ReadonlySet<string>): string[] {
  return delta.findings.filter((f) => !citesKnownEvent(f.relatedEventIds, known)).map((f) => f.id);
}

/** True when most findings cite nothing — a structural omission worth one more model call. */
export function needsCitationRetry(uncited: number, total: number): boolean {
  return uncited >= MIN_UNCITED_FOR_RETRY && uncited * 2 > total;
}

function idsNamedIn(text: string, literalIds: ReadonlySet<string>): string[] {
  const found: string[] = [];
  for (const sentence of text.split(SENTENCE_END)) {
    if (!sentence || CONTRAST.test(sentence)) continue;
    const hits: Array<{ id: string; at: number }> = [];
    for (const id of literalIds) {
      if (!sentence.includes(id)) continue;
      const m = new RegExp(`(?<![${ID_CHAR}])${escapeRegExp(id)}(?![${ID_CHAR}])`).exec(sentence);
      if (m) hits.push({ id, at: m.index });
    }
    hits.sort((a, b) => a.at - b.at);
    for (const h of hits) if (!found.includes(h.id)) found.push(h.id);
  }
  return found;
}

export interface ProseRecovery {
  delta: AnalysisDelta;
  recovered: Array<{ findingId: string; eventIds: string[] }>;
}

/**
 * Give each finding that cites no `known` event the ids its title and description name, taken from
 * `literalIds` only — the rows the prompt printed on their own line. A grouped member the model never
 * saw by id is reached, as before, through the representative (groupedCitation.ts). A finding that
 * already cites a known event is never widened. Returns the same delta when nothing is recovered.
 */
export function recoverProseCitations(
  delta: AnalysisDelta,
  literalIds: ReadonlySet<string>,
  known: ReadonlySet<string>,
): ProseRecovery {
  const recovered: ProseRecovery["recovered"] = [];
  const findings = delta.findings.map((f) => {
    if (citesKnownEvent(f.relatedEventIds, known)) return f;
    const eventIds = idsNamedIn(`${f.title}\n${f.description}`, literalIds).filter((id) => known.has(id));
    if (!eventIds.length) return f;
    recovered.push({ findingId: f.id, eventIds });
    return { ...f, relatedEventIds: eventIds };
  });
  return recovered.length ? { delta: { ...delta, findings }, recovered } : { delta, recovered };
}

export interface CitationCounts {
  uncited: number;
  total: number;
  /** Set when the citation retry ran: the first answer's counts. */
  retriedAfter?: { uncited: number; total: number };
}

/** The run-record warnings for findings that cite no event. Empty for a fully cited run. */
export function citationRunWarnings(c: CitationCounts): string[] {
  return [
    ...(c.retriedAfter
      ? [
          `citation retry ran: the first answer left ${c.retriedAfter.uncited} of ${c.retriedAfter.total} AI finding(s) with no cited event`,
        ]
      : []),
    ...(c.total > 0 && c.uncited > 0
      ? [
          `${c.uncited} of ${c.total} AI finding(s) cite no event, so the High backfill cannot tell which rows they cover`,
        ]
      : []),
  ];
}
