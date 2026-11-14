import { stateEventResolver } from "../../eventAliasLookup.js";
import type { ForensicEvent, InvestigationState } from "../../stateTypes.js";
import { loadScopedEvents, type AiCallContext } from "../aiContext.js";
import { promptDescription } from "../promptDescription.js";
import { describeLookup } from "./lookupSchema.js";
import type { WatsonLookedUp, WatsonLookup } from "./types.js";

// Watson's on-demand timeline lookup (Task 11). It selects from the SCOPED FORENSIC TIMELINE only —
// the same in-scope set the round's case packet is cut from (loadScopedEvents) — and never from the
// raw super-timeline record (CLAUDE.md §7; tests/analysis/forensicBoundary.test.ts). Rows render
// exactly as the packet's timeline rows do, and the whole prompt is masked by the same callAiJson.

export const WATSON_LOOKUP_MAX_EVENTS = 200;
export const WATSON_LOOKUP_MAX_CHARS = 20_000;
const NONE = "(no event matched the lookup)";

/** One forensic-timeline row as Watson's prompt shows it: the case packet and the lookup share it. */
export function timelineRow(e: ForensicEvent): string {
  return `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${promptDescription(e.description)}`;
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const shortHost = (h: string): string => {
  const low = h.trim().toLowerCase();
  return IPV4.test(low) ? low : low.split(".")[0];
};

/** The ids the lookup names: its event ids plus every event its findings cite, aliases followed. */
function namedIds(
  state: Pick<InvestigationState, "findings" | "eventAliases" | "forensicTimeline">,
  q: WatsonLookup,
): Set<string> | null {
  if (!q.findingIds && !q.eventIds) return null;
  const resolve = stateEventResolver(state);
  const wanted = new Set(q.findingIds ?? []);
  const cited = (state.findings ?? [])
    .filter((f) => wanted.has(f.id))
    .flatMap((f) => f.relatedEventIds ?? []);
  return new Set([...cited, ...(q.eventIds ?? [])].map(resolve));
}

function inWindow(e: ForensicEvent, q: WatsonLookup): boolean {
  if (!q.from || !q.to) return true;
  const t = Date.parse(e.timestamp);
  return Number.isFinite(t) && t >= Date.parse(q.from) && t <= Date.parse(q.to);
}

const onHost = (e: ForensicEvent, host: string | undefined): boolean =>
  !host || [e.asset, e.assetRecord].some((a) => !!a && shortHost(a) === shortHost(host));

function hasText(e: ForensicEvent, text: string | undefined): boolean {
  if (!text) return true;
  const needle = text.toLowerCase();
  return [e.description, e.asset, e.path, e.callerName].some((f) => !!f && f.toLowerCase().includes(needle));
}

const timeKey = (e: ForensicEvent): number => {
  const t = Date.parse(e.timestamp);
  return Number.isFinite(t) ? t : Number.POSITIVE_INFINITY; // undated last
};

/**
 * Every event of `scoped` the lookup matches, oldest first. `scoped` is the round's in-scope forensic
 * timeline; an id outside it (out of scope, marked false positive, or raw-only) is never returned.
 */
export function selectLookupEvents(
  scoped: readonly ForensicEvent[],
  state: Pick<InvestigationState, "findings" | "eventAliases" | "forensicTimeline">,
  q: WatsonLookup,
): ForensicEvent[] {
  const ids = namedIds(state, q);
  return scoped
    .filter((e) => (!ids || ids.has(e.id)) && inWindow(e, q) && onHost(e, q.host) && hasText(e, q.text))
    .sort((a, b) => timeKey(a) - timeKey(b) || a.id.localeCompare(b.id));
}

/** The lookup's rows: at most 200 and 20,000 characters, and a line saying when more matched. */
export function renderLookup(matches: readonly ForensicEvent[]): {
  text: string;
  shown: number;
  matched: number;
} {
  if (!matches.length) return { text: NONE, shown: 0, matched: 0 };
  const more = (n: number) => `(showing ${n} of ${matches.length} matching events — narrow the lookup)`;
  const reserve = more(matches.length).length + 1;
  const rows: string[] = [];
  let used = 0;
  for (const e of matches.slice(0, WATSON_LOOKUP_MAX_EVENTS)) {
    const row = timelineRow(e);
    if (used + row.length + 1 + reserve > WATSON_LOOKUP_MAX_CHARS) break;
    rows.push(row);
    used += row.length + 1;
  }
  const tail = rows.length < matches.length ? [more(rows.length)] : [];
  return { text: [...rows, ...tail].join("\n"), shown: rows.length, matched: matches.length };
}

/** What the prompt's TIMELINE LOOKUP block shows. */
export interface WatsonLookupExcerpt {
  what: string;
  text: string;
}

/** Run one lookup over the case's in-scope forensic timeline: the prompt block and the disclosure. */
export async function lookupTimeline(
  ctx: AiCallContext,
  caseId: string,
  state: InvestigationState,
  q: WatsonLookup,
): Promise<{ excerpt: WatsonLookupExcerpt; lookedUp: WatsonLookedUp }> {
  const { scoped } = await loadScopedEvents(ctx, caseId, state);
  const out = renderLookup(selectLookupEvents(scoped, state, q));
  const what = describeLookup(q);
  return { excerpt: { what, text: out.text }, lookedUp: { shown: out.shown, matched: out.matched, what } };
}
