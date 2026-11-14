import { stateEventResolver } from "../../eventAliasLookup.js";
import { filterFalsePositiveEvents } from "../../falsePositive.js";
import { canonicalHostName, resolveHost, type HostAliasIndex } from "../../hostAlias.js";
import { filterEventsByScope } from "../../scope.js";
import { eventMatchesSearch } from "../../searchFilter.js";
import type { ForensicEvent, InvestigationState } from "../../stateTypes.js";
import type { SuperQuery } from "../../superTimeline.js";
import type { SuperTimelineMeta } from "../../superTimelineStore.js";
import { loadCtxAliasIndex, loadScopedEvents, type AiCallContext } from "../aiContext.js";
import { promptDescription } from "../promptDescription.js";
import type { WriterDeps } from "./writers/writerTypes.js";
import { describeLookup } from "./lookupSchema.js";
import { rosterOf, type WatsonMaskRoster } from "./superRoster.js";
import { sameHost } from "./timelineLookup.js";
import type { WatsonLookedUp, WatsonLookup } from "./types.js";

export type { WatsonMaskRoster } from "./superRoster.js";

// Watson's targeted search of the analyst-only super-timeline (phase 4). This is the ONE AI-facing
// door to the raw record besides the analyst's own buttons (CLAUDE.md §7): synthesis and the deep
// pass never come here. It is bounded twice — every store query stops at WATSON_SUPER_SCAN_ROWS
// matches, and at most WATSON_SUPER_MAX_ROWS rows / WATSON_SUPER_MAX_CHARS characters reach the
// model. The case's rules hold: out-of-scope rows, false positives and rows already in the forensic
// timeline never come back. Every predicate Watson gave is re-checked on every row shown.

export const WATSON_SUPER_MAX_ROWS = 100;
export const WATSON_SUPER_MAX_CHARS = 20_000;
export const WATSON_SUPER_SCAN_ROWS = 5_000;
const MAX_HOST_TERMS = 5;
const FIELD_MAX = 300;
const NONE = "(no super-timeline row matched the search)";
const fmt = (n: number): string => n.toLocaleString("en-US");
const STOPPED = `the search stopped counting at ${fmt(WATSON_SUPER_SCAN_ROWS)} matches — `;

/** The two store reads Watson may make. SuperTimelineStore satisfies it. */
export interface WatsonRawReader {
  query(
    caseId: string,
    q: SuperQuery,
  ): Promise<{ events: ForensicEvent[]; total: number; totalIsLowerBound?: boolean }>;
  meta(caseId: string): Promise<Pick<SuperTimelineMeta, "evictedTotal">>;
}

/** Route-built (D12): the reader, the writer deps the promotion uses, and the frozen/AI-off guard (D6c). */
export interface WatsonRawSearchDeps {
  reader: WatsonRawReader;
  writer: WriterDeps;
  writable(caseId: string): Promise<boolean>;
}

// JS `\s` misses NEL (U+0085) and the C0 separators U+001C-U+001E, which some readers break lines on.
const VERTICAL_OR_SPACE = /[\s\u0085\u001c-\u001e]+/g;

/** One field value on one line, bounded: a hostile value can neither forge a row nor crowd others out. */
function flat(v: string | undefined): string {
  if (!v) return "";
  const one = v.replace(VERTICAL_OR_SPACE, " ").trim();
  return one.length > FIELD_MAX ? `${one.slice(0, FIELD_MAX - 1)}…` : one;
}

const accountOf = (e: ForensicEvent): string | undefined => e.canonical?.account?.name ?? e.callerName;

/** One super-timeline row as Watson's prompt shows it: the fields a hash or path hit lives in. */
export function superRow(e: ForensicEvent): string {
  const fields = [
    ["host", e.asset],
    ["path", e.path],
    ["sha256", e.sha256],
    ["md5", e.md5],
    ["user", accountOf(e)],
    ["src", e.srcIp],
    ["dst", e.dstIp],
    ["cmd", e.commandLine],
  ]
    .map(([k, v]) => [k, flat(v)])
    .filter(([, v]) => v)
    .map(([k, v]) => `${k}=${v}`);
  const lead = `[${flat(e.id)}] ${flat(e.timestamp) || "(undated)"} [${flat(e.severity)}]`;
  const desc = flat(promptDescription(e.description));
  return [lead, [...fields, desc].join(" | ")].join(" ");
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
// A Velociraptor client id the alias index links (C.<hex>): its first label "c" would match anything.
const CLIENT_ID = /^c\.[0-9a-f]+$/i;

function termOf(spelling: string): string | null {
  const h = canonicalHostName(spelling);
  if (!h || CLIENT_ID.test(h)) return null;
  if (IPV4.test(h) || h.includes(":")) return h; // an IP is searched whole
  const label = h.split(".")[0];
  return label.length >= 2 ? label : null; // a client id or 1-letter label would match anything
}

/** Store search terms for a host: its first label, then each alias spelling's, at most 5 (D2b). */
export function hostTerms(host: string, aliases?: HostAliasIndex): string[] {
  const canonical = aliases ? resolveHost(aliases, host) : undefined;
  const group = canonical ? [canonical, ...(aliases?.aliasesOf.get(canonical) ?? [])] : [];
  // Watson's own spelling is always searched: whole, when no label of it can be (a client id, "x").
  const own = termOf(host) ?? (canonicalHostName(host) || null);
  const terms = [own, ...group.map(termOf)].filter((t): t is string => t !== null);
  return [...new Set(terms)].slice(0, MAX_HOST_TERMS);
}

function inWindow(e: ForensicEvent, q: WatsonLookup): boolean {
  if (!q.from || !q.to) return true;
  const t = Date.parse(e.timestamp);
  return Number.isFinite(t) && t >= Date.parse(q.from) && t <= Date.parse(q.to); // undated: out
}

function matchesAsked(e: ForensicEvent, q: WatsonLookup, aliases: HostAliasIndex | undefined): boolean {
  const onHost = !q.host || [e.asset, e.assetRecord].some((a) => !!a && sameHost(a, q.host!, aliases));
  return (
    onHost &&
    inWindow(e, q) &&
    (!q.hash || eventMatchesSearch(e, q.hash)) &&
    (!q.text || eventMatchesSearch(e, q.text))
  );
}

const timeKey = (e: ForensicEvent): number => {
  const t = Date.parse(e.timestamp);
  return Number.isFinite(t) ? t : Number.POSITIVE_INFINITY;
};

/** Candidates merged by id, kept by the case's rules and every predicate Watson gave, oldest first. */
export function selectSuperRows(
  candidates: readonly ForensicEvent[],
  keep: (e: ForensicEvent) => boolean,
  q: WatsonLookup,
  aliases?: HostAliasIndex,
): ForensicEvent[] {
  const byId = new Map<string, ForensicEvent>();
  for (const e of candidates) if (!byId.has(e.id)) byId.set(e.id, e);
  return [...byId.values()]
    .filter((e) => keep(e) && matchesAsked(e, q, aliases))
    .sort((a, b) => timeKey(a) - timeKey(b) || a.id.localeCompare(b.id));
}

/** At most 100 rows and 20,000 characters, a line when more matched, and "at least" on a floor. */
export function renderSuperRows(
  matches: readonly ForensicEvent[],
  matchedIsFloor: boolean,
): { text: string; shown: ForensicEvent[]; matched: number } {
  const floorLine = `(${STOPPED}narrow the search)`;
  if (!matches.length) {
    return { text: matchedIsFloor ? `${NONE}\n${floorLine}` : NONE, shown: [], matched: 0 };
  }
  const count = `${matchedIsFloor ? "at least " : ""}${fmt(matches.length)}`;
  const more = (n: number) =>
    `(showing ${n} of ${count} matching super-timeline rows — ${matchedIsFloor ? STOPPED : ""}narrow the search)`;
  const reserve = more(matches.length).length + 1;
  const lines: string[] = [];
  let used = 0;
  for (const e of matches.slice(0, WATSON_SUPER_MAX_ROWS)) {
    const row = superRow(e);
    if (used + row.length + 1 + reserve > WATSON_SUPER_MAX_CHARS) break;
    lines.push(row);
    used += row.length + 1;
  }
  const tail = lines.length < matches.length || matchedIsFloor ? [more(lines.length)] : [];
  return {
    text: [...lines, ...tail].join("\n"),
    shown: matches.slice(0, lines.length),
    matched: matches.length,
  };
}

/** The warning the prompt and card carry when the store's size cap has dropped rows. */
export function capNote(evicted: number): string {
  return `The super-timeline has dropped ${fmt(evicted)} old rows to its size limit (DFIR_SUPERTIMELINE_MAX), so this search may have missed rows. Re-importing the artifact brings them back.`;
}

/** The store terms: the hash (or text), else the host's terms, else none for a window-only search. */
function storeTerms(q: WatsonLookup, aliases: HostAliasIndex | undefined): (string | undefined)[] {
  const term = q.hash ?? q.text;
  if (term) return [term];
  if (q.host) return hostTerms(q.host, aliases);
  return [undefined];
}

async function fetchCandidates(
  reader: WatsonRawReader,
  caseId: string,
  q: WatsonLookup,
  aliases: HostAliasIndex | undefined,
): Promise<{ events: ForensicEvent[]; floor: boolean }> {
  const terms = storeTerms(q, aliases);
  const window = q.from && q.to ? { from: q.from, to: q.to } : {};
  const pages = await Promise.all(
    terms.map((search) =>
      reader.query(caseId, {
        ...(search !== undefined ? { search } : {}),
        ...window,
        offset: 0,
        limit: WATSON_SUPER_SCAN_ROWS,
        countCeiling: WATSON_SUPER_SCAN_ROWS,
      }),
    ),
  );
  // A floor only when a query really stopped short: merged pages counted after the filters are exact.
  const cut = pages.some((p) => p.totalIsLowerBound || p.total > p.events.length);
  return { events: pages.flatMap((p) => p.events), floor: cut };
}

/** What one search hands the round: the prompt block, the disclosure, the rows shown and the roster. */
export interface WatsonSuperSearch {
  excerpt: { what: string; text: string; capNote?: string };
  lookedUp: WatsonLookedUp;
  shown: ForensicEvent[];
  roster: WatsonMaskRoster;
}

/** The case's rules: drop out-of-scope and false-positive rows, and rows already forensic. */
async function inCaseRows(
  ctx: AiCallContext,
  caseId: string,
  state: InvestigationState,
  candidates: ForensicEvent[],
): Promise<{ rows: ForensicEvent[]; keep: (e: ForensicEvent) => boolean }> {
  const { markers, scope } = await loadScopedEvents(ctx, caseId, state);
  const resolve = stateEventResolver(state);
  const forensic = new Set(state.forensicTimeline.map((e) => e.id)); // the FULL timeline (D3)
  const keep = (e: ForensicEvent) => !forensic.has(e.id) && !forensic.has(resolve(e.id));
  return { rows: filterFalsePositiveEvents(filterEventsByScope([...candidates], scope), markers), keep };
}

/** A host search with no term the store can run: refused in words, never reported as "no match". */
function unsearchableHost(q: WatsonLookup, aliases: HostAliasIndex | undefined): WatsonSuperSearch | null {
  if (!q.host || q.hash || q.text || hostTerms(q.host, aliases).length) return null;
  const what = describeLookup(q);
  const text = `host '${flat(q.host)}' could not be searched — name it by hostname or IP`;
  return {
    excerpt: { what, text },
    lookedUp: { source: "supertimeline", shown: 0, matched: 0, what },
    shown: [],
    roster: { hosts: [], users: [], ips: [] },
  };
}

/** Run one bounded search of the super-timeline for Watson. */
export async function searchSuperTimeline(
  ctx: AiCallContext & Parameters<typeof loadCtxAliasIndex>[0],
  reader: WatsonRawReader,
  caseId: string,
  state: InvestigationState,
  q: WatsonLookup,
): Promise<WatsonSuperSearch> {
  const aliases = q.host ? await loadCtxAliasIndex(ctx, caseId) : undefined;
  const refused = unsearchableHost(q, aliases);
  if (refused) return refused;
  const [fetched, meta] = await Promise.all([
    fetchCandidates(reader, caseId, q, aliases),
    reader.meta(caseId),
  ]);
  const { rows, keep } = await inCaseRows(ctx, caseId, state, fetched.events);
  const out = renderSuperRows(selectSuperRows(rows, keep, q, aliases), fetched.floor);
  const what = describeLookup(q);
  const evicted = meta.evictedTotal > 0 ? meta.evictedTotal : 0;
  const lookedUp: WatsonLookedUp = {
    source: "supertimeline",
    shown: out.shown.length,
    matched: out.matched,
    what,
    ...(fetched.floor ? { matchedIsFloor: true } : {}),
    ...(evicted ? { capEvicted: evicted } : {}),
  };
  const excerpt = { what, text: out.text, ...(evicted ? { capNote: capNote(evicted) } : {}) };
  return { excerpt, lookedUp, shown: out.shown, roster: rosterOf(out.shown) };
}
