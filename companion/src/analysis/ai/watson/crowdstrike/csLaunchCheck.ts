import { isPlausibleHuntQuery } from "../../../languageHuntSuggest.js";
import { checkSearchWindow, siemQueryFingerprint, type SiemLimits } from "../../../siemSearch.js";

// The launch check for Watson's CrowdStrike Next-Gen SIEM search (#2666). It runs before a card is
// made and again when the card is run: a query that fails it never becomes a card, and Watson's turn
// says there is nothing to approve. Pure, no I/O.
//
// A search is remembered by its query (whitespace-normalised), repository and time range — the same
// hunt over another window is a new search, as a Velociraptor collection on another host is a new run.
// The keys live in the case's hunt fingerprint index with a `cql:` prefix, beside the VQL keys; the
// analyst's own Run on a CQL hunt adds its key there too.

export const CS_KEY_PREFIX = "cql:";
export const CS_QUERY_MAX = 20_000;
const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
// Control and invisible characters (bidi overrides, zero-width): a query must read as it runs.
const HIDDEN = new RegExp(
  "[\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f\\u007f\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069\\ufeff]",
);

export const CS_ALREADY_RAN = "This search already ran on the case.";

/** The fingerprint key one search is remembered by in the hunt fingerprint index. */
export function csSearchKey(query: string, repository: string, start: string, end: string): string {
  return CS_KEY_PREFIX + siemQueryFingerprint(query, repository, start, end);
}

export interface CsSearchInput {
  query: string;
  start?: string;
  end?: string;
}

export type CsCheck =
  { ok: true; start: string; end: string; key: string } | { ok: false; reason: string; duplicate?: true };

/**
 * Whether Watson may propose (or run) this search. With no range, the last `maxWindowDays` days up to
 * the current hour — whole hours, so the same request in the same hour keys the same search.
 */
export function checkCsSearch(
  r: CsSearchInput,
  limits: Pick<SiemLimits, "maxWindowDays" | "repository">,
  ran: ReadonlySet<string>,
  now: number,
): CsCheck {
  const query = r.query ?? "";
  if (!query.trim()) return { ok: false, reason: "The search has no query." };
  if (query.length > CS_QUERY_MAX) {
    return { ok: false, reason: `The query is longer than ${CS_QUERY_MAX} characters.` };
  }
  if (HIDDEN.test(query)) return { ok: false, reason: "The query has hidden or control characters." };
  if (!isPlausibleHuntQuery("cql", query)) return { ok: false, reason: "The query is not CrowdStrike CQL." };
  const hasStart = !!r.start?.trim();
  if (hasStart !== !!r.end?.trim())
    return { ok: false, reason: "Give both a start and an end time, or neither." };
  let start = r.start;
  let end = r.end;
  if (!hasStart) {
    const endMs = Math.floor(now / HOUR_MS) * HOUR_MS;
    end = new Date(endMs).toISOString();
    start = new Date(endMs - limits.maxWindowDays * DAY_MS).toISOString();
  }
  const window = checkSearchWindow(start, end, limits.maxWindowDays, now);
  if (!window.ok) return { ok: false, reason: window.error };
  const startIso = new Date(window.startMs).toISOString();
  const endIso = new Date(window.endMs).toISOString();
  const key = csSearchKey(query, limits.repository, startIso, endIso);
  if (ran.has(key)) return { ok: false, reason: CS_ALREADY_RAN, duplicate: true };
  return { ok: true, start: startIso, end: endIso, key };
}
