// Cross-case IOC correlation (#679). A single campaign is often split across several
// investigations — the same C2 domain in last month's phishing case and in today's ransomware
// case — and until now nothing in the companion could see across that boundary. Every index,
// graph and ranking the analysis owns is scoped to one case, so the correlation was done in a
// spreadsheet or not at all.
//
// This module is the pure half. It takes one SNAPSHOT PER CASE (id, display name, lifecycle
// status, and that case's IOC list — nothing else) and builds a value-keyed index over all of
// them, then answers the two questions the routes ask: "which cases hold this indicator?" and
// "which cases overlap with this one, and on what?".
//
// No I/O, no AI, no network — derived entirely from the snapshots handed in, like iocAnchors.ts
// and assetGraph.ts.
//
// IT HAS NO CONCEPT OF A PERMISSION, DELIBERATELY. Which cases a caller may see is decided
// before a snapshot reaches this module, so a case that must stay hidden must never be handed
// in. routes/crossCase.ts owns that gate; putting the check here as well would mean two places
// could disagree about who may read what.

import type { IOC } from "./stateTypes.js";
import { isInternalTarget } from "./iocValue.js";

export type IocType = IOC["type"];
export type CaseStatus = "open" | "closed" | "archived";

/** One case's contribution to the index. Built by the caller from that case's meta + state. */
export interface CaseIocSnapshot {
  caseId: string;
  name: string;
  status: CaseStatus;
  iocs: readonly IOC[];
}

/**
 * The IOC types worth pivoting on across cases, and the default for every entry point here.
 *
 * The excluded types are not less important — they are less DISCRIMINATING. `process` is
 * `powershell.exe`, `file` is `C:\Windows\Temp`, `sid` is `S-1-5-18`, and `other` is whatever an
 * importer could not classify. Those values appear in essentially every Windows investigation
 * ever opened, so indexing them would relate every pair of cases to every other pair and bury the
 * one domain that actually links two intrusions. A caller that wants a wider net passes `types`.
 */
export const PIVOT_IOC_TYPES: readonly IocType[] = ["ip", "domain", "url", "hash"];

/** Shortest `q` that may match on substring; below it, only an exact value match is considered. */
export const MIN_SUBSTRING_QUERY = 3;

/**
 * Weight of an indicator that resolves to a private/loopback target. An RFC1918 address or
 * `localhost` recurs across every case in one estate for reasons that have nothing to do with a
 * shared adversary, so it stays in the index — an analyst pivoting on 10.0.0.5 still wants the
 * answer — but it must not be what makes two cases look related. Same reasoning as the
 * `internalConflict` de-rating in iocAnchors.ts.
 */
export const INTERNAL_PIVOT_WEIGHT = 0.25;

/** A file hash matching across two cases is a stronger claim than a shared domain or address. */
const HASH_PIVOT_WEIGHT = 1.5;

/** Added when third-party intel already graded the indicator malicious or suspicious. */
const MALICIOUS_PIVOT_BONUS = 2;

const MALICIOUS_VERDICTS = new Set(["malicious", "suspicious"]);

/** One case's hold on one indexed value. */
export interface CrossCaseIocHit {
  caseId: string;
  caseName: string;
  caseStatus: CaseStatus;
  iocId: string;
  type: IocType;
  /** The value the owning case stores. Differs from the index key on an alias match. */
  value: string;
  firstSeen: string;
  /** A third-party verdict on this IOC is malicious or suspicious. */
  malicious: boolean;
  /** This hit's contribution to a relatedness score. See {@link pivotWeight}. */
  weight: number;
}

/** Every case holding one normalized indicator value. */
export interface CrossCaseIocEntry {
  /** Normalized (trimmed, lower-cased) indicator value — the index key. */
  value: string;
  /** Distinct IOC types the hits carry, sorted. Two importers may classify one value differently. */
  types: IocType[];
  hits: CrossCaseIocHit[];
  /** Distinct case ids among the hits, sorted. */
  caseIds: string[];
}

export interface CrossCaseIndex {
  byValue: Map<string, CrossCaseIocEntry>;
  /** Cases that contributed a snapshot, including ones that contributed no indexable IOC. */
  caseCount: number;
  /** Indexable IOCs read, counted once each regardless of how many alias keys they landed under. */
  iocCount: number;
}

export interface CrossCaseIndexOptions {
  /** IOC types to index. Defaults to {@link PIVOT_IOC_TYPES}. */
  types?: readonly IocType[];
}

/** scheme :// authority (with optional userinfo) / the rest, which this module must not fold. */
const URL_PARTS = /^([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^/?#]*)([\s\S]*)$/;

/**
 * A URL is the ONE indicator type that is not case-insensitive throughout.
 *
 * RFC 3986 makes the scheme and the host case-insensitive and leaves the path, query and fragment
 * to the origin server — which on any Unix-backed host distinguishes `/Object` from `/object`.
 * Folding the whole value would merge two distinct resources into one index key, and the panel
 * would then assert a shared indicator between two cases that never touched the same URL. That is
 * a false claim in a report, so scheme and host fold and nothing after the authority does.
 *
 * Userinfo sits inside the authority and is case-sensitive (a password is), so it is preserved too.
 */
function normalizeUrlValue(value: string): string {
  const m = URL_PARTS.exec(value);
  if (!m) return value.toLowerCase(); // not actually URL-shaped — treat it like any other value
  const [, scheme, authority, rest] = m;
  const at = authority.lastIndexOf("@");
  const userinfo = at === -1 ? "" : authority.slice(0, at + 1);
  const host = at === -1 ? authority : authority.slice(at + 1);
  return scheme.toLowerCase() + userinfo + host.toLowerCase() + rest;
}

/**
 * The index key for an indicator value. Surrounding whitespace goes, and case folds as far as the
 * type allows — for every type but `url` that is the whole value (a domain, an address and a hash
 * are all case-insensitive); see {@link normalizeUrlValue} for why a URL is different.
 *
 * Nothing else is folded, on purpose, because a cross-case claim has to be defensible in a report.
 * Two spellings of one domain are reconciled where the analyst already said they are the same
 * thing — the per-case merge that writes `aliasValues` — and never by this module guessing.
 *
 * `type` is omitted only by a free-text search, which has no type to go on; there the URL rule is
 * inferred from the value's own shape, so a query for a URL is keyed the way that URL was indexed.
 */
export function normalizeCrossCaseValue(value: string, type?: IocType): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  if (type === "url" || (type === undefined && URL_PARTS.test(trimmed))) {
    return normalizeUrlValue(trimmed);
  }
  return trimmed.toLowerCase();
}

export function isMaliciousIoc(ioc: IOC): boolean {
  return (ioc.enrichments ?? []).some((e) => MALICIOUS_VERDICTS.has(e.verdict));
}

/** How much one hit may contribute to a relatedness score. */
export function pivotWeight(type: IocType, value: string, malicious: boolean): number {
  if (isInternalTarget(value, type)) return INTERNAL_PIVOT_WEIGHT;
  const base = type === "hash" ? HASH_PIVOT_WEIGHT : 1;
  return malicious ? base + MALICIOUS_PIVOT_BONUS : base;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/** Every key one IOC is indexed under: its own value plus each analyst-merged alias. */
function indexKeys(ioc: IOC): string[] {
  const keys = new Set<string>();
  for (const raw of [ioc.value, ...(ioc.aliasValues ?? [])]) {
    const key = normalizeCrossCaseValue(raw ?? "", ioc.type);
    if (key) keys.add(key);
  }
  return [...keys];
}

/**
 * Build the value-keyed index over every snapshot handed in.
 *
 * An IOC is indexed under its own value AND under every value an analyst folded onto it with the
 * per-case merge (#82). Without that, a case that merged "www.evil.com" into "evil.com" would
 * stop matching a second case that only ever saw the "www." spelling — the merge would have
 * destroyed the cross-case link it was meant to clarify.
 */
export function buildCrossCaseIndex(
  snapshots: readonly CaseIocSnapshot[],
  options: CrossCaseIndexOptions = {},
): CrossCaseIndex {
  const types = new Set<IocType>(options.types ?? PIVOT_IOC_TYPES);
  const byValue = new Map<string, CrossCaseIocEntry>();
  let iocCount = 0;

  for (const snapshot of snapshots) {
    for (const ioc of snapshot.iocs) {
      if (!types.has(ioc.type)) continue;
      const keys = indexKeys(ioc);
      if (!keys.length) continue;
      iocCount += 1;
      const malicious = isMaliciousIoc(ioc);
      const hit: Omit<CrossCaseIocHit, "weight"> = {
        caseId: snapshot.caseId,
        caseName: snapshot.name,
        caseStatus: snapshot.status,
        iocId: ioc.id,
        type: ioc.type,
        value: ioc.value,
        firstSeen: ioc.firstSeen,
        malicious,
      };
      for (const key of keys) {
        let entry = byValue.get(key);
        if (!entry) {
          entry = { value: key, types: [], hits: [], caseIds: [] };
          byValue.set(key, entry);
        }
        // The weight is computed per KEY, not per IOC: an alias may be an internal address while
        // the canonical value is not, and the score must reflect the value that actually matched.
        entry.hits.push({ ...hit, weight: pivotWeight(ioc.type, key, malicious) });
      }
    }
  }

  for (const entry of byValue.values()) {
    entry.types = [...new Set(entry.hits.map((h) => h.type))].sort();
    entry.caseIds = [...new Set(entry.hits.map((h) => h.caseId))].sort();
    entry.hits.sort((a, b) => (a.caseId === b.caseId ? cmp(a.iocId, b.iocId) : cmp(a.caseId, b.caseId)));
  }

  return { byValue, caseCount: snapshots.length, iocCount };
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export interface CrossCaseSearchOptions {
  /** Max entries returned. Defaults to 50. */
  limit?: number;
  /** Only report values held by at least this many cases. Defaults to 1 (a plain lookup). */
  minCases?: number;
  /** Only report hits of these types. Defaults to every type already in the index. */
  types?: readonly IocType[];
}

export interface CrossCaseSearchResult {
  query: string;
  entries: CrossCaseIocEntry[];
  /** Matching entries before `limit` was applied. */
  total: number;
  truncated: boolean;
}

/**
 * Find indexed values matching `query`.
 *
 * An exact (normalized) match always wins and is listed first. A query of at least
 * {@link MIN_SUBSTRING_QUERY} characters additionally matches on substring, so an analyst who
 * remembers "evil.co" still finds "mail.evil.com" — shorter queries stay exact, because "10."
 * matching every address in the estate is not a search result, it is the whole index.
 *
 * THE TWO MATCH MODES FOLD CASE DIFFERENTLY, and the asymmetry is the point. An exact match is a
 * claim that two things are the same indicator, so it respects the URL rule above and compares
 * keys as they were indexed. A substring match is a search affordance — nobody types a path's
 * capitalisation from memory — so it folds case on both sides. A search hit is a place to look;
 * only the exact key is ever used to link two cases (see {@link relatedCases}).
 */
export function searchCrossCaseIocs(
  index: CrossCaseIndex,
  query: string,
  options: CrossCaseSearchOptions = {},
): CrossCaseSearchResult {
  const q = normalizeCrossCaseValue(query);
  const limit = Math.max(1, options.limit ?? 50);
  const minCases = Math.max(1, options.minCases ?? 1);
  const typeFilter = options.types ? new Set<IocType>(options.types) : null;
  if (!q) return { query: q, entries: [], total: 0, truncated: false };
  // A URL-shaped query is keyed by the URL rule, but the same string may ALSO sit in the index
  // under a fully folded key, because the case that holds it typed the indicator "other" rather
  // than "url". Accept either spelling as exact rather than make the answer depend on how a
  // different case classified its own row.
  const exactKeys = new Set([q, query.trim().toLowerCase()]);
  const qLower = q.toLowerCase();

  const matched: CrossCaseIocEntry[] = [];
  for (const entry of index.byValue.values()) {
    const exact = exactKeys.has(entry.value);
    if (!exact && (q.length < MIN_SUBSTRING_QUERY || !entry.value.toLowerCase().includes(qLower))) {
      continue;
    }
    const hits = typeFilter ? entry.hits.filter((h) => typeFilter.has(h.type)) : entry.hits;
    if (!hits.length) continue;
    const caseIds = [...new Set(hits.map((h) => h.caseId))].sort();
    if (caseIds.length < minCases) continue;
    matched.push({
      value: entry.value,
      types: [...new Set(hits.map((h) => h.type))].sort(),
      hits,
      caseIds,
    });
  }

  matched.sort((a, b) => {
    const exactA = exactKeys.has(a.value) ? 0 : 1;
    const exactB = exactKeys.has(b.value) ? 0 : 1;
    if (exactA !== exactB) return exactA - exactB;
    if (a.caseIds.length !== b.caseIds.length) return b.caseIds.length - a.caseIds.length;
    if (a.hits.length !== b.hits.length) return b.hits.length - a.hits.length;
    return cmp(a.value, b.value);
  });

  return {
    query: q,
    entries: matched.slice(0, limit),
    total: matched.length,
    truncated: matched.length > limit,
  };
}

/** One indicator two cases have in common. */
export interface SharedIndicator {
  /** The index key that matched — the normalized value both cases hold. */
  value: string;
  types: IocType[];
  /** Either case's copy carries a malicious/suspicious verdict. */
  malicious: boolean;
  /**
   * `true` when the value resolves to a private/loopback target — a weak link, kept but de-rated.
   *
   * Named `isInternal` rather than the plainer `internal`, because the repo's secret scanner
   * reads a dotted property access ending in that word as a hostname on the reserved TLD of
   * the same name. Renaming the field costs nothing and keeps that rule sharp for a real
   * internal FQDN, which adding this object to the scanner's allowlist would not.
   */
  isInternal: boolean;
  weight: number;
}

export interface RelatedCase {
  caseId: string;
  name: string;
  status: CaseStatus;
  /** Sum of the shared indicators' weights, rounded to two decimals. Higher is a stronger link. */
  score: number;
  /** Distinct indicators in common, including any not listed in `shared`. */
  sharedCount: number;
  /** How many of them carry a malicious/suspicious verdict. */
  maliciousCount: number;
  /** The strongest shared indicators, capped by `sharedLimit`. */
  shared: SharedIndicator[];
}

export interface RelatedCasesOptions {
  /** Max related cases returned. Defaults to 20. */
  limit?: number;
  /** Max shared indicators listed per related case. Defaults to 10. */
  sharedLimit?: number;
  /** Drop links weaker than this. Defaults to 0 — any overlap at all is reported. */
  minScore?: number;
}

/**
 * Rank the other cases in the index by how much they overlap with `caseId`.
 *
 * ONE SHARED INDICATOR IS COUNTED ONCE, and that takes three guards rather than one, because the
 * same indicator can arrive twice in three unrelated ways:
 *
 *   - It lands under SEVERAL KEYS — its own value plus every alias the analyst merged onto it. The
 *     value differs on each pass, so only the row identity catches it.
 *   - THIS case holds several rows carrying one value. That is supported existing state (iocRepair
 *     deliberately leaves same-value/different-id duplicates alone), so the subject row differs on
 *     each pass and only the value catches it.
 *   - THE OTHER case holds several rows for one value, or one merged row answering two of this
 *     case's values. The subject row and the value can both be new while the thing being shared is
 *     the same row on their side.
 *
 * So a pass counts only when all three are new for that related case: this case's row, the other
 * case's row, and the value. Any weaker guard inflates `sharedCount`, `maliciousCount` and the
 * score — a ranking that would promote whichever case has the messiest IOC table. Keys are visited
 * in sorted order, so which pass wins is the same on every call.
 */
export function relatedCases(
  index: CrossCaseIndex,
  caseId: string,
  options: RelatedCasesOptions = {},
): RelatedCase[] {
  const limit = Math.max(1, options.limit ?? 20);
  const sharedLimit = Math.max(1, options.sharedLimit ?? 10);
  const minScore = options.minScore ?? 0;

  interface Accumulator {
    caseId: string;
    name: string;
    status: CaseStatus;
    shared: SharedIndicator[];
    /** Subject-case rows already counted — catches one row matched under several alias keys. */
    seenOwn: Set<string>;
    /** Other-case rows already counted — catches the same, from their side. */
    seenOther: Set<string>;
    /** Values already counted — catches several rows in one case holding the same value. */
    seenValues: Set<string>;
  }
  const byCase = new Map<string, Accumulator>();

  const keys = [...index.byValue.keys()].sort();
  for (const key of keys) {
    const entry = index.byValue.get(key);
    if (!entry) continue;
    const mine = entry.hits.filter((h) => h.caseId === caseId);
    if (!mine.length) continue;
    const theirs = entry.hits.filter((h) => h.caseId !== caseId);
    if (!theirs.length) continue;

    for (const other of theirs) {
      let acc = byCase.get(other.caseId);
      if (!acc) {
        acc = {
          caseId: other.caseId,
          name: other.caseName,
          status: other.caseStatus,
          shared: [],
          seenOwn: new Set<string>(),
          seenOther: new Set<string>(),
          seenValues: new Set<string>(),
        };
        byCase.set(other.caseId, acc);
      }
      for (const own of mine) {
        if (acc.seenOwn.has(own.iocId) || acc.seenOther.has(other.iocId) || acc.seenValues.has(key)) {
          continue;
        }
        acc.seenOwn.add(own.iocId);
        acc.seenOther.add(other.iocId);
        acc.seenValues.add(key);
        const malicious = own.malicious || other.malicious;
        // Both hits carry the same key, so either weight already reflects the matched value;
        // taking the max lets one side's intel verdict raise a link the other side has not
        // enriched yet.
        const weight = Math.max(own.weight, other.weight);
        acc.shared.push({
          value: key,
          types: [...new Set([own.type, other.type])].sort(),
          malicious,
          isInternal: weight === INTERNAL_PIVOT_WEIGHT,
          weight,
        });
      }
    }
  }

  const results: RelatedCase[] = [];
  for (const acc of byCase.values()) {
    const score = round2(acc.shared.reduce((sum, s) => sum + s.weight, 0));
    if (score < minScore) continue;
    const shared = [...acc.shared].sort((a, b) =>
      a.weight === b.weight ? cmp(a.value, b.value) : b.weight - a.weight,
    );
    results.push({
      caseId: acc.caseId,
      name: acc.name,
      status: acc.status,
      score,
      sharedCount: shared.length,
      maliciousCount: shared.filter((s) => s.malicious).length,
      shared: shared.slice(0, sharedLimit),
    });
  }

  results.sort((a, b) => {
    if (a.score !== b.score) return b.score - a.score;
    if (a.sharedCount !== b.sharedCount) return b.sharedCount - a.sharedCount;
    return cmp(a.caseId, b.caseId);
  });
  return results.slice(0, limit);
}
