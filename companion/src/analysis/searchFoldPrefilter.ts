/**
 * The store-side prefilter for a forensic-timeline search (#1914), worked out from the search term.
 *
 * WHY THIS EXISTS. The store narrows candidates with SQL LIKE over the raw stored JSON, and the
 * matcher (searchFilter.ts) then decides. LIKE folds case for ASCII only; the matcher folds with
 * toLowerCase(), which folds all of Unicode. The old answer to that gap was "every row holding any
 * non-ASCII character is a candidate". On a real Hayabusa case every description carries an em dash,
 * so EVERY row was a candidate, and a 70,000-event case parsed all 70,000 payloads twice per search:
 * about 5 s for a term that matched nothing.
 *
 * The gap is much narrower than "any non-ASCII character". A non-ASCII character in the payload can
 * only matter if its LOWERCASE form holds a character of the folded term. That set is computable,
 * and it is tiny:
 *  - an ASCII term: only U+0130 (İ -> "i̇") and U+212A (KELVIN SIGN -> "k") fold into ASCII at all,
 *    and each matters only when the term holds that letter;
 *  - a term with a non-ASCII character c: only c itself and the characters that fold to c.
 * Rows holding one of those characters are checked exactly by `dfir_fold_contains` in the worker
 * (caseSqliteWorkerSearch.ts): the lowercased payload against the JSON-encoded folded term.
 *
 * SOUNDNESS — the prefilter may let extra rows through (the matcher drops them) but must never drop
 * a row the matcher accepts; a "no results" reads as proof of absence. It holds because the payload
 * is JSON.stringify(event): JSON escapes character by character, and lowercasing maps character by
 * character too, with one exception — Greek capital sigma becomes σ or ς by context. The fold check
 * treats ς as σ on both sides, so the context never matters. JSON escapes a LONE surrogate (as the
 * ASCII text "\udXXX") but not a paired one, so a term holding a lone surrogate gets no prefilter at
 * all: every row is a candidate. Such a term cannot even arrive over HTTP (invalid UTF-8 decodes to
 * U+FFFD), so that path costs nothing in practice.
 *
 * READ-TIME UPGRADES. The matcher sees the event AFTER upgradeForensicEvent (canonicalEvent.ts), not
 * the stored JSON. Two upgrades add searchable text the payload does not hold, so their rows stay
 * candidates whatever the term (Codex review of #1914):
 *  - a row with no canonical envelope gets one synthesised (legacyCanonical) — always a candidate;
 *  - restampEdgeObserved writes network.source.provenance "edge-observed" on an envelope that has a
 *    source address — a candidate when the term can match inside that one string.
 * Migrating a 1.0.0 envelope adds no text (only schemaVersion, which is not searched).
 */

/** What the store needs to narrow a search's candidates. */
export interface SearchPrefilterPlan {
  /** Every row is a candidate: the term holds a lone surrogate. No other field is set. */
  readonly scanAll: boolean;
  /** LIKE pattern over the stored JSON. Only for a term that is pure ASCII once folded. */
  readonly like?: string;
  /**
   * Single non-ASCII characters. A row holding one of them is checked exactly with `foldNeedle`.
   * Empty for an ASCII term that holds neither "i" nor "k".
   */
  readonly foldChars: readonly string[];
  /** The folded term as stored JSON text, with ς written as σ. */
  readonly foldNeedle?: string;
  /** Rows with a canonical source address are candidates: the read-time restamp may match. */
  readonly edgeObserved?: boolean;
}

/** The value restampEdgeObserved writes on read (canonicalProvenanceRestamp.ts); a test pins the two. */
export const READ_TIME_EDGE_OBSERVED = "edge-observed";

const SIGMA_GROUP = ["Σ", "σ", "ς"];

/** ς and σ are one letter for matching: which one toLowerCase() picks depends on its neighbours. */
export function normaliseSigma(text: string): string {
  return text.replace(/ς/g, "σ");
}

/**
 * A term as a SQL LIKE pattern to be matched against the raw STORED JSON text.
 *
 * Two escapings, and getting only the second one right is a silent evidence-loss bug. The pattern
 * is compared against JSON source, where a Windows path is held as "C:\\\\Users\\\\bob" — two characters
 * per backslash. An analyst types ONE backslash, so a pattern built from the raw term matched
 * nothing at all for the most common search in Windows forensics, while the in-memory matcher on
 * the same event said yes. The term is therefore JSON-encoded first (quotes, backslashes, control
 * characters — exactly what the payload holds), and only then are LIKE's own wildcards escaped so
 * "100%" and "foo_bar" stay literal.
 */
export function searchLikePattern(term: string): string {
  return "%" + asStoredJson(term).replace(/[\\%_]/g, (char) => "\\" + char) + "%";
}

function asStoredJson(term: string): string {
  return JSON.stringify(term).slice(1, -1);
}

function hasLoneSurrogate(text: string): boolean {
  return /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(text);
}

let reverseFold: Map<string, string[]> | null = null;

/**
 * Every character, keyed by each code point of its lowercase form, for the characters whose
 * lowercase differs from themselves (~1,460 of them). Built once, on the first search (~70 ms).
 */
function foldSources(): Map<string, string[]> {
  if (reverseFold) return reverseFold;
  const map = new Map<string, string[]>();
  for (let code = 0x80; code <= 0x10ffff; code++) {
    if (code >= 0xd800 && code <= 0xdfff) continue;
    const char = String.fromCodePoint(code);
    const lower = char.toLowerCase();
    if (lower === char) continue;
    for (const target of new Set(lower)) {
      const list = map.get(target);
      if (list) list.push(char);
      else map.set(target, [char]);
    }
  }
  reverseFold = map;
  return map;
}

/** The non-ASCII characters whose lowercase form holds `char`, plus `char` itself when non-ASCII. */
export function charsFoldingTo(char: string): string[] {
  if (SIGMA_GROUP.includes(char)) return [...SIGMA_GROUP];
  const out = new Set(foldSources().get(char) ?? []);
  if (/[^\u0000-\u007f]/.test(char)) out.add(char);
  return [...out].sort();
}

/** The prefilter for an already-folded (lowercased) search term. */
export function searchPrefilterPlan(folded: string): SearchPrefilterPlan {
  if (hasLoneSurrogate(folded)) return { scanAll: true, foldChars: [] };
  const foldNeedle = normaliseSigma(asStoredJson(folded));
  const edgeObserved = READ_TIME_EDGE_OBSERVED.includes(folded);
  const firstNonAscii = [...folded].find((char) => /[^\u0000-\u007f]/.test(char));
  if (firstNonAscii === undefined) {
    const sources = new Set<string>();
    for (const char of new Set(folded)) for (const source of charsFoldingTo(char)) sources.add(source);
    const like = searchLikePattern(folded);
    return { scanAll: false, like, foldChars: [...sources].sort(), foldNeedle, edgeObserved };
  }
  return { scanAll: false, foldChars: charsFoldingTo(firstNonAscii), foldNeedle, edgeObserved };
}
