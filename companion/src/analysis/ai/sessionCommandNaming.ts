/**
 * "Does a finding already name this quiet command?" (#1594), indexed (#2058).
 *
 * Only a finding about the command's host can name it: one that cites the row itself, or cites some
 * row on the same host. Checking every such finding for every candidate was quadratic on a
 * hayabusa-sized case (one finding per distinct rule, thousands per host), so each host keeps a word
 * index of its findings' texts and a candidate is checked only against the findings whose words could
 * possibly contain it. The exact checks are unchanged; the index only skips findings that cannot match.
 *
 * A finding text is ` <normalized words> ` (single spaces, padded). The checks are:
 *   - the full command is a SUBSTRING of the text,
 *   - the command's core (when long enough to count) is a whole-word run in the text,
 *   - for a finding that cites the row, the program is a whole word in the text.
 * Why the prefilter is safe, with full = "t1 … tk" (no empty tokens):
 *   - k ≥ 3: " t2 " is inside the match, so t2 is a word of the text.
 *   - k = 2: t2 follows a space in the match, so some word of the text starts with t2.
 *   - k = 1: t1 has no space, so it sits inside one word of the text.
 *   - a whole-word core run starts with its first token as a word of the text.
 */

export interface NamingQuery {
  eventId: string;
  host: string;
  /** The normalized command text, matched as a substring. */
  full: string;
  /** The normalized core (program plus two arguments, or a file name), matched as whole words. */
  core: string;
  /** Whether the core is specific enough to count on its own. */
  coreCounts: boolean;
  /** The program, matched as a whole word, by a finding that cites the row only. */
  program: string;
}

interface HostWords {
  /** Word -> the ids of this host's findings whose text has that word. */
  postings: Map<string, Set<string>>;
  /** Memoised prefilter results, keyed by mode + token. */
  memo: Map<string, ReadonlySet<string>>;
  ids: Set<string>;
}

export interface NamingIndex {
  texts: ReadonlyMap<string, string>;
  cited: ReadonlyMap<string, ReadonlySet<string>>;
  hosts: ReadonlyMap<string, HostWords>;
}

export function wordIn(text: string, word: string): boolean {
  return word.length > 0 && text.includes(` ${word} `);
}

/** Built once per run from live finding texts, row -> citing findings, and finding -> hosts. */
export function buildNamingIndex(
  texts: ReadonlyMap<string, string>,
  cited: ReadonlyMap<string, ReadonlySet<string>>,
  hostsOf: ReadonlyMap<string, ReadonlySet<string>>,
): NamingIndex {
  const hosts = new Map<string, HostWords>();
  for (const [id, findingHosts] of hostsOf) {
    const text = texts.get(id);
    if (text === undefined) continue;
    const words = new Set(text.split(" ").filter(Boolean));
    for (const host of findingHosts) {
      let entry = hosts.get(host);
      if (!entry) {
        entry = { postings: new Map(), memo: new Map(), ids: new Set() };
        hosts.set(host, entry);
      }
      entry.ids.add(id);
      for (const w of words) {
        const set = entry.postings.get(w);
        if (set) set.add(id);
        else entry.postings.set(w, new Set([id]));
      }
    }
  }
  return { texts, cited, hosts };
}

export function isNamedBy(index: NamingIndex, q: NamingQuery): boolean {
  const citing = index.cited.get(q.eventId);
  for (const id of citing ?? []) if (names(index.texts.get(id), q, true)) return true;
  const host = index.hosts.get(q.host);
  if (!host) return false;
  for (const id of mayName(host, q))
    if (!citing?.has(id) && names(index.texts.get(id), q, false)) return true;
  return false;
}

function names(text: string | undefined, q: NamingQuery, citing: boolean): boolean {
  if (text === undefined) return false;
  if (text.includes(q.full)) return true;
  if (q.coreCounts && wordIn(text, q.core)) return true;
  return citing && wordIn(text, q.program);
}

/** A superset of the host's findings that could pass the full-text or the core check. */
function mayName(host: HostWords, q: NamingQuery): Set<string> {
  const out = new Set<string>(fullCandidates(host, q.full));
  if (q.coreCounts && q.core) for (const id of exactWord(host, q.core.split(" ")[0])) out.add(id);
  return out;
}

function fullCandidates(host: HostWords, full: string): ReadonlySet<string> {
  const tokens = full.split(" ").filter(Boolean);
  if (!tokens.length) return host.ids; // "" is in every text
  if (tokens.length >= 3) return exactWord(host, tokens[1]);
  if (tokens.length === 2) return scanWords(host, "prefix", tokens[1], (w) => w.startsWith(tokens[1]));
  return scanWords(host, "infix", tokens[0], (w) => w.includes(tokens[0]));
}

const EMPTY: ReadonlySet<string> = new Set();

function exactWord(host: HostWords, word: string): ReadonlySet<string> {
  return host.postings.get(word) ?? EMPTY;
}

function scanWords(
  host: HostWords,
  mode: string,
  token: string,
  keep: (word: string) => boolean,
): ReadonlySet<string> {
  const key = `${mode}\u0000${token}`;
  const hit = host.memo.get(key);
  if (hit) return hit;
  const out = new Set<string>();
  for (const [word, ids] of host.postings) if (keep(word)) for (const id of ids) out.add(id);
  host.memo.set(key, out);
  return out;
}
