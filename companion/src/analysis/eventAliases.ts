// Correlation folds a group of events into one and drops every other member's id (#1714). #1714
// rewrites the citations inside the case state; analyst records kept OUTSIDE it (tags, stars,
// comments, hypothesis links) still name the dropped id, and the analyst's mark fell off the event
// it was made on (#1715). The case therefore keeps its lineage — absorbed id -> surviving id — in the
// state itself, written in the same save as the fold, and every reader resolves through it.
//
// The analyst's records are never rewritten: a tag still says what the analyst tagged. Resolution is
// LIVE-FIRST — an id that is an event today is itself; only a missing id follows its lineage — so the
// record is safe against a bulk append, a rollback or an undo that brings the old id back. Lineage is
// never deleted for the same reason. Ids are exact-case, as everywhere else an event id is compared.

export type EventAliases = Readonly<Record<string, string>>;

/** Deepest lineage a reader follows; a real chain collapses to one hop, so this only bounds bad data. */
const MAX_HOPS = 64;

/** The well-formed entries of a stored record: string keys to a different, non-empty string. */
function entriesOf(aliases: EventAliases | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!aliases || typeof aliases !== "object") return out;
  for (const [from, to] of Object.entries(aliases)) {
    if (from && typeof to === "string" && to && to !== from) out.set(from, to);
  }
  return out;
}

/** The end of `id`'s chain in `map`, stopping on a loop. */
function terminal(map: ReadonlyMap<string, string>, id: string): string {
  const seen = new Set([id]);
  let cur = id;
  for (let hop = 0; hop < MAX_HOPS; hop++) {
    const next = map.get(cur);
    if (next === undefined || seen.has(next)) return cur;
    seen.add(next);
    cur = next;
  }
  return cur;
}

/**
 * The case lineage with this fold's absorbed -> survivor pairs added and every chain collapsed to its
 * newest survivor. The existing record is returned as is when nothing was absorbed.
 */
export function recordEventAliases(
  existing: EventAliases | undefined,
  absorbed: ReadonlyMap<string, string>,
): Record<string, string> | undefined {
  if (absorbed.size === 0) return existing;
  const map = entriesOf(existing);
  for (const [from, to] of absorbed) if (from && to && from !== to) map.set(from, to);
  const out: Record<string, string> = {};
  for (const from of map.keys()) {
    const to = terminal(map, from);
    // defineProperty, not assignment: an id spelled "__proto__" must stay data.
    if (to !== from) Object.defineProperty(out, from, { value: to, enumerable: true, writable: true });
  }
  return out;
}

/** A resolver for event ids: the id when it is live, else the first live id on its lineage, else the id. */
export function eventAliasResolver(
  aliases: EventAliases | undefined,
  isLive: (id: string) => boolean,
): (id: string) => string {
  const map = entriesOf(aliases);
  return (id) => {
    if (map.size === 0 || isLive(id)) return id;
    const seen = new Set([id]);
    let cur = id;
    for (let hop = 0; hop < MAX_HOPS; hop++) {
      const next = map.get(cur);
      if (next === undefined || seen.has(next)) return id;
      if (isLive(next)) return next;
      seen.add(next);
      cur = next;
    }
    return id;
  };
}

/** Every id a resolver for `ids` could need to test for liveness: the ids and their lineages. */
export function aliasCandidates(aliases: EventAliases | undefined, ids: readonly string[]): string[] {
  const map = entriesOf(aliases);
  const out = new Set<string>();
  for (const id of ids) {
    let cur: string | undefined = id;
    for (let hop = 0; cur !== undefined && !out.has(cur) && hop <= MAX_HOPS; hop++) {
      out.add(cur);
      cur = map.get(cur);
    }
  }
  return [...out];
}

/** The state without its lineage — internal bookkeeping, never sent to a client or written to an export. */
export function withoutEventAliases<T extends { eventAliases?: EventAliases }>(
  state: T,
): Omit<T, "eventAliases"> {
  if (!("eventAliases" in state)) return state;
  const { eventAliases: _lineage, ...rest } = state;
  return rest;
}
