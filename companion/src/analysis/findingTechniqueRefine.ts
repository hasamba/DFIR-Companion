import { techniqueName } from "./attackTechniqueNames.js";
import { AUTO_FINDING_ID_PREFIX } from "./responseSchema.js";

/**
 * Reconciles a MODEL finding's ATT&CK tags with the tags on the events it cites (#2556).
 *
 * The synthesis prompt never shows the model an event's tags, so it writes techniques from its own
 * reading: the parent (T1114) where the cited rows carry the sub-technique (T1114.003), and now and
 * then a technique none of its rows supports. `f-auto-*` findings already take their events' tags
 * (rederiveAutoFindingTechniques); this is the bounded equivalent for the model's own findings:
 *
 *   1. Refine — a base tag whose sub-techniques the cited rows carry is replaced, in place, by them.
 *   2. Drop   — a tag that shares no base with anything the cited rows carry is removed.
 *   3. Never empty — if that would leave nothing, the cited rows' tags are used instead.
 *
 * Only when the cited rows carry tags at all: a finding that cites nothing, or only untagged rows
 * (screenshot and AI-extracted cases), is left exactly as the model wrote it. Nothing is ADDED
 * beyond refinement and the empty fallback — no "every cited-row tag" rule.
 *
 * Runs on the delta BEFORE the merge, because the merge links table rows to findings from the
 * delta's tags; a rewrite after it would leave the parent linked and the sub-technique not. Pure:
 * returns the same delta when nothing changes, and never mutates its input.
 */

interface RefinableFinding {
  id: string;
  status: string;
  mitreTechniques: string[];
  relatedEventIds?: string[];
}

interface RefinableDelta {
  findings: RefinableFinding[];
  mitreTechniques: Array<{ id: string; name: string }>;
}

type EventTags = ReadonlyMap<string, { mitreTechniques: readonly string[] }>;
type Members = ReadonlyMap<string, readonly string[]> | undefined;

const baseOf = (id: string): string => id.trim().toUpperCase().split(".")[0] ?? "";
const isSub = (id: string): boolean => id.includes(".");

/** The tags on the rows a finding cites — a live finding's grouped row stands for its members. */
function carriedTags(f: RefinableFinding, events: EventTags, membersOf: Members): string[] {
  const out = new Set<string>();
  for (const eid of f.relatedEventIds ?? []) {
    const ids = f.status === "dismissed" ? [eid] : [eid, ...(membersOf?.get(eid) ?? [])];
    for (const id of ids) for (const t of events.get(id)?.mitreTechniques ?? []) if (t) out.add(t);
  }
  return [...out];
}

/** The finding's tags after refine / drop / never-empty, given what its rows carry (non-empty). */
export function refineTags(tags: readonly string[], carried: readonly string[]): string[] {
  const carriedBases = new Set(carried.map(baseOf));
  const out = new Set<string>();
  for (const t of tags) {
    const base = baseOf(t);
    const subs = isSub(t) ? [] : carried.filter((c) => isSub(c) && baseOf(c) === base);
    if (subs.length > 0) for (const s of subs) out.add(s);
    else if (carriedBases.has(base)) out.add(t);
  }
  return out.size > 0 ? [...out] : [...carried];
}

const sameList = (a: readonly string[], b: readonly string[]): boolean =>
  a.length === b.length && a.every((t, i) => t === b[i]);

export function refineFindingTechniques<D extends RefinableDelta>(
  delta: D,
  events: EventTags,
  membersOf?: Members,
): D {
  const introduced: string[] = [];
  let changed = false;
  const findings = delta.findings.map((f) => {
    if (f.id.startsWith(AUTO_FINDING_ID_PREFIX)) return f;
    const carried = carriedTags(f, events, membersOf);
    if (carried.length === 0) return f;
    const next = refineTags(f.mitreTechniques, carried);
    if (sameList(next, f.mitreTechniques)) return f;
    changed = true;
    for (const t of next) if (!f.mitreTechniques.includes(t)) introduced.push(t);
    return { ...f, mitreTechniques: next };
  });
  if (!changed) return delta;
  const have = new Set(delta.mitreTechniques.map((t) => t.id));
  const rows = [...new Set(introduced)].filter((id) => !have.has(id));
  return {
    ...delta,
    findings,
    mitreTechniques: [...delta.mitreTechniques, ...rows.map((id) => ({ id, name: techniqueName(id) }))],
  };
}
