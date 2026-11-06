// Bring a newer rule set into an analyst's edited copy (#2344). PURE: no I/O, never mutates inputs.
//
// GENERIC ON PURPOSE. The "upstream" here is whatever newer rule set the caller names — the bundled
// data/tags.yaml today (taggerStore.ts), a separately released rule pack next (#2349). Nothing in
// this file knows which one it is looking at.
//
// THREE-WAY, BY RULE KEY. A two-way compare of the analyst's copy against upstream cannot tell "the
// analyst deleted this rule" from "upstream added it", or "the analyst edited this" from "upstream
// changed it". So the caller keeps a BASE record — a content hash per rule key, taken from the
// upstream set the copy was derived from — and every rule is classified against it:
//
//   in upstream, not base, not mine         → added
//   in upstream and base, not mine          → removed by you (never re-added unless asked)
//   upstream changed since base, mine not   → changed
//   mine changed since base, upstream not   → analyst-edited (kept, no action)
//   both changed, differently               → conflict (the analyst picks a side)
//   in mine only, not in base               → analyst-added (kept, no action)
//   in mine and base, gone from upstream    → retired upstream (kept, informational)
//
// A copy saved before base records existed has none. Then the compare is by key alone, and what it
// cannot attribute is flagged `uncertain`: a missing key is "new, or removed by you", a different one
// is "changed — unknown which side" (reported as a conflict, so the analyst decides).
//
// Hashes are over the PARSED rule with object keys sorted, never over YAML text: a comment-only edit
// to the shipped file, or the reformatting stringifyYaml does on every structural edit, must not
// read as a change.

import { createHash } from "node:crypto";

export type RuleMap = Readonly<Record<string, unknown>>;

/** Which upstream rule content the analyst's copy was taken from: key → content hash. */
export interface RuleBase {
  /** ruleSetRevision() of the upstream set this record was last brought up to. Informational. */
  revision: string;
  rules: Readonly<Record<string, string>>;
}

export interface RuleUpdateItem {
  key: string;
  /** The upstream version (absent only for nothing — every offered item has one). */
  upstream: unknown;
  /** The analyst's current version; absent for added and removed-by-you items. */
  mine?: unknown;
  /** No base record: the side that changed (or whether it was deleted) cannot be told. */
  uncertain: boolean;
}

export interface RuleUpdateReport {
  upstreamRevision: string;
  /** True when a base record exists, so every classification is exact. */
  tracked: boolean;
  added: RuleUpdateItem[];
  changed: RuleUpdateItem[];
  conflicts: RuleUpdateItem[];
  removedByYou: RuleUpdateItem[];
  analystEdited: string[];
  analystAdded: string[];
  retiredUpstream: string[];
  inSync: number;
  /** Something new to bring in: added + changed + conflicts > 0. Removed-by-you alone is not news. */
  hasNews: boolean;
}

/** "upstream" brings the upstream version in (add / update / restore); "mine" keeps the analyst's. */
export type RuleChoice = "upstream" | "mine";

export interface RuleUpdateInput {
  upstream: RuleMap;
  mine: RuleMap;
  base: RuleBase | null;
}

export interface RuleUpdateResult {
  rules: Record<string, unknown>;
  /** The base record to store with the new copy. */
  base: RuleBase;
  /** Keys whose upstream version was written into the copy. */
  applied: string[];
  /** Keys where the analyst chose to keep their version (recorded as decided). */
  kept: string[];
}

// Plain assignment of a "__proto__" key would set the prototype instead of an own property. Rule
// keys come from YAML the caller does not control (a downloaded rule pack, #2349), so define them.
function setOwn<T>(target: Record<string, T>, key: string, value: T): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(obj)
        .sort()
        .map((k) => [k, canonical(obj[k])]),
    );
  }
  return value;
}

/** Content hash of one parsed rule, independent of key order and YAML formatting. */
export function ruleHash(rule: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(canonical(rule ?? null)))
    .digest("hex")
    .slice(0, 16);
}

/** Content revision of a whole rule set: changes when any rule's content, or the key set, does. */
export function ruleSetRevision(rules: RuleMap): string {
  const lines = Object.keys(rules)
    .sort()
    .map((k) => `${k}\u0000${ruleHash(rules[k])}`);
  return createHash("sha256").update(lines.join("\n")).digest("hex").slice(0, 16);
}

/** A base record saying "this copy matches `rules` exactly" — taken when a copy is first made. */
export function snapshotBase(rules: RuleMap): RuleBase {
  return {
    revision: ruleSetRevision(rules),
    rules: Object.fromEntries(Object.keys(rules).map((k) => [k, ruleHash(rules[k])])),
  };
}

type Bucket = "added" | "changed" | "conflicts" | "removedByYou" | "analystEdited" | "inSync";

function classifyTracked(key: string, input: RuleUpdateInput, base: RuleBase): Bucket {
  const { upstream, mine } = input;
  const hu = ruleHash(upstream[key]);
  const hb = Object.hasOwn(base.rules, key) ? base.rules[key] : undefined;
  if (!Object.hasOwn(mine, key)) return hb === undefined ? "added" : "removedByYou";
  const hm = ruleHash(mine[key]);
  if (hm === hu) return "inSync";
  if (hb === undefined) return "conflicts"; // both sides added the same key, differently
  if (hu === hb) return "analystEdited";
  if (hm === hb) return "changed";
  return "conflicts";
}

function classifyLegacy(key: string, input: RuleUpdateInput): Bucket {
  if (!Object.hasOwn(input.mine, key)) return "added";
  return ruleHash(input.mine[key]) === ruleHash(input.upstream[key]) ? "inSync" : "conflicts";
}

/** Compare the analyst's copy against a newer rule set. */
export function diffRuleSets(input: RuleUpdateInput): RuleUpdateReport {
  const { upstream, mine, base } = input;
  const buckets: Record<Bucket, string[]> = {
    added: [],
    changed: [],
    conflicts: [],
    removedByYou: [],
    analystEdited: [],
    inSync: [],
  };
  for (const key of Object.keys(upstream)) {
    buckets[base ? classifyTracked(key, input, base) : classifyLegacy(key, input)].push(key);
  }
  const analystAdded: string[] = [];
  const retiredUpstream: string[] = [];
  for (const key of Object.keys(mine)) {
    if (Object.hasOwn(upstream, key)) continue;
    if (base && Object.hasOwn(base.rules, key)) retiredUpstream.push(key);
    else analystAdded.push(key);
  }
  const item = (key: string): RuleUpdateItem => ({
    key,
    upstream: upstream[key],
    ...(Object.hasOwn(mine, key) ? { mine: mine[key] } : {}),
    uncertain: !base,
  });
  const added = buckets.added.map(item);
  const changed = buckets.changed.map(item);
  const conflicts = buckets.conflicts.map(item);
  return {
    upstreamRevision: ruleSetRevision(upstream),
    tracked: base !== null,
    added,
    changed,
    conflicts,
    removedByYou: buckets.removedByYou.map(item),
    analystEdited: buckets.analystEdited,
    analystAdded,
    retiredUpstream,
    inSync: buckets.inSync.length,
    hasNews: added.length + changed.length + conflicts.length > 0,
  };
}

/**
 * Apply the analyst's choices. Only keys on offer (added, changed, conflict, removed by you) are
 * acted on; a choice for any other key is ignored, so a stale or forged selection can never
 * overwrite an analyst-edited or analyst-added rule. Unchosen offers stay offered.
 *
 * A copy with no base record gets a full snapshot of `upstream` as its new base — the only way it
 * stops being "unknown" — so undecided "new or removed" keys then read as removed by you
 * (restorable), and undecided "unknown side" differences as analyst-edited (kept).
 */
export function applyRuleUpdates(
  input: RuleUpdateInput & { choices: Readonly<Record<string, RuleChoice>> },
): RuleUpdateResult {
  const report = diffRuleSets(input);
  const offered = new Set(
    [...report.added, ...report.changed, ...report.conflicts, ...report.removedByYou].map((i) => i.key),
  );
  const applied: string[] = [];
  const kept: string[] = [];
  for (const [key, choice] of Object.entries(input.choices)) {
    if (!offered.has(key)) continue;
    if (choice === "upstream") applied.push(key);
    else if (choice === "mine") kept.push(key);
  }
  const rules: Record<string, unknown> = { ...input.mine };
  for (const key of applied) setOwn(rules, key, input.upstream[key]);
  const baseRules: Record<string, string> = input.base
    ? { ...input.base.rules }
    : { ...snapshotBase(input.upstream).rules };
  for (const key of [...applied, ...kept]) setOwn(baseRules, key, ruleHash(input.upstream[key]));
  return { rules, base: { revision: report.upstreamRevision, rules: baseRules }, applied, kept };
}
