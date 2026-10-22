// Analyst exclusions for Sigma rules (#2218): keep a rule on, but skip records whose field holds a
// known-benign value in this environment (a backup role's ARN, a scanner's address). Persisted in
// <dataRoot>/sigma/exclusions.yml beside disabled.yml; server-wide, like the disabled list.
//
// One exclusion = rule id + field + value + reason. Several for one rule are OR-ed. The value uses
// Sigma's own exact-match semantics (case-insensitive, `*` / `?` wildcards, `\*` escapes), and the
// field is read through the log source's resolver, so `userIdentity.arn` resolves the way a rule
// field does. A truncated lookup never suppresses a match: an exclusion that cannot be proven must
// not hide a hit (the "definite only" stance of sigmaMatch.ts).
//
// The file is analyst-editable, so every entry is checked on load; a bad entry is dropped and a
// broken file loads as empty. Nothing here throws.

import { createHash } from "node:crypto";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { stringTest, type SigmaFieldResolver } from "./sigmaMatch.js";

type Row = Record<string, unknown>;

export const SIGMA_EXCLUSION_LIMITS = { id: 200, field: 200, value: 500, reason: 300, count: 1000 } as const;
const DEFAULT_REASON = "excluded by the analyst";

export interface SigmaExclusion {
  /** The Sigma rule id the exclusion belongs to. */
  id: string;
  field: string;
  value: string;
  reason: string;
}

/** What matching needs from one exclusion. The reason never changes a match. */
export interface SigmaExclusionSpec {
  field: string;
  value: string;
}

export interface CompiledSigmaExclusion extends SigmaExclusionSpec {
  test: (text: string) => boolean;
}

/** One rule, field and value names one exclusion. Letter case is ignored, as matching ignores it. */
export const sigmaExclusionKey = (e: { id: string; field: string; value: string }): string =>
  `${e.id}\0${e.field.toLowerCase()}\0${e.value.toLowerCase()}`;

const cleanPart = (v: unknown, max: number): string | undefined => {
  if (typeof v !== "string") return undefined;
  const t = v.trim();
  return t && t.length <= max ? t : undefined;
};

/** One checked entry, or undefined when any part is missing, empty, not a string or too long. */
export function checkSigmaExclusion(raw: unknown): SigmaExclusion | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const r = raw as Record<string, unknown>;
  const id = cleanPart(r.id, SIGMA_EXCLUSION_LIMITS.id);
  const field = cleanPart(r.field, SIGMA_EXCLUSION_LIMITS.field);
  const value = cleanPart(r.value, SIGMA_EXCLUSION_LIMITS.value);
  if (!id || !field || !value) return undefined;
  const reason =
    typeof r.reason === "string" && r.reason.trim()
      ? r.reason.trim().slice(0, SIGMA_EXCLUSION_LIMITS.reason)
      : DEFAULT_REASON;
  return { id, field, value, reason };
}

/** The exclusions in an exclusions.yml text. Never throws; the first of duplicates wins. */
export function parseSigmaExclusions(text: string): SigmaExclusion[] {
  let doc: unknown;
  try {
    doc = parseYaml(text);
  } catch {
    return [];
  }
  const list = (doc as { exclusions?: unknown } | null)?.exclusions;
  if (!Array.isArray(list)) return [];
  const seen = new Set<string>();
  const out: SigmaExclusion[] = [];
  for (const raw of list) {
    const e = checkSigmaExclusion(raw);
    if (!e || seen.has(sigmaExclusionKey(e))) continue;
    seen.add(sigmaExclusionKey(e));
    out.push(e);
    if (out.length >= SIGMA_EXCLUSION_LIMITS.count) break;
  }
  return out;
}

export function stringifySigmaExclusions(list: readonly SigmaExclusion[]): string {
  return stringifyYaml({
    exclusions: list.map(({ id, field, value, reason }) => ({ id, field, value, reason })),
  });
}

/** Rule id → its exclusions, in list order. */
export function exclusionsByRule(list: readonly SigmaExclusion[]): Map<string, SigmaExclusionSpec[]> {
  const out = new Map<string, SigmaExclusionSpec[]>();
  for (const e of list) out.set(e.id, [...(out.get(e.id) ?? []), { field: e.field, value: e.value }]);
  return out;
}

/**
 * First 8 hex of a SHA-256 over the sorted rule id / field / value triples ("none" when empty).
 * It joins the provenance token, so two imports graded under different exclusions never share one.
 */
export function sigmaExclusionsHash(byRule: ReadonlyMap<string, readonly SigmaExclusionSpec[]>): string {
  const keys = [...byRule].flatMap(([id, specs]) => specs.map((s) => sigmaExclusionKey({ id, ...s })));
  if (keys.length === 0) return "none";
  return createHash("sha256")
    .update([...new Set(keys)].sort().join("\n"))
    .digest("hex")
    .slice(0, 8);
}

export function compileSigmaExclusions(
  byRule: ReadonlyMap<string, readonly SigmaExclusionSpec[]>,
): Map<string, CompiledSigmaExclusion[]> {
  return new Map(
    [...byRule].map(([id, specs]) => [id, specs.map((s) => ({ ...s, test: stringTest(s.value, "exact") }))]),
  );
}

/** True only when a retained, complete value of some exclusion's field passes its test. */
export function isSigmaExcluded(
  record: Row,
  resolve: SigmaFieldResolver,
  exclusions: readonly CompiledSigmaExclusion[] | undefined,
): boolean {
  if (!exclusions?.length) return false;
  return exclusions.some((x) => {
    const lookup = resolve(record, x.field);
    if (lookup.incomplete) return false;
    return lookup.values.some((v) => v !== null && x.test(v));
  });
}
