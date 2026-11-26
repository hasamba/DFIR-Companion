import { BlockList, isIP } from "node:net";
import { escapeRegExp } from "./regexEscape.js";
import type { AnonTokenCategory, CustomEntity } from "./anonymize.js";

// Custom-entity matching rules: the exact-value regex every known-value pass uses, plus the
// wildcard patterns and CIDR ranges an analyst can type into the custom list (#2946).

// Exact-match tokenizing of a KNOWN value (hostname, internal domain, analyst-added or
// Presidio-approved custom entity) needs a word boundary so "DC01" doesn't fire inside "DC01X"
// and "Jane" doesn't fire inside "Janes". JS `\b` CANNOT be used for that here: it is defined
// against ASCII `\w` ([A-Za-z0-9_]), so a value whose first or last character is outside that
// set — every Hebrew, Cyrillic, Greek, CJK or accented name, and anything starting with "+" —
// puts `\b` between two non-word characters, where it never matches. The value was then NEVER
// masked, silently and permanently: once approved it lives in known.custom, so the Presidio
// gate sees it as already-known and never asks again, and the analyst is told it is tokenized
// while it goes to the provider (and into the redacted export) in cleartext.
//
// The replacement is an explicit Unicode-aware boundary: refuse to match when the character
// immediately before/after is a letter, a number or "_" in ANY script. Unlike `\b` it is not a
// transition test, so a value whose own edge is a non-word character (".corp.local", "-corp")
// does not fire glued inside a longer word either. A suffix like that is what a wildcard
// pattern ("*.corp.local") is for. The `u` flag is safe with escapeRegExp — see regexEscape.ts.
export const UNICODE_WORD = "\\p{L}\\p{N}_";
export function exactValueRegExp(value: string): RegExp {
  return new RegExp(`(?<![${UNICODE_WORD}])${escapeRegExp(value)}(?![${UNICODE_WORD}])`, "giu");
}

const IP_CATEGORIES: ReadonlySet<AnonTokenCategory> = new Set(["IP", "EXTIP"]);
const MIN_PATTERN_LITERAL = 3;
const MIN_PREFIX = { 4: 8, 6: 16 } as const;
const MAX_PREFIX = { 4: 32, 6: 128 } as const;

// What one `*` may stand for, per category. A star never crosses whitespace, and never a
// sentinel ( IPv6 placeholder,  secret placeholder). Bounded so a 50k-character
// base64 run without whitespace costs a fixed amount per run, never a quadratic scan.
interface StarClass {
  cls: string; // the inside of a [...] character class
  max: number;
}
const HOSTISH: StarClass = { cls: "\\p{L}\\p{N}_.\\-", max: 253 };
const PATHISH: StarClass = { cls: "^\\s\"'<>|*?\\uE000\\uE001", max: 1024 };
const BROAD: StarClass = { cls: "^\\s\"'<>()\\[\\]{},;|\\uE000\\uE001", max: 1024 };
const STAR_CLASSES: Partial<Record<AnonTokenCategory, StarClass>> = {
  HOST: HOSTISH,
  DOMAIN: HOSTISH,
  EMAIL: { cls: "\\p{L}\\p{N}_.\\-+%@", max: 253 },
  USER: { cls: "\\p{L}\\p{N}_.\\-$@\\\\", max: 253 },
  PATH: PATHISH,
  REG: PATHISH,
};
const starClass = (category: AnonTokenCategory): StarClass => STAR_CLASSES[category] ?? BROAD;

/** Whether a typed value should be read as a pattern: any `*`, or a `/` in an IP category. */
export function isPatternShaped(value: string, category: AnonTokenCategory): boolean {
  return value.includes("*") || (IP_CATEGORIES.has(category) && value.includes("/"));
}

/** A parsed CIDR range, or a reason it is not one. */
export function parseCidr(value: string): { addr: string; prefix: number; family: 4 | 6 } | string {
  const m = /^([^/\s]+)\/(\d{1,3})$/.exec(value.trim());
  if (!m) return "Write the range as address/prefix, for example 10.20.0.0/16.";
  const family = isIP(m[1]);
  if (family !== 4 && family !== 6) return `${m[1]} is not a valid IPv4 or IPv6 address.`;
  const prefix = Number(m[2]);
  if (prefix > MAX_PREFIX[family]) return `/${prefix} is not a valid prefix for an IPv${family} address.`;
  if (prefix < MIN_PREFIX[family])
    return `A /${prefix} range is too wide. The widest allowed is /${MIN_PREFIX[family]} for IPv${family}.`;
  return { addr: m[1], prefix, family };
}

function wildcardProblem(value: string): string | null {
  if (!value.includes("*")) return "A pattern needs a * (for example prod-* or *-dev).";
  if (value.includes("**")) return "Two * in a row mean nothing more than one. Use a single *.";
  const literal = value.replace(/\*/g, "");
  if (literal.trim().length < MIN_PATTERN_LITERAL)
    return `A pattern needs at least ${MIN_PATTERN_LITERAL} characters besides *, or it would hide almost everything.`;
  if (!/[\p{L}\p{N}]/u.test(literal)) return "A pattern needs at least one letter or digit besides *.";
  if (/anon_/i.test(literal)) return "A pattern cannot contain ANON_: that is what masking tokens look like.";
  const interior = value.slice(1, -1).split("*").length - 1;
  if (interior > 1) return "Use at most one * in the middle of a pattern (one more at each end is fine).";
  return null;
}

/** Why a pattern entity cannot be saved, or null when it is valid. */
export function validatePatternEntity(e: CustomEntity): string | null {
  const value = e.value.trim();
  if (IP_CATEGORIES.has(e.category)) {
    if (value.includes("*")) return "Addresses take a CIDR range instead of *, for example 10.20.0.0/16.";
    const cidr = parseCidr(value);
    return typeof cidr === "string" ? cidr : null;
  }
  return wildcardProblem(value);
}

/** Where a wildcard match's star parts are trimmed back (a host at a sentence end, "(path)"). */
export const LEAD_TRIM = /^[.([{\-]+/u;
export const TRAIL_TRIM = /[.,;:)\]}\-]+$/u;

function splitPattern(value: string): { lead: boolean; trail: boolean; parts: string[] } {
  const lead = value.startsWith("*");
  const trail = value.length > 1 && value.endsWith("*");
  const core = value.slice(lead ? 1 : 0, trail ? -1 : undefined);
  return { lead, trail, parts: core.split("*") };
}

/**
 * The search regex for a valid wildcard pattern. A leading star starts only at the START of a run
 * of star characters (so a long run offers one start, not one per character) and a trailing star
 * is atomic (a lookahead capture, no backtracking). A side without a star keeps the exact-value
 * word boundary, so "prod-*" never fires inside "myprod-web01". Named groups l / t hold the star
 * parts so the caller can trim them.
 */
export function wildcardRegExp(value: string, category: AnonTokenCategory): RegExp {
  const { cls, max } = starClass(category);
  const C = `[${cls}]`;
  const { lead, trail, parts } = splitPattern(value.trim());
  const body = parts.map(escapeRegExp).join(`${C}{0,${max}}?`);
  const left = lead ? `(?<!${C})(?<l>${C}{0,${max}}?)` : `(?<![${UNICODE_WORD}])`;
  const right = trail ? `(?=(?<t>${C}{0,${max}}))\\k<t>(?!${C})` : `(?![${UNICODE_WORD}])`;
  return new RegExp(left + body + right, "giu");
}

function wholeRegExp(value: string, category: AnonTokenCategory): RegExp {
  const C = `[${starClass(category).cls}]`;
  const { lead, trail, parts } = splitPattern(value.trim());
  const body = parts.map(escapeRegExp).join(`${C}*`);
  return new RegExp(`^${lead ? `${C}*` : ""}${body}${trail ? `${C}*` : ""}$`, "iu");
}

/** Whether a whole value is covered by a valid pattern or range entity (counts, decisions). */
export function patternMatchesWhole(e: CustomEntity, value: string): boolean {
  if (e.match !== "pattern" || validatePatternEntity(e) !== null) return false;
  if (IP_CATEGORIES.has(e.category)) return cidrContains(e.value, value);
  return wholeRegExp(e.value, e.category).test(value.trim());
}

function cidrContains(range: string, ip: string): boolean {
  const cidr = parseCidr(range);
  const family = isIP(ip.trim());
  if (typeof cidr === "string" || family === 0) return false;
  return cidrBlock(cidr).check(ip.trim(), family === 6 ? "ipv6" : "ipv4");
}

export function cidrBlock(cidr: { addr: string; prefix: number; family: 4 | 6 }): BlockList {
  const block = new BlockList();
  block.addSubnet(cidr.addr, cidr.prefix, cidr.family === 4 ? "ipv4" : "ipv6");
  return block;
}

/** What the editor shows beside one pattern: how many known values it covers, or why it is broken. */
export interface PatternReport {
  value: string;
  category: AnonTokenCategory;
  count: number;
  sample: string[];
  invalid?: string;
}
export const PATTERN_SAMPLE_MAX = 50;

/**
 * For every pattern entity, the distinct known values of this case it covers (case-insensitive).
 * "Known" means values the case has already listed or masked — not every value that will ever
 * match — so the editor labels it as such.
 */
export function describeCustomPatterns(
  custom: readonly CustomEntity[],
  values: Iterable<string>,
): PatternReport[] {
  const distinct = new Map<string, string>();
  for (const v of values) if (v && !distinct.has(v.toLowerCase())) distinct.set(v.toLowerCase(), v);
  return custom
    .filter((e) => e.match === "pattern")
    .map((e) => {
      const invalid = validatePatternEntity(e);
      if (invalid) return { value: e.value, category: e.category, count: 0, sample: [], invalid };
      const hits = [...distinct.values()].filter((v) => patternMatchesWhole(e, v));
      return {
        value: e.value,
        category: e.category,
        count: hits.length,
        sample: hits.slice(0, PATTERN_SAMPLE_MAX),
      };
    });
}

/** The first pattern entity in a posted list that cannot be saved, with the reason. */
export function firstInvalidPattern(raw: unknown): { value: string; reason: string } | null {
  if (!Array.isArray(raw)) return null;
  for (const item of raw as Array<Partial<CustomEntity>>) {
    if (item?.match !== "pattern" || typeof item.value !== "string") continue;
    const reason = validatePatternEntity({
      value: item.value,
      category: item.category ?? "OTHER",
      match: "pattern",
    });
    if (reason) return { value: item.value.trim(), reason };
  }
  return null;
}
