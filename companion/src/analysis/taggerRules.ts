// Content-based event tagger — the PURE rule layer (Timesketch tagger analyzer, ported to
// Companion's typed event model). Timesketch matches Elasticsearch/Plaso docs with a Lucene
// query_string (`source_short:REG AND key_path:*ProfileList*`); a Companion ForensicEvent is a
// typed struct, so rules match against its REAL fields instead. That is deliberate: a rule that
// references a field the model does not have is a LOAD ERROR here, never a silent no-op.
//
// This module is pure + table-driven + unit-tested (mirrors tradecraftRules.ts). Zod validates and
// COMPILES a ruleset (precompiling every regex once); matchEvent() then evaluates a compiled rule
// against one event. I/O (reading the YAML file) lives in taggerStore.ts; the runner that applies
// matches to a case lives in tagger.ts.

import { z } from "zod";
import type { ForensicEvent, Severity } from "./stateTypes.js";

// The ForensicEvent fields a rule may match against, grouped by runtime kind so the matcher knows
// how to extract comparable strings. Only fields that carry analyst-meaningful CONTENT are exposed
// (ids, timestamps, screenshot refs and nested objects are intentionally omitted). Extending the
// event model with a new content field is the one reason to touch this list.
const STRING_FIELDS = [
  "description", "message", "asset", "path", "artifactName",
  "processName", "parentName", "sha256", "md5", "srcIp", "dstIp", "veloUrl", "severity", "action",
] as const;
const ARRAY_FIELDS = ["sources", "mitreTechniques", "relatedFindingIds", "provenance"] as const;
const NUMBER_FIELDS = ["port", "pid", "count"] as const;

/** Every field a tagger condition may reference. An unknown field fails validation. */
export const MATCHABLE_FIELDS: readonly string[] = [
  ...STRING_FIELDS, ...ARRAY_FIELDS, ...NUMBER_FIELDS,
];
const MATCHABLE_SET = new Set(MATCHABLE_FIELDS);
const ARRAY_SET = new Set<string>(ARRAY_FIELDS);
const NUMBER_SET = new Set<string>(NUMBER_FIELDS);

// Per-field character cap on the text a condition scans. `message` can hold an entire PowerShell
// ScriptBlock; capping bounds both regex cost (ReDoS safety, alongside the "no nested quantifiers"
// discipline in tradecraftRules.ts) and needless work on pathological inputs.
export const FIELD_SCAN_CAP = 16_384;

export const SEVERITIES: readonly Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

// ── Raw (YAML) schema ──────────────────────────────────────────────────────────────────────────
// A single condition names one field and exactly one operator.
const stringOrList = z.union([z.string(), z.array(z.string())]);

const rawConditionSchema = z
  .object({
    field: z.string(),
    contains: stringOrList.optional(),
    equals: stringOrList.optional(),
    regex: z.string().optional(),
    flags: z.string().optional(),
    exists: z.boolean().optional(),
  })
  .strict()
  .superRefine((c, ctx) => {
    if (!MATCHABLE_SET.has(c.field)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `unknown field "${c.field}" — matchable fields: ${MATCHABLE_FIELDS.join(", ")}`,
      });
    }
    const ops = ["contains", "equals", "regex", "exists"].filter((k) => (c as Record<string, unknown>)[k] !== undefined);
    if (ops.length !== 1) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `condition on "${c.field}" needs exactly one operator (contains | equals | regex | exists); got ${ops.length}`,
      });
    }
    if (c.flags !== undefined && c.regex === undefined) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: `"flags" is only valid with "regex"` });
    }
    if (c.regex !== undefined) {
      try {
        new RegExp(c.regex, c.flags);
      } catch (err) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `invalid regex: ${(err as Error).message}` });
      }
    }
  });

const rawRuleSchema = z
  .object({
    description: z.string().optional(),
    any: z.array(rawConditionSchema).optional(),
    all: z.array(rawConditionSchema).optional(),
    none: z.array(rawConditionSchema).optional(),
    tags: z.array(z.string()).optional(),
    mitre: z.array(z.string()).optional(),
    severity: z.enum(["Critical", "High", "Medium", "Low", "Info"]).optional(),
    view: z.string().optional(),
  })
  .strict()
  .superRefine((r, ctx) => {
    const hasCondition = (r.any?.length ?? 0) + (r.all?.length ?? 0) + (r.none?.length ?? 0) > 0;
    if (!hasCondition) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "rule needs at least one condition (any | all | none)" });
    }
    const hasAction = (r.tags?.length ?? 0) + (r.mitre?.length ?? 0) > 0 || r.severity !== undefined || (r.view?.length ?? 0) > 0;
    if (!hasAction) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "rule needs at least one action (tags | mitre | severity | view)" });
    }
  });

/** The ruleset as authored: a map of rule id → rule. */
export const rawRulesetSchema = z.record(rawRuleSchema);
export type RawRule = z.infer<typeof rawRuleSchema>;
export type RawRuleset = z.infer<typeof rawRulesetSchema>;

// ── Compiled form ────────────────────────────────────────────────────────────────────────────
type Operator =
  | { kind: "contains"; needles: string[] }        // lowercased
  | { kind: "equals"; needles: string[] }           // lowercased
  | { kind: "regex"; re: RegExp }
  | { kind: "exists"; want: boolean };

interface CompiledCondition {
  field: string;
  op: Operator;
}

export interface CompiledRule {
  id: string;
  description?: string;
  all: CompiledCondition[];
  any: CompiledCondition[];
  none: CompiledCondition[];
  tags: string[];
  mitre: string[];
  severity?: Severity;
  view?: string;
}

export interface CompiledRuleset {
  rules: CompiledRule[];
}

function asList(v: string | string[]): string[] {
  return Array.isArray(v) ? v : [v];
}

function compileCondition(c: z.infer<typeof rawConditionSchema>): CompiledCondition {
  let op: Operator;
  if (c.contains !== undefined) op = { kind: "contains", needles: asList(c.contains).map((s) => s.toLowerCase()) };
  else if (c.equals !== undefined) op = { kind: "equals", needles: asList(c.equals).map((s) => s.toLowerCase()) };
  else if (c.regex !== undefined) op = { kind: "regex", re: new RegExp(c.regex, c.flags) };
  else op = { kind: "exists", want: c.exists ?? true };
  return { field: c.field, op };
}

/**
 * Validate + compile a raw ruleset (precompiling regexes). Throws a ZodError describing every
 * problem (unknown field, bad operator count, invalid regex/severity, missing condition/action) —
 * an invalid ruleset must never partially load.
 */
export function compileRuleset(raw: unknown): CompiledRuleset {
  const result = rawRulesetSchema.safeParse(raw);
  if (!result.success) {
    // Flatten Zod issues into a concise, human-readable message (rule id + path → problem) instead
    // of leaking the raw ZodError JSON to the dashboard/editor.
    const lines = result.error.issues.map((i) => {
      const where = i.path.length ? i.path.join(".") : "(ruleset)";
      return `• ${where}: ${i.message}`;
    });
    throw new Error(`invalid tagger ruleset:\n${lines.join("\n")}`);
  }
  const parsed = result.data;
  const rules: CompiledRule[] = Object.entries(parsed).map(([id, r]) => ({
    id,
    description: r.description,
    all: (r.all ?? []).map(compileCondition),
    any: (r.any ?? []).map(compileCondition),
    none: (r.none ?? []).map(compileCondition),
    tags: r.tags ?? [],
    mitre: r.mitre ?? [],
    severity: r.severity,
    view: r.view,
  }));
  return { rules };
}

// Extract the comparable strings for a field: array fields yield one string per element, scalars a
// single string, numbers their decimal form. Each string is capped (ReDoS/perf). Absent/empty → [].
function fieldValues(event: ForensicEvent, field: string): string[] {
  const raw = (event as unknown as Record<string, unknown>)[field];
  if (raw === undefined || raw === null) return [];
  const cap = (s: string): string => (s.length > FIELD_SCAN_CAP ? s.slice(0, FIELD_SCAN_CAP) : s);
  if (ARRAY_SET.has(field)) {
    if (!Array.isArray(raw)) return [];
    return raw.map((x) => cap(String(x))).filter((s) => s.length > 0);
  }
  if (NUMBER_SET.has(field)) {
    return Number.isFinite(raw as number) ? [String(raw)] : [];
  }
  const s = cap(String(raw));
  return s.length > 0 ? [s] : [];
}

function conditionMatches(event: ForensicEvent, cond: CompiledCondition): boolean {
  const values = fieldValues(event, cond.field);
  switch (cond.op.kind) {
    case "exists":
      return cond.op.want ? values.length > 0 : values.length === 0;
    case "contains": {
      const needles = cond.op.needles;
      return values.some((v) => { const lv = v.toLowerCase(); return needles.some((n) => lv.includes(n)); });
    }
    case "equals": {
      const needles = cond.op.needles;
      return values.some((v) => { const lv = v.toLowerCase(); return needles.some((n) => lv === n); });
    }
    case "regex": {
      const re = cond.op.re;
      // Reset lastIndex defensively in case a global flag was supplied.
      re.lastIndex = 0;
      return values.some((v) => re.test(v));
    }
  }
}

/** Whether an event satisfies a compiled rule: all `all` match, ≥1 `any` matches, no `none` matches. */
export function matchEvent(event: ForensicEvent, rule: CompiledRule): boolean {
  if (!rule.all.every((c) => conditionMatches(event, c))) return false;
  if (rule.any.length > 0 && !rule.any.some((c) => conditionMatches(event, c))) return false;
  if (rule.none.some((c) => conditionMatches(event, c))) return false;
  return true;
}
