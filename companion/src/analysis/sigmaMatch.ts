// Sigma rule evaluation against one raw record, for the import-time engine (#2202). Deterministic,
// pure, no AI. The parser (sigmaRule.ts) decides what a rule means; this file decides whether one
// record satisfies it.
//
// Semantics, per the Sigma specification:
//   - string values compare case-insensitively; `*` and `?` are wildcards, `\*` `\?` `\\` are
//     their literal escapes, and any other backslash is itself;
//   - a value list is an OR, `|all` makes it an AND; a field matches when ANY value it reaches does;
//   - `re` is case-sensitive unless the pattern opens with `(?i)`; `cidr` covers IPv4 and IPv6;
//   - `field: null` matches an absent key or JSON null — never "" and never an empty list.
//
// Results are three-valued. A field lookup that hit its size bound answers "incomplete", and
// Kleene logic carries that through not / and / or, so only a definite `true` is ever a match.

import { BlockList, isIP } from "node:net";
import { lookupPath, recordText, type SigmaFieldLookup } from "./sigmaLookup.js";
import type {
  SigmaCondition,
  SigmaFieldMatch,
  SigmaRule,
  SigmaScalar,
  SigmaSelection,
} from "./sigmaRuleTypes.js";

export {
  lookupPath,
  SIGMA_LOOKUP_MAX_JSON_CHARS,
  SIGMA_LOOKUP_MAX_LEAVES,
  type SigmaFieldLookup,
} from "./sigmaLookup.js";

type Row = Record<string, unknown>;

export type SigmaTri = boolean | "incomplete";
export type SigmaFieldResolver = (record: Row, field: string) => SigmaFieldLookup;

export interface CompiledSigmaRule {
  readonly rule: SigmaRule;
  evaluate(record: Row, resolve: SigmaFieldResolver): SigmaTri;
}

type ValueTest = (text: string) => boolean;
type Mode = "exact" | "contains" | "startswith" | "endswith";

// ── Kleene three-valued logic ─────────────────────────────────────────────────────────────────

function and3(parts: Iterable<() => SigmaTri>): SigmaTri {
  let unknown = false;
  for (const part of parts) {
    const v = part();
    if (v === false) return false;
    if (v === "incomplete") unknown = true;
  }
  return unknown ? "incomplete" : true;
}

function or3(parts: Iterable<() => SigmaTri>): SigmaTri {
  let unknown = false;
  for (const part of parts) {
    const v = part();
    if (v === true) return true;
    if (v === "incomplete") unknown = true;
  }
  return unknown ? "incomplete" : false;
}

const not3 = (v: SigmaTri): SigmaTri => (v === "incomplete" ? v : !v);

// ── Value tests ───────────────────────────────────────────────────────────────────────────────

const REGEX_META = /[.+^${}()|[\]\\]/;

/** A Sigma string as a regex body plus whether it held a wildcard, escapes resolved. */
function globBody(value: string): { body: string; literal: string; wildcard: boolean } {
  let body = "";
  let literal = "";
  let wildcard = false;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    const next = value[i + 1];
    if (ch === "\\" && (next === "*" || next === "?" || next === "\\")) {
      body += "\\" + next;
      literal += next;
      i++;
    } else if (ch === "*" || ch === "?") {
      body += ch === "*" ? ".*" : ".";
      wildcard = true;
    } else {
      body += REGEX_META.test(ch) ? "\\" + ch : ch;
      literal += ch;
    }
  }
  return { body, literal, wildcard };
}

/** One Sigma string value as a test, in the given mode. Exported for analyst exclusions (#2218). */
export function stringTest(value: SigmaScalar, mode: Mode): ValueTest {
  const { body, literal, wildcard } = globBody(String(value));
  if (wildcard) {
    const anchored =
      mode === "exact"
        ? `^${body}$`
        : mode === "startswith"
          ? `^${body}`
          : mode === "endswith"
            ? `${body}$`
            : body;
    const re = new RegExp(anchored, "is");
    return (text) => re.test(text);
  }
  const want = literal.toLowerCase();
  if (mode === "exact") return (text) => text.toLowerCase() === want;
  if (mode === "contains") return (text) => text.toLowerCase().includes(want);
  if (mode === "startswith") return (text) => text.toLowerCase().startsWith(want);
  return (text) => text.toLowerCase().endsWith(want);
}

/** Sigma `re` values are RE2: lift a leading inline flag group and spell named groups the JS way. */
function regexTest(value: SigmaScalar): ValueTest {
  const pattern = String(value);
  const inline = /^\(\?([imsU]+)\)/.exec(pattern);
  const body = (inline ? pattern.slice(inline[0].length) : pattern).replace(/\(\?P</g, "(?<");
  const flags = [...new Set((inline?.[1] ?? "").replace(/U/g, ""))].join("");
  const re = new RegExp(body, flags);
  return (text) => re.test(text);
}

function cidrTest(value: SigmaScalar): ValueTest {
  const [addr, bits] = String(value).split("/");
  const family = isIP(addr) === 6 ? "ipv6" : "ipv4";
  const list = new BlockList();
  list.addSubnet(addr, Number(bits), family);
  return (text) => {
    const kind = isIP(text.trim());
    return kind !== 0 && list.check(text.trim(), kind === 6 ? "ipv6" : "ipv4");
  };
}

function numericTest(value: SigmaScalar, op: "gt" | "gte" | "lt" | "lte"): ValueTest {
  const want = Number(value);
  return (text) => {
    if (!text.trim()) return false;
    const n = Number(text);
    if (!Number.isFinite(n)) return false;
    return op === "gt" ? n > want : op === "gte" ? n >= want : op === "lt" ? n < want : n <= want;
  };
}

function valueTest(field: SigmaFieldMatch, value: SigmaScalar): ValueTest {
  const mods = field.modifiers;
  if (mods.includes("re")) return regexTest(value);
  if (mods.includes("cidr")) return cidrTest(value);
  for (const op of ["gt", "gte", "lt", "lte"] as const) if (mods.includes(op)) return numericTest(value, op);
  const mode: Mode = mods.includes("contains")
    ? "contains"
    : mods.includes("startswith")
      ? "startswith"
      : mods.includes("endswith")
        ? "endswith"
        : "exact";
  return stringTest(value, mode);
}

// ── Fields, selections, condition ─────────────────────────────────────────────────────────────

type FieldEval = (lookup: SigmaFieldLookup) => SigmaTri;

function compileField(field: SigmaFieldMatch): FieldEval {
  if (field.nullValue) {
    // Absent or JSON null. A retained non-null value settles it (false); otherwise a truncated
    // lookup cannot establish absence, so the answer is unknown, never a match (Codex review).
    return (l) => {
      if (l.values.some((v) => v !== null)) return false;
      if (l.incomplete) return "incomplete";
      return !l.present || l.values.length > 0;
    };
  }
  const tests = field.values.map((v) => valueTest(field, v));
  const all = field.modifiers.includes("all");
  return (l) => {
    const texts = l.values.filter((v): v is string => v !== null);
    const hit = (t: ValueTest) => texts.some(t);
    const matched = all ? tests.every(hit) : tests.some(hit);
    return matched ? true : l.incomplete ? "incomplete" : false;
  };
}

type SelectionEval = (record: Row, resolve: SigmaFieldResolver) => SigmaTri;

function compileFieldMap(fields: readonly SigmaFieldMatch[]): SelectionEval {
  const compiled = fields.map((f) => ({ name: f.field, run: compileField(f) }));
  return (record, resolve) => and3(compiled.map((c) => () => c.run(resolve(record, c.name))));
}

function compileSelection(sel: SigmaSelection): SelectionEval {
  if (sel.kind === "map") return compileFieldMap(sel.fields);
  if (sel.kind === "list") {
    const alts = sel.alternatives.map(compileFieldMap);
    return (record, resolve) => or3(alts.map((a) => () => a(record, resolve)));
  }
  const tests = sel.values.map((v) => stringTest(v, "contains"));
  return (record) => {
    const text = recordText(record);
    if (text === undefined) return "incomplete";
    return tests.some((t) => t(text));
  };
}

function evalCondition(cond: SigmaCondition, sel: (name: string) => SigmaTri): SigmaTri {
  switch (cond.kind) {
    case "ref":
      return sel(cond.name);
    case "not":
      return not3(evalCondition(cond.operand, sel));
    case "and":
      return and3(cond.operands.map((o) => () => evalCondition(o, sel)));
    case "or":
      return or3(cond.operands.map((o) => () => evalCondition(o, sel)));
    case "oneOf":
      return or3(cond.names.map((n) => () => sel(n)));
    case "allOf":
      return and3(cond.names.map((n) => () => sel(n)));
  }
}

/** Compile a parsed rule once; throws only when a `re` value is not a valid JS regex. */
export function compileSigmaRule(rule: SigmaRule): CompiledSigmaRule {
  const selections = new Map(rule.detection.selections.map((s) => [s.name, compileSelection(s)]));
  return {
    rule,
    evaluate(record, resolve) {
      const memo = new Map<string, SigmaTri>();
      const sel = (name: string): SigmaTri => {
        const known = memo.get(name);
        if (known !== undefined) return known;
        const run = selections.get(name);
        const v: SigmaTri = run ? run(record, resolve) : false;
        memo.set(name, v);
        return v;
      };
      return evalCondition(rule.detection.condition, sel);
    },
  };
}

/** The plain-path resolver: a field name is the path it names. */
export const plainResolver: SigmaFieldResolver = (record, field) => lookupPath(record, field);
