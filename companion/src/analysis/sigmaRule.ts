// Sigma rule → typed detection (#796). Deterministic, pure, no I/O, no AI.
//
// The contract: a rule the Companion understands in full becomes a SigmaRule; anything else comes
// back as the COMPLETE list of what it cannot express, each entry at a YAML path, in a sentence an
// analyst can act on. Nothing is guessed and nothing is dropped — a modifier or construct outside
// the supported set is a refusal, never a best-effort translation. The dashboard (#798) shows these
// lines as written, so they are worded for the analyst, not for a developer.
//
// A Sigma rule is imported content and can be adversary-authored (pasted from a shared repo), so
// sizes are capped before parsing and every `re` value goes through checkRegexSafety.

import { parseAllDocuments } from "yaml";
import { checkRegexSafety } from "./regexSafety.js";
import { parseSigmaCondition } from "./sigmaCondition.js";
import {
  SIGMA_MODIFIERS,
  type SigmaFieldMatch,
  type SigmaLogsource,
  type SigmaModifier,
  type SigmaParseResult,
  type SigmaRefusal,
  type SigmaRule,
  type SigmaScalar,
  type SigmaSelection,
} from "./sigmaRuleTypes.js";

// Mirrors huntQueryParser.ts (MAX_QUERY_LENGTH 20 000 chars, MAX_REGEX_LENGTH 256): a Sigma rule
// carries a whole detection, so it gets a larger text budget, and the same regex budget.
export const SIGMA_MAX_RULE_BYTES = 64 * 1024;
export const SIGMA_MAX_SELECTIONS = 50;
export const SIGMA_MAX_VALUES_PER_SELECTION = 200;
export const SIGMA_MAX_REGEX_LENGTH = 256;

const NUMERIC_MODIFIERS: ReadonlySet<SigmaModifier> = new Set(["gt", "gte", "lt", "lte"]);
const CIDR_RE = /^[0-9a-fA-F.:]+\/\d{1,3}$/;
const ATTACK_TECHNIQUE_TAG = /^attack\.(t\d{4}(?:\.\d{3})?)$/i;

type Plain = Record<string, unknown>;

const isPlain = (v: unknown): v is Plain => v !== null && typeof v === "object" && !Array.isArray(v);
const isScalar = (v: unknown): v is SigmaScalar =>
  typeof v === "string" || typeof v === "number" || typeof v === "boolean";

/** Collects refusals in document order; a rule is returned only when this stays empty. */
class Refusals {
  readonly list: SigmaRefusal[] = [];
  add(path: string, message: string): void {
    this.list.push({ path, message });
  }
}

// ── YAML boundary ─────────────────────────────────────────────────────────────────────────────

function readDocument(text: string, out: Refusals): Plain | null {
  if (Buffer.byteLength(text, "utf8") > SIGMA_MAX_RULE_BYTES) {
    out.add(
      "yaml",
      `the rule text is too large (over ${SIGMA_MAX_RULE_BYTES / 1024} KB); a Sigma rule is a few hundred bytes`,
    );
    return null;
  }
  const docs = parseAllDocuments(text).filter((d) => d.contents !== null);
  if (docs.length > 1) {
    out.add("yaml", "the text holds more than one YAML document; paste one rule per file");
    return null;
  }
  const doc = docs[0];
  if (!doc) {
    out.add("yaml", "the text is empty; paste one Sigma rule");
    return null;
  }
  if (doc.errors.length) {
    out.add("yaml", `the YAML does not parse: ${doc.errors[0].message.split("\n")[0]}`);
    return null;
  }
  let value: unknown;
  try {
    value = doc.toJS();
  } catch (error) {
    // The yaml package guards itself against anchor/alias expansion bombs by THROWING from toJS()
    // (doc.errors stays empty for that payload — #805). Adversary-authored input is a refusal.
    const reason = error instanceof Error ? error.message.split("\n")[0] : String(error);
    out.add(
      "yaml",
      `the YAML is too complex to read (the parser stopped it: ${reason}); paste a plain Sigma rule without anchors or aliases`,
    );
    return null;
  }
  if (!isPlain(value)) {
    out.add("yaml", "the rule must be a YAML map with title, logsource and detection keys");
    return null;
  }
  return value;
}

// ── Metadata ──────────────────────────────────────────────────────────────────────────────────

function readString(doc: Plain, key: string, out: Refusals): string | undefined {
  const v = doc[key];
  if (v === undefined || v === null) return undefined;
  if (!isScalar(v)) {
    out.add(key, `${key} must be a single value, not a list or a map`);
    return undefined;
  }
  return String(v);
}

function readTags(doc: Plain, out: Refusals): string[] {
  const raw = doc.tags;
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    out.add("tags", "tags must be a list");
    return [];
  }
  const tags: string[] = [];
  raw.forEach((t, i) => {
    if (typeof t === "string") tags.push(t);
    else out.add(`tags[${i}]`, "each tag must be a string");
  });
  return tags;
}

function techniquesFromTags(tags: readonly string[]): string[] {
  const out: string[] = [];
  for (const tag of tags) {
    const m = ATTACK_TECHNIQUE_TAG.exec(tag.trim());
    if (m) out.push(m[1].toUpperCase());
  }
  return out;
}

function readLogsource(doc: Plain, out: Refusals): SigmaLogsource | null {
  const raw = doc.logsource;
  if (!isPlain(raw)) {
    out.add("logsource", "logsource is required and must be a map (category / product / service)");
    return null;
  }
  const source: SigmaLogsource = {};
  for (const key of ["category", "product", "service"] as const) {
    const v = raw[key];
    if (v === undefined || v === null) continue;
    if (!isScalar(v)) out.add(`logsource.${key}`, `logsource.${key} must be a single value`);
    else source[key] = String(v);
  }
  return source;
}

// ── Detection: fields and selections ──────────────────────────────────────────────────────────

function readValues(path: string, raw: unknown, out: Refusals): SigmaScalar[] | null {
  if (raw === null || raw === undefined) {
    out.add(path, "a null value is not supported; give the field a value or remove the line");
    return null;
  }
  const items = Array.isArray(raw) ? raw : [raw];
  if (items.length === 0) {
    out.add(path, "the value list is empty");
    return null;
  }
  const values: SigmaScalar[] = [];
  for (const item of items) {
    if (!isScalar(item)) {
      out.add(
        path,
        item === null
          ? "a null value is not supported inside a value list"
          : "values must be strings, numbers or booleans, not maps or lists",
      );
      return null;
    }
    values.push(item);
  }
  return values;
}

function checkModifierValues(
  path: string,
  modifiers: readonly SigmaModifier[],
  values: readonly SigmaScalar[],
  out: Refusals,
): boolean {
  for (const mod of modifiers) {
    if (NUMERIC_MODIFIERS.has(mod) && !values.every((v) => typeof v === "number")) {
      out.add(path, `the ${mod} modifier needs a number to compare against`);
      return false;
    }
    if (mod === "cidr" && !values.every((v) => typeof v === "string" && CIDR_RE.test(v))) {
      out.add(path, "the cidr modifier needs a CIDR range such as 10.0.0.0/8");
      return false;
    }
    if (mod === "re" && !checkRegexValues(path, values, out)) return false;
  }
  return true;
}

function checkRegexValues(path: string, values: readonly SigmaScalar[], out: Refusals): boolean {
  for (const v of values) {
    const pattern = String(v);
    if (pattern.length > SIGMA_MAX_REGEX_LENGTH) {
      out.add(path, `a regular expression is limited to ${SIGMA_MAX_REGEX_LENGTH} characters`);
      return false;
    }
    // Sigma `re` values are RE2 and often open with an inline flag group, `(?i)…`, which the
    // JavaScript RegExp inside checkRegexSafety rejects as an invalid group. Lift the flags out
    // and hand them over separately; RE2's `U` (ungreedy) has no JS twin and is dropped for the
    // safety check only — the pattern itself reaches the endpoint unchanged.
    const inline = /^\(\?([imsU]+)\)/.exec(pattern);
    const body = inline ? pattern.slice(inline[0].length) : pattern;
    const flags = inline ? inline[1].replace(/U/g, "") : "";
    const safety = checkRegexSafety(body, flags);
    if (!safety.ok) {
      out.add(
        path,
        `the regular expression is not safe to run: ${safety.reason ?? "it can backtrack without bound"}`,
      );
      return false;
    }
  }
  return true;
}

function readFieldMatch(path: string, key: string, raw: unknown, out: Refusals): SigmaFieldMatch | null {
  const [field, ...mods] = key.split("|");
  const fieldPath = `${path}.${key}`;
  const modifiers: SigmaModifier[] = [];
  for (const mod of mods) {
    if ((SIGMA_MODIFIERS as readonly string[]).includes(mod)) modifiers.push(mod as SigmaModifier);
    else {
      out.add(
        fieldPath,
        `the ${mod} modifier is not supported; supported modifiers are ${SIGMA_MODIFIERS.join(", ")}`,
      );
      return null;
    }
  }
  const values = readValues(fieldPath, raw, out);
  if (!values) return null;
  if (!checkModifierValues(fieldPath, modifiers, values, out)) return null;
  return { field, modifiers, values };
}

function readFieldMap(path: string, raw: Plain, out: Refusals): SigmaFieldMatch[] {
  const fields: SigmaFieldMatch[] = [];
  for (const [key, value] of Object.entries(raw)) {
    const match = readFieldMatch(path, key, value, out);
    if (match) fields.push(match);
  }
  return fields;
}

function countValues(raw: unknown): number {
  if (Array.isArray(raw)) return raw.reduce<number>((n, item) => n + countValues(item), 0);
  if (isPlain(raw)) return Object.values(raw).reduce<number>((n, v) => n + countValues(v), 0);
  return 1;
}

// An empty map `{}` matches nothing in Sigma and would compile to `WHERE ()` (#806): refused here,
// before the compiler, so the analyst reads the reason at the selection that carries it.
const NO_FIELDS = "this selection has no fields, so it matches nothing; give it at least one field";

function readSelection(name: string, raw: unknown, out: Refusals): SigmaSelection | null {
  const path = `detection.${name}`;
  if (countValues(raw) > SIGMA_MAX_VALUES_PER_SELECTION) {
    out.add(path, `a selection is limited to ${SIGMA_MAX_VALUES_PER_SELECTION} values`);
    return null;
  }
  if (isPlain(raw)) {
    if (Object.keys(raw).length === 0) {
      out.add(path, NO_FIELDS);
      return null;
    }
    return { kind: "map", name, fields: readFieldMap(path, raw, out) };
  }
  if (!Array.isArray(raw) || raw.length === 0) {
    out.add(path, "a selection must be a map of fields, a list of such maps, or a list of keywords");
    return null;
  }
  if (raw.every(isPlain)) {
    const empty = raw.findIndex((m) => Object.keys(m).length === 0);
    if (empty >= 0) {
      out.add(`${path}[${empty}]`, NO_FIELDS.replace("this selection", "this entry of the selection list"));
      return null;
    }
    return { kind: "list", name, alternatives: raw.map((m) => readFieldMap(path, m, out)) };
  }
  if (raw.every(isScalar)) return { kind: "keywords", name, values: raw };
  out.add(path, "a selection list must not mix field maps with bare values");
  return null;
}

function readDetection(doc: Plain, out: Refusals): SigmaRule["detection"] | null {
  const raw = doc.detection;
  if (!isPlain(raw)) {
    out.add("detection", "detection is required and must be a map of selections plus a condition");
    return null;
  }
  const { condition, timeframe, ...blocks } = raw;
  if (timeframe !== undefined)
    out.add("detection.timeframe", "a timeframe is not supported; the hunt runs once, without a time window");
  const names = Object.keys(blocks);
  if (names.length > SIGMA_MAX_SELECTIONS) {
    out.add("detection", `a rule is limited to ${SIGMA_MAX_SELECTIONS} selections`);
    return null;
  }
  const selections: SigmaSelection[] = [];
  for (const name of names) {
    const sel = readSelection(name, blocks[name], out);
    if (sel) selections.push(sel);
  }
  if (typeof condition !== "string" || !condition.trim()) {
    out.add("detection.condition", "detection.condition is required and must be one line of text");
    return null;
  }
  const parsed = parseSigmaCondition(condition, names);
  if (!parsed.ok) {
    out.add("detection.condition", parsed.message);
    return null;
  }
  return { selections, condition: parsed.condition };
}

// ── Entry point ───────────────────────────────────────────────────────────────────────────────

/**
 * Parse one Sigma rule. Returns the typed rule, or every reason it cannot be expressed. Pure and
 * deterministic; never throws on input.
 */
export function parseSigmaRule(text: string): SigmaParseResult {
  const out = new Refusals();
  const doc = readDocument(text, out);
  if (!doc) return { ok: false, refusals: out.list };

  const title = readString(doc, "title", out);
  if (!title?.trim()) out.add("title", "title is required");
  const id = readString(doc, "id", out);
  const level = readString(doc, "level", out);
  const description = readString(doc, "description", out);
  const tags = readTags(doc, out);
  const logsource = readLogsource(doc, out);
  const detection = readDetection(doc, out);

  if (out.list.length || !title || !logsource || !detection) return { ok: false, refusals: out.list };
  return {
    ok: true,
    rule: {
      title,
      ...(id !== undefined ? { id } : {}),
      ...(level !== undefined ? { level } : {}),
      ...(description !== undefined ? { description } : {}),
      tags,
      mitreTechniques: techniquesFromTags(tags),
      logsource,
      detection,
    },
  };
}
