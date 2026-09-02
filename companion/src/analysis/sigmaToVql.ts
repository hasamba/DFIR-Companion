// Sigma → VQL (#797): a parsed rule becomes one VQL query, the same bytes every time.
//
// Design rules, in the order they bite:
//  1. One fixed template per logsource category (sigmaVqlTemplates.ts). No category, no VQL.
//  2. A field outside the template's map is a refusal, not a warning. The rule's meaning survives
//     intact or the rule does not compile.
//  3. Every string match is a case-insensitive RE2 regex (sigmaVqlValues.ts).
//  4. Each compiled source is one blank-line-free block — header comments, LET stages, one SELECT —
//     because launchHunt() splits statements on blank lines and drops comment lines. A rule whose
//     `logsource.category` template cannot answer every selection MAY still compile to several such
//     blocks, blank-line-separated, when its condition is a top-level `1 of …` / `or` of whole
//     selections and every selection resolves against SOME template (#802): one source per category,
//     packaged into a single hunt by the launcher that already splits on blank lines. A `not` or an
//     `and` reaching across selections keeps the rule on the single-template path, where a field
//     outside that one template still refuses by name, as it always has.
//
// Refusals mirror the parser's: every problem in one list, each at a YAML path, in a sentence for
// the analyst. Parse refusals stop the pipeline; compile refusals exist only for rules that parsed.

import { parseSigmaRule } from "./sigmaRule.js";
import type {
  SigmaCondition,
  SigmaFieldMatch,
  SigmaModifier,
  SigmaRefusal,
  SigmaRule,
  SigmaSelection,
} from "./sigmaRuleTypes.js";
import {
  CONTROL_CHAR_RE,
  fileGlob,
  re2Objection,
  registryPath,
  sigmaRegex,
  vqlString,
  vqlStringList,
  WHOLE_DISK_GLOB,
  type SigmaMatchMode,
} from "./sigmaVqlValues.js";
import {
  SIGMA_VQL_CATEGORIES,
  templateField,
  templateFieldNames,
  templateFor,
  VQL_TEMPLATES,
  type TemplateColumn,
  type VqlTemplate,
} from "./sigmaVqlTemplates.js";

export { SIGMA_VQL_CATEGORIES };

export interface SigmaCompiled {
  ok: true;
  vql: string;
  /** The header sentence: which plugin ran and what it covers, for the dashboard to show above the VQL. */
  coverage: string;
  title: string;
  id?: string;
  level?: string;
  mitreTechniques: string[];
  /** True when the VQL reads live state, so an empty result is not a miss (#803). */
  snapshot: boolean;
}

export type SigmaCompileResult = SigmaCompiled | { ok: false; refusals: SigmaRefusal[] };

const MATCH_MODES: Readonly<Record<string, SigmaMatchMode>> = {
  contains: "contains",
  startswith: "startswith",
  endswith: "endswith",
};
const NUMERIC_OPS: Readonly<Record<string, string>> = { gt: ">", gte: ">=", lt: "<", lte: "<=" };
const HASH_MEMBERS: Readonly<Record<string, string>> = {
  md5: "Hashes.MD5",
  sha1: "Hashes.SHA1",
  sha256: "Hashes.SHA256",
};

class CompileRefusal extends Error {
  constructor(
    readonly path: string,
    message: string,
  ) {
    super(message);
  }
}

/** What one field match needs from the template, gathered while compiling. */
interface Needs {
  extras: Set<NonNullable<TemplateColumn["needs"]>>;
  globs: string[];
}

const fieldKey = (m: SigmaFieldMatch): string =>
  m.modifiers.length ? `${m.field}|${m.modifiers.join("|")}` : m.field;

// ── One field ─────────────────────────────────────────────────────────────────────────────────

function matchMode(modifiers: readonly SigmaModifier[]): SigmaMatchMode | "re" | "cidr" | string {
  const op = modifiers.find((m) => m !== "all");
  if (!op) return "exact";
  return MATCH_MODES[op] ?? op;
}

function stringValue(path: string, v: string | number | boolean): string {
  if (typeof v === "boolean")
    throw new CompileRefusal(
      path,
      "a yes/no value has no column in this template; match a named field instead",
    );
  const s = String(v);
  if (CONTROL_CHAR_RE.test(s))
    throw new CompileRefusal(
      path,
      "the value holds a control character, which cannot be placed in a VQL string",
    );
  return s;
}

function stringComparison(
  path: string,
  column: string,
  mode: string,
  value: string | number | boolean,
): string {
  const s = stringValue(path, value);
  if (mode === "re") {
    const objection = re2Objection(s);
    if (objection) throw new CompileRefusal(path, objection);
    return `${column} =~ ${vqlString(s)}`;
  }
  return `${column} =~ ${vqlString(sigmaRegex(s, mode as SigmaMatchMode))}`;
}

function numberComparison(
  path: string,
  column: string,
  mode: string,
  value: string | number | boolean,
  field: string,
): string {
  if (typeof value !== "number")
    throw new CompileRefusal(path, `${field} is a number column and needs a number to compare against`);
  if (mode === "exact") return `${column} = ${value}`;
  const op = NUMERIC_OPS[mode];
  if (!op)
    throw new CompileRefusal(
      path,
      `${field} is a number column; the ${mode} modifier does not apply to a number`,
    );
  return `${column} ${op} ${value}`;
}

function hashesComparison(path: string, mode: string, value: string | number | boolean): string {
  const s = stringValue(path, value);
  const tagged = /^(md5|sha1|sha256|imphash)=(.*)$/i.exec(s);
  if (tagged) {
    const member = HASH_MEMBERS[tagged[1].toLowerCase()];
    if (!member)
      throw new CompileRefusal(path, `hash(path=Exe) has no ${tagged[1]} member; use md5, sha1 or sha256`);
    return stringComparison(path, member, mode, tagged[2]);
  }
  const all = Object.values(HASH_MEMBERS).map((m) => stringComparison(path, m, mode, s));
  return `(${all.join(" OR ")})`;
}

function oneComparison(
  path: string,
  name: string,
  column: TemplateColumn,
  mode: string,
  value: string | number | boolean,
): string {
  const expr = column.expr ?? name;
  switch (column.kind) {
    case "number":
      return numberComparison(path, expr, mode, value, name);
    case "hashes":
      return hashesComparison(path, mode, value);
    case "ip":
    case "string":
    case "hash": {
      if (mode === "cidr")
        throw new CompileRefusal(
          path,
          `the cidr modifier applies to an IP address column; ${name} is not one`,
        );
      if (NUMERIC_OPS[mode])
        throw new CompileRefusal(
          path,
          `the ${mode} modifier compares numbers; ${name} is not a number column`,
        );
      return stringComparison(path, expr, mode, value);
    }
  }
}

function compileField(template: VqlTemplate, selPath: string, m: SigmaFieldMatch, needs: Needs): string {
  const path = `${selPath}.${fieldKey(m)}`;
  const found = templateField(template, m.field);
  if (!found || found.column.hint) {
    throw new CompileRefusal(
      path,
      found?.column.hint ??
        `${m.field} has no column in the ${template.source} template; fields it knows: ${templateFieldNames(template).join(", ")}`,
    );
  }
  const { name, column } = found;
  if (column.needs) needs.extras.add(column.needs);
  const mode = matchMode(m.modifiers);
  if (column.globSource) collectGlobs(template, path, mode, m.values, needs);
  if (mode === "cidr") {
    if (column.kind !== "ip")
      throw new CompileRefusal(path, `the cidr modifier applies to an IP address column; ${name} is not one`);
    const ranges = m.values.map((v) => stringValue(path, v));
    const col = column.expr ?? name;
    // `all` means the address must sit inside EVERY range (nested ranges); one call per range, ANDed.
    if (m.modifiers.includes("all") && ranges.length > 1)
      return `(${ranges.map((r) => `cidr_contains(ip=${col}, ranges=${vqlStringList([r])})`).join(" AND ")})`;
    return `cidr_contains(ip=${col}, ranges=${vqlStringList(ranges)})`;
  }
  const parts = m.values.map((v) => oneComparison(path, name, column, mode, v));
  if (parts.length === 1) return parts[0];
  return `(${parts.join(m.modifiers.includes("all") ? " AND " : " OR ")})`;
}

// ── Globs for the file and registry templates ─────────────────────────────────────────────────

function collectGlobs(
  template: VqlTemplate,
  path: string,
  mode: string,
  values: readonly (string | number | boolean)[],
  needs: Needs,
): void {
  for (const raw of values) {
    const value = stringValue(path, raw);
    if (template.registry) {
      if (mode !== "exact" && mode !== "startswith") {
        throw new CompileRefusal(
          path,
          "a registry key must be given whole or as a prefix rooted in a hive (HKLM, HKCU, HKU, HKCR); anything looser would walk the whole registry",
        );
      }
      const rp = registryPath(value, mode);
      if (!rp)
        throw new CompileRefusal(
          path,
          `'${value}' is not rooted in a hive (HKLM, HKCU, HKU, HKCR), so the hunt would walk the whole registry`,
        );
      for (const g of rp.globs) if (!needs.globs.includes(g)) needs.globs.push(g);
      continue;
    }
    const globs = mode === "re" ? [WHOLE_DISK_GLOB] : fileGlob(value, mode as SigmaMatchMode);
    for (const g of globs) if (!needs.globs.includes(g)) needs.globs.push(g);
  }
}

// The registry accessor reports HKEY_LOCAL_MACHINE\…, so a TargetObject regex must match the full
// hive name too; the template's string comparison is rewritten through registryPath for that field.
function registryComparison(path: string, m: SigmaFieldMatch): string {
  const mode = matchMode(m.modifiers) as "exact" | "startswith";
  const parts = m.values.map((v) => {
    const rp = registryPath(stringValue(path, v), mode);
    if (!rp) throw new CompileRefusal(path, `'${String(v)}' is not rooted in a hive`);
    return `TargetObject =~ ${vqlString(`(?i)^${rp.regexBody}${mode === "exact" ? "$" : ""}`)}`;
  });
  return parts.length === 1 ? parts[0] : `(${parts.join(m.modifiers.includes("all") ? " AND " : " OR ")})`;
}

// ── Selections and the condition ──────────────────────────────────────────────────────────────

function compileFieldMap(
  template: VqlTemplate,
  selPath: string,
  fields: readonly SigmaFieldMatch[],
  needs: Needs,
  out: SigmaRefusal[],
): string | null {
  const parts: string[] = [];
  for (const m of fields) {
    try {
      const isRegistryKey = template.registry && m.field.toLowerCase() === "targetobject";
      if (isRegistryKey)
        collectGlobs(template, `${selPath}.${fieldKey(m)}`, matchMode(m.modifiers), m.values, needs);
      parts.push(
        isRegistryKey
          ? registryComparison(`${selPath}.${fieldKey(m)}`, m)
          : compileField(template, selPath, m, needs),
      );
    } catch (e) {
      if (e instanceof CompileRefusal) out.push({ path: e.path, message: e.message });
      else throw e;
    }
  }
  if (parts.length !== fields.length) return null;
  return parts.length === 1 ? parts[0] : `(${parts.join(" AND ")})`;
}

function compileSelection(
  template: VqlTemplate,
  sel: SigmaSelection,
  needs: Needs,
  out: SigmaRefusal[],
): string | null {
  const path = `detection.${sel.name}`;
  if (sel.kind === "keywords") {
    out.push({
      path,
      message: "a keyword list has no field to match against; name the field the keywords belong to",
    });
    return null;
  }
  if (sel.kind === "map") return compileFieldMap(template, path, sel.fields, needs, out);
  const alts = sel.alternatives.map((fields) => compileFieldMap(template, path, fields, needs, out));
  if (alts.some((a) => a === null)) return null;
  return alts.length === 1 ? alts[0] : `(${alts.join(" OR ")})`;
}

function compileCondition(c: SigmaCondition, exprs: ReadonlyMap<string, string>): string {
  const ref = (name: string): string => exprs.get(name) ?? `/* ${name} */`;
  switch (c.kind) {
    case "ref":
      return ref(c.name);
    case "not":
      return `NOT (${compileCondition(c.operand, exprs)})`;
    case "and":
      return `(${c.operands.map((o) => compileCondition(o, exprs)).join(" AND ")})`;
    case "or":
      return `(${c.operands.map((o) => compileCondition(o, exprs)).join(" OR ")})`;
    case "oneOf":
      return c.names.length === 1 ? ref(c.names[0]) : `(${c.names.map(ref).join(" OR ")})`;
    case "allOf":
      return c.names.length === 1 ? ref(c.names[0]) : `(${c.names.map(ref).join(" AND ")})`;
  }
}

// ── Assembly ──────────────────────────────────────────────────────────────────────────────────

const oneLine = (s: string): string =>
  s
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .replace(/"/g, "'")
    .trim();

function assemble(template: VqlTemplate, rule: SigmaRule, where: string, needs: Needs): SigmaCompiled {
  const coverage = template.coverage(needs.globs);
  const idPart = rule.id ? ` (${oneLine(rule.id)})` : "";
  const order: NonNullable<TemplateColumn["needs"]>[] = ["hash", "parent", "procLookup"];
  const used = order.filter((n) => needs.extras.has(n));
  const columns = [
    ...template.baseColumns,
    ...used.map((n) => template.extraColumns[n]).filter((c): c is string => !!c),
  ];
  const from = template.globFrom ? template.globFrom(needs.globs) : template.source;
  const lines = [
    `-- Sigma "${oneLine(rule.title)}"${idPart} → ${coverage}`,
    "-- Compiled by DFIR Companion from a Sigma rule; the same rule always yields this VQL",
    ...used.map((n) => template.extraStages[n]).filter((s): s is string => !!s),
    `LET ${template.stage} <= SELECT ${columns.join(", ")} FROM ${from}`,
    `SELECT * FROM ${template.stage}`,
    `WHERE ${where}`,
  ];
  return {
    ok: true,
    vql: lines.join("\n"),
    coverage,
    title: rule.title,
    ...(rule.id !== undefined ? { id: rule.id } : {}),
    ...(rule.level !== undefined ? { level: rule.level } : {}),
    mitreTechniques: [...rule.mitreTechniques],
    snapshot: template.snapshot,
  };
}

// ── Mixed-category rules: one source per category (#802) ─────────────────────────────────────

// The selection names a top-level "1 of …" / "or" condition names WHOLE, or null when the
// condition reaches deeper (a `not`, an `and`, or an `or` over anything but bare selection refs) —
// the cases the single-template path keeps handling exactly as it always has.
function wholeSelectionNames(c: SigmaCondition): string[] | null {
  if (c.kind === "oneOf") return c.names;
  if (c.kind === "or" && c.operands.every((o) => o.kind === "ref"))
    return c.operands.map((o) => (o as { kind: "ref"; name: string }).name);
  return null;
}

// Compile one selection against the first template (declared category first) that answers every
// field it uses. A glob template that resolves zero glob roots does not count as answering it — an
// empty glob() would silently return nothing (see the sibling check in compileSigmaToVql).
function bestTemplateFor(
  order: readonly VqlTemplate[],
  sel: SigmaSelection,
): { template: VqlTemplate; expr: string; needs: Needs } | null {
  for (const template of order) {
    const trialOut: SigmaRefusal[] = [];
    const trialNeeds: Needs = { extras: new Set(), globs: [] };
    const expr = compileSelection(template, sel, trialNeeds, trialOut);
    if (expr === null || trialOut.length) continue;
    if (template.globFrom && trialNeeds.globs.length === 0) continue;
    return { template, expr, needs: trialNeeds };
  }
  return null;
}

// Try the mixed-category path: only reachable once the single-template compile has already failed.
// Every selection the condition names whole must resolve against some template, declared category
// preferred, or this returns null and the original single-template refusals stand — they are
// already correct for a genuine capability gap (e.g. no template has a hostname column) and for a
// condition this function does not touch (`not` / `and` across selections).
function compileMultiSource(rule: SigmaRule): SigmaCompiled | null {
  const names = wholeSelectionNames(rule.detection.condition);
  if (!names) return null;
  const selections = new Map(rule.detection.selections.map((s) => [s.name, s]));
  const declared = templateFor(rule.logsource.category);
  const order = declared ? [declared, ...VQL_TEMPLATES.filter((t) => t !== declared)] : VQL_TEMPLATES;

  const groups = new Map<VqlTemplate, { needs: Needs; parts: string[] }>();
  for (const name of names) {
    const sel = selections.get(name);
    if (!sel) return null;
    const best = bestTemplateFor(order, sel);
    if (!best) return null;
    let group = groups.get(best.template);
    if (!group) {
      group = { needs: { extras: new Set(), globs: [] }, parts: [] };
      groups.set(best.template, group);
    }
    group.parts.push(best.expr);
    for (const extra of best.needs.extras) group.needs.extras.add(extra);
    for (const g of best.needs.globs) if (!group.needs.globs.includes(g)) group.needs.globs.push(g);
  }
  if (groups.size < 2) return null; // one category throughout — the single-template refusal stands

  const sources = [...groups.entries()].map(([template, group]) => {
    const where = group.parts.length === 1 ? group.parts[0] : `(${group.parts.join(" OR ")})`;
    return assemble(template, rule, where, group.needs);
  });
  return {
    ok: true,
    vql: sources.map((s) => s.vql).join("\n\n"),
    coverage: sources.map((s) => s.coverage).join("; "),
    title: rule.title,
    ...(rule.id !== undefined ? { id: rule.id } : {}),
    ...(rule.level !== undefined ? { level: rule.level } : {}),
    mitreTechniques: [...rule.mitreTechniques],
    snapshot: sources.some((s) => s.snapshot),
  };
}

/** Compile a parsed rule. Pure and deterministic; never throws on input. */
export function compileSigmaToVql(rule: SigmaRule): SigmaCompileResult {
  const template = templateFor(rule.logsource.category);
  if (!template) {
    const supported = `supported categories: ${SIGMA_VQL_CATEGORIES.join(", ")}`;
    const message = rule.logsource.category
      ? `the ${rule.logsource.category} category has no VQL template; ${supported}`
      : `logsource.category is required to pick a VQL template; ${supported}`;
    return { ok: false, refusals: [{ path: "logsource.category", message }] };
  }
  const product = rule.logsource.product?.trim();
  if (product && product.toLowerCase() !== "windows") {
    return {
      ok: false,
      refusals: [
        {
          path: "logsource.product",
          message: `the ${product} product has no VQL template; every template is a Windows plugin with Windows path roots, so only product: windows (or no product) compiles`,
        },
      ],
    };
  }
  const out: SigmaRefusal[] = [];
  const needs: Needs = { extras: new Set(), globs: [] };
  const exprs = new Map<string, string>();
  for (const sel of rule.detection.selections) {
    const expr = compileSelection(template, sel, needs, out);
    if (expr !== null) exprs.set(sel.name, expr);
  }
  if (template.globFrom && needs.globs.length === 0 && out.length === 0) {
    const source = Object.entries(template.fields).find(([, c]) => c.globSource)?.[0] ?? "a path";
    out.push({
      path: "detection",
      message: `no ${source} value to derive a path from; the hunt needs at least one to know where to look`,
    });
  }
  if (out.length) return compileMultiSource(rule) ?? { ok: false, refusals: out };
  return assemble(template, rule, compileCondition(rule.detection.condition, exprs), needs);
}

/** Parse then compile. Parse refusals come back as they are; compile runs only on a parsed rule. */
export function compileSigmaText(text: string): SigmaCompileResult {
  const parsed = parseSigmaRule(text);
  if (!parsed.ok) return parsed;
  return compileSigmaToVql(parsed.rule);
}
