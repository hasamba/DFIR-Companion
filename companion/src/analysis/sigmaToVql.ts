// Sigma → VQL (#797): a parsed rule becomes one VQL query, the same bytes every time.
//
// Design rules, in the order they bite:
//  1. One fixed template per logsource category (sigmaVqlTemplates.ts). No category, no VQL.
//  2. A field outside the template's map is a refusal, not a warning. The rule's meaning survives
//     intact or the rule does not compile.
//  3. Every string match is a case-insensitive RE2 regex (sigmaVqlValues.ts).
//  4. Each compiled source is one blank-line-free block — header comments, LET stages, one SELECT —
//     because launchHunt() splits statements on blank lines and drops comment lines.
//  5. A rule whose category template cannot answer every selection may still compile to several
//     such blocks, blank-line-separated, when its condition is a top-level `1 of …` / `or` of whole
//     selections and each one resolves against some template (#802): one source per category, which
//     the launcher packages into one hunt. A block moves to another category only on a field that
//     category owns (DestinationIp, TargetFilename…), never on the acting-process fields every Sigma
//     event carries. A `not` or an `and` across selections keeps the single-template path, where a
//     field outside that one template refuses by name, as it always has.
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
    if (!globs)
      throw new CompileRefusal(
        path,
        `'${value}' is rooted on a drive or a host, and ${mode} searches every folder of C: for it, where a rooted path can never appear; match it with startswith or exactly, or drop the root to hunt the fragment`,
      );
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
  if (fields.length === 0) {
    // The parser refuses this first (#806); here for a SigmaRule built without it, so `WHERE ()`
    // is never assembled.
    out.push({
      path: selPath,
      message: "this selection has no fields, so it matches nothing; give it at least one field",
    });
    return null;
  }
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

function assemble(
  template: VqlTemplate,
  rule: SigmaRule,
  where: string,
  needs: Needs,
  unreferenced: readonly string[] = [],
): SigmaCompiled {
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
    ...(unreferenced.length
      ? [`-- Not in the condition, so not in this hunt: ${unreferenced.map(oneLine).join(", ")}`]
      : []),
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

// ── Which selections the condition actually uses (#808) ──────────────────────────────────────

// A selection the condition never names is dead text: it must not add a glob root, a lookup stage
// or a word to the coverage sentence, or an unused `contains` block turns the hunt into a
// whole-disk walk the condition never asked for. It is still compiled, so a broken unused block
// refuses like any other — nothing half-understood is left in the rule — and the header names it.
function referencedSelectionNames(c: SigmaCondition, into = new Set<string>()): Set<string> {
  switch (c.kind) {
    case "ref":
      into.add(c.name);
      break;
    case "not":
      referencedSelectionNames(c.operand, into);
      break;
    case "and":
    case "or":
      for (const o of c.operands) referencedSelectionNames(o, into);
      break;
    case "oneOf":
    case "allOf":
      for (const n of c.names) into.add(n);
      break;
  }
  return into;
}

const unreferencedSelectionNames = (rule: SigmaRule): string[] => {
  const used = referencedSelectionNames(rule.detection.condition);
  return rule.detection.selections.map((s) => s.name).filter((n) => !used.has(n));
};

const mergeNeeds = (into: Needs, from: Needs): void => {
  for (const extra of from.extras) into.extras.add(extra);
  for (const g of from.globs) if (!into.globs.includes(g)) into.globs.push(g);
};

// ── Mixed-category rules: one source per category (#802) ─────────────────────────────────────

// Sigma puts the acting process on every event: a file write, a registry set and a connection all
// carry the Image (and User, ProcessId) that did it. A selection made only of those fields describes
// that process, not a process_creation event, so on its own it never moves a block to pslist(). A
// field that belongs to another category — DestinationIp, TargetFilename, TargetObject… — is what
// moves a block there.
const PROCESS_CONTEXT_FIELDS: ReadonlySet<string> = new Set(["image", "user", "processid"]);

const selectionFields = (sel: SigmaSelection): readonly SigmaFieldMatch[] =>
  sel.kind === "map" ? sel.fields : sel.kind === "list" ? sel.alternatives.flat() : [];

// The selection names a top-level `1 of …` / `or` ORs together whole, or null when the condition
// reaches deeper (a `not`, an `and`, or an `or` over anything but bare selection refs). Those rules
// stay on the single-template path, exactly as before.
function wholeSelectionNames(c: SigmaCondition): string[] | null {
  if (c.kind === "oneOf") return c.names;
  if (c.kind !== "or") return null;
  const names: string[] = [];
  for (const o of c.operands) {
    if (o.kind !== "ref") return null;
    names.push(o.name);
  }
  return names;
}

/** One selection compiled against one template: its WHERE fragment, or why the template refused. */
interface SelectionTrial {
  template: VqlTemplate;
  expr: string | null;
  needs: Needs;
  refusals: SigmaRefusal[];
  /** How many of the selection's fields this template knows at all (hint-only ones included). */
  known: number;
}

function trySelection(template: VqlTemplate, sel: SigmaSelection): SelectionTrial {
  const refusals: SigmaRefusal[] = [];
  const needs: Needs = { extras: new Set(), globs: [] };
  let expr = compileSelection(template, sel, needs, refusals);
  // A glob template with no root would run an empty glob() and return nothing, silently — the same
  // check compileSigmaToVql makes for the whole rule, here for one selection.
  if (expr !== null && template.globFrom && needs.globs.length === 0) {
    const source = Object.entries(template.fields).find(([, c]) => c.globSource)?.[0] ?? "a path";
    refusals.push({
      path: `detection.${sel.name}`,
      message: `no ${source} value to derive a path from; the hunt needs at least one to know where to look`,
    });
    expr = null;
  }
  const known = selectionFields(sel).filter((m) => templateField(template, m.field)).length;
  return { template, expr: refusals.length ? null : expr, needs, refusals, known };
}

// Resolve one selection: the first template in `order` (declared category first) that answers every
// field, subject to the process-context rule above. When none does, the refusal comes from the
// template that knows the most of its fields — so a DestinationHostname block gets netstat()'s hint
// ("use DestinationIp") rather than pslist()'s "no such column".
function resolveSelection(
  order: readonly VqlTemplate[],
  declared: VqlTemplate,
  sel: SigmaSelection,
): { ok: true; trial: SelectionTrial } | { ok: false; refusals: SigmaRefusal[] } {
  const trials = order.map((t) => trySelection(t, sel));
  const fields = selectionFields(sel);
  const contextOnly =
    fields.length > 0 && fields.every((m) => PROCESS_CONTEXT_FIELDS.has(m.field.toLowerCase()));
  for (const trial of trials) {
    if (trial.expr === null) continue;
    if (trial.template !== declared && contextOnly) continue;
    return { ok: true, trial };
  }
  if (contextOnly) {
    const category = declared.categories[0];
    return {
      ok: false,
      refusals: trials[0].refusals.map((r) => ({
        path: r.path,
        message: `${r.message}; on its own the field names the process behind a ${category} event, so it does not move this block to another source`,
      })),
    };
  }
  const closest = trials.reduce((best, t) => (t.known > best.known ? t : best), trials[0]);
  return { ok: false, refusals: closest.refusals };
}

// The mixed-category path, reachable only once the single-template compile has refused. Every
// selection the condition ORs together must resolve against some template, declared category first.
// When at least one resolves and another cannot, the refusals name only the blocks that cannot —
// the rest would have compiled as their own sources. When nothing resolves, or the condition is not
// a whole-selection OR, or every block lands on one template, null lets the single-template
// refusals stand: they are already right for a rule whose category is simply wrong.
function compileMultiSource(rule: SigmaRule, declared: VqlTemplate): SigmaCompileResult | null {
  const names = wholeSelectionNames(rule.detection.condition);
  if (!names) return null;
  const selections = new Map(rule.detection.selections.map((s) => [s.name, s]));
  const order = [declared, ...VQL_TEMPLATES.filter((t) => t !== declared)];

  const groups = new Map<VqlTemplate, { needs: Needs; parts: string[] }>();
  const unresolved: SigmaRefusal[] = [];
  let resolved = 0;
  for (const name of names) {
    const sel = selections.get(name);
    if (!sel) return null;
    const r = resolveSelection(order, declared, sel);
    if (!r.ok) {
      unresolved.push(...r.refusals);
      continue;
    }
    resolved++;
    let group = groups.get(r.trial.template);
    if (!group) {
      group = { needs: { extras: new Set(), globs: [] }, parts: [] };
      groups.set(r.trial.template, group);
    }
    group.parts.push(r.trial.expr as string);
    mergeNeeds(group.needs, r.trial.needs);
  }
  if (unresolved.length) return resolved ? { ok: false, refusals: unresolved } : null;
  if (groups.size < 2) return null;

  const unreferenced = unreferencedSelectionNames(rule);
  const sources = [...groups.entries()].map(([template, group]) => {
    const where = group.parts.length === 1 ? group.parts[0] : `(${group.parts.join(" OR ")})`;
    return assemble(template, rule, where, group.needs, unreferenced);
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
  const referenced = referencedSelectionNames(rule.detection.condition);
  for (const sel of rule.detection.selections) {
    // Every selection compiles (a broken one refuses), but only a selection the condition names
    // contributes its glob roots and lookup stages to the hunt (#808).
    const own: Needs = { extras: new Set(), globs: [] };
    const expr = compileSelection(template, sel, own, out);
    if (expr !== null) exprs.set(sel.name, expr);
    if (referenced.has(sel.name)) mergeNeeds(needs, own);
  }
  if (template.globFrom && needs.globs.length === 0 && out.length === 0) {
    const source = Object.entries(template.fields).find(([, c]) => c.globSource)?.[0] ?? "a path";
    out.push({
      path: "detection",
      message: `no ${source} value to derive a path from; the hunt needs at least one to know where to look`,
    });
  }
  // A selection the condition never names is left out of the hunt (#808). One that some template
  // could answer — a file block under a process rule — is not broken, so its refusal against the
  // declared template is dropped and only the header records it. One no template can answer is a
  // broken block and still refuses, on the single-template path and the mixed-category one alike,
  // which resolves only the named selections and would otherwise let it vanish.
  const unreferenced = unreferencedSelectionNames(rule);
  const order = [template, ...VQL_TEMPLATES.filter((t) => t !== template)];
  const belongsTo = (r: SigmaRefusal, n: string): boolean =>
    r.path === `detection.${n}` || r.path.startsWith(`detection.${n}.`);
  const ignorable = unreferenced.filter((n) => {
    const sel = rule.detection.selections.find((s) => s.name === n);
    return !!sel && resolveSelection(order, template, sel).ok;
  });
  const live = out.filter((r) => !ignorable.some((n) => belongsTo(r, n)));
  if (live.length) {
    const multi = compileMultiSource(rule, template);
    if (!multi) return { ok: false, refusals: live };
    const dead = live.filter((r) => unreferenced.some((n) => belongsTo(r, n)));
    if (!dead.length) return multi;
    return { ok: false, refusals: multi.ok ? dead : [...multi.refusals, ...dead] };
  }
  return assemble(template, rule, compileCondition(rule.detection.condition, exprs), needs, unreferenced);
}

/** Parse then compile. Parse refusals come back as they are; compile runs only on a parsed rule. */
export function compileSigmaText(text: string): SigmaCompileResult {
  const parsed = parseSigmaRule(text);
  if (!parsed.ok) return parsed;
  return compileSigmaToVql(parsed.rule);
}
