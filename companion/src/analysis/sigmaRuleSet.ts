// The import-time Sigma rule set (#2202): which rules load for which log source, why every other
// rule did not, and the per-record match. Pure — rule texts come in as strings; the bundled
// files are read by sigmaBundledRules.ts.
//
// Every rule ends in exactly one inventory outcome, so the analyst can see what the engine runs:
//   loaded     — parsed, bound to a log source, every field mapped
//   status     — its status is not in the allowed list (default stable + test)
//   disabled   — on the Companion's (or, later, the analyst's) disabled list, with the reason
//   refused    — the parser refused it, it has no level, or a field is not mapped (sentences)
//   no-source  — its logsource is not one the Companion grades at import
//
// Matching is indexed: a rule whose condition REQUIRES a literal value on one of the source's
// index fields (eventName, OperationName) is only evaluated for records carrying that value.
// The index is a necessary condition, so it never changes which rules match — only how many run.

import { createHash } from "node:crypto";
import { compileSigmaRule, type CompiledSigmaRule, type SigmaFieldResolver } from "./sigmaMatch.js";
import {
  fieldResolvers,
  SIGMA_LOG_SOURCES,
  sourceResolver,
  type SigmaLogSourceDef,
} from "./sigmaLogSources.js";
import { parseSigmaRule } from "./sigmaRule.js";
import type { SigmaCondition, SigmaRule, SigmaSelection } from "./sigmaRuleTypes.js";

type Row = Record<string, unknown>;

/** Statuses loaded when the caller names none. `deprecated` / `unsupported` are never in a release. */
export const DEFAULT_SIGMA_STATUSES: readonly string[] = ["stable", "test"];
export const SIGMA_LEVELS = ["informational", "low", "medium", "high", "critical"] as const;
export type SigmaLevel = (typeof SIGMA_LEVELS)[number];

export interface SigmaRuleFile {
  /** Path relative to the release root, e.g. rules/cloud/aws/cloudtrail/x.yml. */
  path: string;
  text: string;
}

export interface SigmaReleaseMeta {
  release: string;
  commit: string;
}

/** What a match records about its rule — enough for the DRL (author, link) and the report. */
export interface SigmaRuleRef {
  id: string;
  title: string;
  level: SigmaLevel;
  status: string;
  author?: string;
  path: string;
  url: string;
  release: string;
  mitre: string[];
  /** The rule's own `modified` (or `date`) — versions the match (#2204). */
  modified?: string;
  /** Under rules-threat-hunting/: low-fidelity by design, so it only ever tags (#2204). */
  huntingOnly: boolean;
  /** Lower-cased field names the rule's detection reads (#2203: a rule that constrains sc-status). */
  fields?: string[];
}

/** The release folders a rule set is read from, in load order. */
export const SIGMA_RULE_DIRS = ["rules", "rules-emerging-threats", "rules-threat-hunting"] as const;
export const SIGMA_HUNTING_DIR = "rules-threat-hunting";

export type SigmaInventoryOutcome = "loaded" | "status" | "disabled" | "refused" | "no-source";

export interface SigmaInventoryEntry {
  path: string;
  id: string;
  title: string;
  outcome: SigmaInventoryOutcome;
  source?: string;
  reasons?: string[];
}

export interface LoadedSigmaRule {
  ref: SigmaRuleRef;
  compiled: CompiledSigmaRule;
  /** Load order, so matches always come back in the same order. */
  order: number;
}

interface SourceRules {
  def: SigmaLogSourceDef;
  resolve: SigmaFieldResolver;
  always: LoadedSigmaRule[];
  /** Lower-cased index field → lower-cased literal value → rules that require it. */
  index: Map<string, Map<string, LoadedSigmaRule[]>>;
}

export interface SigmaRuleSet {
  release: string;
  commit: string;
  /** Sentences about the folder itself (too many files, unreadable) — shown in status and logged. */
  problems: string[];
  /** The statuses this set was built with (lower-case). */
  statuses: string[];
  /** First 12 hex of a SHA-256 over every rule file's path and text: identifies the content. */
  contentSha: string;
  /** First 8 hex of a SHA-256 over the sorted disabled ids ("none" when empty). */
  disabledHash: string;
  inventory: SigmaInventoryEntry[];
  sources: ReadonlyMap<string, SourceRules>;
}

export interface SigmaRuleSetOptions {
  statuses?: readonly string[];
  /** Rule id → why it is off. */
  disabled?: ReadonlyMap<string, string>;
  sources?: readonly SigmaLogSourceDef[];
}

// ── Building ──────────────────────────────────────────────────────────────────────────────────

function ruleFields(rule: SigmaRule): string[] {
  return rule.detection.selections.flatMap((s) =>
    s.kind === "map"
      ? s.fields.map((f) => f.field)
      : s.kind === "list"
        ? s.alternatives.flat().map((f) => f.field)
        : [],
  );
}

/** Selections the top-level condition requires to be true. */
function requiredSelections(cond: SigmaCondition): string[] {
  if (cond.kind === "ref") return [cond.name];
  if (cond.kind === "allOf") return cond.names;
  if (cond.kind === "and")
    return cond.operands.flatMap((o) =>
      o.kind === "ref" || o.kind === "allOf" ? requiredSelections(o) : [],
    );
  return [];
}

/** The literal values one index field must hold for the rule to match, or null when none is required. */
function gateOf(rule: SigmaRule, def: SigmaLogSourceDef): { field: string; values: string[] } | null {
  const indexFields = new Set(def.indexFields.map((f) => f.toLowerCase()));
  const byName = new Map<string, SigmaSelection>(rule.detection.selections.map((s) => [s.name, s]));
  for (const name of requiredSelections(rule.detection.condition)) {
    const sel = byName.get(name);
    if (sel?.kind !== "map") continue;
    for (const f of sel.fields) {
      if (!indexFields.has(f.field.toLowerCase()) || f.modifiers.length || f.nullValue) continue;
      const literal = f.values.every((v) => typeof v !== "string" || !/[*?\\]/.test(v));
      if (literal)
        return { field: f.field.toLowerCase(), values: f.values.map((v) => String(v).toLowerCase()) };
    }
  }
  return null;
}

const asLevel = (level: string | undefined): SigmaLevel | undefined =>
  SIGMA_LEVELS.find((l) => l === level?.trim().toLowerCase());

type Classified = {
  entry: SigmaInventoryEntry;
  loaded?: { def: SigmaLogSourceDef; rule: LoadedSigmaRule; rawRule: SigmaRule };
};

function classify(
  file: SigmaRuleFile,
  meta: SigmaReleaseMeta,
  opts: Required<SigmaRuleSetOptions>,
): Classified {
  const parsed = parseSigmaRule(file.text, { allowNull: true });
  const base = { path: file.path, id: file.path, title: file.path };
  if (!parsed.ok)
    return {
      entry: { ...base, outcome: "refused", reasons: parsed.refusals.map((r) => `${r.path}: ${r.message}`) },
    };
  const rule = parsed.rule;
  const head = { path: file.path, id: rule.id ?? file.path, title: rule.title };
  const def = opts.sources.find((s) => s.matches(rule.logsource));
  if (!def) return { entry: { ...head, outcome: "no-source" } };
  const status = rule.status?.trim().toLowerCase() ?? "";
  if (!opts.statuses.includes(status))
    return {
      entry: { ...head, source: def.id, outcome: "status", reasons: [`status is ${status || "missing"}`] },
    };
  const off = opts.disabled.get(head.id);
  if (off !== undefined) return { entry: { ...head, source: def.id, outcome: "disabled", reasons: [off] } };
  const level = asLevel(rule.level);
  const reasons = level ? [] : [`the rule has no usable level (got ${rule.level ?? "none"})`];
  for (const field of new Set(ruleFields(rule))) {
    const r = fieldResolvers(def, field);
    if (!Array.isArray(r)) reasons.push(r.refused);
  }
  let compiled: CompiledSigmaRule | undefined;
  try {
    compiled = compileSigmaRule(rule);
  } catch (error) {
    reasons.push(
      `a regular expression does not compile: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (reasons.length || !compiled || !level)
    return { entry: { ...head, source: def.id, outcome: "refused", reasons } };
  const ref: SigmaRuleRef = {
    id: head.id,
    title: rule.title,
    level,
    status,
    ...(rule.author ? { author: rule.author } : {}),
    path: file.path,
    url: `https://github.com/SigmaHQ/sigma/blob/${meta.commit}/${file.path}`,
    release: meta.release,
    mitre: rule.mitreTechniques,
    ...(rule.modified || rule.date ? { modified: rule.modified ?? rule.date } : {}),
    huntingOnly: file.path.startsWith(`${SIGMA_HUNTING_DIR}/`),
    fields: [...new Set(ruleFields(rule).map((f) => f.toLowerCase()))],
  };
  const loadedRule = { ref, compiled, order: 0 };
  return {
    entry: { ...head, source: def.id, outcome: "loaded" },
    loaded: { def, rule: loadedRule, rawRule: rule },
  };
}

/** A content identity for a set of rule files, independent of their order. */
export function contentSha(files: readonly SigmaRuleFile[]): string {
  const hash = createHash("sha256");
  for (const f of [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)))
    hash.update(f.path).update("\0").update(f.text).update("\0");
  return hash.digest("hex").slice(0, 12);
}

function disabledHash(disabled: ReadonlyMap<string, string>): string {
  if (disabled.size === 0) return "none";
  return createHash("sha256")
    .update([...disabled.keys()].sort().join("\n"))
    .digest("hex")
    .slice(0, 8);
}

/** Build the rule set from rule texts. Never throws; every file lands in the inventory. */
export function buildSigmaRuleSet(
  files: readonly SigmaRuleFile[],
  meta: SigmaReleaseMeta,
  options: SigmaRuleSetOptions = {},
): SigmaRuleSet {
  const opts: Required<SigmaRuleSetOptions> = {
    statuses: (options.statuses ?? DEFAULT_SIGMA_STATUSES).map((s) => s.toLowerCase()),
    disabled: options.disabled ?? new Map(),
    sources: options.sources ?? SIGMA_LOG_SOURCES,
  };
  const sources = new Map<string, SourceRules>();
  const inventory: SigmaInventoryEntry[] = [];
  // A rule id names one rule. A later file reusing it is refused, so what loads is exactly what a
  // preview's diff (keyed by id, first occurrence) shows (Codex review of #2204).
  const firstPathOfId = new Map<string, string>();
  for (const file of files) {
    const classified = classify(file, meta, opts);
    const firstPath = firstPathOfId.get(classified.entry.id);
    if (firstPath === undefined) firstPathOfId.set(classified.entry.id, file.path);
    const { entry, loaded: found } =
      firstPath === undefined
        ? classified
        : {
            entry: {
              ...classified.entry,
              outcome: "refused" as const,
              reasons: [`duplicate rule id, first seen in ${firstPath}`],
            },
            loaded: undefined,
          };
    inventory.push(entry);
    if (!found) continue;
    const loaded = { ...found, rule: { ...found.rule, order: inventory.length } };
    let bucket = sources.get(loaded.def.id);
    if (!bucket) {
      bucket = { def: loaded.def, resolve: sourceResolver(loaded.def), always: [], index: new Map() };
      sources.set(loaded.def.id, bucket);
    }
    const gate = gateOf(loaded.rawRule, loaded.def);
    if (!gate) {
      bucket.always.push(loaded.rule);
      continue;
    }
    const byValue = bucket.index.get(gate.field) ?? new Map<string, LoadedSigmaRule[]>();
    bucket.index.set(gate.field, byValue);
    for (const v of new Set(gate.values)) byValue.set(v, [...(byValue.get(v) ?? []), loaded.rule]);
  }
  return {
    release: meta.release,
    commit: meta.commit,
    problems: [],
    statuses: [...opts.statuses],
    contentSha: contentSha(files),
    disabledHash: disabledHash(opts.disabled),
    inventory,
    sources,
  };
}

// ── Matching ──────────────────────────────────────────────────────────────────────────────────

export interface SigmaRecordMatch {
  matches: LoadedSigmaRule[];
  /** Rules whose answer was unknown because a field hit its size bound — never counted as matches. */
  incomplete: number;
}

function candidates(src: SourceRules, record: Row): LoadedSigmaRule[] {
  const out = new Set<LoadedSigmaRule>(src.always);
  for (const [field, byValue] of src.index) {
    for (const v of src.resolve(record, field).values) {
      if (v === null) continue;
      for (const r of byValue.get(v.toLowerCase()) ?? []) out.add(r);
    }
  }
  return [...out];
}

/** Every loaded rule of `sourceId` that definitely matches `record`, in load order. */
export function matchSigmaRecord(set: SigmaRuleSet, sourceId: string, record: Row): SigmaRecordMatch {
  const src = set.sources.get(sourceId);
  if (!src) return { matches: [], incomplete: 0 };
  const matches: LoadedSigmaRule[] = [];
  let incomplete = 0;
  for (const rule of candidates(src, record)) {
    const v = rule.compiled.evaluate(record, src.resolve);
    if (v === true) matches.push(rule);
    else if (v === "incomplete") incomplete++;
  }
  return { matches: matches.sort((a, b) => a.order - b.order), incomplete };
}
