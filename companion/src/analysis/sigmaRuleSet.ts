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
import {
  compileSigmaExclusions,
  isSigmaExcluded,
  sigmaExclusionsHash,
  type CompiledSigmaExclusion,
  type SigmaExclusionSpec,
} from "./sigmaExclusions.js";
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
  /**
   * Key into `SigmaRuleSetOptions.origins` for a rule that is not from the SigmaHQ release (#2499:
   * Suzaku). Absent = the release named by the set's meta.
   */
  origin?: string;
}

/** The project a rule comes from when it is not the SigmaHQ release itself (#2499). */
export const SIGMAHQ_ORIGIN = "SigmaHQ";

/** A second rule source bundled beside the SigmaHQ release (#2499), with its own status filter. */
export interface SigmaRuleOrigin {
  /** Shown on every match and in every note, e.g. "Suzaku" — the DRL names the rule set. */
  name: string;
  release: string;
  commit: string;
  /** `${urlBase}/${commit}/${path}` links the rule; paths are the upstream repo's own paths. */
  urlBase: string;
  statuses: readonly string[];
  /** The lowest level of THIS source's rules that raises severity; absent = the shared minimum. */
  minLevel?: SigmaLevel;
}

/** What a set records about each extra origin that contributed files — for notes and the token. */
export interface SigmaOriginSummary {
  name: string;
  release: string;
  commit: string;
  statuses: string[];
  minLevel?: SigmaLevel;
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
  /** The project the rule comes from (#2499); absent on refs recorded before it = SigmaHQ. */
  origin?: string;
  /** Its source's own minimum level to raise severity (#2499: Suzaku); absent = the snapshot's. */
  gradeFloor?: SigmaLevel;
  mitre: string[];
  /** The rule's own `modified` (or `date`) — versions the match (#2204). */
  modified?: string;
  /** Under rules-threat-hunting/: low-fidelity by design, so it only ever tags (#2204). */
  huntingOnly: boolean;
  /** Lower-cased field names the rule's detection reads (#2203: a rule that constrains sc-status). */
  fields?: string[];
  /**
   * Lower-cased fields tested by value in a selection the condition REQUIRES (#2499) — not under a
   * `not`, not inside an `or`, not an `exists` test. The #2351 not-found veto reads it: a rule that
   * only excludes an error code (`not filter`) has not decided about a not-found failure.
   */
  requiredFields?: string[];
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
  /** The log source (aws-cloudtrail, …) — not the project; that is `origin`. */
  source?: string;
  /** The project the rule comes from, when not SigmaHQ (#2499). */
  origin?: string;
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
  /** The statuses the SigmaHQ rules were filtered with (lower-case). */
  statuses: string[];
  /** Extra rule sources that contributed files, e.g. Suzaku (#2499); [] for SigmaHQ alone. */
  origins: SigmaOriginSummary[];
  /** First 12 hex of a SHA-256 over every rule file's path and text: identifies the content. */
  contentSha: string;
  /** First 8 hex of a SHA-256 over the sorted disabled ids ("none" when empty). */
  disabledHash: string;
  /** First 8 hex of a SHA-256 over the analyst's exclusions ("none" when empty) — #2218. */
  exclusionsHash: string;
  /** Rule id → the analyst's exclusions for it, compiled once (#2218). */
  exclusions: ReadonlyMap<string, readonly CompiledSigmaExclusion[]>;
  inventory: SigmaInventoryEntry[];
  sources: ReadonlyMap<string, SourceRules>;
}

export interface SigmaRuleSetOptions {
  statuses?: readonly string[];
  /** Rule id → why it is off. */
  disabled?: ReadonlyMap<string, string>;
  /** Rule id → records to skip for that rule (#2218). */
  exclusions?: ReadonlyMap<string, readonly SigmaExclusionSpec[]>;
  sources?: readonly SigmaLogSourceDef[];
  /** Origin key → the extra source it names (#2499). */
  origins?: ReadonlyMap<string, SigmaRuleOrigin>;
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

/**
 * Lower-cased fields the rule tests by VALUE — an `exists`-only field is left out (#2499). Readers of
 * `ref.fields` ask "did this rule decide about this field's value?" (the #2351 not-found veto on
 * errorCode, #2203 sc-status); "is there an error at all" has not decided which error.
 */
function valueFields(rule: SigmaRule, only?: ReadonlySet<string>): string[] {
  const all = rule.detection.selections
    .filter((s) => !only || only.has(s.name))
    .flatMap((s) => (s.kind === "map" ? s.fields : s.kind === "list" ? s.alternatives.flat() : []));
  return [...new Set(all.filter((f) => f.exists === undefined).map((f) => f.field.toLowerCase()))];
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
      if (
        !indexFields.has(f.field.toLowerCase()) ||
        f.modifiers.length ||
        f.nullValue ||
        f.exists !== undefined
      )
        continue;
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
  const origin = file.origin === undefined ? undefined : opts.origins.get(file.origin);
  const base = {
    path: file.path,
    id: file.path,
    title: file.path,
    ...(origin ? { origin: origin.name } : {}),
  };
  if (file.origin !== undefined && !origin)
    return { entry: { ...base, outcome: "refused", reasons: [`unknown rule source ${file.origin}`] } };
  if (!parsed.ok)
    return {
      entry: { ...base, outcome: "refused", reasons: parsed.refusals.map((r) => `${r.path}: ${r.message}`) },
    };
  const rule = parsed.rule;
  const head = {
    path: file.path,
    id: rule.id ?? file.path,
    title: rule.title,
    ...(origin ? { origin: origin.name } : {}),
  };
  const def = opts.sources.find((s) => s.matches(rule.logsource));
  if (!def) return { entry: { ...head, outcome: "no-source" } };
  const status = rule.status?.trim().toLowerCase() ?? "";
  const statuses = origin ? origin.statuses.map((s) => s.toLowerCase()) : opts.statuses;
  if (!statuses.includes(status))
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
    url: origin
      ? `${origin.urlBase}/${origin.commit}/${file.path}`
      : `https://github.com/SigmaHQ/sigma/blob/${meta.commit}/${file.path}`,
    release: origin ? origin.release : meta.release,
    ...(origin ? { origin: origin.name } : {}),
    ...(origin?.minLevel ? { gradeFloor: origin.minLevel } : {}),
    mitre: rule.mitreTechniques,
    ...(rule.modified || rule.date ? { modified: rule.modified ?? rule.date } : {}),
    huntingOnly: file.path.startsWith(`${SIGMA_HUNTING_DIR}/`),
    fields: valueFields(rule),
    requiredFields: valueFields(rule, new Set(requiredSelections(rule.detection.condition))),
  };
  const loadedRule = { ref, compiled, order: 0 };
  return {
    entry: { ...head, source: def.id, outcome: "loaded" },
    loaded: { def, rule: loadedRule, rawRule: rule },
  };
}

/**
 * Rule text with CRLF and lone CR turned into LF, for hashing only (#2215). A hash is a content
 * identity, so line endings must not change it: Windows checkouts and the Windows EXE build carry
 * CRLF. LF text comes back unchanged, so LF hashes keep their previous value.
 */
export function normalizeRuleText(text: string): string {
  return text.replace(/\r\n?/g, "\n");
}

/** A content identity for a set of rule files, independent of their order and line endings. */
export function contentSha(files: readonly SigmaRuleFile[]): string {
  const hash = createHash("sha256");
  for (const f of [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)))
    hash.update(f.path).update("\0").update(normalizeRuleText(f.text)).update("\0");
  return hash.digest("hex").slice(0, 12);
}

function disabledHash(disabled: ReadonlyMap<string, string>): string {
  if (disabled.size === 0) return "none";
  return createHash("sha256")
    .update([...disabled.keys()].sort().join("\n"))
    .digest("hex")
    .slice(0, 8);
}

/** The extra origins that contributed at least one file, in first-file order. */
function originSummaries(
  files: readonly SigmaRuleFile[],
  origins: ReadonlyMap<string, SigmaRuleOrigin>,
): SigmaOriginSummary[] {
  const keys = [...new Set(files.flatMap((f) => (f.origin === undefined ? [] : [f.origin])))];
  return keys.flatMap((k) => {
    const o = origins.get(k);
    return o
      ? [
          {
            name: o.name,
            release: o.release,
            commit: o.commit,
            statuses: o.statuses.map((s) => s.toLowerCase()),
            ...(o.minLevel ? { minLevel: o.minLevel } : {}),
          },
        ]
      : [];
  });
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
    exclusions: options.exclusions ?? new Map(),
    sources: options.sources ?? SIGMA_LOG_SOURCES,
    origins: options.origins ?? new Map(),
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
    origins: originSummaries(files, opts.origins),
    contentSha: contentSha(files),
    disabledHash: disabledHash(opts.disabled),
    exclusionsHash: sigmaExclusionsHash(opts.exclusions),
    exclusions: compileSigmaExclusions(opts.exclusions),
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

/**
 * Every loaded rule of `sourceId` that definitely matches `record`, in load order. A match the
 * analyst excluded for this record (#2218) is dropped; an exclusion that cannot be proven is not.
 */
export function matchSigmaRecord(set: SigmaRuleSet, sourceId: string, record: Row): SigmaRecordMatch {
  const src = set.sources.get(sourceId);
  if (!src) return { matches: [], incomplete: 0 };
  const matches: LoadedSigmaRule[] = [];
  let incomplete = 0;
  for (const rule of candidates(src, record)) {
    const v = rule.compiled.evaluate(record, src.resolve);
    if (v === true) {
      if (!isSigmaExcluded(record, src.resolve, set.exclusions.get(rule.ref.id))) matches.push(rule);
    } else if (v === "incomplete") incomplete++;
  }
  return { matches: matches.sort((a, b) => a.order - b.order), incomplete };
}
