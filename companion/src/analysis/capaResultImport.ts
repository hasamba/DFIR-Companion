// capa (Mandiant/FLARE capability-detection tool) `-j` static-analysis results document (#932
// item 6, "932.7"): named capabilities capa's rule-matching statically found present in a
// sample. Never a claim any capability ran, never a verdict from any single match — see
// RECOMMENDATION-6.md for the guardrails this enforces (legitimate/commercial software packs
// and uses the same APIs too) and why "unusual sections" is out of scope (no capa-rules
// namespace covers it — #1124). A dynamic-flavor report (capa's own DynamicAnalysis schema) is
// real and documented upstream but never parsed here (#1124: zero real-case evidence to validate
// against) — `capaUnsupportedFlavorReason` gives an honest diagnostic instead of silently
// falling through to "could not detect the file type", turning the first real occurrence into
// the trigger to build real support rather than leaving it unfalsifiable.
//
// Schema verified live against a REAL serialized capa 9.4.0 static report
// (DefectDojo/django-DefectDojo's own test fixture), not just source-read dataclasses.

import { createHash } from "node:crypto";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import {
  CAPA_COMPOSITE_LEAD_BASIS,
  CAPA_MATCH_BASIS,
  MAX_FEATURE_DETAIL_LEN,
  MAX_FIELD_LEN,
  MAX_MAPPINGS,
  RECOVERY_CITATIONS_MAX,
  capaNamespaceFamilies,
  type AttackMapping,
  type CapaAddress,
  type CapaFeatureEvidence,
  type MbcMapping,
} from "./canonicalCapaMatch.js";
import { MAX_PRODUCER_VERSION_LEN, type SampleHash } from "./canonicalMalwareSample.js";
import {
  addIoc,
  isObject,
  mergeRowIocs,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";
import { aggregateEvents } from "./eventAggregate.js";

export const MAX_DISTINCT_RULES = 2000;
export const MAX_MATCHES_SCANNED = 50_000; // total match tuples across all rules

const HASH_RE = { md5: /^[a-f0-9]{32}$/i, sha1: /^[a-f0-9]{40}$/i, sha256: /^[a-f0-9]{64}$/i };
const MAX_TREE_DEPTH = 32;
const MAX_TREE_NODES = 200_000; // REPORT-WIDE, across every match tuple in every rule

export interface CapaResultOptions {
  aggregate?: boolean;
  maxEvents?: number;
}

export interface CapaResultResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  malformedRules: number;
  malformedMatches: number;
  notCitedRules: number;
  matchesTruncated: boolean;
  nodesTruncated: boolean;
}

/** `flavor === "static"` is capa's own real discriminator (confirmed against a real serialized
 * report — a StaticAnalysis-vs-DynamicAnalysis field-set diff was NOT trustworthy on its own,
 * Codex design review finding). `meta.sample` must carry all four identity fields as strings —
 * capa's own schema makes them non-optional — and `rules` must be an object (zero matches is a
 * real, valid result). */
/** `meta.sample` carrying all four identity fields as strings is capa's own real, non-optional
 * schema shape — the signal that a document is genuinely capa-produced, independent of flavor. */
function isCapaShapedSample(sample: unknown): boolean {
  return (
    isObject(sample) &&
    typeof sample.md5 === "string" &&
    typeof sample.sha1 === "string" &&
    typeof sample.sha256 === "string" &&
    typeof sample.path === "string"
  );
}

export function isCapaResult(root: unknown): boolean {
  if (!isObject(root)) return false;
  const meta = root.meta;
  if (!isObject(meta) || meta.flavor !== "static") return false;
  if (!isCapaShapedSample(meta.sample)) return false;
  return isObject(root.rules);
}

const MAX_FLAVOR_LEN = 40;

/** A recognizable-but-unsupported capa report: `meta.sample` has capa's own real identity-field
 * shape (so this is genuinely capa-produced, not an arbitrary unrelated document), but
 * `meta.flavor` isn't `"static"` — e.g. `"dynamic"` (capa's own DynamicAnalysis schema, real and
 * documented upstream, never parsed here — #1124: no real-case evidence to build against yet).
 * Returns a bounded, honest reason string instead of the caller falling through to a generic
 * "could not detect the file type" message. Never a false positive: an unrelated JSON object, or
 * one whose `meta.sample` doesn't carry capa's own identity fields, returns undefined. */
export function capaUnsupportedFlavorReason(root: unknown): string | undefined {
  if (!isObject(root)) return undefined;
  const meta = root.meta;
  if (!isObject(meta) || !isCapaShapedSample(meta.sample)) return undefined;
  if (meta.flavor === "static") return undefined;
  const flavor = typeof meta.flavor === "string" ? clip(meta.flavor, MAX_FLAVOR_LEN).text : "unrecognized";
  return `capa report flavor "${flavor}" is not yet supported (only "static" reports are parsed)`;
}

/** `capaUnsupportedFlavorReason` over raw text a caller hasn't parsed yet (a route body, or a
 * sniffed file-head sample that may be truncated) — never throws; a JSON.parse failure (including
 * a truncated sample) safely means "no capa-specific hint available", not an error. */
export function capaFlavorHintFor(text: string): string | undefined {
  try {
    return capaUnsupportedFlavorReason(JSON.parse(text));
  } catch {
    return undefined;
  }
}

function nonNegSafeInt(v: unknown): number | undefined {
  return typeof v === "number" && Number.isInteger(v) && Number.isSafeInteger(v) && v >= 0 ? v : undefined;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function clip(text: string, max: number): { text: string; truncated: boolean } {
  if (text.length <= max) return { text, truncated: false };
  return { text: text.slice(0, max), truncated: true };
}

function parseSampleHash(sample: Record<string, unknown>): SampleHash {
  const md5 = str(sample.md5);
  const sha1 = str(sample.sha1);
  const sha256 = str(sample.sha256);
  const out: SampleHash = { hashUnavailable: false };
  if (md5 && HASH_RE.md5.test(md5)) out.md5 = md5.toLowerCase();
  if (sha1 && HASH_RE.sha1.test(sha1)) out.sha1 = sha1.toLowerCase();
  if (sha256 && HASH_RE.sha256.test(sha256)) out.sha256 = sha256.toLowerCase();
  out.hashUnavailable = !out.md5 && !out.sha1 && !out.sha256;
  return out;
}

/** Static-only: "process"/"thread"/"call" are dynamic-analysis-only address kinds by capa's own
 * model — a static report naming one is itself malformed, never silently accepted. */
function parseAddress(raw: unknown): CapaAddress | undefined {
  if (!isObject(raw)) return undefined;
  const type = raw.type;
  if (type === "absolute" || type === "relative" || type === "file") {
    const value = nonNegSafeInt(raw.value);
    return value === undefined ? undefined : { type, value };
  }
  if (type === "dn token") {
    const value = nonNegSafeInt(raw.value);
    return value === undefined ? undefined : { type, value };
  }
  if (type === "dn token offset") {
    const tuple = raw.value;
    if (!Array.isArray(tuple) || tuple.length !== 2) return undefined;
    const a = nonNegSafeInt(tuple[0]);
    const b = nonNegSafeInt(tuple[1]);
    return a === undefined || b === undefined ? undefined : { type, value: [a, b] };
  }
  // capa's own JSON serializer omits `value` entirely for a null field (Pydantic's
  // exclude_none=True) — a real "no address" is `{"type": "no address"}` with NO `value` key at
  // all, confirmed against a real serialized report, not just `value: null`.
  if (type === "no address")
    return raw.value === null || raw.value === undefined ? { type, value: null } : undefined;
  return undefined; // process/thread/call, or an unrecognized type — rejected, not coerced
}

function parseAddressList(raw: unknown): CapaAddress[] {
  if (!Array.isArray(raw)) return [];
  const out: CapaAddress[] = [];
  for (const a of raw) {
    const parsed = parseAddress(a);
    if (parsed) out.push(parsed);
  }
  return out;
}

interface MatchNode {
  success?: unknown;
  node?: unknown;
  children?: unknown;
  locations?: unknown;
}

/** A report-WIDE budget, threaded (by reference) through every match tuple's tree walk across
 * every rule — Codex code review finding: a per-tuple-only counter reset for each of up to
 * 50,000 tuples let the aggregate workload reach into the tens of millions of nodes regardless of
 * the per-tuple cap. */
interface NodeBudget {
  visited: number;
  truncated: boolean;
}

/** Bounded (depth AND a REPORT-WIDE total node count, checked at ENQUEUE time, not just before a
 * pop) walk collecting evidence from successful nodes anywhere in the match tree that carry their
 * OWN non-empty `locations` — covers both an ordinary successful feature leaf (api/string/...,
 * locations on the feature match) AND a successful `range` statement (locations live on the
 * STATEMENT match itself, not on a nested feature) — capa's `statement | feature` node dichotomy
 * is exhaustive, and either kind can be the thing worth citing (Codex code review finding: the
 * prior feature-only check silently produced zero evidence for a valid range match). Every node
 * in the tree is visited regardless of its OWN success, since a successful AND/OR node's
 * successful children are what matters, not the node's own success flag; a "match" feature
 * (referencing another rule) is captured the same generic way, and its own children — the
 * referenced rule's match — are still walked for their own leaves. */
function collectFeatureEvidence(root: unknown, budget: NodeBudget): CapaFeatureEvidence[] {
  const evidence: CapaFeatureEvidence[] = [];
  if (budget.visited >= MAX_TREE_NODES) {
    budget.truncated = true;
    return evidence;
  }
  budget.visited += 1;
  const stack: { node: unknown; depth: number }[] = [{ node: root, depth: 0 }];
  while (stack.length > 0) {
    const { node, depth } = stack.pop()!;
    if (!isObject(node) || depth > MAX_TREE_DEPTH) continue;
    const m = node as MatchNode;
    const inner = m.node;
    const hasOwnLocations = Array.isArray(m.locations) && m.locations.length > 0;
    if (m.success === true && hasOwnLocations && isObject(inner)) {
      const isFeature = inner.type === "feature" && isObject(inner.feature);
      const isStatement = inner.type === "statement" && isObject(inner.statement);
      if (isFeature || isStatement) {
        const src = (isFeature ? inner.feature : inner.statement) as Record<string, unknown>;
        const kindType = str(src.type) ?? "unknown";
        const featureType = isFeature ? kindType : `statement:${kindType}`;
        const rest = { ...src };
        delete rest.type;
        evidence.push({
          featureType: clip(featureType, MAX_FIELD_LEN).text,
          detail: clip(JSON.stringify(rest), MAX_FEATURE_DETAIL_LEN).text,
          // Kept FULL here (not capped) — capping before dedup would collapse two evidence items
          // that differ only past the cap (Codex code review finding); capped only once, after
          // dedup, when the kept item is finalized for storage.
          locations: parseAddressList(m.locations),
        });
      }
    }
    const children = m.children;
    if (Array.isArray(children)) {
      for (const c of children) {
        if (budget.visited >= MAX_TREE_NODES) {
          budget.truncated = true;
          break;
        }
        budget.visited += 1;
        stack.push({ node: c, depth: depth + 1 });
      }
    }
  }
  return evidence;
}

function evidenceKey(e: CapaFeatureEvidence): string {
  return createHash("sha256")
    .update(e.featureType)
    .update("\n")
    .update(e.detail)
    .update("\n")
    .update(JSON.stringify(e.locations))
    .digest("hex");
}

function dedupeEvidence(list: readonly CapaFeatureEvidence[]): {
  kept: CapaFeatureEvidence[];
  notCited: number;
} {
  const seen = new Map<string, CapaFeatureEvidence>();
  for (const e of list) {
    const key = evidenceKey(e);
    if (seen.has(key)) continue;
    if (seen.size >= RECOVERY_CITATIONS_MAX) continue;
    seen.set(key, e);
  }
  const distinctTotal = new Set(list.map(evidenceKey)).size;
  // Locations are capped here, AFTER dedup decided what to keep by its FULL identity.
  const kept = [...seen.values()].map((e) => ({
    ...e,
    locations: e.locations.slice(0, RECOVERY_CITATIONS_MAX),
  }));
  return { kept, notCited: Math.max(0, distinctTotal - kept.length) };
}

function dedupeAddresses(list: readonly CapaAddress[]): { kept: CapaAddress[]; notCited: number } {
  const seen = new Map<string, CapaAddress>();
  for (const a of list) {
    const key = JSON.stringify(a);
    if (seen.has(key)) continue;
    if (seen.size >= RECOVERY_CITATIONS_MAX) continue;
    seen.set(key, a);
  }
  const distinctTotal = new Set(list.map((a) => JSON.stringify(a))).size;
  const kept = [...seen.values()];
  return { kept, notCited: Math.max(0, distinctTotal - kept.length) };
}

function parseMapping<T extends { id: string }>(
  raw: unknown,
  build: (parts: Record<string, unknown>) => T | undefined,
): T[] {
  if (!Array.isArray(raw)) return [];
  const out: T[] = [];
  for (const r of raw) {
    if (!isObject(r)) continue;
    const built = build(r);
    if (built) out.push(built);
  }
  return out.slice(0, MAX_MAPPINGS);
}

function parseAttack(raw: unknown): AttackMapping[] {
  return parseMapping<AttackMapping>(raw, (r) => {
    const tactic = str(r.tactic);
    const technique = str(r.technique);
    const id = str(r.id);
    if (!tactic || !technique || !id) return undefined;
    const subtechnique = str(r.subtechnique);
    return {
      tactic: clip(tactic, MAX_FIELD_LEN).text,
      technique: clip(technique, MAX_FIELD_LEN).text,
      ...(subtechnique ? { subtechnique: clip(subtechnique, MAX_FIELD_LEN).text } : {}),
      id: clip(id, 64).text,
    };
  });
}

function parseMbc(raw: unknown): MbcMapping[] {
  return parseMapping<MbcMapping>(raw, (r) => {
    const objective = str(r.objective);
    const behavior = str(r.behavior);
    const id = str(r.id);
    if (!objective || !behavior || !id) return undefined;
    const method = str(r.method);
    return {
      objective: clip(objective, MAX_FIELD_LEN).text,
      behavior: clip(behavior, MAX_FIELD_LEN).text,
      ...(method ? { method: clip(method, MAX_FIELD_LEN).text } : {}),
      id: clip(id, 64).text,
    };
  });
}

interface RuleResult {
  ruleName: string;
  ruleNameHash: string; // sha256 of the FULL, unclipped name — the aggKey identity component
  ruleNamespace: string | undefined;
  ruleSourceFingerprint: string;
  attack: AttackMapping[];
  mbc: MbcMapping[];
  outerLocations: CapaAddress[];
  notCitedOuterLocations: number;
  evidence: CapaFeatureEvidence[];
  notCitedEvidence: number;
  occurrences: number;
}

/** Returns null when the rule entry itself is too malformed to use at all (no name, no source, or
 * `matches` isn't an array) — counted as a malformed rule, never a crash. `scanned`/`truncated`
 * mirror item 5's own now-fixed discipline: every match tuple examined counts toward the budget,
 * and truncation is only ever true when a tuple was genuinely left unscanned.
 *
 * A match tuple is only counted as a real occurrence when ALL of: it's a 2-element array, its
 * root Match itself has `success: true` (a failed root is not a match at all — Codex code review
 * finding), AND its outer Address validates against the static-only schema. An address capa's
 * own model marks dynamic-only (process/thread/call) — or any other malformed shape — makes the
 * WHOLE TUPLE malformed, never silently accepted with the address just dropped (the design's own
 * "not silently accepted" promise, which the prior version didn't actually keep). */
function parseRule(
  name: string,
  entry: unknown,
  scannedSoFar: number,
  budget: NodeBudget,
): { rule: RuleResult | null; scanned: number; truncated: boolean; malformedMatches: number } {
  if (!name.trim()) return { rule: null, scanned: scannedSoFar, truncated: false, malformedMatches: 0 };
  if (!isObject(entry)) return { rule: null, scanned: scannedSoFar, truncated: false, malformedMatches: 0 };
  const meta = entry.meta;
  const source = entry.source;
  const matches = entry.matches;
  if (!isObject(meta) || typeof source !== "string" || !Array.isArray(matches)) {
    return { rule: null, scanned: scannedSoFar, truncated: false, malformedMatches: 0 };
  }
  const ruleNamespace = str(meta.namespace);
  const ruleSourceFingerprint = createHash("sha256").update(source).digest("hex");
  const attack = parseAttack(meta.attack);
  const mbc = parseMbc(meta.mbc);

  const outerAddrs: CapaAddress[] = [];
  const allEvidence: CapaFeatureEvidence[] = [];
  let scanned = scannedSoFar;
  let truncated = false;
  let occurrences = 0;
  let malformedMatches = 0;
  for (const tuple of matches) {
    if (scanned >= MAX_MATCHES_SCANNED) {
      truncated = true;
      break;
    }
    scanned += 1;
    if (!Array.isArray(tuple) || tuple.length !== 2) {
      malformedMatches += 1;
      continue;
    }
    const [rawAddr, rawMatch] = tuple;
    const addr = parseAddress(rawAddr);
    const rootSucceeded = isObject(rawMatch) && (rawMatch as MatchNode).success === true;
    if (!addr || !rootSucceeded) {
      malformedMatches += 1;
      continue;
    }
    outerAddrs.push(addr);
    occurrences += 1;
    allEvidence.push(...collectFeatureEvidence(rawMatch, budget));
  }
  const { kept: outerLocations, notCited: notCitedOuterLocations } = dedupeAddresses(outerAddrs);
  const { kept: evidence, notCited: notCitedEvidence } = dedupeEvidence(allEvidence);

  if (occurrences === 0) return { rule: null, scanned, truncated, malformedMatches };

  return {
    rule: {
      ruleName: clip(name, MAX_FIELD_LEN).text,
      ruleNameHash: createHash("sha256").update(name).digest("hex"),
      ruleNamespace: ruleNamespace ? clip(ruleNamespace, MAX_FIELD_LEN).text : undefined,
      ruleSourceFingerprint,
      attack,
      mbc,
      outerLocations,
      notCitedOuterLocations,
      evidence,
      notCitedEvidence,
      occurrences,
    },
    scanned,
    truncated,
    malformedMatches,
  };
}

function namespaceFamily(namespace: string | undefined): string | undefined {
  if (!namespace) return undefined;
  const first = namespace.split("/")[0];
  return (capaNamespaceFamilies as readonly string[]).includes(first) ? first : undefined;
}

function mapRuleEvent(
  rule: RuleResult,
  reportFingerprint: string,
  sampleHash: SampleHash,
  producerVersion: string,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const body = boundedTextTo(
    `capa capability match: ${rule.ruleName}${rule.ruleNamespace ? ` (${rule.ruleNamespace})` : ""} — ` +
      `${rule.occurrences} occurrence(s) in this upload; not proof this capability ran, not a verdict; ` +
      `[undated: capa's results document carries no event time]`,
    600 - reportTag.length,
  );
  const description = `${body}${reportTag}`;

  // A "rule|" type segment (Codex code review finding) so a rule literally NAMED "composite-lead"
  // can never collide with the report's own composite-lead aggKey; keyed on a hash of the FULL,
  // unclipped rule name so two overlong names sharing the same clipped prefix don't collide either.
  const aggKey = boundedAggKey(`capa|${reportFingerprint}|rule|${rule.ruleNameHash}`);

  const hashSink = new Map<string, SiemIoc>();
  for (const h of [sampleHash.sha256, sampleHash.sha1, sampleHash.md5]) if (h) addIoc(hashSink, "hash", h);
  mergeRowIocs(sink, hashSink, aggKey);

  const producerVersionClipped = clip(producerVersion, MAX_PRODUCER_VERSION_LEN).text;
  const mitre = [...new Set(rule.attack.map((a) => a.id))];

  return {
    timestamp: "",
    description,
    severity: "Info",
    mitre,
    aggKey,
    sources: ["capa"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "capability-match", action: "matched" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "capa-result", locator: `rule:${rule.ruleSourceFingerprint}` }] },
      producer: { importer: "capa-result", parserVersion: "1", mappingVersion: "capa-rule-match-v1" },
      capaMatch: {
        tool: "capa",
        ruleName: rule.ruleName,
        ruleNamespace: rule.ruleNamespace,
        ruleSourceFingerprint: rule.ruleSourceFingerprint,
        attack: rule.attack,
        mbc: rule.mbc,
        sampleHash,
        reportFingerprint,
        producerVersion: producerVersionClipped,
        mappingVersion: "capa-rule-match-v1",
        outerLocations: rule.outerLocations,
        notCitedOuterLocations: rule.notCitedOuterLocations,
        evidence: rule.evidence,
        notCitedEvidence: rule.notCitedEvidence,
        occurrences: rule.occurrences,
        basis: CAPA_MATCH_BASIS,
      },
    }),
  };
}

function mapCompositeLead(
  families: readonly string[],
  ruleNames: readonly string[],
  reportFingerprint: string,
  sampleHash: SampleHash,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  const bounded = ruleNames.slice(0, MAX_MAPPINGS);
  const notCitedRules = Math.max(0, ruleNames.length - bounded.length);
  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const body = boundedTextTo(
    `capa composite inspection lead: ${families.join(" + ")} — ${bounded.join(", ")}; ` +
      `an inspection lead, not a verdict; [undated: capa's results document carries no event time]`,
    600 - reportTag.length,
  );
  const description = `${body}${reportTag}`;
  const aggKey = boundedAggKey(`capa|${reportFingerprint}|lead|composite`);

  const hashSink = new Map<string, SiemIoc>();
  for (const h of [sampleHash.sha256, sampleHash.sha1, sampleHash.md5]) if (h) addIoc(hashSink, "hash", h);
  mergeRowIocs(sink, hashSink, aggKey);

  return {
    timestamp: "",
    description,
    severity: "Low",
    mitre: [],
    aggKey,
    sources: ["capa"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "composite-inspection-lead", action: "flagged" },
      time: { observed: "", normalized: "" },
      evidence: {
        rawRecords: [{ source: "capa-result", locator: `composite:${reportFingerprint.slice(0, 16)}` }],
      },
      producer: { importer: "capa-result", parserVersion: "1", mappingVersion: "capa-rule-match-v1" },
      capaCompositeLead: {
        tool: "capa",
        reportFingerprint,
        sampleHash,
        contributingFamilies: [...families],
        contributingRules: bounded,
        notCitedRules,
        basis: CAPA_COMPOSITE_LEAD_BASIS,
      },
    }),
  };
}

export function parseCapaResult(text: string, opts: CapaResultOptions = {}): CapaResultResult | null {
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isCapaResult(root)) return null;
  const r = root as Record<string, unknown>;
  const meta = r.meta as Record<string, unknown>;
  const sample = meta.sample as Record<string, unknown>;
  const producerVersion = str(meta.version) ?? "";
  const sampleHash = parseSampleHash(sample);
  const reportFingerprint = createHash("sha256").update(text).digest("hex");
  const rulesObj = r.rules as Record<string, unknown>;

  let scanned = 0;
  let matchesTruncated = false;
  let malformedRules = 0;
  let malformedMatches = 0;
  let notCitedRules = 0;
  const budget: NodeBudget = { visited: 0, truncated: false };
  const rules: RuleResult[] = [];
  let total = 0;
  for (const [name, entry] of Object.entries(rulesObj)) {
    total += 1;
    if (rules.length >= MAX_DISTINCT_RULES) {
      notCitedRules += 1;
      continue;
    }
    const result = parseRule(name, entry, scanned, budget);
    scanned = result.scanned;
    malformedMatches += result.malformedMatches;
    if (result.truncated) matchesTruncated = true;
    if (result.rule) rules.push(result.rule);
    else malformedRules += 1;
  }

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = rules.map((rule) =>
    mapRuleEvent(rule, reportFingerprint, sampleHash, producerVersion, sink),
  );

  const families = new Set<string>();
  const familyRules = new Map<string, string[]>();
  for (const rule of rules) {
    const family = namespaceFamily(rule.ruleNamespace);
    if (!family) continue;
    families.add(family);
    const list = familyRules.get(family) ?? [];
    list.push(rule.ruleName);
    familyRules.set(family, list);
  }
  if (families.has("anti-analysis") && families.size >= 2) {
    const contributingRuleNames = [...families].flatMap((f) => familyRules.get(f) ?? []);
    mapped.push(mapCompositeLead([...families], contributingRuleNames, reportFingerprint, sampleHash, sink));
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? MAX_DISTINCT_RULES + 1,
  });

  return {
    events,
    iocs: [...sink.values()],
    total,
    kept: events.length,
    dropped: malformedRules,
    groups,
    format: "CapaResultDocument",
    malformedRules,
    malformedMatches,
    notCitedRules,
    matchesTruncated,
    nodesTruncated: budget.truncated,
  };
}
