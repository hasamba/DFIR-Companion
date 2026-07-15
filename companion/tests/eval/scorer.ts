// Prompt-regression evaluation harness — the PURE scorer (issue #64, Phase 1).
//
// Deterministic, dependency-free scoring of extraction/synthesis output against a golden dataset. No I/O,
// no clock, no AI — so it runs in normal CI and is exhaustively unit-testable (mirrors the codebase's
// "pure core + I/O wrapper" philosophy, e.g. hypothesis.ts / confidence.ts). Phase 2 wires a REAL provider
// in front of it via the harness; Phase 1 drives it with a MockProvider so the score is deterministic and
// the plumbing + scoring math are what get gated.
//
// Extraction is scored as precision/recall with a FUZZY match predicate (LLM output never equals a golden
// string, so exact match is useless): a produced event matches a golden expectation when every constraint
// the golden SPECIFIES holds — timestamp within tolerance, description keywords all present, ATT&CK
// technique overlap, and asset equality. Constraints the golden omits are not checked.

import type { Severity, Finding, ForensicEvent } from "../../src/analysis/stateTypes.js";

// A golden expectation. Every field is OPTIONAL: only the fields present are asserted, so a fixture can be
// as loose ("some High event mentioning mimikatz") or as tight ("T1003.001 on DC01 at 10:02Z") as needed.
export interface GoldenEvent {
  timestamp?: string;          // ISO — matched within MatchOptions.toleranceMinutes
  keywords?: string[];         // all must appear (case-insensitive substring) in the produced description
  severity?: Severity;         // exact severity, if asserted
  mitreTechniques?: string[];  // at least one must overlap the produced techniques, if asserted
  asset?: string;              // host/FQDN — case-insensitive equality, if asserted
}

// Minimal produced-event shape the scorer needs — a structural subset of ForensicEvent so callers can pass
// real pipeline output directly, or a hand-built fixture in tests.
export type ProducedEvent = Pick<ForensicEvent, "id" | "timestamp" | "description" | "severity"> &
  Partial<Pick<ForensicEvent, "mitreTechniques" | "asset" | "relatedFindingIds">>;

export interface MatchOptions {
  toleranceMinutes: number;    // timestamp match window (± minutes); default 5
}

export const DEFAULT_MATCH_OPTIONS: MatchOptions = { toleranceMinutes: 5 };

const norm = (s: string | undefined): string => String(s ?? "").trim().toLowerCase();
const normTechnique = (t: string): string => String(t ?? "").trim().toUpperCase();

// A produced technique satisfies a golden one when it's the same technique OR a SUB-technique of it:
// tagging password guessing as T1110.001 is a strictly more precise — and still correct — answer to a
// golden asking for T1110, and must not score as a miss. Not symmetric: a golden that names the specific
// sub-technique (T1110.001) is NOT satisfied by the bare parent (T1110), which is the less precise answer.
export function techniqueSatisfies(golden: string, produced: string): boolean {
  const g = normTechnique(golden);
  const p = normTechnique(produced);
  return p === g || p.startsWith(`${g}.`);
}

// True when the produced event satisfies EVERY constraint the golden expectation specifies. A constraint
// the golden omits (undefined/empty) is not checked. Pure and total — an unparseable required timestamp
// simply fails to match (never throws).
export function eventMatches(
  golden: GoldenEvent,
  produced: ProducedEvent,
  opts: MatchOptions = DEFAULT_MATCH_OPTIONS,
): boolean {
  if (golden.timestamp) {
    const g = Date.parse(golden.timestamp);
    const p = Date.parse(produced.timestamp ?? "");
    if (Number.isNaN(g) || Number.isNaN(p)) return false;
    if (Math.abs(g - p) > Math.max(0, opts.toleranceMinutes) * 60_000) return false;
  }
  if (golden.keywords && golden.keywords.length) {
    const hay = norm(produced.description);
    if (!golden.keywords.every((k) => hay.includes(norm(k)))) return false;
  }
  if (golden.severity && produced.severity !== golden.severity) return false;
  if (golden.mitreTechniques && golden.mitreTechniques.length) {
    const have = produced.mitreTechniques ?? [];
    if (!golden.mitreTechniques.some((t) => have.some((h) => techniqueSatisfies(t, h)))) return false;
  }
  if (golden.asset && norm(produced.asset) !== norm(golden.asset)) return false;
  return true;
}

export interface ExtractionScore {
  truePositives: number;
  falsePositives: number;      // produced events matching no golden expectation (extra / possible noise)
  falseNegatives: number;      // golden expectations no produced event satisfied (missed)
  precision: number;           // TP / (TP + FP)
  recall: number;              // TP / (TP + FN)
  f1: number;
  missedGolden: number[];      // indices into the golden array that went unmatched
  extraProduced: string[];     // ids of produced events that matched nothing
}

// Greedy bipartite matching of golden expectations to produced events. Each produced event is consumed by
// at most one golden (first match wins, in golden order), so N produced copies of one event can't inflate
// recall past the number of golden expectations. Denominator-zero is defined conventionally: precision 1
// when nothing was produced, recall 1 when nothing was expected.
//
// A false positive is a produced event that satisfies NO golden — not merely one left unconsumed by the
// 1:1 matching. The distinction matters on real model output: asked about a 10-row password-guessing
// burst, a model may emit one event per row instead of a single aggregated one. Those rows all satisfy
// the same golden; they are the same fact at finer granularity, not inventions. Counting the 9 leftovers
// as FPs dropped precision to 10% and failed a substantively correct extraction. Recall is unaffected —
// each golden still yields at most one TP.
export function scoreExtraction(
  golden: readonly GoldenEvent[],
  produced: readonly ProducedEvent[],
  opts: MatchOptions = DEFAULT_MATCH_OPTIONS,
): ExtractionScore {
  const used = new Set<number>();
  const missedGolden: number[] = [];
  let truePositives = 0;
  golden.forEach((g, gi) => {
    const hit = produced.findIndex((p, pi) => !used.has(pi) && eventMatches(g, p, opts));
    if (hit === -1) missedGolden.push(gi);
    else { used.add(hit); truePositives += 1; }
  });
  const extraProduced = produced
    .filter((p, pi) => !used.has(pi) && !golden.some((g) => eventMatches(g, p, opts)))
    .map((p) => p.id);
  const falsePositives = extraProduced.length;
  const falseNegatives = missedGolden.length;
  const precision = truePositives + falsePositives === 0 ? 1 : truePositives / (truePositives + falsePositives);
  const recall = truePositives + falseNegatives === 0 ? 1 : truePositives / (truePositives + falseNegatives);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { truePositives, falsePositives, falseNegatives, precision, recall, f1, missedGolden, extraProduced };
}

// Minimal produced-finding shape for the synthesis checks.
export type ProducedFinding = Pick<Finding, "id" | "severity"> &
  Partial<Pick<Finding, "confidence" | "confidenceReason" | "relatedEventIds" | "relatedIocs">>;

export interface SynthesisReport {
  highSeverity: { total: number; covered: number; uncovered: { id: string; severity: Severity; description: string }[] };
  grounding: { total: number; grounded: number; ungrounded: string[] };        // finding ids with no real supporting event
  danglingEventRefs: { findingId: string; badRefs: string[] }[];                // referenced event ids absent from the timeline = invented
  confidenceIssues: string[];                                                    // finding ids with a confidence score but no reason (rubric)
}

// Deterministic synthesis-quality checks over a produced (events, findings) pair — no golden needed:
// - COVERAGE: every Critical/High event should be cited by at least one finding (via finding.relatedEventIds
//   or the event's own relatedFindingIds). Uncovered high-severity events are a regression.
// - HALLUCINATION: a finding citing an event id that is NOT in the timeline invented that reference; a
//   finding citing no real event AND no IOC is ungrounded (unsupported claim).
// - RUBRIC: a finding carrying a numeric confidence must also carry a confidenceReason.
export function checkSynthesis(
  events: readonly ProducedEvent[],
  findings: readonly ProducedFinding[],
): SynthesisReport {
  const eventIds = new Set(events.map((e) => e.id));
  const citedByFinding = new Set<string>();
  for (const f of findings) for (const id of f.relatedEventIds ?? []) citedByFinding.add(id);

  const highSevEvents = events.filter((e) => e.severity === "Critical" || e.severity === "High");
  const uncovered = highSevEvents
    .filter((e) => !citedByFinding.has(e.id) && !(e.relatedFindingIds ?? []).length)
    .map((e) => ({ id: e.id, severity: e.severity, description: e.description }));

  const ungrounded: string[] = [];
  const danglingEventRefs: { findingId: string; badRefs: string[] }[] = [];
  const confidenceIssues: string[] = [];
  for (const f of findings) {
    const refs = f.relatedEventIds ?? [];
    const realRefs = refs.filter((id) => eventIds.has(id));
    const badRefs = refs.filter((id) => !eventIds.has(id));
    if (badRefs.length) danglingEventRefs.push({ findingId: f.id, badRefs });
    if (realRefs.length === 0 && !(f.relatedIocs ?? []).length) ungrounded.push(f.id);
    if (typeof f.confidence === "number" && !String(f.confidenceReason ?? "").trim()) confidenceIssues.push(f.id);
  }

  return {
    highSeverity: { total: highSevEvents.length, covered: highSevEvents.length - uncovered.length, uncovered },
    grounding: { total: findings.length, grounded: findings.length - ungrounded.length, ungrounded },
    danglingEventRefs,
    confidenceIssues,
  };
}

export interface Thresholds {
  minPrecision: number;
  minRecall: number;
}

export const DEFAULT_THRESHOLDS: Thresholds = { minPrecision: 0.8, minRecall: 0.8 };

// Gate for --real (Phase 2) runs: RECALL only. Precision is still computed and printed, but it does not
// gate, because a golden is a MUST-FIND list rather than an exhaustive enumeration of the input. This
// pipeline is meant to extract everything and then grade severity (that's what the super-timeline is), so
// a thorough model correctly emits the benign rows a fixture seeds as noise — none of which appear in the
// golden, all of which score as false positives. Measured: gemini-2.5-pro hits 100% recall on all four
// extraction fixtures across repeated runs while landing at 25-50% precision purely by extracting real,
// unlisted, benign events. Gating on precision would fail the BETTER model for doing its job.
//
// Recall is the signal that actually regresses: "the prompt stopped finding the brute force" is a bug,
// "the prompt also mentioned a notepad launch" is not. Invention is still caught — a produced event that
// matches no golden is only counted once against precision, and the synthesis checks gate hallucination
// (dangling event refs) separately and strictly.
export const REAL_THRESHOLDS: Thresholds = { minPrecision: 0, minRecall: 0.7 };

export function passesExtraction(score: ExtractionScore, thresholds: Thresholds = DEFAULT_THRESHOLDS): boolean {
  return score.precision >= thresholds.minPrecision && score.recall >= thresholds.minRecall;
}

// A synthesis result passes when nothing invented (no dangling refs), nothing ungrounded, and every
// high-severity event is covered. Confidence-rubric issues are reported but don't fail the gate (advisory).
export function passesSynthesis(report: SynthesisReport): boolean {
  return report.danglingEventRefs.length === 0 &&
    report.grounding.ungrounded.length === 0 &&
    report.highSeverity.uncovered.length === 0;
}

const pct = (n: number): string => `${(n * 100).toFixed(1)}%`;

// One-line-per-metric human report for the CLI runner (issue #64 "summary report").
export function formatExtractionReport(name: string, score: ExtractionScore, thresholds: Thresholds = DEFAULT_THRESHOLDS): string {
  const ok = passesExtraction(score, thresholds);
  return [
    `[${ok ? "PASS" : "FAIL"}] extraction: ${name}`,
    `  precision ${pct(score.precision)} (min ${pct(thresholds.minPrecision)})  recall ${pct(score.recall)} (min ${pct(thresholds.minRecall)})  f1 ${pct(score.f1)}`,
    `  TP ${score.truePositives}  FP ${score.falsePositives}  FN ${score.falseNegatives}` +
      (score.missedGolden.length ? `  missed golden #${score.missedGolden.join(",")}` : "") +
      (score.extraProduced.length ? `  extra ${score.extraProduced.join(",")}` : ""),
  ].join("\n");
}

export function formatSynthesisReport(name: string, report: SynthesisReport): string {
  const ok = passesSynthesis(report);
  const lines = [
    `[${ok ? "PASS" : "FAIL"}] synthesis: ${name}`,
    `  high-sev coverage ${report.highSeverity.covered}/${report.highSeverity.total}` +
      `  grounded findings ${report.grounding.grounded}/${report.grounding.total}`,
  ];
  if (report.highSeverity.uncovered.length) lines.push(`  UNCOVERED high-sev: ${report.highSeverity.uncovered.map((e) => e.id).join(", ")}`);
  if (report.grounding.ungrounded.length) lines.push(`  UNGROUNDED findings: ${report.grounding.ungrounded.join(", ")}`);
  if (report.danglingEventRefs.length) lines.push(`  INVENTED event refs: ${report.danglingEventRefs.map((d) => `${d.findingId}→[${d.badRefs.join(",")}]`).join("; ")}`);
  if (report.confidenceIssues.length) lines.push(`  confidence w/o reason (advisory): ${report.confidenceIssues.join(", ")}`);
  return lines.join("\n");
}
