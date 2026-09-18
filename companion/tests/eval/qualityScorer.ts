import type { IOC, UncertaintyStatus } from "../../src/analysis/stateTypes.js";

export interface GoldenClaim {
  id: string;
  requiredTerms: string[];
  evidenceEventIds: string[];
  confidence?: { min: number; max: number };
}

export interface GoldenIoc {
  type: IOC["type"];
  value: string;
}

export interface ForbiddenConclusion {
  id: string;
  terms: string[];
}

export interface GoldenUncertainty {
  id: string;
  topicTerms: string[];
  allowedStatuses: UncertaintyStatus[];
}

export interface GoldenNextStep {
  id: string;
  requiredTerms: string[];
}

export interface CaseGolden {
  claims: GoldenClaim[];
  iocs: GoldenIoc[];
  forbiddenConclusions: ForbiddenConclusion[];
  uncertainties: GoldenUncertainty[];
  nextSteps: GoldenNextStep[];
  expectAbstention: boolean;
}

export interface QualityClaim {
  id: string;
  title: string;
  description: string;
  evidenceEventIds: string[];
  confidence?: number;
  confidenceReason?: string;
}

export interface QualityIoc {
  id: string;
  type: IOC["type"];
  value: string;
}

export interface QualityUncertainty {
  topic: string;
  status: UncertaintyStatus;
  basis: string;
  gap: string;
}

export interface QualityNextStep {
  action: string;
  rationale: string;
  pointer: string;
}

export interface QualityOutput {
  evidenceEventIds: string[];
  claims: QualityClaim[];
  iocs: QualityIoc[];
  uncertainties: QualityUncertainty[];
  nextSteps: QualityNextStep[];
}

export interface CaseQualityScore {
  claims: {
    total: number;
    matched: number;
    precision: number;
    recall: number;
    missed: string[];
    falseConclusions: string[];
  };
  iocs: {
    total: number;
    matched: number;
    precision: number;
    recall: number;
    missed: string[];
    unexpected: string[];
  };
  danglingEvidenceRefs: Array<{ claimId: string; evidenceEventIds: string[] }>;
  forbiddenConclusions: string[];
  confidenceIssues: string[];
  uncertainties: { total: number; matched: number; recall: number; missed: string[] };
  nextSteps: { total: number; matched: number; recall: number; missed: string[] };
  abstentionPassed: boolean;
}

const norm = (value: string): string => value.trim().toLowerCase();
const ratio = (numerator: number, denominator: number): number =>
  denominator === 0 ? 1 : numerator / denominator;

function containsTerms(text: string, terms: readonly string[]): boolean {
  const normalized = norm(text);
  return terms.every((term) => normalized.includes(norm(term)));
}

// A claim must CITE (at least) its required evidence, not reproduce the golden's exact id set. Two
// real models (openrouter/google/gemini-3.7-flash and anthropic/claude-sonnet-4.6) both scored a
// hard 0.0% claims precision AND recall on 8-9 of 9 production cases despite getting IOCs,
// uncertainties and next-steps mostly right — a real model reliably citing the identical id
// combination the corpus author happened to type is not a realistic bar. Missing required evidence
// still fails (coveredBy is not symmetric); an id-for-id match is no longer required.
function coveredBy(required: readonly string[], actual: readonly string[]): boolean {
  const have = new Set(actual);
  return required.every((id) => have.has(id));
}

function claimText(claim: QualityClaim): string {
  return `${claim.title}\n${claim.description}`;
}

// A claim quoting/discussing a forbidden term to REJECT it (e.g. reporting a prompt-injection
// attempt and explicitly declining to adopt its content) is the opposite of asserting it as fact —
// a naive substring check can't tell the two apart, and was flagging a model for correctly
// recognizing and neutralizing an injection attempt (#1217). These are the domain-standard ways
// this project's own prompts already ask a model to signal exactly that rejection, so a claim
// carrying one of these alongside the forbidden term is read as REPORTING it, not adopting it.
//
// Deliberately multi-word phrases only (#1227) — a bare word like "misdirection" or "untrusted"
// is ordinary vocabulary that can appear in a genuine, wrongful assertion for unrelated reasons
// (e.g. "...the NIGHTFALL actor's misdirection TTPs" describes the actor's OWN tradecraft, not a
// rejection of an injected instruction).
const REJECTION_SIGNALS = [
  "prompt injection",
  "prompt-injection",
  "false flag",
  "false-flag",
  "should be treated as",
  "was not followed",
];

// Split on sentence-ish boundaries. Known pathological cases (abbreviations like "e.g.",
// decimals, IPs, punctuation inside quoted attacker text) can fragment a clause unexpectedly —
// none of the current corpus fixtures' finding text hits this, but a live model run could.
// Accepted residual risk; a real tokenizer is out of scope for a pure, dependency-free scorer.
function splitClauses(text: string): string[] {
  return text.split(/[.!?;]+/);
}

// Per-mention, DIRECTIONAL check (#1227): a rejection signal only excuses a mention of the
// forbidden term if it's in that SAME clause or the clause immediately AFTER it — never one
// before. This closes "reject, then separately re-assert" constructions (a signal in an EARLIER
// clause must not reach forward to excuse a later, independent assertion of the same term),
// while still matching every real rejection pattern observed so far, where the forbidden term is
// mentioned first (e.g. quoting the injected instruction) and the rejection language follows.
// A signal separated by 2+ clauses (e.g. only in the title, term deep in the description) is NOT
// excused — deliberately narrow: this check is never relaxed elsewhere, so erring toward a false
// alarm on a legitimate rejection is the safer failure mode than missing a real one.
function assertsAsFact(text: string, terms: readonly string[]): boolean {
  const clauses = splitClauses(text);
  const hasSignal = (clause: string): boolean => {
    const normalized = norm(clause);
    return REJECTION_SIGNALS.some((signal) => normalized.includes(signal));
  };
  return clauses.some((clause, index) => {
    if (!containsTerms(clause, terms)) return false;
    const nextClause = clauses[index + 1];
    return !hasSignal(clause) && !(nextClause !== undefined && hasSignal(nextClause));
  });
}

// A case-level narrative claim (e.g. "ransomware impact") may legitimately be told across several
// SEPARATE atomic findings — the production synthesis prompt explicitly forbids collapsing distinct
// techniques into one "campaign" finding (analysis/ai/prompts/synthesis.ts), so a single golden claim
// spanning several seed events must be satisfiable by the findings that jointly make it up (#1217).
//
// Greedy MINIMAL cover: repeatedly add the not-yet-used candidate covering the most still-uncovered
// required ids, and never add one that covers zero new ids — so an unrelated or duplicate finding
// can't ride along "used" for free just because it happens to be in the pool.
function greedyMinimalCover(
  required: readonly string[],
  candidates: readonly { index: number; ids: readonly string[] }[],
): number[] | null {
  const remaining = new Set(required);
  const chosen: number[] = [];
  const pool = [...candidates];
  while (remaining.size > 0) {
    let bestIndex = -1;
    let bestNewCoverage = 0;
    for (let i = 0; i < pool.length; i += 1) {
      const newCoverage = pool[i].ids.filter((id) => remaining.has(id)).length;
      if (newCoverage > bestNewCoverage) {
        bestNewCoverage = newCoverage;
        bestIndex = i;
      }
    }
    if (bestIndex < 0) return null; // no remaining candidate covers anything new — unsatisfiable
    const [best] = pool.splice(bestIndex, 1);
    chosen.push(best.index);
    for (const id of best.ids) remaining.delete(id);
  }
  return chosen;
}

function scoreClaims(golden: readonly GoldenClaim[], produced: readonly QualityClaim[]) {
  const used = new Set<number>();
  const missed: string[] = [];
  for (const expected of golden) {
    const availableIndices = produced.map((_, index) => index).filter((index) => !used.has(index));

    // Fast path: one claim alone satisfies it (today's behavior, unchanged).
    const soloHit = availableIndices.find(
      (index) =>
        coveredBy(expected.evidenceEventIds, produced[index].evidenceEventIds) &&
        containsTerms(claimText(produced[index]), expected.requiredTerms),
    );
    if (soloHit !== undefined) {
      used.add(soloHit);
      continue;
    }

    // Fallback: the union of several atomic findings, each contributing at least one required id.
    const candidates = availableIndices
      .map((index) => ({ index, ids: produced[index].evidenceEventIds }))
      .filter((c) => c.ids.some((id) => expected.evidenceEventIds.includes(id)));
    const cover = greedyMinimalCover(expected.evidenceEventIds, candidates);
    let matchedIndices: number[] | null = null;
    if (cover) {
      const coverText = cover.map((index) => claimText(produced[index])).join("\n\n");
      if (containsTerms(coverText, expected.requiredTerms)) {
        matchedIndices = cover;
      } else {
        // The minimal ID-cover's own text doesn't carry the required term — e.g. it greedily
        // picked one aggregate finding that covers every id but not the specific phrasing. Retry
        // against the FULL candidate pool (still guaranteed to cover the required ids, since it's
        // a superset of `cover`): its union may carry the term via a claim the minimal cover
        // didn't need for id coverage alone. Without this, a term-blind aggregate finding can
        // shadow the atomic findings that DO carry the required language and reintroduce the
        // exact miss this fallback exists to fix (#1217).
        const allIndices = candidates.map((c) => c.index);
        const fullText = allIndices.map((index) => claimText(produced[index])).join("\n\n");
        if (containsTerms(fullText, expected.requiredTerms)) matchedIndices = allIndices;
      }
    }
    if (matchedIndices) {
      for (const index of matchedIndices) used.add(index);
    } else {
      missed.push(expected.id);
    }
  }
  const falseConclusions = produced.filter((_, index) => !used.has(index)).map((claim) => claim.id);
  return {
    total: golden.length,
    matched: golden.length - missed.length,
    precision: ratio(used.size, used.size + falseConclusions.length),
    recall: ratio(golden.length - missed.length, golden.length),
    missed,
    falseConclusions,
  };
}

function iocKey(ioc: GoldenIoc | QualityIoc): string {
  return `${ioc.type}:${norm(ioc.value)}`;
}

function scoreIocs(golden: readonly GoldenIoc[], produced: readonly QualityIoc[]) {
  const expected = new Set(golden.map(iocKey));
  const actual = new Set(produced.map(iocKey));
  const matched = [...expected].filter((key) => actual.has(key)).length;
  const missed = [...expected].filter((key) => !actual.has(key));
  const unexpected = [...actual].filter((key) => !expected.has(key));
  return {
    total: expected.size,
    matched,
    precision: ratio(matched, matched + unexpected.length),
    recall: ratio(matched, expected.size),
    missed,
    unexpected,
  };
}

function danglingRefs(output: QualityOutput): CaseQualityScore["danglingEvidenceRefs"] {
  const evidence = new Set(output.evidenceEventIds);
  return output.claims.flatMap((claim) => {
    const bad = claim.evidenceEventIds.filter((id) => !evidence.has(id));
    return bad.length ? [{ claimId: claim.id, evidenceEventIds: bad }] : [];
  });
}

function confidenceIssues(golden: readonly GoldenClaim[], claims: readonly QualityClaim[]): string[] {
  const issues: string[] = [];
  for (const claim of claims) {
    const expected = golden.find((candidate) => containsTerms(claimText(claim), candidate.requiredTerms));
    if (expected?.confidence && typeof claim.confidence === "number") {
      const { min, max } = expected.confidence;
      if (claim.confidence < min || claim.confidence > max) {
        issues.push(`${claim.id}: confidence outside ${min}-${max}`);
      }
    }
    if (typeof claim.confidence === "number" && !String(claim.confidenceReason ?? "").trim()) {
      issues.push(`${claim.id}: confidence has no reason`);
    }
  }
  return issues;
}

function scoreUncertainties(
  golden: readonly GoldenUncertainty[],
  produced: readonly QualityUncertainty[],
): CaseQualityScore["uncertainties"] {
  const missed = golden
    .filter(
      (expected) =>
        !produced.some(
          (actual) =>
            containsTerms(actual.topic, expected.topicTerms) &&
            expected.allowedStatuses.includes(actual.status) &&
            actual.gap.trim().length > 0,
        ),
    )
    .map((expected) => expected.id);
  return {
    total: golden.length,
    matched: golden.length - missed.length,
    recall: ratio(golden.length - missed.length, golden.length),
    missed,
  };
}

function scoreNextSteps(
  golden: readonly GoldenNextStep[],
  produced: readonly QualityNextStep[],
): CaseQualityScore["nextSteps"] {
  const missed = golden
    .filter(
      (expected) =>
        !produced.some((actual) =>
          containsTerms(`${actual.action}\n${actual.rationale}\n${actual.pointer}`, expected.requiredTerms),
        ),
    )
    .map((expected) => expected.id);
  return {
    total: golden.length,
    matched: golden.length - missed.length,
    recall: ratio(golden.length - missed.length, golden.length),
    missed,
  };
}

export function scoreCaseQuality(golden: CaseGolden, output: QualityOutput): CaseQualityScore {
  return {
    claims: scoreClaims(golden.claims, output.claims),
    iocs: scoreIocs(golden.iocs, output.iocs),
    danglingEvidenceRefs: danglingRefs(output),
    forbiddenConclusions: golden.forbiddenConclusions
      .filter((forbidden) => output.claims.some((claim) => assertsAsFact(claimText(claim), forbidden.terms)))
      .map((forbidden) => forbidden.id),
    confidenceIssues: confidenceIssues(golden.claims, output.claims),
    uncertainties: scoreUncertainties(golden.uncertainties, output.uncertainties),
    nextSteps: scoreNextSteps(golden.nextSteps, output.nextSteps),
    abstentionPassed: !golden.expectAbstention || output.claims.length === 0,
  };
}

export interface PassesCaseQualityOptions {
  // A real (non-deterministic) model run does not gate on PRECISION for claims or IOCs — a
  // thorough model correctly surfacing an extra, legitimate finding or observation is not a
  // regression (mirrors scorer.ts's REAL_THRESHOLDS reasoning for the sibling extraction
  // evaluator). This was reconsidered from an earlier draft that kept IOC precision gated on the
  // theory that `iocs.unexpected` is a hallucination signal: verified against 7 live real-model
  // runs across every corpus case and found ZERO fabricated IOCs, but 3 different cases where the
  // model correctly extracted additional real, evidence-grounded observations (a rule name, an
  // account, a file path) that the golden's IOC list simply never anticipated — the exact
  // benign-thoroughness pattern REAL_THRESHOLDS already exists to not punish. RECALL still must
  // be 1 for both: missing a required fact is a real regression either way.
  // Hallucination/forbidden-conclusion/confidence-rubric checks are never relaxed — those catch
  // invention, not phrasing variance.
  real?: boolean;
}

export function passesCaseQuality(score: CaseQualityScore, options: PassesCaseQualityOptions = {}): boolean {
  const precisionOk = options.real ? true : score.claims.precision === 1 && score.iocs.precision === 1;
  return (
    precisionOk &&
    score.claims.recall === 1 &&
    score.iocs.recall === 1 &&
    score.danglingEvidenceRefs.length === 0 &&
    score.forbiddenConclusions.length === 0 &&
    score.confidenceIssues.length === 0 &&
    score.uncertainties.recall === 1 &&
    score.nextSteps.recall === 1 &&
    score.abstentionPassed
  );
}

export function formatCaseQualityReport(
  name: string,
  score: CaseQualityScore,
  options: PassesCaseQualityOptions = {},
): string {
  const pct = (value: number): string => `${(value * 100).toFixed(1)}%`;
  const details = [
    `  claims precision ${pct(score.claims.precision)} recall ${pct(score.claims.recall)}`,
    `  IOC precision ${pct(score.iocs.precision)} recall ${pct(score.iocs.recall)}`,
    `  uncertainty recall ${pct(score.uncertainties.recall)} next-step recall ${pct(score.nextSteps.recall)}`,
  ];
  const problems = [
    ...score.claims.missed.map((id) => `missed claim ${id}`),
    ...score.claims.falseConclusions.map((id) => `false conclusion ${id}`),
    ...score.forbiddenConclusions.map((id) => `forbidden conclusion ${id}`),
    ...score.confidenceIssues,
    ...score.uncertainties.missed.map((id) => `missed uncertainty ${id}`),
    ...score.nextSteps.missed.map((id) => `missed next step ${id}`),
  ];
  if (!score.abstentionPassed) problems.push("clean-case abstention failed");
  return [
    `[${passesCaseQuality(score, options) ? "PASS" : "FAIL"}] production: ${name}`,
    ...details,
    ...(problems.length ? [`  ${problems.join("; ")}`] : []),
  ].join("\n");
}
