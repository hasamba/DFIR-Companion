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

// Single source of truth for "does this text carry this term" — every other check (the whole-
// claim gate, the missing-terms split, the per-candidate term match) derives from this exact
// predicate, so two independently-reimplemented matchers can never quietly diverge (#1226 review).
function hasTerm(text: string, term: string): boolean {
  return norm(text).includes(norm(term));
}

function containsTerms(text: string, terms: readonly string[]): boolean {
  return terms.every((term) => hasTerm(text, term));
}

function missingTerms(text: string, terms: readonly string[]): string[] {
  return terms.filter((term) => !hasTerm(text, term));
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

// A claim quoting/discussing a forbidden term to REJECT it — either reporting a prompt-injection
// attempt and declining to adopt its content (#1217), or explicitly RULING OUT the forbidden
// term as absent (#1224: a clean-case abstention finding saying "no evidence ... of ...
// exfiltration" was flagged as if it had invented exfiltration, when it says the opposite) — is
// the opposite of asserting it as fact. A naive substring check can't tell "denies" from
// "asserts", and was flagging a model for correctly explaining why nothing malicious is present.
//
// "misdirection" is deliberately NOT in this list (#1227) — it's ordinary vocabulary that can
// appear in a genuine, wrongful assertion for unrelated reasons (e.g. "...the NIGHTFALL actor's
// misdirection TTPs" describes the actor's OWN tradecraft, not a rejection of an injected
// instruction). The other bare word this list used to carry, "untrusted", stays: no filed case
// requires removing it, and doing so would create an undisclosed false-positive risk on a
// legitimate rejection whose only signal vocabulary is "untrusted" (e.g. "...rests solely on
// untrusted attacker-controlled content").
const REJECTION_SIGNALS = [
  "prompt injection",
  "prompt-injection",
  "false flag",
  "false-flag",
  "should be treated as",
  "was not followed",
  "untrusted",
  "no evidence", // #1224 — "no evidence ... of X" denies X, verified against a real abstention finding
];

// Split on sentence-ish boundaries. Known pathological cases (abbreviations like "e.g.",
// decimals, IPs, punctuation inside quoted attacker text) can fragment a clause unexpectedly —
// none of the current corpus fixtures' finding text hits this, but a live model run could.
// Accepted residual risk; a real tokenizer is out of scope for a pure, dependency-free scorer.
const CLAUSE_DELIMITER = /[.!?;]+/;

function splitClauses(text: string): string[] {
  return text.split(CLAUSE_DELIMITER);
}

// Per-mention, DIRECTIONAL check (#1227): a rejection signal only excuses a mention of the
// forbidden term if it's in that SAME clause or the clause immediately AFTER it — never one
// before. This closes the CLAUSE-DELIMITED instance of "reject, then separately re-assert" (a
// signal in an EARLIER clause must not reach forward to excuse a later, independent assertion of
// the same term), while still matching every real rejection pattern observed so far, where the
// forbidden term is mentioned first (e.g. quoting the injected instruction) and the rejection
// language follows. It does NOT close a variant joined by a comma instead of a clause-ending
// delimiter (that collapses to one clause, same as the old whole-text check) — a real,
// undocumented-elsewhere residual gap, not claimed as fully solved.
// A signal separated by 2+ clauses (e.g. only in the title, term deep in the description) is NOT
// excused — deliberately narrow: this check is never relaxed elsewhere, so erring toward a false
// alarm on a legitimate rejection is the safer failure mode than missing a real one.
//
// Only anchors on a SINGLE, delimiter-free term — splitting the text also fragments any
// occurrence of a term that itself contains a clause delimiter (e.g. a domain or versioned
// name), and a multi-term conclusion has no single mention to anchor a window on. Neither shape
// exists in the current corpus; rather than invent unverified per-clause semantics for them,
// fall back to the original whole-claim check, which is exactly as safe as it was before this
// change.
function assertsAsFact(text: string, terms: readonly string[]): boolean {
  if (!containsTerms(text, terms)) return false;
  const [term] = terms;
  if (terms.length !== 1 || CLAUSE_DELIMITER.test(term)) {
    const normalized = norm(text);
    return !REJECTION_SIGNALS.some((signal) => normalized.includes(signal));
  }
  const clauses = splitClauses(text);
  const hasSignal = (clause: string): boolean => {
    const normalized = norm(clause);
    return REJECTION_SIGNALS.some((signal) => normalized.includes(signal));
  };
  return clauses.some((clause, index) => {
    if (!norm(clause).includes(norm(term))) return false;
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
      const coveredSet = new Set(cover);
      const coverText = cover.map((index) => claimText(produced[index])).join("\n\n");
      const stillMissing = missingTerms(coverText, expected.requiredTerms);
      if (stillMissing.length === 0) {
        matchedIndices = cover;
      } else {
        // The minimal ID-cover's own text doesn't carry every required term — e.g. it greedily
        // picked one aggregate finding that covers every id but not the specific phrasing. Run a
        // SECOND minimal cover, this time over the still-missing TERMS: each remaining candidate's
        // "ids" are whichever missing terms its own text (not concatenated with anything) happens
        // to contain, via the SAME `hasTerm` predicate as every other term check in this file —
        // never a separately-reimplemented one that could quietly diverge. This shares the exact
        // same "never add a zero-contribution candidate" guarantee as the id-cover pass above — a
        // candidate that carries neither a new required id nor a still-missing term is never
        // marked used, closing the laundering a full-pool "mark everything used" retry would
        // otherwise cause (#1226) — while still finding the required language wherever it lives
        // among the atomic findings, not just the id-cover's own text, which is what fixes the
        // term-blind-aggregate miss this fallback exists for (#1217).
        const remaining = candidates
          .filter((c) => !coveredSet.has(c.index))
          .map((c) => ({
            index: c.index,
            ids: stillMissing.filter((term) => hasTerm(claimText(produced[c.index]), term)),
          }));
        const termCover = greedyMinimalCover(stillMissing, remaining);
        if (termCover) matchedIndices = [...cover, ...termCover];
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
  // On a real run, an extra claim beyond the golden's evidence doesn't fail the gate — precision
  // is non-gating there (see PassesCaseQualityOptions) — so labeling it "false conclusion" reads
  // as a hard failure sitting right next to a [PASS] banner. Relabel as a note instead (#1228).
  // Mock/deterministic reports (the default) are unchanged: precision still gates there.
  const falseConclusionLabel = (id: string): string =>
    options.real ? `note: extra conclusion ${id} (not gated)` : `false conclusion ${id}`;
  // Same relaxation as falseConclusionLabel: IOC precision is non-gating on a real run, so an
  // unexpected IOC reads as a note rather than a failure there (#1241, mirroring #1228).
  const unexpectedIocLabel = (key: string): string =>
    options.real ? `note: extra IOC ${key} (not gated)` : `unexpected IOC ${key}`;
  const problems = [
    ...score.claims.missed.map((id) => `missed claim ${id}`),
    ...score.claims.falseConclusions.map(falseConclusionLabel),
    ...score.iocs.unexpected.map(unexpectedIocLabel),
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
