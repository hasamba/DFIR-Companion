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

function sameIds(left: readonly string[], right: readonly string[]): boolean {
  const a = [...new Set(left)].sort();
  const b = [...new Set(right)].sort();
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function claimText(claim: QualityClaim): string {
  return `${claim.title}\n${claim.description}`;
}

function scoreClaims(golden: readonly GoldenClaim[], produced: readonly QualityClaim[]) {
  const used = new Set<number>();
  const missed: string[] = [];
  for (const expected of golden) {
    const hit = produced.findIndex(
      (claim, index) =>
        !used.has(index) &&
        sameIds(expected.evidenceEventIds, claim.evidenceEventIds) &&
        containsTerms(claimText(claim), expected.requiredTerms),
    );
    if (hit < 0) missed.push(expected.id);
    else used.add(hit);
  }
  const falseConclusions = produced.filter((_, index) => !used.has(index)).map((claim) => claim.id);
  return {
    total: golden.length,
    matched: used.size,
    precision: ratio(used.size, used.size + falseConclusions.length),
    recall: ratio(used.size, golden.length),
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
      .filter((forbidden) => output.claims.some((claim) => containsTerms(claimText(claim), forbidden.terms)))
      .map((forbidden) => forbidden.id),
    confidenceIssues: confidenceIssues(golden.claims, output.claims),
    uncertainties: scoreUncertainties(golden.uncertainties, output.uncertainties),
    nextSteps: scoreNextSteps(golden.nextSteps, output.nextSteps),
    abstentionPassed: !golden.expectAbstention || output.claims.length === 0,
  };
}

export function passesCaseQuality(score: CaseQualityScore): boolean {
  return (
    score.claims.precision === 1 &&
    score.claims.recall === 1 &&
    score.iocs.precision === 1 &&
    score.iocs.recall === 1 &&
    score.danglingEvidenceRefs.length === 0 &&
    score.forbiddenConclusions.length === 0 &&
    score.confidenceIssues.length === 0 &&
    score.uncertainties.recall === 1 &&
    score.nextSteps.recall === 1 &&
    score.abstentionPassed
  );
}

export function formatCaseQualityReport(name: string, score: CaseQualityScore): string {
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
    `[${passesCaseQuality(score) ? "PASS" : "FAIL"}] production: ${name}`,
    ...details,
    ...(problems.length ? [`  ${problems.join("; ")}`] : []),
  ].join("\n");
}
