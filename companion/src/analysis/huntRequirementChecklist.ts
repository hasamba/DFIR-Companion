import type { Hypothesis, ResolvedSubjectScope } from "./hypothesis.js";
import type { ForensicEvent } from "./stateTypes.js";
import type { HostAliasIndex } from "./hostAlias.js";
import { resolveHost } from "./hostAlias.js";
import {
  requiredEvidenceClasses,
  collectedEvidenceClasses,
  collectedEvidenceClassesByHost,
  collectedForScope,
  type EvidenceClass,
  type AttestedEvidenceClass,
} from "./refutationGate.js";
import type { HuntRequirement } from "./huntRequirementStore.js";

// Turns one analyst-authored HuntRequirement (#933 item 17) into a bounded, read-only checklist —
// required evidence classes, what is actually available, the gap, a coarse cost signal, and a
// suggested next observation drawn from this case's own live hypothesis discriminators. Nothing
// here writes anything, executes a hunt, or queries an external provider; it is a pure function of
// data already in the case, computed FRESH on every call — never cached or persisted, which is
// what actually keeps a revoked/superseded requirement's own stale match from leaking into a
// newer one's checklist.

export interface HuntGap {
  evidenceClass: EvidenceClass;
  // Present only when the requirement's own scope resolved to something concrete ("hosts" or
  // "caseWide"). Absent for "unknown" scope — a cost label there would be a guess about hosts
  // that were never actually resolved.
  cost?: "low" | "high";
}

export interface HuntChecklist {
  requiredClasses: EvidenceClass[];
  // True when expectedObservableEvidence keyword-matched no known evidence class at all — the
  // spec's own "unsupported evidence sources" guardrail case.
  unsupportedEvidenceSource: boolean;
  gaps: HuntGap[];
  // Required classes covered ONLY by an analyst attestation, not automatic detection — disclosed
  // distinctly, mirroring refutationGate.ts's own #1111 disclosure rule.
  attestedOnly: EvidenceClass[];
  // True when subjectScope.kind === "unknown" — no cost label is emitted in this case.
  scopeUnresolved: boolean;
  discriminator: string | null;
  discriminatorAvailable: boolean;
  expired: boolean;
}

function scopesOverlap(
  a: ResolvedSubjectScope,
  b: ResolvedSubjectScope,
  aliasIndex: HostAliasIndex,
): boolean {
  if (a.kind === "caseWide" || b.kind === "caseWide") return true;
  if (a.kind === "unknown" || b.kind === "unknown") return a.kind === b.kind;
  const aHosts = new Set(a.hosts.map((h) => resolveHost(aliasIndex, h)));
  return b.hosts.some((h) => aHosts.has(resolveHost(aliasIndex, h)));
}

// The single candidate hypothesis whose own discriminator is the checklist's suggested next
// observation — the first OPEN, non-exhausted, scope-overlapping hypothesis whose own real
// free-text fields (never relatedTechniques, which are ATT&CK ids and cannot match the keyword
// matcher) require an evidence class this requirement is missing, and whose own discriminator is
// non-empty.
function findDiscriminator(
  requirement: HuntRequirement,
  hypotheses: readonly Hypothesis[],
  gapClasses: ReadonlySet<EvidenceClass>,
  aliasIndex: HostAliasIndex,
): string | null {
  for (const hyp of hypotheses) {
    if (hyp.status !== "open" || hyp.exhausted) continue;
    if (!hyp.discriminator) continue;
    const scope = hyp.subjectScope ?? { kind: "caseWide" as const };
    if (!scopesOverlap(requirement.subjectScope, scope, aliasIndex)) continue;
    const hypClasses = requiredEvidenceClasses(`${hyp.expectedOutcome} ${hyp.title} ${hyp.description}`);
    if (!hypClasses.some((c) => gapClasses.has(c))) continue;
    return hyp.discriminator;
  }
  return null;
}

export function buildHuntChecklist(input: {
  requirement: HuntRequirement;
  events: readonly ForensicEvent[];
  hypotheses: readonly Hypothesis[];
  attested: ReadonlyMap<EvidenceClass, AttestedEvidenceClass>;
  aliasIndex: HostAliasIndex;
  now: string;
}): HuntChecklist {
  const { requirement, events, hypotheses, attested, aliasIndex, now } = input;

  const requiredClasses = requiredEvidenceClasses(requirement.expectedObservableEvidence);
  const unsupportedEvidenceSource = requiredClasses.length === 0;

  const byHost = collectedEvidenceClassesByHost(events, aliasIndex);
  const knownHosts = new Set(byHost.keys());
  const scoped = collectedForScope(requirement.subjectScope, byHost, knownHosts, aliasIndex);
  const effectivelyCollected = (c: EvidenceClass): boolean => scoped.has(c) || attested.has(c);

  const gapClasses = requiredClasses.filter((c) => !effectivelyCollected(c));
  const attestedOnly = requiredClasses.filter((c) => !scoped.has(c) && attested.has(c));

  const scopeUnresolved = requirement.subjectScope.kind === "unknown";
  const caseWideUnion = scopeUnresolved ? null : collectedEvidenceClasses(events);

  const gaps: HuntGap[] = gapClasses.map((evidenceClass) => ({
    evidenceClass,
    ...(caseWideUnion
      ? { cost: caseWideUnion.has(evidenceClass) ? ("low" as const) : ("high" as const) }
      : {}),
  }));

  const gapClassSet = new Set(gapClasses);
  const discriminator = unsupportedEvidenceSource
    ? null
    : findDiscriminator(requirement, hypotheses, gapClassSet, aliasIndex);

  return {
    requiredClasses,
    unsupportedEvidenceSource,
    gaps,
    attestedOnly,
    scopeUnresolved,
    discriminator,
    discriminatorAvailable: discriminator !== null,
    expired: new Date(requirement.deadline).getTime() < new Date(now).getTime(),
  };
}
