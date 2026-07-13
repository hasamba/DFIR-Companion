// Rabbit-hole detection (investigation-guidance #13). "Which findings are rabbit holes?" has no
// taxonomy today — veridia's planted red herring became a High finding; halcyon's benign USB copy was
// indistinguishable from the real exfil. This module answers it deterministically: a finding whose
// supporting evidence sits in the evidence graph but in a DIFFERENT connected component than the
// corroborated Critical/High attack mass (the "main component") has no causal link to the known attack
// path — a rabbit-hole candidate. The AI adds a nuance the graph can't: a disconnected finding that is
// nonetheless genuine-but-unrelated activity (a second, separate issue) vs undetermined noise.
//
// Crucially, "not in the main component" is only claimed for evidence that IS in the graph. A finding
// whose events carry no graph-modeled relationship (no process chain / hash / account / network flow)
// is 'undetermined', NOT 'disconnected' — we never brand a finding a rabbit hole just because its
// evidence type isn't one the causal graph models.

import type { Finding, ForensicEvent } from "./stateTypes.js";
import { mainComponent, componentHostLabels, type EvidenceGraph } from "./evidenceGraph.js";

export type FindingRelevance = "connected" | "disconnected" | "unrelated-but-real" | "undetermined";
export type AiRelevance = "connected" | "unrelated-but-real" | "undetermined";

// The three triage buckets the dashboard groups findings into.
export type RelevanceBucket = "lead" | "rabbit-hole" | "parked";

export function relevanceBucket(relevance: FindingRelevance | undefined): RelevanceBucket {
  if (relevance === "disconnected") return "rabbit-hole";
  if (relevance === "unrelated-but-real") return "parked";
  return "lead"; // connected + undetermined default to the main list (never hide a possible lead)
}

// Gather the forensic-event ids a finding cites as evidence: its own relatedEventIds PLUS the reverse
// links (events whose relatedFindingIds name it) — same two-way resolution groundAndScoreFindings uses,
// so a confidence-backfill finding (linked only in reverse) still resolves.
function findingEventIds(finding: Finding, reverseByFinding: ReadonlyMap<string, Set<string>>): string[] {
  const ids = new Set<string>(finding.relatedEventIds ?? []);
  for (const id of reverseByFinding.get(finding.id) ?? []) ids.add(id);
  return [...ids];
}

// Combine the deterministic linkage verdict with the optional AI verdict. The graph is authoritative
// about linkage (a real edge is a fact); the AI only refines a DISCONNECTED finding into a genuine-
// but-unrelated issue vs undetermined noise, and classifies findings the graph couldn't place.
function resolveRelevance(deterministic: FindingRelevance, ai: AiRelevance | undefined): FindingRelevance {
  if (deterministic === "connected") return "connected";               // linkage is a fact; AI can't override
  if (deterministic === "disconnected") {
    if (ai === "unrelated-but-real") return "unrelated-but-real";       // real, but a separate issue → Parked
    if (ai === "undetermined") return "undetermined";
    if (ai === "connected") return "undetermined";                     // AI↔graph conflict → don't brand a rabbit hole
    return "disconnected";                                              // no AI signal → rabbit-hole candidate
  }
  // deterministic 'undetermined' (evidence not in the causal graph): defer to the AI when it spoke.
  return ai ?? "undetermined";
}

export interface ScoreRelevanceInput {
  findings: readonly Finding[];
  scopedEvents: readonly ForensicEvent[];  // in-scope events (for reverse finding links)
  graph: EvidenceGraph;
  aiRelevanceById?: ReadonlyMap<string, AiRelevance>;
}

// Score every finding's relevance + connectedness (0..1) against the main component, merging the AI
// verdict, and attach a "to link it, look for:" discriminator to disconnected findings. Pure +
// idempotent; only sets the three relevance fields. Returns NEW finding objects (never mutates).
export function scoreFindingsRelevance(input: ScoreRelevanceInput): Finding[] {
  const main = mainComponent(input.graph);
  const allGraphEventIds = new Set<string>();
  for (const n of input.graph.nodes) for (const eid of n.eventIds) allGraphEventIds.add(eid);
  const mainEventIds = main?.eventIds ?? new Set<string>();

  // Reverse index: finding id → set of event ids that name it (built once).
  const reverseByFinding = new Map<string, Set<string>>();
  for (const e of input.scopedEvents) {
    for (const fid of e.relatedFindingIds ?? []) {
      const set = reverseByFinding.get(fid) ?? new Set<string>();
      set.add(e.id);
      reverseByFinding.set(fid, set);
    }
  }

  const hostHint = main ? componentHostLabels(input.graph, main) : [];
  const discriminator = hostHint.length
    ? `no causal link to the main attack path — to link it, look for a shared host (${hostHint.join(", ")}), binary hash, account, or network flow`
    : "no causal link to the main attack path — look for a shared host, binary hash, account, or network flow that ties it in";

  return input.findings.map((f) => {
    const evs = findingEventIds(f, reverseByFinding);
    const graphEvs = evs.filter((id) => allGraphEventIds.has(id));
    let deterministic: FindingRelevance;
    let connectedness: number;
    if (!main || graphEvs.length === 0) {
      // No main component, or the finding's evidence doesn't participate in the causal graph → can't
      // judge linkage. Never a rabbit hole on that basis.
      deterministic = "undetermined";
      connectedness = 0;
    } else {
      const inMain = graphEvs.filter((id) => mainEventIds.has(id)).length;
      connectedness = inMain / graphEvs.length;
      deterministic = connectedness > 0 ? "connected" : "disconnected";
    }
    const relevance = resolveRelevance(deterministic, input.aiRelevanceById?.get(f.id));
    const next: Finding = { ...f, relevance, connectedness: Math.round(connectedness * 100) / 100 };
    if (relevance === "disconnected") next.relevanceDiscriminator = discriminator;
    else delete next.relevanceDiscriminator;
    return next;
  });
}
