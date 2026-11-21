import type { VeloHuntJob } from "./veloHuntStore.js";

/**
 * Hunt-mode framing (#2670): the block synthesis and Watson read in a THREAT HUNT case, and the
 * coverage summary it states its verdict against. PURE — no I/O, no AI.
 *
 * A hunt has no incident. The model is asked to rank anomalies, to state its verdict WITHIN the
 * coverage the hunts actually achieved, and not to force a kill chain or attribution. The block is a
 * per-case data block (like the incident-type hint), never system-prompt text, so it also reaches a
 * model whose prompts were ejected to prompts/*.txt.
 *
 * Coverage comes only from what Velociraptor reported for a Companion-launched hunt: the clients whose
 * flow finished cleanly (`reachedClients`, #1625) and the hunt's client counts (`clientCounts`,
 * #1612). An uploaded hunt export, or a job collected before those were recorded, has neither — its
 * coverage is UNKNOWN, and the block says so instead of guessing a denominator.
 */

export interface HuntCoverageKnown {
  known: true;
  /** Distinct clients whose hunt flow finished without error, across every hunt with a record. */
  answered: number;
  /** The largest scheduled count any one hunt reported; null when no hunt reported counts. */
  targeted: number | null;
  /** targeted − answered when both are known and the difference is positive; else 0. */
  notAnswered: number;
  /** Hunts whose coverage IS recorded. */
  huntsWithCoverage: number;
  /** Imported hunts with no coverage record (an older job or a failed stats read). */
  huntsWithoutCoverage: number;
  /** Artifacts read only partly (row cap, unread source list, failed fetch) across those hunts. */
  partialArtifacts: number;
  /** Their names, distinct and sorted: rarity is not graded for the items they reported (#2732). */
  partialArtifactNames: string[];
  /** Every artifact those hunts collected, distinct and sorted — an item from any other is not graded while one is partial. */
  collectedArtifactNames: string[];
  /** The answering hosts, for the report's scope table. */
  answeredHosts: { clientId: string; hostname: string }[];
}

export interface HuntCoverageUnknown {
  known: false;
  reason: string;
}

export type HuntCoverage = HuntCoverageKnown | HuntCoverageUnknown;

const COLLECTED = new Set(["imported", "collecting"]);

const hasCoverage = (j: VeloHuntJob): boolean => Array.isArray(j.reachedClients) && !!j.clientCounts;

function partialCount(j: VeloHuntJob): number {
  return (
    (j.truncatedArtifacts?.length ?? 0) + (j.unreadArtifacts?.length ?? 0) + (j.skippedArtifacts?.length ?? 0)
  );
}

function partialNames(jobs: readonly VeloHuntJob[]): string[] {
  const names = jobs.flatMap((j) =>
    [...(j.truncatedArtifacts ?? []), ...(j.unreadArtifacts ?? []), ...(j.skippedArtifacts ?? [])].map(
      (a) => a.name,
    ),
  );
  return [...new Set(names)].sort();
}

/** What the case's Velociraptor hunt jobs say about coverage. Never guesses a denominator. */
export function huntCoverageFromJobs(jobs: readonly VeloHuntJob[]): HuntCoverage {
  const collected = jobs.filter((j) => COLLECTED.has(j.status));
  const withCov = collected.filter(hasCoverage);
  if (withCov.length === 0) {
    return {
      known: false,
      reason: collected.length
        ? `coverage unknown: ${collected.length} collected hunt(s) carry no client-coverage record`
        : "coverage unknown: no Companion-launched hunt was collected (uploaded hunt exports carry no coverage record)",
    };
  }
  const hosts = new Map<string, string>();
  for (const j of withCov)
    for (const c of j.reachedClients ?? []) hosts.set(c.clientId, c.hostname || c.fqdn);
  const targeted = Math.max(...withCov.map((j) => j.clientCounts?.scheduled ?? 0));
  const answered = hosts.size;
  return {
    known: true,
    answered,
    targeted: targeted > 0 ? targeted : null,
    notAnswered: targeted > answered ? targeted - answered : 0,
    huntsWithCoverage: withCov.length,
    huntsWithoutCoverage: collected.length - withCov.length,
    partialArtifacts: withCov.reduce((n, j) => n + partialCount(j), 0),
    partialArtifactNames: partialNames(withCov),
    collectedArtifactNames: [...new Set(withCov.flatMap((j) => j.artifacts))].sort(),
    answeredHosts: [...hosts].map(([clientId, hostname]) => ({ clientId, hostname })),
  };
}

/** One plain sentence describing coverage, shared by the AI block and the report. */
export function coverageSentence(c: HuntCoverage): string {
  if (!c.known) return `Coverage: ${c.reason}. No absence can be claimed and no percentage stated.`;
  const of = c.targeted !== null ? ` of ${c.targeted} targeted` : "";
  const gaps = c.notAnswered > 0 ? `; ${c.notAnswered} did not answer (coverage gap)` : "";
  const partial =
    c.partialArtifacts > 0
      ? `; ${c.partialArtifacts} artifact collection(s) were partial, so absence is not proven for them`
      : "";
  const unknown =
    c.huntsWithoutCoverage > 0 ? `; ${c.huntsWithoutCoverage} further hunt(s) have unknown coverage` : "";
  return `Coverage: ${c.answered} host(s)${of} answered cleanly${gaps}${partial}${unknown}.`;
}

/**
 * The HUNT MODE block for synthesis and Watson. Returned with a trailing blank line so callers can
 * concatenate it unconditionally after the incident-type block.
 */
export function renderHuntFramingBlock(c: HuntCoverage): string {
  return (
    "HUNT MODE: this case is a proactive threat hunt, not an incident response. There may be no attacker at all.\n" +
    "- Rank anomalies by how suspicious they are; benign administration and approved software are expected background.\n" +
    "- State the verdict WITHIN COVERAGE, e.g. 'no compromise found on the N hosts that answered; K did not answer'.\n" +
    "- Do NOT force a kill chain, an attacker path or attribution when the evidence does not show one.\n" +
    "- Rows labelled 'Approved by client' are expected; only unusual use of them (new host, odd path, odd time) is an anomaly.\n" +
    "- Policy findings are policy violations, not proof of malicious activity.\n" +
    "- If you find REAL attacker activity, say so prominently in the summary and grade it High or Critical, so the analyst can convert the hunt to an incident.\n" +
    `${coverageSentence(c)}\n\n`
  );
}
