// The intel retirement review (#933 item 19, second half — #1024): the findings whose intel
// corroboration rested on assertions that are now ALL expired, revoked, not returned, errored
// or superseded — a list to REVIEW, never an action. Nothing here changes a finding's severity or
// status, a deployed detection, or the history a rule produced; the analyst records a decision
// (`retire` / `keep`) and acts on it with the finding's own controls. A `retire` decision is a
// recorded recommendation: the STIX bundle and the block-list stop asserting that finding's
// intel-derived relationships, and the report labels it.

import type {
  Finding,
  IntelRetirementDecision,
  InvestigationState,
  IOC,
  IocEnrichment,
} from "./stateTypes.js";
import { actionableAssertions, assertionLabel, lastKnownAssertions } from "./intelViews.js";

export interface RetirementAssertion {
  iocId: string;
  iocValue: string;
  source: string;
  verdict: IocEnrichment["verdict"];
  status: string;
  label: string;
  assertionId: string;
  tags: string[];
}

export interface RetirementItem {
  findingId: string;
  title: string;
  severity: Finding["severity"];
  /** Every last-known assertion on the finding's related IOCs — none of them actionable. */
  assertions: RetirementAssertion[];
  /** What else corroborates the finding, from its stored rollup, when one exists. */
  otherCorroboration: {
    distinctTools: number;
    distinctHosts: number;
    graphLinked: boolean;
    kevLinked: boolean;
  } | null;
  recommendation: string;
  decision?: IntelRetirementDecision;
}

export interface RetirementReview {
  items: RetirementItem[];
  /** Findings whose IOCs still carry at least one actionable assertion — not up for review. */
  stillActionable: number;
  at: string;
}

const ITEMS_MAX = 256;
const ASSERTIONS_PER_ITEM_MAX = 32;

/** The findings whose every intel assertion is non-actionable at `at`, with the assertions named and the decision on file. */
export function intelRetirementReview(
  state: InvestigationState,
  at: string = new Date().toISOString(),
): RetirementReview {
  const iocById = new Map<string, IOC>(state.iocs.map((i) => [i.id, i]));
  const decisions = new Map((state.intelRetirementDecisions ?? []).map((d) => [d.findingId, d]));
  const items: RetirementItem[] = [];
  let stillActionable = 0;
  for (const f of state.findings) {
    const related = (f.relatedIocs ?? []).map((id) => iocById.get(id)).filter((i): i is IOC => !!i);
    const known = related.flatMap((i) =>
      lastKnownAssertions(i)
        .filter((e) => e.verdict === "malicious" || e.verdict === "suspicious")
        .map((e) => ({ ioc: i, e })),
    );
    if (known.length === 0) continue;
    const live = related.some((i) =>
      actionableAssertions(i, at).some((e) => e.verdict === "malicious" || e.verdict === "suspicious"),
    );
    if (live) {
      stillActionable += 1;
      continue;
    }
    const c = f.corroboration;
    const other = c
      ? {
          distinctTools: c.distinctTools,
          distinctHosts: c.distinctHosts,
          graphLinked: c.graphLinked,
          kevLinked: c.kevLinked ?? false,
        }
      : null;
    const stands = other ? other.distinctTools >= 2 || other.graphLinked || other.kevLinked : false;
    const assertions = known.slice(0, ASSERTIONS_PER_ITEM_MAX).map(({ ioc, e }) => ({
      iocId: ioc.id,
      iocValue: ioc.value,
      source: e.source,
      verdict: e.verdict,
      status: e.status,
      label: assertionLabel(e, at),
      assertionId: e.assertionId,
      tags: (e.tags ?? []).slice(0, 8),
    }));
    items.push({
      findingId: f.id,
      title: f.title,
      severity: f.severity,
      assertions,
      otherCorroboration: other,
      recommendation:
        `review: the intel this finding rested on is no longer actionable (${assertions.length} assertion${assertions.length === 1 ? "" : "s"}${known.length > assertions.length ? ` of ${known.length}` : ""}: ${summarizeStatuses(assertions)}); ` +
        (other
          ? `the finding's other corroboration (${other.distinctTools} tool${other.distinctTools === 1 ? "" : "s"}, ${other.distinctHosts} host${other.distinctHosts === 1 ? "" : "s"}${other.graphLinked ? ", graph-linked" : ""}${other.kevLinked ? ", KEV-linked" : ""}) ${stands ? "stands" : "does not stand on its own"}`
          : "no corroboration rollup is on file for this finding") +
        "; nothing changes until you decide",
      ...(decisions.has(f.id) ? { decision: decisions.get(f.id) } : {}),
    });
    if (items.length >= ITEMS_MAX) break;
  }
  return { items, stillActionable, at };
}

function summarizeStatuses(assertions: readonly RetirementAssertion[]): string {
  const counts = new Map<string, number>();
  for (const a of assertions) counts.set(a.status, (counts.get(a.status) ?? 0) + 1);
  return [...counts.entries()].map(([s, n]) => `${n} ${s}`).join(", ");
}

/** Record the analyst's decision: keyed by finding id, replacing an earlier one; nothing else changes. */
export function recordRetirementDecision(
  state: InvestigationState,
  decision: Omit<IntelRetirementDecision, "decidedAt" | "assertionIds"> & { decidedAt?: string },
  at: string = new Date().toISOString(),
): InvestigationState {
  const review = intelRetirementReview(state, at);
  const item = review.items.find((i) => i.findingId === decision.findingId);
  const record: IntelRetirementDecision = {
    findingId: decision.findingId,
    decision: decision.decision,
    ...(decision.note ? { note: decision.note.slice(0, 2000) } : {}),
    decidedAt: decision.decidedAt ?? at,
    assertionIds: item ? item.assertions.map((a) => a.assertionId) : [],
  };
  const others = (state.intelRetirementDecisions ?? []).filter((d) => d.findingId !== decision.findingId);
  return {
    ...state,
    intelRetirementDecisions: [...others, record],
    timeline: [
      ...state.timeline,
      {
        timestamp: record.decidedAt,
        windowSequence: 0,
        description: `Intel retirement review: ${decision.decision === "retire" ? "retire" : "keep"} finding ${decision.findingId}${decision.note ? ` — ${decision.note.slice(0, 200)}` : ""} (a recorded recommendation; the finding's severity and status are unchanged)`,
        sourceScreenshots: [],
      },
    ],
  };
}
