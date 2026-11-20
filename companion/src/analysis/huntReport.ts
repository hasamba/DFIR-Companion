import type { Finding, ForensicEvent, InvestigationState, Severity } from "./stateTypes.js";
import type { HuntCoverage } from "./huntFraming.js";

/**
 * What the Threat hunt summary report reads (#2670), assembled by composition and handed to the
 * renderer — the report layer renders only what it is given. PURE types + the deterministic verdict.
 *
 * Every list here is DERIVED from the hunt inventory recorded at import and the client profile; none
 * is read from the super-timeline.
 */

export interface HuntReportHunt {
  huntId: string;
  bundleName: string;
  launchedAt: string;
  status: string;
}

/** One graded hunt item (a rare / new / policy / download entry), one per distinct program. */
export interface HuntReportItem {
  kind: "policy" | "new" | "rare" | "download";
  label: string;
  hosts: string[];
  moreHosts: number;
  hostCount: number;
  severity: Severity;
  reason: string;
}

/** One candidate still waiting for the client's answer. */
export interface HuntReportPending {
  label: string;
  hostCount: number;
  firstSeen: string;
  huntsUnconfirmed: number;
}

export interface HuntReportComparison {
  previousCaseId: string;
  previousAt: string;
  newItems: number;
  goneItems: number;
}

export interface HuntReportData {
  clientName?: string;
  coverage: HuntCoverage;
  hunts: HuntReportHunt[];
  items: HuntReportItem[];
  pending: HuntReportPending[];
  /** null: no earlier comparable hunt (or none the reader may open) — said plainly. */
  comparison: HuntReportComparison | null;
  baselineVersion?: number;
}

export type HuntVerdict = "compromise-suspected" | "anomalies" | "clean";

const HIGH: ReadonlySet<Severity> = new Set(["High", "Critical"]);

/** A hunt-derived entry (policy, rare, new, download) is never itself evidence of compromise. */
export function isHuntDerived(e: Pick<ForensicEvent, "id">): boolean {
  return e.id.startsWith("hunt-item:");
}

const liveFinding = (f: Finding): boolean => f.status !== "dismissed";

/** Any High/Critical finding or detection — the trigger for "Convert to incident" (D6). */
export function hasHighOrCritical(state: Pick<InvestigationState, "findings" | "forensicTimeline">): boolean {
  return (
    state.findings.some((f) => liveFinding(f) && HIGH.has(f.severity)) ||
    state.forensicTimeline.some((e) => !isHuntDerived(e) && HIGH.has(e.severity))
  );
}

/** The deterministic verdict, before the coverage qualification. */
export function huntVerdict(
  state: Pick<InvestigationState, "findings" | "forensicTimeline">,
  items: readonly HuntReportItem[],
): HuntVerdict {
  if (hasHighOrCritical(state)) return "compromise-suspected";
  const medium = (s: Severity): boolean => s === "Medium";
  if (
    items.length > 0 ||
    state.findings.some((f) => liveFinding(f) && medium(f.severity)) ||
    state.forensicTimeline.some((e) => medium(e.severity))
  )
    return "anomalies";
  return "clean";
}

export const VERDICT_TEXT: Record<HuntVerdict, string> = {
  "compromise-suspected":
    "Compromise suspected — at least one High or Critical finding needs incident response",
  anomalies: "Anomalies need follow-up — no compromise confirmed",
  clean: "No compromise found",
};
