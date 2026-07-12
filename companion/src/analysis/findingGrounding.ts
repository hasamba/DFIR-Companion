// Per-finding grounding + corroboration rollup (investigation-guidance #6). A finding's `confidence`
// was an unverifiable AI-emitted number, and findings routinely shipped with no cited events (halcyon:
// 0/7), so a claim could not be checked from the UI and a single stale CTI verdict became a Critical
// finding (northpeak). This deterministic pass, run after the finding backfills, does three things:
//   GROUNDING  — resolve each finding's supporting IN-SCOPE events (via BOTH the finding's own
//                relatedEventIds AND the reverse links on forensicTimeline[].relatedFindingIds, so the
//                deterministic high-severity backfill findings — which carry only reverse links — are
//                correctly grounded). A finding with no supporting event is `ungrounded`: a hypothesis,
//                not a fact — confidence hard-capped and badged.
//   ROLLUP     — from those events compute { distinctTools, distinctHosts, intelSources, graphLinked }.
//   CAPS       — a single-tool, single-host, uncorroborated finding can't keep a high confidence.
// It only ever LOWERS confidence (never invents grounding, never raises a score) and is pure + idempotent.

import type { Finding, ForensicEvent, IOC, FindingCorroboration } from "./stateTypes.js";

// A finding with no cited in-scope evidence is a hypothesis — cap hard so it can't outrank grounded work.
export const UNGROUNDED_CONFIDENCE_CAP = 45;
// A grounded but single-source (one tool, one host, no corroborating IOC/graph) finding is capped here —
// it may be real, but it can't claim high confidence on one uncorroborated observation.
export const SINGLE_SOURCE_CONFIDENCE_CAP = 65;

function appendReason(existing: string | undefined, note: string): string {
  const base = (existing ?? "").trim();
  return base ? `${base} | ${note}` : note;
}

export interface GroundingInput {
  findings: readonly Finding[];
  scopedEvents: readonly ForensicEvent[];      // in-scope events, carrying relatedFindingIds (reverse links)
  iocs: readonly IOC[];
  graphLinkedEventIds: ReadonlySet<string>;     // event ids that participate in an evidence-graph edge
}

// The IOC ids that carry at least one malicious/suspicious intel verdict — the finding-level "intel
// backs this" signal.
function intelFlaggedIocIds(iocs: readonly IOC[]): Set<string> {
  const out = new Set<string>();
  for (const i of iocs) {
    if ((i.enrichments ?? []).some((e) => e.verdict === "malicious" || e.verdict === "suspicious")) out.add(i.id);
  }
  return out;
}

export function groundAndScoreFindings(input: GroundingInput): Finding[] {
  const { findings, scopedEvents, iocs, graphLinkedEventIds } = input;
  const scopedById = new Map(scopedEvents.map((e) => [e.id, e] as const));
  const intelIocs = intelFlaggedIocIds(iocs);

  return findings.map((f) => {
    // Supporting in-scope events: forward links (finding.relatedEventIds present in scope) UNION reverse
    // links (a scoped event names this finding). De-duped, order-stable by scoped-event order.
    const forward = new Set((f.relatedEventIds ?? []).filter((id) => scopedById.has(id)));
    const supporting: ForensicEvent[] = [];
    const seen = new Set<string>();
    const push = (id: string): void => {
      if (seen.has(id)) return;
      const e = scopedById.get(id);
      if (e) { seen.add(id); supporting.push(e); }
    };
    for (const id of forward) push(id);
    for (const e of scopedEvents) if ((e.relatedFindingIds ?? []).includes(f.id)) push(e.id);

    const distinctTools = new Set(supporting.flatMap((e) => e.sources ?? [])).size;
    const distinctHosts = new Set(supporting.map((e) => e.asset).filter((a): a is string => !!a)).size;
    const graphLinked = supporting.some((e) => graphLinkedEventIds.has(e.id));
    const intelSources = (f.relatedIocs ?? []).filter((id) => intelIocs.has(id)).length;
    const corroboration: FindingCorroboration = { distinctTools, distinctHosts, intelSources, graphLinked };

    // Rewrite relatedEventIds to the resolved supporting set so the forward link is consistent and
    // auditable (adds the reverse-linked backfill events; drops hallucinated ids).
    const relatedEventIds = supporting.map((e) => e.id);

    let confidence = f.confidence;
    let confidenceReason = f.confidenceReason;
    let ungrounded = false;

    if (supporting.length === 0) {
      ungrounded = true;
      confidence = Math.min(confidence ?? UNGROUNDED_CONFIDENCE_CAP, UNGROUNDED_CONFIDENCE_CAP);
      confidenceReason = appendReason(confidenceReason, "capped: no cited evidence in scope — treat as a hypothesis, not a fact");
    } else if (distinctTools <= 1 && distinctHosts <= 1 && intelSources === 0 && !graphLinked) {
      if ((confidence ?? 100) > SINGLE_SOURCE_CONFIDENCE_CAP) {
        confidence = SINGLE_SOURCE_CONFIDENCE_CAP;
        confidenceReason = appendReason(confidenceReason, "capped: single-source, uncorroborated");
      }
    }

    // Clean the old flag first so a since-corrected finding loses `ungrounded` (idempotent recompute).
    const { ungrounded: _prev, ...rest } = f;
    return {
      ...rest,
      relatedEventIds,
      corroboration,
      ...(ungrounded ? { ungrounded: true } : {}),
      ...(confidence !== undefined ? { confidence } : {}),
      ...(confidenceReason !== undefined ? { confidenceReason } : {}),
    };
  });
}

// A compact one-liner for the existing-findings prompt echo and the report/dashboard, e.g.
// "2 tools / 3 hosts / intel ✓" or "uncorroborated". Pure.
export function corroborationLabel(f: Finding): string {
  if (f.ungrounded) return "uncorroborated (no cited evidence)";
  const c = f.corroboration;
  if (!c) return "";
  const parts = [`${c.distinctTools} tool${c.distinctTools === 1 ? "" : "s"}`, `${c.distinctHosts} host${c.distinctHosts === 1 ? "" : "s"}`];
  if (c.intelSources > 0) parts.push("intel ✓");
  if (c.graphLinked) parts.push("graph-linked");
  const corroborated = c.distinctTools >= 2 || c.intelSources > 0 || c.graphLinked;
  return `${parts.join(" / ")}${corroborated ? "" : " — uncorroborated"}`;
}
