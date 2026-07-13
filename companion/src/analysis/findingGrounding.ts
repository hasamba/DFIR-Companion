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

import type { Finding, ForensicEvent, IOC, FindingCorroboration, Severity, NextStep } from "./stateTypes.js";
import { classifyVerdict, iocHasBehavioralEvent } from "./iocAnchors.js";

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

// An intel-only High/Critical finding can't keep its severity — the confidence cap (investigation-
// guidance #7 coordinating with #6). A finding whose ONLY malicious signal is threat-intel (all its
// verdict-carrying IOCs are lone-intel/conflicted) and which has no behavioral corroboration (≤1 tool,
// not graph-linked) is floored to Medium / confidence ≤ 60 with a reason. This is the northpeak class:
// a stale OpenCTI verdict on the org's own db-01 became a Critical "C2" finding on a benign connection.
export const INTEL_ONLY_SEVERITY_FLOOR: Severity = "Medium";
export const INTEL_ONLY_CONFIDENCE_CAP = 60;
const SEV_ORDER: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

export interface IntelCapInput {
  findings: readonly Finding[];
  iocs: readonly IOC[];
  scopedEvents: readonly ForensicEvent[];
  hostNames: ReadonlySet<string>;          // the case's own host short-names (see iocAnchors.shortHost)
}

// The intel-only classification for ONE finding: null when it's not an over-graded intel-only finding,
// else the verdict-carrying IOCs it rests on and whether any verdict conflicts with the case's own
// infrastructure. Shared by the cap (below) and the corroborate-nextStep builder so the two never drift.
interface IntelOnlyVerdict { verdictIocs: IOC[]; hasConflict: boolean; }
function classifyIntelOnlyFinding(
  f: Finding,
  iocById: ReadonlyMap<string, IOC>,
  scopedEvents: readonly ForensicEvent[],
  hostNames: ReadonlySet<string>,
): IntelOnlyVerdict | null {
  if (SEV_ORDER[f.severity] > SEV_ORDER.High) return null;   // only High/Critical can be over-graded by intel
  const verdictIocs = (f.relatedIocs ?? [])
    .map((id) => iocById.get(id))
    .filter((i): i is IOC => !!i && (i.enrichments ?? []).some((e) => e.verdict === "malicious" || e.verdict === "suspicious"));
  if (!verdictIocs.length) return null;   // not intel-driven
  const classes = verdictIocs.map((i) =>
    classifyVerdict(i, { hasBehavioralEvent: iocHasBehavioralEvent(i.value, scopedEvents), hostNames }));
  const intelOnly = classes.every((c) => c === "lone-intel" || c === "conflicted");
  const behavioralGrounding = !!f.corroboration && (f.corroboration.distinctTools >= 2 || f.corroboration.graphLinked);
  if (!intelOnly || behavioralGrounding) return null;
  return { verdictIocs, hasConflict: classes.some((c) => c === "conflicted") };
}

export function capIntelOnlyFindings(input: IntelCapInput): Finding[] {
  const { findings, iocs, scopedEvents, hostNames } = input;
  const iocById = new Map(iocs.map((i) => [i.id, i] as const));
  return findings.map((f) => {
    const v = classifyIntelOnlyFinding(f, iocById, scopedEvents, hostNames);
    if (!v) return f;
    const note = v.hasConflict
      ? "capped: rests on a threat-intel verdict about the case's OWN infrastructure — most likely stale/wrong, verify before acting"
      : "capped: rests on uncorroborated single-provider threat-intel only — a lead, not a confirmed compromise; verify before acting";
    return {
      ...f,
      severity: INTEL_ONLY_SEVERITY_FLOOR,
      confidence: Math.min(f.confidence ?? INTEL_ONLY_CONFIDENCE_CAP, INTEL_ONLY_CONFIDENCE_CAP),
      confidenceReason: appendReason(f.confidenceReason, note),
    };
  });
}

// Auto-generated "corroborate <ioc>" next-steps (investigation-guidance #7, deferred piece). For every
// finding the intel-verdict gate floored to intel-only, emit ONE concrete verification step: go get the
// behavioral evidence (an actual process/connection) that would confirm or drop the reputation hit — so
// a capped lead turns into a directed action instead of a dead end. Stable, idempotent ids so re-synthesis
// doesn't duplicate them. Pure. Returns [] when nothing was intel-capped.
export function buildIntelCorroborationSteps(input: IntelCapInput): NextStep[] {
  const { findings, iocs, scopedEvents, hostNames } = input;
  const iocById = new Map(iocs.map((i) => [i.id, i] as const));
  const steps: NextStep[] = [];
  for (const f of findings) {
    const v = classifyIntelOnlyFinding(f, iocById, scopedEvents, hostNames);
    if (!v) continue;
    const values = [...new Set(v.verdictIocs.map((i) => i.value))].slice(0, 3);
    const list = values.join(", ");
    // Best-effort host: the asset on a scoped event that mentions one of these IOC values.
    const host = scopedEvents.find((e) => e.asset && values.some((val) => (e.description || "").toLowerCase().includes(val.toLowerCase())))?.asset;
    steps.push({
      id: `n-corroborate-${f.id}`,
      priority: "high",
      action: `Corroborate the threat-intel verdict on ${list} with behavioral evidence`,
      rationale: v.hasConflict
        ? "This finding rests on an intel verdict about the case's OWN infrastructure — likely stale; confirm with a real process/connection before acting."
        : "This finding rests on uncorroborated single-provider intel — find the behavioral evidence that confirms it, or drop it.",
      pointer: `finding ${f.id}; indicators ${list}`,
      collect: {
        ...(host ? { host } : {}),
        logSource: `endpoint/EDR process + network telemetry referencing ${list}`,
        expectedOutcome: `a real process execution or network connection tied to ${list} (not just a reputation hit) — its absence downgrades this to a false positive`,
      },
      relatedFindingIds: [f.id],
    });
  }
  return steps;
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
