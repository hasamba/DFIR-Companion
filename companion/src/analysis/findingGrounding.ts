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
import { classifyVerdict, iocHasBehavioralEvent, shortHost } from "./iocAnchors.js";
import { SEVERITY_RANK } from "./forensicGate.js";
import { extractCveIds } from "./kev.js";
import { trustForSources, type SourceTrustMap } from "./sourceTrust.js";
import { deriveSemanticKey } from "./semanticKey.js";

// A finding with no cited in-scope evidence is a hypothesis — cap hard so it can't outrank grounded work.
export const UNGROUNDED_CONFIDENCE_CAP = 45;
// A grounded but single-source (one tool, one host, no corroborating IOC/graph) finding is capped here —
// it may be real, but it can't claim high confidence on one uncorroborated observation.
export const SINGLE_SOURCE_CONFIDENCE_CAP = 65;
// A finding that rests ONLY on raw hunt-collection artifacts (every supporting event is Info telemetry —
// no tool adjudicated it, no intel/KEV lift) is capped here (issue #61): it's a lead someone still has to
// triage, not a confirmed detection. Lower than the single-source cap because nothing has verdicted it.
export const HUNT_ARTIFACT_CONFIDENCE_CAP = 55;
// Rank at/above which a supporting event counts as an adjudicated "detection" (verdict-first) rather than
// raw telemetry — the same Low+ cut iocProvenance.ts uses for detection-vs-telemetry.
const DETECTION_RANK = SEVERITY_RANK.Low;
// Per-source trust (#66): a finding whose best supporting source is below this trust (e.g. supported only
// by a generic log or a noisy artifact row) can't claim high confidence. Applied as a CAP — this pass only
// ever LOWERS confidence, so trust never boosts a high-trust finding, it only reins in a low-trust one.
export const LOW_TRUST_THRESHOLD = 0.7;
export const LOW_TRUST_CONFIDENCE_CAP = 55;
// A High/Critical finding that names a specific IP in its own title/description, but whose cited
// in-scope events never mention that IP, is citing evidence that does not back its own claim — a
// subtler ungroundedness than an empty relatedEventIds list (both the id-existence check above and the
// AI's own citation can look fine while the claim's content is simply wrong). Deep-pass on veridia-breach
// (2026-07-22) produced exactly this: "External RDP logon from public IP 45.33.32.156" cited three benign
// internal-IP logons (real event ids, wrong content) instead of the one event that actually matched.
// IP-only by design — concrete, regex-extractable, and the exact entity type that produced that false
// positive — not a general fact-checker.
export const CONTENT_MISMATCH_CONFIDENCE_CAP = 40;
export const CONTENT_MISMATCH_SEVERITY_FLOOR: Severity = "Medium";

// Actor-provenance gate for lateral-movement findings (meridian-tax-ransomware benchmark 2026-07-23).
// A High/Critical finding that claims the attacker moved/pivoted TO a host counts as confirmed only if
// that destination is itself tied to the attack. The failure this gates: the AI saw a harvested-but-also-
// legitimate admin account (kevin.obrien) logged onto WS-17 in its own routine session — and an entirely
// uninvolved user (nathan.brooks) logged onto WS-09 — and wired both benign logons into "RDP lateral
// movement". A benign LogonType=3 event grades Low, which is >= DETECTION_RANK, so it slips past the
// hunt-artifact/single-source caps and even earned confidence 82 in the deep pass. The gate: a lateral
// claim naming a destination host that has NO High/Critical event of its own in scope, and whose own cited
// evidence carries no High/Critical event and no graph edge, is resting on ordinary login noise — floor it.
export const LATERAL_UNCONFIRMED_CONFIDENCE_CAP = 40;
export const LATERAL_UNCONFIRMED_SEVERITY_FLOOR: Severity = "Medium";
// Lateral-movement / pivot language in a finding's own title or description. Deliberately targets the
// destination-reaching claim ("moved laterally to", "pivoted to", "RDP to <host>"), not mere mentions of
// a remote host, so a finding that only *references* another host isn't swept in.
const LATERAL_MOVEMENT_RE =
  /\b(lateral\s+movement|moved\s+laterally|pivot(?:ed|ing|s)?|remote(?:d)?\s+(?:in)?to|rdp(?:'?d)?\s+(?:in)?to|logged?\s+(?:in|on)to|smb\s+(?:admin\s+)?share|remote\s+(?:desktop|services)\b)/i;

function appendReason(existing: string | undefined, note: string): string {
  const base = (existing ?? "").trim();
  return base ? `${base} | ${note}` : note;
}

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
function extractIpv4(text: string): string[] {
  return [...new Set(text.match(IPV4_RE) ?? [])];
}

// IPs the finding's own text claims but that never appear anywhere in its cited supporting events —
// empty when every claimed IP is actually backed, or when the finding names no IP at all.
function claimedIpsNotInEvidence(f: Finding, supporting: readonly ForensicEvent[]): string[] {
  const claimed = extractIpv4(`${f.title} ${f.description}`);
  if (!claimed.length) return [];
  const evidenceIps = new Set(extractIpv4(supporting.map((e) => `${e.description} ${e.message ?? ""}`).join(" ")));
  return claimed.filter((ip) => !evidenceIps.has(ip));
}

// The set of case host short-names that carry at least one High/Critical event in scope — the hosts the
// evidence itself confirms as attack-involved (LSASS dump, ransomware, exfil, log-clear, …). A lateral
// claim whose destination is NOT in this set has to earn its grading from its own cited evidence.
function confirmedCompromisedHosts(scopedEvents: readonly ForensicEvent[]): Set<string> {
  const out = new Set<string>();
  for (const e of scopedEvents) {
    if ((e.severity === "Critical" || e.severity === "High") && e.asset) out.add(shortHost(e.asset));
  }
  return out;
}

// Host short-names a lateral-movement finding names as a DESTINATION but that no High/Critical event in
// the case pins to the attack. Empty ⇒ not a lateral claim, or every named host is independently confirmed.
// The check is host-token based (short-host), so "…to WS-17.meridiancpa.com" and "WS-17" both resolve.
function unconfirmedLateralDestinations(
  f: Finding,
  supporting: readonly ForensicEvent[],
  compromisedHosts: ReadonlySet<string>,
): string[] {
  if (!LATERAL_MOVEMENT_RE.test(`${f.title} ${f.description}`)) return [];
  // If the finding's OWN cited evidence carries a High/Critical event or a benign-defeating anchor, defer:
  // something concrete ties the movement to the attack, so let the normal caps handle it.
  const hasHighSupport = supporting.some((e) => e.severity === "Critical" || e.severity === "High");
  if (hasHighSupport) return [];
  // Extract only hosts that are the DESTINATION of the movement — the grammatical object of a
  // reach-verb (to / onto / into / toward / reached / targeted <HOST>). This is deliberately narrower
  // than "any host token the finding names": a discovery finding that mentions "…not DC-01… staging for
  // lateral movement" trips the LATERAL_MOVEMENT_RE gate above but names no movement *destination*, so it
  // must not be floored. A pivot's SOURCE host follows "from", never a reach-verb, so it's excluded too.
  const dests = new Set<string>();
  for (const m of `${f.title} ${f.description}`.matchAll(
    /\b(?:to|onto|into|towards?|reach(?:ed|ing)?|target(?:ed|ing)?)\s+(?:the\s+)?(?:host\s+)?([A-Za-z][A-Za-z0-9]*-\d{1,3})\b/gi,
  )) {
    dests.add(shortHost(m[1]));
  }
  return [...dests].filter((h) => !compromisedHosts.has(h));
}

export interface GroundingInput {
  findings: readonly Finding[];
  scopedEvents: readonly ForensicEvent[];      // in-scope events, carrying relatedFindingIds (reverse links)
  iocs: readonly IOC[];
  graphLinkedEventIds: ReadonlySet<string>;     // event ids that participate in an evidence-graph edge
  // CVE ids (upper-cased) present in the case that MATCH the CISA KEV catalog (issue #61). A finding is
  // `kevLinked` when it references one of these. Optional — omit/empty when no KEV catalog is loaded.
  kevCveIds?: ReadonlySet<string>;
  sourceTrust?: SourceTrustMap;                 // #66: per-source trust; absent → no trust-based capping
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

// A finding is KEV-linked when any CVE it references — in its own title/description, its supporting
// events' text, or its related IOC values — is in the case's KEV-matched set. Empty set ⇒ never linked.
function findingIsKevLinked(
  f: Finding,
  supporting: readonly ForensicEvent[],
  iocById: ReadonlyMap<string, IOC>,
  kevCveIds: ReadonlySet<string>,
): boolean {
  if (!kevCveIds.size) return false;
  const texts: string[] = [f.title, f.description];
  for (const e of supporting) { texts.push(e.description); if (e.message) texts.push(e.message); }
  for (const id of f.relatedIocs ?? []) { const i = iocById.get(id); if (i) texts.push(i.value); }
  for (const t of texts) {
    for (const cve of extractCveIds(t)) if (kevCveIds.has(cve)) return true;
  }
  return false;
}

export function groundAndScoreFindings(input: GroundingInput): Finding[] {
  const { findings, scopedEvents, iocs, graphLinkedEventIds, sourceTrust } = input;
  const kevCveIds = input.kevCveIds ?? new Set<string>();
  const scopedById = new Map(scopedEvents.map((e) => [e.id, e] as const));
  const iocById = new Map(iocs.map((i) => [i.id, i] as const));
  const intelIocs = intelFlaggedIocIds(iocs);
  // Hosts the evidence independently confirms as attack-involved — the actor-provenance gate's allow-list.
  const compromisedHosts = confirmedCompromisedHosts(scopedEvents);

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
    // Issue #61 signals: verdict-first = any supporting event is a graded (Low+) detection a tool
    // adjudicated; hunt-artifact-only = grounded but EVERY supporting event is raw Info telemetry;
    // KEV-linked = references an actively-exploited CVE.
    const verdictFirst = supporting.some((e) => (SEVERITY_RANK[e.severity] ?? 0) >= DETECTION_RANK);
    const huntArtifactOnly = supporting.length > 0 && !verdictFirst;
    const kevLinked = findingIsKevLinked(f, supporting, iocById, kevCveIds);
    const corroboration: FindingCorroboration = { distinctTools, distinctHosts, intelSources, graphLinked, verdictFirst, huntArtifactOnly, kevLinked };

    // Rewrite relatedEventIds to the resolved supporting set so the forward link is consistent and
    // auditable (adds the reverse-linked backfill events; drops hallucinated ids).
    const relatedEventIds = supporting.map((e) => e.id);

    let confidence = f.confidence;
    let confidenceReason = f.confidenceReason;
    let ungrounded = false;
    let contentMismatch = false;
    let lateralUnconfirmed = false;

    // KEV is an independent corroboration signal (an external catalog confirms active exploitation),
    // so it exempts a finding from the single-source cap alongside 2+ tools / intel / graph linkage.
    const corroborated = distinctTools >= 2 || intelSources > 0 || graphLinked || kevLinked;

    if (supporting.length === 0) {
      ungrounded = true;
      confidence = Math.min(confidence ?? UNGROUNDED_CONFIDENCE_CAP, UNGROUNDED_CONFIDENCE_CAP);
      confidenceReason = appendReason(confidenceReason, "capped: no cited evidence in scope — treat as a hypothesis, not a fact");
    } else {
      if (!corroborated && distinctHosts <= 1) {
        if ((confidence ?? 100) > SINGLE_SOURCE_CONFIDENCE_CAP) {
          confidence = SINGLE_SOURCE_CONFIDENCE_CAP;
          confidenceReason = appendReason(confidenceReason, "capped: single-source, uncorroborated");
        }
      }
      // Hunt-artifact penalty (#61): rests only on raw collection artifacts with no detection verdict,
      // no intel, and no KEV lift — a triage lead, not a confirmed detection. Applied independently so
      // it can lower a finding even when 2+ raw-telemetry tools "corroborate" the same unadjudicated data.
      if (huntArtifactOnly && intelSources === 0 && !kevLinked) {
        if ((confidence ?? 100) > HUNT_ARTIFACT_CONFIDENCE_CAP) {
          confidence = HUNT_ARTIFACT_CONFIDENCE_CAP;
          confidenceReason = appendReason(confidenceReason, "capped: rests only on raw hunt-collection artifacts — no detection verdict; triage before acting");
        }
      }
    }

    // Low-trust cap (#66): if the finding's BEST supporting source is below the trust threshold (e.g. it
    // rests only on a generic log or a noisy artifact row), it can't claim high confidence — cap it. Runs
    // in addition to the caps above (a low-trust single-source finding takes the lower of the two). Only
    // when a trust map is supplied and evidence exists; only ever lowers.
    if (sourceTrust && supporting.length > 0) {
      const bestTrust = Math.max(...supporting.map((e) => trustForSources(e.sources, sourceTrust)));
      if (bestTrust < LOW_TRUST_THRESHOLD && (confidence ?? 100) > LOW_TRUST_CONFIDENCE_CAP) {
        confidence = LOW_TRUST_CONFIDENCE_CAP;
        confidenceReason = appendReason(confidenceReason, `capped: low-trust source(s) only (max trust ${bestTrust.toFixed(2)})`);
      }
    }

    // Content-mismatch check: only worth running on High/Critical (the severities this exists to gate)
    // and only once the finding actually has cited evidence (an ungrounded finding is already capped above).
    let severity = f.severity;
    if (supporting.length > 0 && (f.severity === "Critical" || f.severity === "High")) {
      const mismatched = claimedIpsNotInEvidence(f, supporting);
      if (mismatched.length) {
        contentMismatch = true;
        severity = CONTENT_MISMATCH_SEVERITY_FLOOR;
        if ((confidence ?? 100) > CONTENT_MISMATCH_CONFIDENCE_CAP) confidence = CONTENT_MISMATCH_CONFIDENCE_CAP;
        confidenceReason = appendReason(
          confidenceReason,
          `capped: claims ${mismatched.join(", ")} but the cited events never mention it — verify the citation before treating as confirmed`,
        );
      }
    }

    // Actor-provenance gate: a High/Critical lateral-movement claim to a host with no High/Critical event
    // of its own, resting only on benign authentication telemetry, is floored to Medium. Runs on the
    // possibly-already-floored severity, so a finding both content-mismatched and lateral-unconfirmed keeps
    // the lower confidence. Skipped once the content-mismatch gate already floored it (same target severity).
    if ((severity === "Critical" || severity === "High")) {
      const unconfirmed = unconfirmedLateralDestinations(f, supporting, compromisedHosts);
      if (unconfirmed.length) {
        lateralUnconfirmed = true;
        severity = LATERAL_UNCONFIRMED_SEVERITY_FLOOR;
        if ((confidence ?? 100) > LATERAL_UNCONFIRMED_CONFIDENCE_CAP) confidence = LATERAL_UNCONFIRMED_CONFIDENCE_CAP;
        confidenceReason = appendReason(
          confidenceReason,
          `capped: claims lateral movement to ${unconfirmed.join(", ")}, which has no confirmed malicious activity of its own — the cited logon(s) may be a legitimate session by a reused account; confirm the source is a compromised node before treating as a pivot`,
        );
      }
    }

    // Clean the old flags first so a since-corrected finding loses them (idempotent recompute).
    const { ungrounded: _prev, contentMismatch: _prevCm, lateralUnconfirmed: _prevLu, ...rest } = f;
    return {
      ...rest,
      severity,
      relatedEventIds,
      corroboration,
      // Stable cross-run identity (issue #69) — recomputed every synthesis so second-opinion deltas
      // key on it instead of the raw title. Deterministic from the (idempotent-safe) title + techniques.
      semanticKey: deriveSemanticKey(f),
      ...(ungrounded ? { ungrounded: true } : {}),
      ...(contentMismatch ? { contentMismatch: true } : {}),
      ...(lateralUnconfirmed ? { lateralUnconfirmed: true } : {}),
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
  if (c.kevLinked) parts.push("KEV ✓");
  if (c.verdictFirst) parts.push("tool-confirmed");
  const corroborated = c.distinctTools >= 2 || c.intelSources > 0 || c.graphLinked || !!c.kevLinked;
  const huntCaution = c.huntArtifactOnly && c.intelSources === 0 && !c.kevLinked ? " — unconfirmed lead" : "";
  return `${parts.join(" / ")}${corroborated ? "" : " — uncorroborated"}${huntCaution}`;
}
