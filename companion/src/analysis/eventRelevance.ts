import type { ForensicEvent } from "./stateTypes.js";

// Pure per-event relevance scoring (issue #75), evaluated against the same signals
// `synthSelect.ts`'s reserved-budget classes already use for selection: severity, finding linkage,
// structured identity (hash/path/process chain), ATT&CK technique tags, cross-source corroboration,
// and (optionally) corpus rarity. It does NOT replace or feed the selector — `synthSelect.ts` is
// unchanged and its selection is byte-identical with or without this module. This is an orthogonal,
// additive display signal: the dashboard uses it to flag rows least likely to matter (see #75's
// "🐇 low signal" ask) without touching what synthesis actually reads.
//
// Class → tier mapping this subsumes: anchor → high; corroborated/technique/rare → medium (a
// structured hash/path/process-chain identity gets the same medium tier, even with no reserved
// class of its own — it's the connective tissue a kill-chain read needs); anchor_context/earliest/
// spread are POSITIONAL (near an anchor, or chronological), not content signals, so they aren't
// modeled here — a context event's content can independently be low, medium, or high.
export type RelevanceTier = "high" | "medium" | "low";

export interface RelevanceScore {
  tier: RelevanceTier;
  reasons: string[];
}

function hasStructuredIdentity(e: ForensicEvent): boolean {
  return !!(e.sha256 || e.md5 || e.path || e.processName || e.parentName || e.chainSignature);
}

// Prevalence threshold mirrors synthSelect.ts's RARE_SCORE_MIN so a "rare" verdict here means the
// same thing it means to the selector's reserved RARE fill.
const RARE_SCORE_MIN = 0.34;

// Count of DISTINCT REAL tool sources backing an event — the same unit correlate.ts, sourceTrust.ts,
// iocCorroboration.ts and the dashboard's realSourceCount() all use. Empty strings and the legacy
// "unknown source" placeholder are not tools, and a repeated source name is still ONE tool, so
// neither may inflate the count. Over-claiming that two tools agree is worse than missing a match:
// an uncorroborated Info row must not be promoted out of the "low" tier by a placeholder.
function realSourceCount(e: ForensicEvent): number {
  const set = new Set<string>();
  for (const s of e.sources ?? []) if (s && s !== "unknown source") set.add(s);
  return set.size;
}

export function scoreEventRelevance(
  e: ForensicEvent,
  rarityOf?: (e: ForensicEvent) => number,
): RelevanceScore {
  if (e.severity === "Critical" || e.severity === "High") {
    return { tier: "high", reasons: [`${e.severity} severity`] };
  }
  if (e.relatedFindingIds.length > 0) {
    return { tier: "high", reasons: ["linked to a finding"] };
  }

  const reasons: string[] = [];
  if (hasStructuredIdentity(e)) reasons.push("structured identity (hash/path/process chain)");
  if (e.mitreTechniques.length > 0) reasons.push("ATT&CK technique tagged");
  if (realSourceCount(e) >= 2) reasons.push("corroborated by multiple sources");
  if (rarityOf && rarityOf(e) >= RARE_SCORE_MIN) reasons.push("rare pattern in this case");

  if (reasons.length > 0) {
    return { tier: "medium", reasons };
  }

  if (e.severity === "Info") {
    return { tier: "low", reasons: ["Info-severity telemetry with no structured identity, technique tag, or corroboration"] };
  }
  // Medium/Low severity with none of the above signals: still a graded detection (a tool judged it),
  // just uncorroborated — treat as medium rather than low so a lone real detection isn't buried.
  return { tier: "medium", reasons: ["graded detection, uncorroborated"] };
}

export function isLowRelevance(e: ForensicEvent, rarityOf?: (e: ForensicEvent) => number): boolean {
  return scoreEventRelevance(e, rarityOf).tier === "low";
}
