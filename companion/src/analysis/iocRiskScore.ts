// Composite IOC risk score (issue #63). A single actionable tier per indicator, aggregated from the
// signals the codebase already derives — so a lone unenriched hash and a hash confirmed malicious by
// three tools in a Critical event are no longer treated alike.
//
// This module is PURE. `scoreIoc` grades one indicator from a pre-derived signal bundle; `scoreIocs`
// is the batch orchestrator that computes those bundles from real IOCs + events using the existing
// helpers (classifyVerdict, deriveIocSources, deriveIocSeverityRank, KEV/NSRL/whitelist lookups) and
// grades each. Derived on read (never persisted): the score always reflects the CURRENT enrichment /
// whitelist / NSRL state, so there is nothing to migrate or invalidate.
//
// Design notes:
//   • Built ON classifyVerdict — a malicious verdict on the case's OWN infrastructure is `conflicted`
//     and hard-capped to `low` (the "northpeak" stale-CTI-on-own-server lesson, same guard as
//     findingGrounding). A naive verdict read would rate that critical.
//   • Whitelist / NSRL known-good are authoritative → `benign`, overriding any verdict.
//   • KEV is a real but MINOR signal for most IOC types (it is CVE-keyed), so it is a bump, not a base.

import type { ForensicEvent, IOC, InvestigationState } from "./stateTypes.js";
import { SEVERITY_RANK } from "./forensicGate.js";
import { buildAssetGraph } from "./assetGraph.js";
import { classifyVerdict, iocHasBehavioralEvent, looksSuspiciousDomain, shortHost, type VerdictClass } from "./iocAnchors.js";
import { deriveIocSources } from "./iocCorroboration.js";
import { deriveIocSeverityRank } from "./iocProvenance.js";
import { extractCveIds, type KevCatalog } from "./kev.js";
import { normalizeHash } from "./nsrl.js";
import { matchIocToWhitelist, type IocWhitelistRule } from "./iocWhitelist.js";

export type IocRiskTier = "critical" | "high" | "medium" | "low" | "benign";

export interface IocRisk {
  score: IocRiskTier;
  factors: string[];   // human-readable reasons, strongest first
}

/** The pre-derived signals scoreIoc grades. Kept explicit so the core rubric is unit-testable. */
export interface IocRiskSignals {
  verdictClass: VerdictClass;   // classifyVerdict: corroborated | lone-intel | conflicted | none
  distinctTools: number;        // deriveIocSources[id].length — how many tools observed the value
  maxSeverityRank: number;      // max SEVERITY_RANK of an event referencing it (-1 = none)
  kevMatch: boolean;            // references a CISA-KEV (actively-exploited) CVE
  nsrlKnownGood: boolean;       // NSRL known-good hash
  whitelisted: boolean;         // matches an IOC-whitelist rule (analyst-marked known-good)
  suspiciousDomain: boolean;    // risky-TLD / DGA-like domain heuristic (domain/url only)
}

const { Low, Medium, High, Critical } = SEVERITY_RANK;

// Points → tier. A weighted sum keeps the rubric transparent and easy to reason about in tests.
const CRITICAL_AT = 7;
const HIGH_AT = 4;
const MEDIUM_AT = 2;

/** Grade one indicator from its signal bundle. Pure. */
export function scoreIoc(s: IocRiskSignals): IocRisk {
  // 1. Authoritative known-good → benign, overriding everything.
  if (s.whitelisted) return { score: "benign", factors: ["whitelisted (analyst-marked known-good)"] };
  if (s.nsrlKnownGood) return { score: "benign", factors: ["NSRL known-good hash"] };

  const factors: string[] = [];
  let points = 0;

  // 2. Threat-intel verdict (the dominant signal), via classifyVerdict.
  if (s.verdictClass === "corroborated") { points += 4; factors.push("malicious/suspicious verdict corroborated by ≥2 sources"); }
  else if (s.verdictClass === "lone-intel") { points += 2; factors.push("single-source threat-intel verdict (unverified lead)"); }
  else if (s.verdictClass === "conflicted") { factors.push("threat-intel verdict on the case's OWN/internal infrastructure — most likely stale"); }

  // 3. Internal severity: the worst graded event the indicator appears in.
  if (s.maxSeverityRank >= Critical) { points += 3; factors.push("seen in a Critical event"); }
  else if (s.maxSeverityRank >= High) { points += 2; factors.push("seen in a High-severity event"); }
  else if (s.maxSeverityRank >= Medium) { points += 1; factors.push("seen in a Medium-severity event"); }

  // 4. Cross-tool corroboration (distinct from intel corroboration).
  if (s.distinctTools >= 3) { points += 2; factors.push(`observed by ${s.distinctTools} tools`); }
  else if (s.distinctTools === 2) { points += 1; factors.push("observed by 2 tools"); }

  // 5. KEV bump (minor, mostly CVE-typed IOCs).
  if (s.kevMatch) { points += 3; factors.push("matches a CISA KEV (actively-exploited) CVE"); }

  // 6. Domain heuristic bump.
  if (s.suspiciousDomain) { points += 1; factors.push("risky TLD / DGA-like domain"); }

  // A conflicted verdict (own/internal infra) is hard-capped to `low` no matter how many events or
  // tools touch the org's own asset — the northpeak guard.
  if (s.verdictClass === "conflicted") {
    return { score: "low", factors };
  }

  const score: IocRiskTier = points >= CRITICAL_AT ? "critical" : points >= HIGH_AT ? "high" : points >= MEDIUM_AT ? "medium" : "low";
  if (!factors.length) factors.push("no threat-intel or behavioral signal");
  return { score, factors };
}

export interface ScoreIocsContext {
  hostNames: ReadonlySet<string>;      // the case's own host short-names (for conflicted classification)
  kevCveIds?: ReadonlySet<string>;     // CVE ids present in the case that match KEV; used when an IOC value is/contains a CVE
  kevCatalog?: KevCatalog;             // alternative to kevCveIds: match an IOC value's CVEs against the catalog directly
  nsrlHashes?: ReadonlySet<string>;    // normalized known-good hashes (omit when the caller lacks store access)
  whitelistRules?: readonly IocWhitelistRule[];  // IOC-whitelist rules (omit when the caller lacks store access)
}

/** Grade every IOC. Derives each signal bundle from the shared helpers, then calls scoreIoc. Pure. */
export function scoreIocs(iocs: readonly IOC[], events: readonly ForensicEvent[], ctx: ScoreIocsContext): Record<string, IocRisk> {
  const sources = deriveIocSources(iocs, events);
  const sevRank = deriveIocSeverityRank(iocs, events);
  const out: Record<string, IocRisk> = {};
  for (const ioc of iocs) {
    const verdictClass = classifyVerdict(ioc, {
      hasBehavioralEvent: iocHasBehavioralEvent(ioc.value, events),
      hostNames: ctx.hostNames,
    });
    const norm = normalizeHash(ioc.value);
    const nsrlKnownGood = ioc.type === "hash" && norm !== null && (ctx.nsrlHashes?.has(norm) ?? false);
    const whitelisted = matchIocToWhitelist({ type: ioc.type, value: ioc.value }, ctx.whitelistRules ?? []) !== null;
    const kevMatch = extractCveIds(ioc.value).some((cve) =>
      ctx.kevCveIds?.has(cve) || (ctx.kevCatalog ? ctx.kevCatalog.has(cve) : false),
    );
    out[ioc.id] = scoreIoc({
      verdictClass,
      distinctTools: sources[ioc.id]?.length ?? 0,
      maxSeverityRank: sevRank[ioc.id] ?? -1,
      kevMatch,
      nsrlKnownGood,
      whitelisted,
      suspiciousDomain: (ioc.type === "domain" || ioc.type === "url") && looksSuspiciousDomain(ioc.value),
    });
  }
  return out;
}

/** Rank ordering for sorting / filtering (higher = riskier). */
export const RISK_TIER_RANK: Record<IocRiskTier, number> = { critical: 4, high: 3, medium: 2, low: 1, benign: 0 };

/**
 * Convenience for callers that only have the investigation state (report CSV/markdown, synthesis
 * context): derives the case's own host-names from the asset graph and scores every IOC. Pass the
 * KEV/NSRL/whitelist context when the caller has store access (the dashboard endpoint) for full
 * fidelity; omit it (report/synthesis) to score on verdict + severity + corroboration alone.
 */
export function scoreIocsFromState(
  state: InvestigationState,
  opts: { kevCatalog?: KevCatalog; nsrlHashes?: ReadonlySet<string>; whitelistRules?: readonly IocWhitelistRule[] } = {},
): Record<string, IocRisk> {
  const hostNames = new Set(buildAssetGraph(state).assets.filter((a) => a.type === "host").map((a) => shortHost(a.name)));
  return scoreIocs(state.iocs, state.forensicTimeline, {
    hostNames,
    kevCatalog: opts.kevCatalog,
    nsrlHashes: opts.nsrlHashes ?? new Set(),
    whitelistRules: opts.whitelistRules ?? [],
  });
}
