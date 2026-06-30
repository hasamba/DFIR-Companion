import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";
import { buildAssetGraph } from "./assetGraph.js";
import { extractCveIds, matchKevEntries, buildKevDigest, type KevCatalog } from "./kev.js";
import { rankConnectiveIocs, buildConnectiveIocDigest } from "./iocAnchors.js";
import { rankHosts, buildSignalConcentrationDigest } from "./hostRanking.js";

const SEV_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

// How many of the earliest events to always keep (initial-access context).
const EARLIEST_KEEP = 15;

// Pick the events that best inform synthesis when the timeline exceeds the prompt budget.
// Severity-only "top N" can bury the kill chain — early low-severity initial-access events
// drop out, and one noisy host crowds out everything else. This keeps ALL Critical/High
// events, the earliest events, and an even time-spread sample of the rest, returned in
// CHRONOLOGICAL order so the model reads the attack as a story.
export function selectSynthesisEvents(events: ForensicEvent[], max: number): ForensicEvent[] {
  const byTime = [...events].sort(byEventTime);
  if (events.length <= max || max <= 0) return byTime;

  const chosen = new Set<string>();
  byTime.slice(0, EARLIEST_KEEP).forEach((e) => chosen.add(e.id));                 // initial-access context
  for (const e of events) if (e.severity === "Critical" || e.severity === "High") chosen.add(e.id);

  if (chosen.size < max) {                                                          // even time-spread fill of the rest
    const rest = byTime.filter((e) => !chosen.has(e.id));
    const slots = max - chosen.size;
    if (rest.length <= slots) {
      rest.forEach((e) => chosen.add(e.id));
    } else {
      const step = rest.length / slots;
      for (let i = 0; i < slots; i++) chosen.add(rest[Math.min(rest.length - 1, Math.floor(i * step))].id);
    }
  }

  let selected = byTime.filter((e) => chosen.has(e.id));
  if (selected.length > max) {                                                      // too many Critical/High — keep severest, then earliest
    selected = [...selected]
      .sort((a, b) => (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || byEventTime(a, b))
      .slice(0, max)
      .sort(byEventTime);
  }
  return selected;
}

// A compact context digest for the synthesis prompt: the compromised assets (host/account
// and the IoCs seen on each), third-party threat-intel verdicts, and — when a KEV catalog is
// loaded — CVEs from the timeline/IOCs that CISA confirms are actively exploited in the wild
// (a strong initial-access signal). Returns "" when there's nothing to add, so it costs no
// tokens on a bare case.
export function buildSynthesisContext(
  state: InvestigationState,
  scopedEvents: ForensicEvent[],
  kevCatalog?: KevCatalog,
): string {
  const graph = buildAssetGraph({ ...state, forensicTimeline: scopedEvents });
  const iocVal = new Map(graph.iocs.map((i) => [i.id, i.value] as const));

  const assetLines = graph.assets.filter((a) => a.compromised).slice(0, 25).map((a) => {
    const iocs = a.iocIds.map((id) => iocVal.get(id) || id).slice(0, 8).join(", ");
    return `- ${a.name} (${a.type})${iocs ? ` ← ${iocs}` : ""}`;
  });

  const verdictLines = state.iocs
    .filter((i) => (i.enrichments ?? []).some((e) => e.verdict === "malicious" || e.verdict === "suspicious"))
    .slice(0, 25)
    .map((i) => {
      const e = (i.enrichments ?? []).find((x) => x.verdict === "malicious")
        ?? (i.enrichments ?? []).find((x) => x.verdict === "suspicious");
      return `- ${i.value} = ${e?.verdict}${e?.source ? ` (${e.source}${e.score ? ` ${e.score}` : ""})` : ""}`;
    });

  // KEV correlation: scan the scoped events + IOC values for CVE ids and cross-reference
  // against the loaded catalog. Only fires when a catalog is provided (opt-in, store starts
  // empty) so it never costs tokens on unconfigured deployments.
  let kevBlock = "";
  if (kevCatalog && kevCatalog.size > 0) {
    const cveIds = new Set<string>();
    for (const e of scopedEvents) extractCveIds(e.description).forEach((id) => cveIds.add(id));
    for (const ioc of state.iocs) extractCveIds(ioc.value).forEach((id) => cveIds.add(id));
    const kevMatches = matchKevEntries([...cveIds], kevCatalog);
    kevBlock = buildKevDigest(kevMatches);
  }

  // Connective indicators (#200): rank IOCs by cross-host / multi-tool reach so the model anchors
  // on the attack's backbone (a C2 seen on multiple hosts by multiple tools) instead of the flat
  // list. Leads the digest — it's the highest-signal context.
  const connectiveBlock = buildConnectiveIocDigest(rankConnectiveIocs(state, scopedEvents));

  // Signal concentration (#202): tell the model which host(s) carry the suspicious activity so an
  // automatic run over a noisy multi-host timeline doesn't anchor its narrative on a benign host.
  const concentrationBlock = buildSignalConcentrationDigest(rankHosts({ ...state, forensicTimeline: scopedEvents }));

  let block = "";
  if (concentrationBlock) block += concentrationBlock;
  if (connectiveBlock) block += connectiveBlock;
  if (assetLines.length) block += `COMPROMISED ASSETS (host/account ← IoCs seen on it):\n${assetLines.join("\n")}\n\n`;
  if (verdictLines.length) block += `THREAT-INTEL VERDICTS (third-party):\n${verdictLines.join("\n")}\n\n`;
  if (kevBlock) block += kevBlock;
  return block;
}
