// Cross-host / multi-source IOC anchoring (#200). In a multi-host investigation the indicators
// that CONNECT the intrusion across hosts (a C2 domain seen on the workstation AND the DB server,
// observed by Zeek + the EDR + the IDS) are the attack's backbone — but in a flat list of thousands
// of mostly per-host telemetry IOCs they're invisible. This pure module ranks indicators by their
// connective reach (distinct hosts touched + distinct tools that observed them), with a small
// OFFLINE, no-network reputation heuristic (risky TLD / DGA-ish label) as a tiebreaker. The result
// is fed into the synthesis prompt so the model anchors on the real spine instead of the flat list.
//
// No AI, no network — purely derived from the case state (the asset↔IoC graph + per-IOC tool
// corroboration), like iocCorroboration / assetGraph.

import type { InvestigationState, ForensicEvent } from "./stateTypes.js";
import { buildAssetGraph } from "./assetGraph.js";
import { deriveIocSources } from "./iocCorroboration.js";

export interface IocAnchor {
  value: string;
  type: string;
  hosts: string[];       // distinct host-type assets the IOC touched
  accounts: string[];    // distinct account-type assets it touched
  tools: string[];       // distinct tools that observed it
  malicious: boolean;    // a third-party threat-intel verdict marked it malicious/suspicious
  suspicious: boolean;   // offline heuristic flagged it (risky TLD / DGA-ish)
  score: number;
}

// High-abuse / commonly-malicious TLDs — a HINT, never a verdict.
const RISKY_TLD = /\.(?:tk|top|bit|gq|ml|cf|ga|xyz|cloud|to|cc|pw|click|link|work|zip|mov)$/i;
const DOMAIN_SHAPE = /^[a-z0-9.-]+\.[a-z]{2,}$/i;

// Offline, no-network reputation hint for a domain/host indicator: a high-abuse TLD or a
// DGA-looking subdomain label (long, contains digits, with a long consonant run). Conservative.
export function looksSuspiciousDomain(value: string): boolean {
  const v = value.trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/:?]/)[0];
  if (!DOMAIN_SHAPE.test(v)) return false;
  if (RISKY_TLD.test(v)) return true;
  const labels = v.split(".");
  for (const l of labels.slice(0, -2)) {              // skip the registrable domain + TLD
    if (l.length >= 8 && /\d/.test(l) && /[bcdfghjklmnpqrstvwxz]{4,}/.test(l)) return true;
  }
  return false;
}

export interface RankConnectiveOptions {
  max?: number;          // cap the returned anchors (default 12)
  minHosts?: number;     // hosts touched to qualify as cross-host (default 2)
  minTools?: number;     // tools observing to qualify as corroborated (default 2)
}

// Rank the case's indicators by connective reach. Only indicators that are connective (touch ≥
// minHosts hosts, OR seen by ≥ minTools tools) OR carry a malicious/suspicious signal are returned.
export function rankConnectiveIocs(
  state: InvestigationState,
  scopedEvents: ForensicEvent[] = state.forensicTimeline,
  opts: RankConnectiveOptions = {},
): IocAnchor[] {
  const max = opts.max ?? 12;
  const minHosts = opts.minHosts ?? 2;
  const minTools = opts.minTools ?? 2;

  const graph = buildAssetGraph({ ...state, forensicTimeline: scopedEvents });
  const assetById = new Map(graph.assets.map((a) => [a.id, a] as const));
  const toolsByIocId = deriveIocSources(state.iocs, scopedEvents);

  const anchors: IocAnchor[] = [];
  for (const gi of graph.iocs) {
    const hosts = new Set<string>();
    const accounts = new Set<string>();
    for (const aid of gi.assetIds) {
      const a = assetById.get(aid);
      if (!a) continue;
      if (a.type === "host") hosts.add(a.name);
      else if (a.type === "account") accounts.add(a.name);
    }
    const tools = toolsByIocId[gi.id] ?? [];
    const malicious = gi.verdict === "malicious" || gi.verdict === "suspicious";
    const suspicious = (gi.type === "domain" || gi.type === "url") && looksSuspiciousDomain(gi.value);

    const connective = hosts.size >= minHosts || tools.length >= minTools;
    if (!connective && !malicious && !suspicious) continue;

    // Cross-host reach is the strongest signal (a C2 touching N hosts IS the backbone), so it
    // dominates the score; a third-party malicious verdict ranks above a lone offline heuristic.
    const score = hosts.size * 4 + tools.length * 2 + accounts.size + (malicious ? 6 : 0) + (suspicious ? 1 : 0);
    anchors.push({
      value: gi.value, type: gi.type,
      hosts: [...hosts].sort(), accounts: [...accounts].sort(), tools,
      malicious, suspicious, score,
    });
  }

  anchors.sort((a, b) =>
    b.score - a.score ||
    b.hosts.length - a.hosts.length ||
    b.tools.length - a.tools.length ||
    a.value.localeCompare(b.value));
  return anchors.slice(0, max);
}

// Compact prompt digest of the top connective indicators, for buildSynthesisContext.
export function buildConnectiveIocDigest(anchors: IocAnchor[]): string {
  if (!anchors.length) return "";
  const lines = anchors.map((a) => {
    const parts: string[] = [];
    if (a.hosts.length) parts.push(`${a.hosts.length} host${a.hosts.length > 1 ? "s" : ""}: ${a.hosts.join(", ")}`);
    if (a.tools.length) parts.push(`${a.tools.length} tool${a.tools.length > 1 ? "s" : ""}: ${a.tools.join(", ")}`);
    if (a.accounts.length) parts.push(`accounts: ${a.accounts.join(", ")}`);
    const flags = [a.malicious ? "threat-intel: malicious" : "", a.suspicious ? "suspicious indicator" : ""].filter(Boolean).join(", ");
    return `- ${a.value}${parts.length ? ` [${parts.join(" | ")}]` : ""}${flags ? ` ⚠ ${flags}` : ""}`;
  });
  return `CONNECTIVE INDICATORS (cross-host / multi-tool — likely the attack backbone, weigh heavily):\n${lines.join("\n")}\n\n`;
}
