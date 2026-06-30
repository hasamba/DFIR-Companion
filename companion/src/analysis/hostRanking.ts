// Suspicious host / account ranking (#202). In a multi-host investigation the real attack is
// concentrated on a couple of entities but drowned by benign telemetry from every other host.
// This pure, derived-on-read module scores each host/account by SIGNAL (severity-weighted events +
// distinct ATT&CK techniques + connective IOCs), not volume — so a chatty-but-benign host (zero
// Critical/High) sinks to the bottom regardless of how many events it produced. It also suggests an
// auto-scope TIME WINDOW covering the top entities' activity (the existing scope is time-based) and
// a compact "signal concentration" hint for the synthesis prompt. No AI, no network.

import type { InvestigationState, ForensicEvent } from "./stateTypes.js";
import { extractAccounts } from "./assetGraph.js";
import { rankConnectiveIocs } from "./iocAnchors.js";

export interface EntityRank {
  name: string;
  type: "host" | "account";
  score: number;
  critical: number;
  high: number;
  medium: number;
  total: number;
  techniques: number;       // distinct ATT&CK techniques seen on it
  connectiveIocs: number;   // cross-host / multi-tool IOCs touching it (hosts only)
  firstSeen: string;
  lastSeen: string;
}

export interface HostRankingResult {
  ranks: EntityRank[];
  suggestedWindow: { start: string | null; end: string | null };
  topHosts: string[];       // the host names that carry the bulk of the signal
}

interface Acc {
  name: string; type: "host" | "account";
  crit: number; high: number; med: number; total: number;
  tech: Set<string>; first: string; last: string;
}

export interface RankHostsOptions { max?: number; coverage?: number }

export function rankHosts(state: InvestigationState, opts: RankHostsOptions = {}): HostRankingResult {
  const max = opts.max ?? 20;
  const coverage = opts.coverage ?? 0.7;

  // Connective IOC reach per host (#200).
  const connByHost = new Map<string, number>();
  for (const a of rankConnectiveIocs(state, state.forensicTimeline, { max: 50 })) {
    for (const h of a.hosts) connByHost.set(h.toLowerCase(), (connByHost.get(h.toLowerCase()) ?? 0) + 1);
  }

  const map = new Map<string, Acc>();
  const ensure = (type: "host" | "account", name: string): Acc => {
    const key = `${type}:${name.toLowerCase()}`;
    let a = map.get(key);
    if (!a) { a = { name, type, crit: 0, high: 0, med: 0, total: 0, tech: new Set(), first: "", last: "" }; map.set(key, a); }
    return a;
  };
  const bump = (a: Acc, e: ForensicEvent): void => {
    a.total++;
    if (e.severity === "Critical") a.crit++;
    else if (e.severity === "High") a.high++;
    else if (e.severity === "Medium") a.med++;
    for (const t of e.mitreTechniques ?? []) a.tech.add(t);
    const ts = e.timestamp ?? "";
    if (ts) { if (!a.first || ts < a.first) a.first = ts; if (!a.last || ts > a.last) a.last = ts; }
  };

  for (const e of state.forensicTimeline) {
    if (e.asset && e.asset.trim()) bump(ensure("host", e.asset.trim()), e);
    for (const acct of extractAccounts(e.description ?? "")) bump(ensure("account", acct), e);
  }

  const ranks: EntityRank[] = [...map.values()].map((a) => {
    const connectiveIocs = a.type === "host" ? (connByHost.get(a.name.toLowerCase()) ?? 0) : 0;
    // Real Critical/High events dominate; the connective-IOC contribution is capped so a host that
    // merely shares many (possibly noisy) cross-host indicators can't flatten the ranking past the
    // host that actually has the severe events.
    const score = a.crit * 5 + a.high * 3 + a.med * 1 + a.tech.size * 2 + Math.min(connectiveIocs, 8) * 3;
    return {
      name: a.name, type: a.type, score,
      critical: a.crit, high: a.high, medium: a.med, total: a.total,
      techniques: a.tech.size, connectiveIocs, firstSeen: a.first, lastSeen: a.last,
    };
  })
    .filter((r) => r.score > 0)                 // only entities that carry signal
    .sort((x, y) => y.score - x.score || y.critical - x.critical || y.high - x.high || x.name.localeCompare(y.name));

  // Top HOSTS that cumulatively cover `coverage` of the host signal (min 1, max 5).
  const hostRanks = ranks.filter((r) => r.type === "host");
  const totalHostScore = hostRanks.reduce((n, r) => n + r.score, 0);
  const topHostRanks: EntityRank[] = [];
  let acc = 0;
  for (const r of hostRanks) {
    topHostRanks.push(r);
    acc += r.score;
    if (topHostRanks.length >= 5 || (totalHostScore > 0 && acc / totalHostScore >= coverage)) break;
  }
  const topHosts = topHostRanks.map((r) => r.name);

  const starts = topHostRanks.map((r) => r.firstSeen).filter(Boolean).sort();
  const ends = topHostRanks.map((r) => r.lastSeen).filter(Boolean).sort();
  const suggestedWindow = {
    start: starts.length ? starts[0] : null,
    end: ends.length ? ends[ends.length - 1] : null,
  };

  return { ranks: ranks.slice(0, max), suggestedWindow, topHosts };
}

// One-line synthesis-prompt hint so an automatic run is less noise-anchored.
export function buildSignalConcentrationDigest(result: HostRankingResult): string {
  if (!result.topHosts.length) return "";
  return `SIGNAL CONCENTRATION: the suspicious activity is concentrated on ${result.topHosts.join(", ")} — focus the attack narrative there; other hosts are likely background/benign.\n\n`;
}
