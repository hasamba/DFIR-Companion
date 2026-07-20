import type { InvestigationState, IOC, ForensicEvent, Severity } from "./stateTypes.js";

// Derives the asset ↔ IoC graph from the investigation state. An "asset" is a victim
// entity an event happened on: a HOST (from each event's `asset` field — populated by THOR,
// CSV/Velociraptor imports and the vision model) or an ACCOUNT (extracted from event text:
// DOMAIN\user or user@domain). An edge means "this IoC was seen in an event on this asset",
// so per asset you get all its IoCs and per IoC all the assets it touched. Pure + deterministic.
//
// v1: hosts and accounts. Services are a future asset type (no extractor yet).

export type AssetType = "host" | "account" | "service" | "other";

export interface GraphAsset {
  id: string;               // stable id, e.g. "host:alclient07"
  name: string;             // display name
  type: AssetType;
  compromised: boolean;     // has a finding, or a Critical/High event
  iocIds: string[];         // connected IoC ids
  findingIds: string[];
  eventCount: number;
  maxSeverity: Severity;
}

export interface GraphIoc {
  id: string;
  type: string;
  value: string;
  verdict?: string;         // worst threat-intel verdict, if enriched
  assetIds: string[];       // connected asset ids
}

export interface AssetGraphEdge { asset: string; ioc: string; }

export interface AssetGraph {
  assets: GraphAsset[];
  iocs: GraphIoc[];         // only IoCs connected to ≥1 asset
  edges: AssetGraphEdge[];
}

// Optional time-window scope (#83): when set, only forensic events whose `timestamp` falls in
// [from, until] contribute to the graph, so brushing a range on the swimlane (or applying a saved
// dwell-window) narrows the asset/evidence graphs to that window. Both bounds are ISO-8601 UTC and
// independently optional (open-ended on either side). Shared by buildAssetGraph + buildEvidenceGraph.
export interface TimeWindow { from?: string; until?: string; }

// True when an event is inside the window. Events with an unparseable/absent timestamp are KEPT —
// mirrors the dashboard's client-side _evMatchesTimeRange ("undated → can't prove out of range →
// keep") so the two filters agree. A null/empty window matches everything.
function eventInWindow(e: ForensicEvent, w?: TimeWindow): boolean {
  if (!w || (!w.from && !w.until)) return true;
  const t = Date.parse(e.timestamp);
  if (Number.isNaN(t)) return true;
  if (w.from) { const f = Date.parse(w.from); if (!Number.isNaN(f) && t < f) return false; }
  if (w.until) { const u = Date.parse(w.until); if (!Number.isNaN(u) && t > u) return false; }
  return true;
}

// The forensic timeline narrowed to a time window (returns the same array when no window is set, so
// the unfiltered path allocates nothing). Both graph builders funnel their timeline through this.
export function filterTimeline(events: readonly ForensicEvent[], w?: TimeWindow): ForensicEvent[] {
  if (!w || (!w.from && !w.until)) return events as ForensicEvent[];
  return events.filter((e) => eventInWindow(e, w));
}

const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
function worse(a: Severity, b: Severity): Severity { return SEV_RANK[b] < SEV_RANK[a] ? b : a; }

// Dotted-quad shape (loose — any 4 dot-separated 1-3 digit groups). Used only to decide whether an
// IOC value needs boundary-aware description matching, not to validate octet ranges.
const IPV4_SHAPE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Per-IOC predicate for "does this IOC value appear in an event description". For IP-shaped values
// a raw substring match over-links — IOC `1.1.1.1` matches inside `11.1.1.10` and `192.168.1.1`
// inside `192.168.1.10` — so we use a digit/dot-boundary regex `(?<![\d.])<ip>(?![\d.])` (mirrors the
// geographic-map fix, #133, and the boundary-aware token match in iocCorroboration.ts). Non-IP values
// keep the cheap substring test. Compiled once per case (not per event).
interface DescMatcher { ioc: IOC; test: (descLower: string) => boolean; }
function buildDescMatchers(iocs: readonly IOC[]): DescMatcher[] {
  const out: DescMatcher[] = [];
  for (const i of iocs) {
    // Match the IOC's own value plus any analyst-merged alias values (#82) — an event mentioning
    // the pre-merge duplicate value should still link to the canonical IOC.
    for (const v of [i.value, ...(i.aliasValues ?? [])].map((s) => s.toLowerCase())) {
      if (v.length < 4) continue;
      if (IPV4_SHAPE.test(v)) {
        const re = new RegExp(`(?<![\\d.])${escapeRegExp(v)}(?![\\d.])`);
        out.push({ ioc: i, test: (d) => re.test(d) });
      } else {
        out.push({ ioc: i, test: (d) => d.includes(v) });
      }
    }
  }
  return out;
}

function basename(p: string): string {
  return (p.split(/[\\/]/).pop() || p).toLowerCase();
}

const VERDICT_ORDER = ["malicious", "suspicious", "harmless", "unknown"];
function worstVerdict(i: IOC): string | undefined {
  let best: string | undefined;
  for (const e of i.enrichments ?? []) {
    if (best === undefined || VERDICT_ORDER.indexOf(e.verdict) < VERDICT_ORDER.indexOf(best)) best = e.verdict;
  }
  return best;
}

// DOMAIN\user — guarded so it doesn't match file-path segments (C:\Users\srv). UPN/email accounts.
const NETBIOS_ACCT = /(?<![\\/:.\w])([A-Za-z][A-Za-z0-9.-]{1,14})\\([A-Za-z0-9._$-]{2,20})(?![\\/\w])/g;
const UPN_ACCT = /([A-Za-z0-9._-]{2,}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/g;
// Registry hive roots are included for the same reason as filesystem roots: "HKU\S-1-5-21-…" is a
// path, not a logon — and because the user half is length-capped, the SID's RID gets truncated, so
// distinct users on distinct hosts would otherwise collapse into one identical bogus "account".
const PATH_DOMAINS = /^(Users|Windows|Program|ProgramData|ProgramFiles|System|System32|AppData|Device|Temp|Documents|Desktop|Downloads|HKU|HKLM|HKCU|HKCR|HKCC|Registry)$/i;
// The right-hand side ends in a file extension → it's a path segment (e.g. Zip\7z.exe), not a
// DOMAIN\user. Real Windows usernames don't end in .exe/.dll/etc. Curated (not "any dotted suffix")
// so legitimate dotted accounts like CORP\first.last are NOT rejected.
const FILE_EXT_USER = /\.(exe|dll|sys|drv|scr|com|cpl|ocx|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|msi|msp|lnk|url|reg|inf|zip|rar|7z|gz|tgz|tar|cab|iso|img|txt|log|csv|tsv|json|xml|yaml|yml|ini|cfg|conf|dat|bin|db|sqlite|tmp|temp|dmp|mem|evtx|pcap|doc|docx|xls|xlsx|ppt|pptx|pdf|rtf|png|jpe?g|gif|bmp|svg|ico|md|sh|py|pl|rb|php|jar|so|dylib|key|pem|crt|cer|pfx)$/i;

// NETBIOS_ACCT's lookbehind only rejects a separator ADJACENT to the domain, so it misses every
// path segment containing a space: in "…\Explorer\Shell Folders\Common Startup" the match begins
// after the space and yields "Folders\Common". Same for "C:\Program Files\Windows Defender\…"
// ("Files\Windows") and "…\Google\Drive File Stream\97.0.1.0\…" ("Stream\97.0.1"). These fake
// accounts then look "shared" across every host that ran the same software.
//
// A match is inside a path when the nearest preceding separator is joined to it by nothing but
// path-segment text (words, spaces, dots, hyphens). Three things end a path, so anything after
// them is a real account reference: prose punctuation (", " / "=" / parens — "(EID 4624) -
// FAIRHAVEN\jdoe"), a spaced dash ("…\Zip\7z.exe - by CORP\jdoe"), and a filename extension,
// which terminates the path at a leaf. The gap is also capped — a long clean run is prose.
const PATH_GAP_MAX = 40;
const PATH_GAP = /^[A-Za-z0-9 ._$-]*$/;
const PATH_ENDED = /\s-\s|\.[A-Za-z0-9]{1,4}\b/;     // spaced dash, or a filename extension
function insidePathSegment(text: string, at: number): boolean {
  if (at === 0) return false;
  // Search the ORIGINAL string with a fromIndex rather than slicing off a prefix per match —
  // descriptions are long and this runs for every DOMAIN\user hit, so the prefix copies alone
  // cost ~270ms on a 10k-event report.
  const sep = Math.max(text.lastIndexOf("\\", at - 1), text.lastIndexOf("/", at - 1));
  if (sep < 0) return false;                         // no path anywhere before this match
  if (at - sep - 1 > PATH_GAP_MAX) return false;     // too far from the path to be part of it
  const gap = text.slice(sep + 1, at);
  return PATH_GAP.test(gap) && !PATH_ENDED.test(gap);
}

export function extractAccounts(text: string): string[] {
  const out = new Set<string>();
  let m: RegExpExecArray | null;
  NETBIOS_ACCT.lastIndex = 0;
  while ((m = NETBIOS_ACCT.exec(text))) {
    if (PATH_DOMAINS.test(m[1])) continue;           // skip path segments masquerading as DOMAIN\user
    if (FILE_EXT_USER.test(m[2])) continue;          // skip Folder\file.ext (e.g. Zip\7z.exe) — a file, not a user
    if (insidePathSegment(text, m.index)) continue;  // skip "Shell Folders\Common" — a spaced path segment, not a user
    out.add(`${m[1]}\\${m[2]}`);
  }
  UPN_ACCT.lastIndex = 0;
  while ((m = UPN_ACCT.exec(text))) out.add(m[1]);
  return [...out];
}

export function buildAssetGraph(state: InvestigationState, window?: TimeWindow): AssetGraph {
  // Scope the timeline first (#83); IoCs/findings are still keyed off the full state, so only those
  // reached by an in-window event end up linked — out-of-window links simply don't form.
  const timeline = filterTimeline(state.forensicTimeline, window);
  const iocs = state.iocs;
  const byId = new Map(iocs.map((i) => [i.id, i] as const));
  const byValue = new Map<string, IOC>();
  for (const i of iocs) {
    byValue.set(i.value.toLowerCase(), i);
    // Analyst-merged duplicate values (#82, iocMerge.ts) still resolve onto this canonical IOC.
    for (const alias of i.aliasValues ?? []) byValue.set(alias.toLowerCase(), i);
  }
  const findingById = new Map(state.findings.map((f) => [f.id, f] as const));
  const descMatchers = buildDescMatchers(iocs);

  const assetMap = new Map<string, GraphAsset>();
  const edgeSet = new Set<string>();
  const edges: AssetGraphEdge[] = [];

  function ensureAsset(type: AssetType, name: string): GraphAsset {
    const id = `${type}:${name.toLowerCase()}`;
    let a = assetMap.get(id);
    if (!a) {
      a = { id, name, type, compromised: false, iocIds: [], findingIds: [], eventCount: 0, maxSeverity: "Info" };
      assetMap.set(id, a);
    }
    return a;
  }
  function link(a: GraphAsset, ioc: IOC): void {
    const key = `${a.id}|${ioc.id}`;
    if (edgeSet.has(key)) return;
    edgeSet.add(key);
    edges.push({ asset: a.id, ioc: ioc.id });
    a.iocIds.push(ioc.id);
  }

  // Which IoCs an event references: structured fields, IoCs from its findings, and IoC
  // values that appear in the event description.
  function referencedIocs(e: ForensicEvent): IOC[] {
    const found = new Map<string, IOC>();
    const add = (i?: IOC) => { if (i) found.set(i.id, i); };
    if (e.sha256) add(byValue.get(e.sha256.toLowerCase()));
    if (e.md5) add(byValue.get(e.md5.toLowerCase()));
    if (e.path) { add(byValue.get(e.path.toLowerCase())); add(byValue.get(basename(e.path))); }
    if (e.processName) add(byValue.get(e.processName.toLowerCase()));
    for (const fid of e.relatedFindingIds) {
      const f = findingById.get(fid);
      if (f) for (const iid of f.relatedIocs) add(byId.get(iid));
    }
    const desc = e.description.toLowerCase();
    for (const m of descMatchers) {
      if (m.test(desc)) add(m.ioc);
    }
    return [...found.values()];
  }

  for (const e of timeline) {
    const assetsForEvent: GraphAsset[] = [];
    if (e.asset && e.asset.trim()) assetsForEvent.push(ensureAsset("host", e.asset.trim()));
    for (const acct of extractAccounts(e.description)) assetsForEvent.push(ensureAsset("account", acct));
    if (assetsForEvent.length === 0) continue;

    const refIocs = referencedIocs(e);
    for (const a of assetsForEvent) {
      a.eventCount++;
      a.maxSeverity = worse(a.maxSeverity, e.severity);
      for (const fid of e.relatedFindingIds) if (!a.findingIds.includes(fid)) a.findingIds.push(fid);
      for (const ioc of refIocs) link(a, ioc);
    }
  }

  for (const a of assetMap.values()) {
    a.compromised = a.findingIds.length > 0 || a.maxSeverity === "Critical" || a.maxSeverity === "High";
  }

  const iocAssetIds = new Map<string, string[]>();
  for (const edge of edges) {
    const arr = iocAssetIds.get(edge.ioc) ?? [];
    arr.push(edge.asset);
    iocAssetIds.set(edge.ioc, arr);
  }
  const graphIocs: GraphIoc[] = [];
  for (const [iid, assetIds] of iocAssetIds) {
    const i = byId.get(iid);
    if (i) graphIocs.push({ id: i.id, type: i.type, value: i.value, verdict: worstVerdict(i), assetIds });
  }

  const assets = [...assetMap.values()].sort((a, b) =>
    (Number(b.compromised) - Number(a.compromised)) ||
    (SEV_RANK[a.maxSeverity] - SEV_RANK[b.maxSeverity]) ||
    a.name.localeCompare(b.name));
  graphIocs.sort((a, b) => a.value.localeCompare(b.value));

  return { assets, iocs: graphIocs, edges };
}
