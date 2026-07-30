import type { ForensicEvent } from "./stateTypes.js";
import { LOGON_TYPES, logonRisk } from "./siemImport.js";

// Builds the Login Graph (Timesketch-style directed account → host logon graph) from the
// super-timeline. PARSES the deterministic descriptions mapWindows() rendered at import time
// ("{tool} Successful logon (EID 4624) - DOMAIN\\user - LogonType=N - IpAddress=… @ host") —
// no new import-time field, so existing stored cases get the graph with no re-import.
// Pure + deterministic, no AI, no I/O. Sibling of assetGraph.ts.

const LOGON_MARKER = /(Successful|Failed) logon \(EID (?:4624|4625)\)/;

export interface ParsedLogon {
  account: string;                  // full form as rendered, e.g. "CORP\\jdoe", "NT AUTHORITY\\SYSTEM"
  host: string;                     // the event's asset (the machine logged ONTO)
  logonType?: number;
  typeName: string;                 // decoded LOGON_TYPES name, "type N", or "Unknown"
  outcome: "success" | "failed";
  sourceIp?: string;
  workstation?: string;
}

// Parse one super-timeline row. Returns null when the row is not a 4624/4625 logon, carries no
// account segment, or has no asset — malformed rows are skipped, never fatal.
export function parseLoginEvent(e: ForensicEvent): ParsedLogon | null {
  const m = LOGON_MARKER.exec(e.description);
  if (!m) return null;
  // Injection guard: on a genuine row the marker sits in the `${tool} ${label} (EID n)` prefix,
  // BEFORE the first ` - ` separator (channelLabel values and event labels are ` - `-free, and every
  // importer path routes through mapWindows). A marker AFTER it is log content echoed into a field
  // value (e.g. a CommandLine containing "Successful logon (EID 4624) - EVIL\\fake @ x") — an
  // attacker-controlled string that must not plant a fake account→host edge in the graph.
  const sep = e.description.indexOf(" - ");
  if (sep !== -1 && m.index > sep) return null;
  const host = (e.asset ?? "").trim();
  if (!host) return null;
  // Accounts segment: everything after the marker up to the first `Key=value` field, the ` @ host`
  // suffix, or the 4624 ` [TypeName …]` overlay. mapWindows renders accounts (when present) as the
  // first ` - `-joined segment, comma-separated, TARGET account first (winAccounts pair order).
  const rest = e.description.slice(m.index + m[0].length);
  const seg = rest.replace(/^ - /, "").split(/ - (?=[A-Za-z]+=)| @ | \[/)[0]?.trim() ?? "";
  const account = seg.split(", ")[0]?.trim();
  if (!account || account.includes("=")) return null;   // no accounts rendered on this row
  const lt = /\bLogonType=(\d+)\b/.exec(e.description);
  const logonType = lt ? Number(lt[1]) : undefined;
  const ip = /\bIpAddress=(\S+)/.exec(e.description)?.[1];
  const ws = /\bWorkstationName=(\S+)/.exec(e.description)?.[1];
  return {
    account,
    host,
    ...(logonType !== undefined ? { logonType } : {}),
    typeName: logonType !== undefined ? (LOGON_TYPES[logonType] ?? `type ${logonType}`) : "Unknown",
    outcome: m[1] === "Successful" ? "success" : "failed",
    ...(ip ? { sourceIp: ip } : {}),
    ...(ws ? { workstation: ws } : {}),
  };
}

// Service/virtual domains whose prefix adds no signal — display "SYSTEM", not "NT AUTHORITY\SYSTEM"
// (matches the Timesketch reference UI). Node IDs keep the full form; only display shortens.
const SERVICE_DOMAINS = /^(NT AUTHORITY|Window Manager|Font Driver Host)\\/i;
export function displayAccountName(account: string): string {
  return account.replace(SERVICE_DOMAINS, "");
}

// Noise accounts for the one-click filter: machine accounts (name$), window-manager /
// font-driver session accounts, ANONYMOUS LOGON. SYSTEM / LOCAL SERVICE / NETWORK SERVICE are
// NOT noise — service-logon edges are meaningful (see the Timesketch reference graph).
export function isNoiseAccount(account: string): boolean {
  const user = account.split("\\").pop() ?? account;
  return /\$$/.test(user) || /^(DWM|UMFD)-\d+$/i.test(user) || /^ANONYMOUS LOGON$/i.test(user);
}

// Graph builder. Aggregation model: ONE edge per (account, host, logon type, outcome) — repeated
// logons fatten the edge's count instead of multiplying edges, and only first/last-seen timestamps
// are kept on it. The individual events behind an edge are served lazily by loginEdgeEvents() when
// the analyst clicks it — mirroring Timesketch's list-of-timestamps-on-the-relationship idea
// without bloating the graph payload. Edge risk is the worst logonRisk() across the edge's events.

export interface LoginGraphNode {
  id: string;                       // "account:<full-lower>" | "host:<lower>"
  name: string;                     // display (service domains shortened)
  type: "account" | "host";
  isNoise: boolean;                 // machine/$, DWM-*, UMFD-*, ANONYMOUS LOGON (accounts only)
  eventCount: number;
}

export interface LoginGraphEdge {
  source: string;                   // account node id — arrow points account → host
  target: string;                   // host node id
  logonType: string;                // decoded name ("Interactive", "type 13", "Unknown")
  outcome: "success" | "failed";
  count: number;
  firstSeen: string;
  lastSeen: string;
  risk: "none" | "medium";          // worst logonRisk() across the edge's events
}

export interface LoginGraph {
  nodes: LoginGraphNode[];
  edges: LoginGraphEdge[];          // sorted by count desc; capped
  totalEdges: number;               // before the cap — powers "showing X of Y"
  truncated: boolean;
}

export const DEFAULT_MAX_EDGES = 500;

export class LoginGraphBuilder {
  private readonly nodes = new Map<string, LoginGraphNode>();
  private readonly edges = new Map<string, LoginGraphEdge>();

  private ensureNode(type: "account" | "host", full: string): LoginGraphNode {
    const id = `${type}:${full.toLowerCase()}`;
    let n = this.nodes.get(id);
    if (!n) {
      n = {
        id,
        name: type === "account" ? displayAccountName(full) : full,
        type,
        isNoise: type === "account" && isNoiseAccount(full),
        eventCount: 0,
      };
      this.nodes.set(id, n);
    }
    return n;
  }

  add(events: readonly ForensicEvent[]): void {
    for (const e of events) this.addOne(e);
  }

  private addOne(e: ForensicEvent): void {
    const p = parseLoginEvent(e);
    if (!p) return;
    const n = e.count ?? 1;
    const acct = this.ensureNode("account", p.account);
    const host = this.ensureNode("host", p.host);
    acct.eventCount += n;
    host.eventCount += n;

    const key = `${acct.id}|${host.id}|${p.typeName}|${p.outcome}`;
    // Clamp: anomalous importer data can carry endTimestamp < timestamp; lastSeen must never precede firstSeen.
    // Compare epoch ms, NOT lexicographic ISO strings — a higher-precision endTimestamp that is
    // chronologically LATER (e.g. ...09:20:00.500Z) sorts BEFORE the shorter ...09:20:00Z because
    // '.' (0x2E) < 'Z' (0x5A), so a string `>` would discard the genuinely-later time (#14).
    const end = e.endTimestamp ?? e.timestamp;
    const endMs = e.endTimestamp ? Date.parse(e.endTimestamp) : NaN;
    const tsMs = Date.parse(e.timestamp);
    const last = !Number.isNaN(endMs) && endMs > tsMs ? end : e.timestamp;
    const risky = p.logonType !== undefined && logonRisk(p.logonType, p.sourceIp ?? "").severity !== undefined;
    const edge = this.edges.get(key);
    if (!edge) {
      this.edges.set(key, {
        source: acct.id, target: host.id, logonType: p.typeName, outcome: p.outcome,
        count: n, firstSeen: e.timestamp, lastSeen: last, risk: risky ? "medium" : "none",
      });
    } else {
      // Same epoch-based comparison for firstSeen/lastSeen merge (avoids the same string-sort bug).
      const eFirstMs = Date.parse(edge.firstSeen);
      const eLastMs = Date.parse(edge.lastSeen);
      const firstSeen = !Number.isNaN(eFirstMs) && tsMs < eFirstMs ? e.timestamp : edge.firstSeen;
      const lastMs = Date.parse(last);
      const lastSeen = !Number.isNaN(lastMs) && !Number.isNaN(eLastMs) && lastMs > eLastMs ? last : edge.lastSeen;
      this.edges.set(key, {
        ...edge,
        count: edge.count + n,
        firstSeen,
        lastSeen,
        risk: risky ? "medium" : edge.risk,
      });
    }
  }

  build(maxEdges = DEFAULT_MAX_EDGES): LoginGraph {
    // Tie-break beyond count so a truncated graph is stable across imports (stored event order can shift).
    const sorted = [...this.edges.values()].sort((a, b) =>
      b.count - a.count || a.source.localeCompare(b.source) || a.target.localeCompare(b.target) || a.logonType.localeCompare(b.logonType));
    const kept = sorted.slice(0, maxEdges);
    const referenced = new Set(kept.flatMap((e) => [e.source, e.target]));
    return {
      nodes: [...this.nodes.values()].filter((n) => referenced.has(n.id)),
      edges: kept,
      totalEdges: sorted.length,
      truncated: sorted.length > kept.length,
    };
  }
}

export function buildLoginGraph(events: readonly ForensicEvent[], maxEdges = DEFAULT_MAX_EDGES): LoginGraph {
  const builder = new LoginGraphBuilder();
  builder.add(events);
  return builder.build(maxEdges);
}

export interface LoginEdgeEvent {
  id: string;
  timestamp: string;
  description: string;
  sourceIp?: string;
  workstation?: string;
  count: number;
}

export interface LoginEdgeEventsQuery {
  account: string;                  // full account form, case-insensitive
  host: string;
  type: string;                     // decoded typeName, e.g. "Interactive"
  outcome: "success" | "failed";
  limit: number;
}

// The events behind ONE edge — lazy-loaded by the dashboard when the analyst clicks it.
export function loginEdgeEvents(events: readonly ForensicEvent[], q: LoginEdgeEventsQuery): { events: LoginEdgeEvent[]; total: number } {
  const matched: { e: ForensicEvent; p: ParsedLogon }[] = [];
  for (const e of events) {
    const p = parseLoginEvent(e);
    if (!p) continue;
    if (p.account.toLowerCase() !== q.account.toLowerCase()) continue;
    if (p.host.toLowerCase() !== q.host.toLowerCase()) continue;
    if (p.typeName !== q.type || p.outcome !== q.outcome) continue;
    matched.push({ e, p });
  }
  matched.sort((a, b) => a.e.timestamp.localeCompare(b.e.timestamp));
  return {
    total: matched.length,
    events: matched.slice(0, Math.max(0, q.limit)).map(({ e, p }) => ({
      id: e.id,
      timestamp: e.timestamp,
      description: e.description,
      ...(p.sourceIp ? { sourceIp: p.sourceIp } : {}),
      ...(p.workstation ? { workstation: p.workstation } : {}),
      count: e.count ?? 1,
    })),
  };
}
