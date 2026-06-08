import type { InvestigationState, ForensicEvent, Severity } from "./stateTypes.js";
import { extractAccounts } from "./assetGraph.js";

// Derives the EVIDENCE CHAIN GRAPH — the *causal* view of an incident, complementing the
// chronological forensic timeline and the (associative) asset↔IoC graph. Where the asset
// graph answers "which IoCs touched which host", this answers "how it happened": which
// process spawned which, and which artifact/account moved between hosts. Pure + deterministic,
// derived on read from fields the importers already populate — NO AI call, NO persisted store.
//
// Phase 1 emits two edge types, both grounded in existing structured fields:
//   • spawned       — parent→child from an event's own processName/parentName pair (same asset).
//                     Process nodes are keyed by (asset, name) so excel→powershell + powershell→cmd
//                     chain into one tree through the shared powershell node — no PID guessing.
//   • lateral_move  — the same binary HASH seen on ≥2 hosts (high confidence), or the same
//                     ACCOUNT active on ≥2 hosts (medium confidence — shared account is signal,
//                     not proof).
//
// Every edge carries `confidence` + the `rule` that produced it + `basis` (human one-liner) +
// the backing `eventIds`, so a causal claim is auditable: a wrong causal edge misleads in a way
// a wrong association edge does not. File-lineage (wrote→executed) and network-flow (src→dst)
// are deferred — they need structured action/direction + src/dst fields that don't exist yet.

export type EvidenceEdgeType = "spawned" | "lateral_move";
export type Confidence = "high" | "medium" | "low";
export type EvidenceNodeKind = "process" | "host" | "account";

export interface EvidenceNode {
  id: string;                 // "proc:<asset>:<name>" | "host:<name>" | "account:<name>"
  kind: EvidenceNodeKind;
  label: string;              // display name
  asset?: string;             // owning host, for process nodes
  maxSeverity: Severity;      // worst severity among the events backing this node
  eventIds: string[];         // forensic events that produced this node (provenance)
}

export interface EvidenceEdge {
  id: string;
  type: EvidenceEdgeType;
  source: string;             // node id
  target: string;             // node id
  confidence: Confidence;
  rule: string;               // derivation rule, e.g. "process-parent-child" | "shared-hash" | "shared-account"
  basis: string;              // human one-liner, e.g. "excel.exe → powershell.exe on ALCLIENT07"
  eventIds: string[];         // backing events (provenance)
}

export interface EvidenceGraph {
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
}

const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
function worse(a: Severity, b: Severity): Severity { return SEV_RANK[b] < SEV_RANK[a] ? b : a; }

const procNodeId = (asset: string, name: string) => `proc:${asset.toLowerCase()}:${name.toLowerCase()}`;
const hostNodeId = (name: string) => `host:${name.toLowerCase()}`;
const accountNodeId = (name: string) => `account:${name.toLowerCase()}`;

function shortHash(h: string): string {
  return h.length > 14 ? `${h.slice(0, 12)}…` : h;
}

// Windows virtual/service principals that are NOT users — every host has a DWM/UMFD/MSI
// session object, so their appearance on many hosts is NOT lateral movement. Dropped from the
// account-lateral rule so it doesn't manufacture host↔host edges from machine noise. (The
// regex captures the truncated tail of spaced namespaces like "Window Manager\DWM-1" as
// "Manager\DWM-1", so match on the user part too.) Kept local to evidence derivation — the
// asset graph still shows these accounts as associations, where they're harmless.
const PSEUDO_ACCT_DOMAIN = /^(global|local|session|nt authority|nt service|window manager|font driver host|iis apppool)$/i;
const PSEUDO_ACCT_USER = /^(dwm-\d+|umfd-\d+|msi[0-9a-f]+|system|local service|network service|anonymous logon)$/i;
function isPseudoAccount(acct: string): boolean {
  const i = acct.indexOf("\\");
  const domain = i >= 0 ? acct.slice(0, i) : "";
  const user = i >= 0 ? acct.slice(i + 1) : acct;
  return PSEUDO_ACCT_DOMAIN.test(domain.trim()) || PSEUDO_ACCT_USER.test(user.trim());
}

export function buildEvidenceGraph(state: InvestigationState): EvidenceGraph {
  // Nodes are materialized lazily so only those that participate in ≥1 edge are emitted.
  const nodeMap = new Map<string, EvidenceNode>();
  function ensureNode(id: string, kind: EvidenceNodeKind, label: string, asset: string | undefined, e: ForensicEvent): EvidenceNode {
    let n = nodeMap.get(id);
    if (!n) {
      n = { id, kind, label, asset, maxSeverity: "Info", eventIds: [] };
      nodeMap.set(id, n);
    }
    n.maxSeverity = worse(n.maxSeverity, e.severity);
    if (!n.eventIds.includes(e.id)) n.eventIds.push(e.id);
    return n;
  }

  const edgeMap = new Map<string, EvidenceEdge>();
  function addEdge(edge: Omit<EvidenceEdge, "eventIds"> & { eventId: string }): void {
    const existing = edgeMap.get(edge.id);
    if (existing) {
      if (!existing.eventIds.includes(edge.eventId)) existing.eventIds.push(edge.eventId);
      return;
    }
    const { eventId, ...rest } = edge;
    edgeMap.set(edge.id, { ...rest, eventIds: [eventId] });
  }

  // ── spawned: parent→child from each event's own process pair ──────────────────────────
  for (const e of state.forensicTimeline) {
    if (!e.parentName || !e.processName) continue;
    const parent = e.parentName.trim(), child = e.processName.trim();
    if (!parent || !child || parent.toLowerCase() === child.toLowerCase()) continue; // skip self-spawn
    const asset = (e.asset ?? "").trim();
    const pId = procNodeId(asset, parent), cId = procNodeId(asset, child);
    ensureNode(pId, "process", parent, asset || undefined, e);
    ensureNode(cId, "process", child, asset || undefined, e);
    addEdge({
      id: `spawned|${pId}|${cId}`, type: "spawned", source: pId, target: cId,
      confidence: "high", rule: "process-parent-child",
      basis: `${parent} → ${child}${asset ? ` on ${asset}` : ""}`, eventId: e.id,
    });
  }

  // ── lateral_move (hash): same binary on ≥2 distinct hosts ─────────────────────────────
  const byHash = new Map<string, Map<string, ForensicEvent>>(); // hash -> assetLower -> a backing event
  for (const e of state.forensicTimeline) {
    const h = (e.sha256 ?? e.md5 ?? "").trim().toLowerCase();
    const asset = (e.asset ?? "").trim();
    if (!h || !asset) continue;
    const hosts = byHash.get(h) ?? new Map();
    if (!hosts.has(asset.toLowerCase())) hosts.set(asset.toLowerCase(), e);
    byHash.set(h, hosts);
  }
  for (const [h, hosts] of byHash) {
    if (hosts.size < 2) continue;
    const entries = [...hosts.entries()].sort((a, b) => a[0].localeCompare(b[0])); // [assetLower, event]
    for (let i = 1; i < entries.length; i++) {
      const [, ea] = entries[i - 1], [, eb] = entries[i]; // chain consecutive hosts → k-1 edges
      const aNode = ensureNode(hostNodeId(ea.asset!.trim()), "host", ea.asset!.trim(), undefined, ea);
      const bNode = ensureNode(hostNodeId(eb.asset!.trim()), "host", eb.asset!.trim(), undefined, eb);
      addEdge({
        id: `lateral|hash:${h}|${aNode.id}|${bNode.id}`, type: "lateral_move",
        source: aNode.id, target: bNode.id, confidence: "high", rule: "shared-hash",
        basis: `same binary ${shortHash(h)} on ${ea.asset!.trim()} + ${eb.asset!.trim()}`, eventId: eb.id,
      });
    }
  }

  // ── lateral_move (account): same account active on ≥2 distinct hosts (account → host star) ──
  const byAccount = new Map<string, Map<string, ForensicEvent>>(); // account -> assetLower -> event
  for (const e of state.forensicTimeline) {
    const asset = (e.asset ?? "").trim();
    if (!asset) continue;
    for (const acct of extractAccounts(e.description)) {
      if (isPseudoAccount(acct)) continue;   // skip DWM/UMFD/MSI… virtual principals — not users
      const hosts = byAccount.get(acct) ?? new Map();
      if (!hosts.has(asset.toLowerCase())) hosts.set(asset.toLowerCase(), e);
      byAccount.set(acct, hosts);
    }
  }
  for (const [acct, hosts] of byAccount) {
    if (hosts.size < 2) continue;
    const acctId = accountNodeId(acct);
    for (const [, e] of [...hosts.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      ensureNode(acctId, "account", acct, undefined, e);
      const hNode = ensureNode(hostNodeId(e.asset!.trim()), "host", e.asset!.trim(), undefined, e);
      addEdge({
        id: `lateral|acct:${acct}|${hNode.id}`, type: "lateral_move",
        source: acctId, target: hNode.id, confidence: "medium", rule: "shared-account",
        basis: `${acct} active on ${e.asset!.trim()}`, eventId: e.id,
      });
    }
  }

  const nodes = [...nodeMap.values()].sort((a, b) =>
    a.kind.localeCompare(b.kind) || a.id.localeCompare(b.id));
  const edges = [...edgeMap.values()].sort((a, b) => a.id.localeCompare(b.id));
  return { nodes, edges };
}
