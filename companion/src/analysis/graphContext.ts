import type { InvestigationState, Severity } from "./stateTypes.js";
import { buildEvidenceGraph, type EvidenceEdge, type EvidenceEdgeType } from "./evidenceGraph.js";

// GraphRAG context for the "Ask the case" feature (issue #98). Serializes the deterministic
// EVIDENCE CHAIN graph (the CAUSAL view — process spawns, file lineage, lateral movement, network
// flows, host anchors) into a compact text block so the AI can trace MULTI-HOP attack paths
// ("show me the path from the phishing email to the Domain Controller") by following the graph's
// real relationships instead of re-deriving them from prose. The associative asset↔IoC digest is
// already supplied by `buildSynthesisContext`; this adds the causal edges that answer "how it
// happened" / "what led to what", which standard context-window RAG over the flat timeline misses.
//
// Pure + deterministic — derived on read from the same structured fields the importers populate,
// NO AI call, NO persisted store (mirrors buildAssetGraph / buildEvidenceGraph). Edges are ranked
// worst-severity-first and capped so the block stays within the prompt budget; each rendered line
// carries its backing [event ids] so the model can cite them in `relatedEventIds`.

export interface GraphContextOptions {
  maxEdges?: number; // overall cap on rendered edges (default DEFAULT_MAX_GRAPH_EDGES)
}

export const DEFAULT_MAX_GRAPH_EDGES = 120;

const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

// Render order — causal edges first (what the model needs to reconstruct a path), the structural
// host anchor last. Each maps to a human-readable section header.
const TYPE_ORDER: EvidenceEdgeType[] = ["spawned", "file_lineage", "lateral_move", "network_flow", "ran_on"];
const TYPE_LABEL: Record<EvidenceEdgeType, string> = {
  spawned: "Process spawns (parent → child)",
  file_lineage: "File lineage (wrote → executed)",
  lateral_move: "Lateral movement (same binary/account across hosts)",
  network_flow: "Network connections (source → destination)",
  ran_on: "Process anchored to host",
};

// How many backing event ids to cite per edge (enough to be auditable without bloating the block).
const CITES_PER_EDGE = 3;

export function buildGraphContext(state: InvestigationState, opts: GraphContextOptions = {}): string {
  const graph = buildEvidenceGraph(state);
  if (graph.edges.length === 0) return "";
  const maxEdges = Math.max(0, opts.maxEdges ?? DEFAULT_MAX_GRAPH_EDGES);
  if (maxEdges === 0) return "";

  const sevRank = new Map(graph.nodes.map((n) => [n.id, SEV_RANK[n.maxSeverity]] as const));
  // An edge's severity = the worst (lowest rank) of its two endpoints. Used to decide which edges
  // survive the cap so the highest-signal relationships are always shown.
  const edgeRank = (e: EvidenceEdge): number =>
    Math.min(sevRank.get(e.source) ?? SEV_RANK.Info, sevRank.get(e.target) ?? SEV_RANK.Info);

  const ranked = [...graph.edges].sort((a, b) =>
    edgeRank(a) - edgeRank(b) ||
    TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type) ||
    a.basis.localeCompare(b.basis));
  const kept = ranked.slice(0, maxEdges);

  const lines: string[] = [];
  for (const type of TYPE_ORDER) {
    const group = kept.filter((e) => e.type === type);
    if (!group.length) continue;
    lines.push(`${TYPE_LABEL[type]}:`);
    for (const e of group) {
      const cites = e.eventIds.slice(0, CITES_PER_EDGE).join(", ");
      lines.push(`- ${e.basis}${cites ? ` [${cites}]` : ""}`);
    }
  }
  if (!lines.length) return "";

  const header =
    "ATTACK GRAPH (deterministic causal relationships — follow these edges to trace multi-hop " +
    "attack paths end-to-end; cite the [event ids] in relatedEventIds):";
  const footer = kept.length < graph.edges.length
    ? `\n(showing ${kept.length} of ${graph.edges.length} graph edges, highest-severity first)`
    : "";
  return `${header}\n${lines.join("\n")}${footer}\n\n`;
}
