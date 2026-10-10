import type { EvidenceEdge, EvidenceNode } from "./evidenceGraph.js";
import { LOLBINS } from "./winProcessBaseline.js";

// "LOLBIN chains" selection for the Evidence Chain graph (#2113). Pure: returns new arrays and
// never mutates its inputs. Derived at view time from the graph that buildEvidenceGraph already
// built — nothing is re-graded.
//
// A process node is a HIT when its image is in the LOLBINS list (the full list, not the Run-key
// subset) AND either (a) it was spawned by an unusual launcher, or (b) its worst backing event is
// Medium or higher. CONTEXT nodes are the hit's ancestors up the spawn chain to the root, plus its
// direct children. A spawned edge from an unusual launcher into a LOLBIN is flagged `launcher`.
//
// Known granularity limit: process nodes are keyed (host, name), so powershell under explorer and
// powershell under winword share one node, and severity is that node's worst event. This matches
// how the graph already colours nodes.

export const UNUSUAL_LAUNCHERS: ReadonlySet<string> = new Set([
  "winword.exe",
  "excel.exe",
  "powerpnt.exe",
  "outlook.exe",
  "onenote.exe",
  "msaccess.exe",
  "chrome.exe",
  "msedge.exe",
  "firefox.exe",
  "iexplore.exe",
  "wmiprvse.exe",
  "wscript.exe",
  "cscript.exe",
]);

const QUALIFYING_SEVERITIES: ReadonlySet<string> = new Set(["Medium", "High", "Critical"]);

/** Lower-case, strip any path, and make sure the name ends in ".exe". */
export function normalizeProcessName(name: string): string {
  const base = (name.split(/[\\/]/).pop() ?? "").trim().toLowerCase();
  if (!base) return "";
  return base.endsWith(".exe") ? base : `${base}.exe`;
}

export interface LolbinMarked {
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
}

function addTo(map: Map<string, string[]>, key: string, value: string): void {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

export function markLolbinChains(
  nodes: readonly EvidenceNode[],
  edges: readonly EvidenceEdge[],
): LolbinMarked {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const spawned = edges.filter((e) => e.type === "spawned");
  const parentsOf = new Map<string, string[]>();
  const childrenOf = new Map<string, string[]>();
  for (const e of spawned) {
    addTo(parentsOf, e.target, e.source);
    addTo(childrenOf, e.source, e.target);
  }
  const nameOf = (id: string): string => {
    const n = byId.get(id);
    return n && n.kind === "process" ? normalizeProcessName(n.label) : "";
  };
  const isLauncherEdge = (e: EvidenceEdge): boolean =>
    LOLBINS.has(nameOf(e.target)) && UNUSUAL_LAUNCHERS.has(nameOf(e.source));

  const hits = new Set<string>();
  for (const n of nodes) {
    if (n.kind !== "process" || !LOLBINS.has(normalizeProcessName(n.label))) continue;
    const fromLauncher = spawned.some((e) => e.target === n.id && isLauncherEdge(e));
    if (fromLauncher || QUALIFYING_SEVERITIES.has(n.maxSeverity)) hits.add(n.id);
  }

  const context = new Set<string>();
  for (const id of hits) {
    const seen = new Set<string>([id]);
    const stack = [...(parentsOf.get(id) ?? [])];
    while (stack.length) {
      const p = stack.pop() as string;
      if (seen.has(p)) continue;
      seen.add(p);
      context.add(p);
      stack.push(...(parentsOf.get(p) ?? []));
    }
    for (const c of childrenOf.get(id) ?? []) context.add(c);
  }

  const markedNodes = nodes.map((n): EvidenceNode => {
    if (hits.has(n.id)) return { ...n, lolbin: "hit" };
    if (context.has(n.id)) return { ...n, lolbin: "context" };
    return n;
  });
  const markedEdges = edges.map((e): EvidenceEdge =>
    e.type === "spawned" && isLauncherEdge(e) ? { ...e, launcher: true } : e,
  );
  return { nodes: markedNodes, edges: markedEdges };
}
