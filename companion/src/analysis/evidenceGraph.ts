import { worstSeverity, type InvestigationState, type ForensicEvent, type Severity } from "./stateTypes.js";
import { filterTimeline, type TimeWindow } from "./assetGraph.js";
import { KILL_CHAIN_ORDER, tacticForTechniques, type IrisTactic } from "./mitreTactics.js";
import {
  canonicalAccounts,
  canonicalNetwork,
  canonicalProcess,
  upgradeForensicEvent,
} from "./canonicalEvent.js";
import { markLolbinChains } from "./lolbinChains.js";
import {
  eventAsset,
  eventHash,
  eventPath,
  hostNodeId,
  isPseudoAccount,
  shortHash,
  timeOf,
  type Confidence,
} from "./evidenceFields.js";
import { directedLateralHops, directedLateralPairs, type LateralHop } from "./lateralDirection.js";

export type { Confidence } from "./evidenceFields.js";
export type { LateralHop } from "./lateralDirection.js";

// Derives the EVIDENCE CHAIN GRAPH — the *causal* view of an incident, complementing the
// chronological forensic timeline and the (associative) asset↔IoC graph. Where the asset
// graph answers "which IoCs touched which host", this answers "how it happened": which
// process spawned which, and which artifact/account moved between hosts. Pure + deterministic,
// derived on read from fields the importers already populate — NO AI call, NO persisted store.
//
// Five edge types, all grounded in existing structured fields:
//   • spawned       — parent→child from an event's own processName/parentName pair (same asset).
//                     Process nodes are keyed by (asset, name) so excel→powershell + powershell→cmd
//                     chain into one tree through the shared powershell node — no PID guessing.
//   • lateral_move  — DIRECTED host→host hops from what the target recorded about an inbound
//                     connection (remote-service install / network logon naming its source,
//                     lateralDirection.ts, #3085). Plus two UNDIRECTED links (`undirected: true`): the
//                     same binary HASH on ≥2 hosts (high) or the same ACCOUNT on ≥2 hosts (medium) —
//                     hosts that share something, never a proven move.
//   • ran_on        — host → the ROOT of each process tree. The host is the BRIDGE: with each tree
//                     hung off its host node, the lateral_move host↔host edges stitch per-host trees
//                     into ONE cross-host attack graph (binary runs on A → moves to B → spawns there)
//                     instead of disconnected islands. Certain from the process's own asset → high.
//   • file_lineage  — wrote→executed: a file written (action="write") then executed (action="execute")
//                     with the same hash. A `file` node sits in the middle, with write-context→file
//                     and file→execute-context edges so the artifact itself is visible in the graph.
//   • network_flow  — src→dst: a connection from srcIp (or host asset) to dstIp:port. `network`
//                     nodes represent IP endpoints; port is folded into the destination node label.
//
// Every edge carries `confidence` + the `rule` that produced it + `basis` (human one-liner) +
// the backing `eventIds`, so a causal claim is auditable: a wrong causal edge misleads in a way
// a wrong association edge does not.

export type EvidenceEdgeType = "spawned" | "lateral_move" | "ran_on" | "file_lineage" | "network_flow";
export type EvidenceNodeKind = "process" | "host" | "account" | "file" | "network";

export interface EvidenceNode {
  id: string; // "proc:<asset>:<name>" | "host:<name>" | "account:<name>" | "file:<hash>" | "net:<ip>[:<port>]"
  kind: EvidenceNodeKind;
  label: string; // display name
  asset?: string; // owning host, for process nodes
  ip?: string; // IP address, for network nodes
  maxSeverity: Severity; // worst severity among the events backing this node
  tactic?: IrisTactic; // dominant ATT&CK tactic across backing events — the kill-chain phase
  // this node sits in. Undefined when no backing event maps to a tactic
  // (powers the dashboard's optional color-by-kill-chain overlay, #93).
  eventIds: string[]; // forensic events that produced this node (provenance)
  // LOLBIN-chains view (#2113): "hit" = a LOLBIN under an unusual launcher or graded Medium+;
  // "context" = a hit's ancestors and direct children. Absent on every other node.
  lolbin?: "hit" | "context";
}

export interface EvidenceEdge {
  id: string;
  type: EvidenceEdgeType;
  source: string; // node id
  target: string; // node id
  confidence: Confidence;
  rule: string; // derivation rule, e.g. "process-parent-child" | "shared-hash" | "shared-account" | "process-on-host"
  basis: string; // human one-liner, e.g. "excel.exe → powershell.exe on ALCLIENT07"
  eventIds: string[]; // backing events (provenance)
  launcher?: true; // spawned edge from an unusual launcher (Office, browser, ...) into a LOLBIN (#2113)
  undirected?: true; // shared-hash / shared-account link: hosts share something, no direction (#3085)
}

export interface EvidenceGraph {
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
}

// Kill-chain order — used only to tie-break the dominant-tactic vote deterministically (the
// earliest stage represented wins a tie, so a node reads as the stage it leads with). Shared with
// burstDetect.ts and sessionSegmentation.ts through mitreTactics.ts.
const CHAIN_ORDER = KILL_CHAIN_ORDER;

// The dominant ATT&CK tactic across a node's backing events: each event resolves to a tactic via
// the canonical technique/keyword mapping (reused from the kill-chain view + IRIS export), the most
// frequent tactic wins, and ties break toward the earliest kill-chain stage. Undefined when no
// backing event maps to any tactic — so a node with no ATT&CK signal degrades cleanly (no overlay
// color). Pure; the eventIds → event lookup is passed in so the whole graph shares one map.
function dominantTactic(
  eventIds: readonly string[],
  eventById: Map<string, ForensicEvent>,
): IrisTactic | undefined {
  const counts = new Map<IrisTactic, number>();
  for (const id of eventIds) {
    const e = eventById.get(id);
    if (!e) continue;
    const tac = tacticForTechniques(e.mitreTechniques, e.description);
    if (tac) counts.set(tac, (counts.get(tac) ?? 0) + 1);
  }
  let best: IrisTactic | undefined;
  let bestCount = 0;
  for (const tac of CHAIN_ORDER) {
    // iterate in chain order so the earliest stage wins ties
    const c = counts.get(tac) ?? 0;
    if (c > bestCount) {
      best = tac;
      bestCount = c;
    }
  }
  return best;
}

const procNodeId = (asset: string, name: string) => `proc:${asset.toLowerCase()}:${name.toLowerCase()}`;
const accountNodeId = (name: string) => `account:${name.toLowerCase()}`;
const fileNodeId = (hash: string) => `file:${hash.toLowerCase()}`;
const netNodeId = (ip: string, port?: number) => `net:${ip.toLowerCase()}${port ? `:${port}` : ""}`;

function eventAction(event: ForensicEvent): string {
  return event.canonical?.event.action ?? event.action ?? "";
}

export function buildEvidenceGraph(state: InvestigationState, window?: TimeWindow): EvidenceGraph {
  // Scope the timeline to the requested window (#83) once, up front; every derivation pass below
  // reads `timeline` instead of state.forensicTimeline, so edges/nodes only form from in-window events.
  const fullTimeline = state.forensicTimeline.map(upgradeForensicEvent);
  const timeline = filterTimeline(fullTimeline, window);
  // Nodes are materialized lazily so only those that participate in ≥1 edge are emitted.
  const nodeMap = new Map<string, EvidenceNode>();
  function mergeNode(
    id: string,
    kind: EvidenceNodeKind,
    label: string,
    asset: string | undefined,
    eventIds: readonly string[],
    sev: Severity,
  ): EvidenceNode {
    let n = nodeMap.get(id);
    if (!n) {
      n = { id, kind, label, asset, maxSeverity: "Info", eventIds: [] };
      nodeMap.set(id, n);
    }
    n.maxSeverity = worstSeverity(n.maxSeverity, sev);
    for (const eid of eventIds) if (!n.eventIds.includes(eid)) n.eventIds.push(eid);
    return n;
  }
  const ensureNode = (
    id: string,
    kind: EvidenceNodeKind,
    label: string,
    asset: string | undefined,
    e: ForensicEvent,
  ) => mergeNode(id, kind, label, asset, [e.id], e.severity);

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
  for (const e of timeline) {
    const process = canonicalProcess(e);
    if (!process?.parent?.name || !process.name) continue;
    const parent = process.parent.name.trim(),
      child = process.name.trim();
    if (!parent || !child || parent.toLowerCase() === child.toLowerCase()) continue; // skip self-spawn
    const asset = eventAsset(e);
    const pId = procNodeId(asset, parent),
      cId = procNodeId(asset, child);
    ensureNode(pId, "process", parent, asset || undefined, e);
    ensureNode(cId, "process", child, asset || undefined, e);
    addEdge({
      id: `spawned|${pId}|${cId}`,
      type: "spawned",
      source: pId,
      target: cId,
      confidence: "high",
      rule: "process-parent-child",
      basis: `${parent} → ${child}${asset ? ` on ${asset}` : ""}`,
      eventId: e.id,
    });
  }

  // ── lateral_move (hash): same binary on ≥2 distinct hosts ─────────────────────────────
  const byHash = new Map<string, Map<string, ForensicEvent>>(); // hash -> assetLower -> a backing event
  for (const e of timeline) {
    const h = eventHash(e);
    const asset = eventAsset(e);
    if (!h || !asset) continue;
    const hosts = byHash.get(h) ?? new Map();
    if (!hosts.has(asset.toLowerCase())) hosts.set(asset.toLowerCase(), e);
    byHash.set(h, hosts);
  }
  for (const [h, hosts] of byHash) {
    if (hosts.size < 2) continue;
    const entries = [...hosts.entries()].sort((a, b) => a[0].localeCompare(b[0])); // [assetLower, event]
    for (let i = 1; i < entries.length; i++) {
      const [, ea] = entries[i - 1],
        [, eb] = entries[i]; // chain consecutive hosts → k-1 edges
      const aAsset = eventAsset(ea),
        bAsset = eventAsset(eb);
      const aNode = ensureNode(hostNodeId(aAsset), "host", aAsset, undefined, ea);
      const bNode = ensureNode(hostNodeId(bAsset), "host", bAsset, undefined, eb);
      addEdge({
        id: `lateral|hash:${h}|${aNode.id}|${bNode.id}`,
        type: "lateral_move",
        source: aNode.id,
        target: bNode.id,
        confidence: "high",
        rule: "shared-hash",
        basis: `same binary ${shortHash(h)} on ${aAsset} + ${bAsset}`,
        eventId: eb.id,
        undirected: true,
      });
    }
  }

  // ── lateral_move (account): same account active on ≥2 distinct hosts (account → host star) ──
  const byAccount = new Map<string, Map<string, ForensicEvent>>(); // account -> assetLower -> event
  for (const e of timeline) {
    const asset = eventAsset(e);
    if (!asset) continue;
    for (const acct of canonicalAccounts(e)) {
      if (isPseudoAccount(acct)) continue; // skip DWM/UMFD/MSI… virtual principals — not users
      const hosts = byAccount.get(acct) ?? new Map();
      if (!hosts.has(asset.toLowerCase())) hosts.set(asset.toLowerCase(), e);
      byAccount.set(acct, hosts);
    }
  }
  for (const [acct, hosts] of byAccount) {
    if (hosts.size < 2) continue;
    const acctId = accountNodeId(acct);
    for (const [, e] of [...hosts.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      const asset = eventAsset(e);
      ensureNode(acctId, "account", acct, undefined, e);
      const hNode = ensureNode(hostNodeId(asset), "host", asset, undefined, e);
      addEdge({
        id: `lateral|acct:${acct}|${hNode.id}`,
        type: "lateral_move",
        source: acctId,
        target: hNode.id,
        confidence: "medium",
        rule: "shared-account",
        basis: `${acct} active on ${asset}`,
        eventId: e.id,
        undirected: true,
      });
    }
  }

  // ── lateral_move (directed): who connected to whom, one edge per ordered host pair (#3085) ──
  for (const hop of directedLateralPairs(directedLateralHops(timeline, fullTimeline))) {
    mergeNode(hop.from, "host", hop.fromHost, undefined, hop.eventIds, hop.severity);
    mergeNode(hop.to, "host", hop.toHost, undefined, hop.eventIds, hop.severity);
    for (const eventId of hop.eventIds) {
      const { from, to, rule, confidence, basis } = hop;
      addEdge({
        id: `lateral|dir:${from}|${to}`,
        type: "lateral_move",
        source: from,
        target: to,
        rule,
        confidence,
        basis,
        eventId,
      });
    }
  }

  // ── file_lineage: wrote→executed (same hash, action="write" + action="execute") ─────────
  // The file node sits in the middle: write-context→file and file→execute-context. This keeps
  // the artifact visible in the graph and lets multiple writers/executors all connect through it.
  const writesByHash = new Map<string, ForensicEvent[]>();
  const execsByHash = new Map<string, ForensicEvent[]>();
  for (const e of timeline) {
    const action = eventAction(e);
    if (!action) continue;
    const h = eventHash(e);
    if (!h) continue;
    if (action === "write") {
      const arr = writesByHash.get(h) ?? [];
      arr.push(e);
      writesByHash.set(h, arr);
    } else if (action === "execute") {
      const arr = execsByHash.get(h) ?? [];
      arr.push(e);
      execsByHash.set(h, arr);
    }
  }
  for (const [h, writes] of writesByHash) {
    const execs = execsByHash.get(h);
    if (!execs?.length) continue;
    const samplePath = writes.map(eventPath).find(Boolean) ?? execs.map(eventPath).find(Boolean);
    const fileName = samplePath?.split(/[/\\]/).pop() ?? shortHash(h);
    const fId = fileNodeId(h);
    // mergeNode is only called when an edge is about to be created so the file node never
    // ends up in the graph without at least one edge referencing it.
    for (const we of writes) {
      const wAsset = eventAsset(we);
      if (!wAsset) continue;
      mergeNode(fId, "file", fileName, undefined, [we.id], we.severity);
      const wHId = hostNodeId(wAsset);
      ensureNode(wHId, "host", wAsset, undefined, we);
      addEdge({
        id: `file_lineage|wrote|${wHId}|${fId}`,
        type: "file_lineage",
        source: wHId,
        target: fId,
        confidence: "high",
        rule: "wrote-file",
        basis: `${wAsset} wrote ${fileName} (${shortHash(h)})`,
        eventId: we.id,
      });
    }
    for (const xe of execs) {
      const xAsset = eventAsset(xe);
      if (!xAsset) continue;
      mergeNode(fId, "file", fileName, undefined, [xe.id], xe.severity);
      let xNodeId: string;
      const processName = canonicalProcess(xe)?.name?.trim();
      if (processName) {
        xNodeId = procNodeId(xAsset, processName);
        ensureNode(xNodeId, "process", processName, xAsset, xe);
      } else {
        xNodeId = hostNodeId(xAsset);
        ensureNode(xNodeId, "host", xAsset, undefined, xe);
      }
      addEdge({
        id: `file_lineage|exec|${fId}|${xNodeId}`,
        type: "file_lineage",
        source: fId,
        target: xNodeId,
        confidence: "high",
        rule: "executed-file",
        basis: `${fileName} (${shortHash(h)}) executed on ${xAsset}`,
        eventId: xe.id,
      });
    }
  }

  // ── network_flow: srcIp → dstIp:port ──────────────────────────────────────────────────
  // Requires dstIp. Source is srcIp (network node) when present, otherwise the event's asset
  // (host node — the host that made the connection). Skips if source cannot be determined.
  for (const e of timeline) {
    const network = canonicalNetwork(e);
    const dst = (network?.destination?.address ?? "").trim();
    if (!dst) continue;
    const srcIp = (network?.source?.address ?? "").trim();
    const srcAsset = eventAsset(e);
    const src = srcIp || srcAsset;
    if (!src || src === dst) continue;
    // Source: use a network node for an explicit srcIp, host node for the event's asset.
    const srcId = srcIp ? netNodeId(srcIp) : hostNodeId(srcAsset);
    if (srcIp) {
      mergeNode(srcId, "network", srcIp, undefined, [e.id], e.severity);
      nodeMap.get(srcId)!.ip = srcIp;
    } else {
      ensureNode(srcId, "host", srcAsset, undefined, e);
    }
    const port = network?.destination?.port;
    const dstId = netNodeId(dst, port);
    const dstLabel = dst + (port ? `:${port}` : "");
    mergeNode(dstId, "network", dstLabel, undefined, [e.id], e.severity);
    nodeMap.get(dstId)!.ip = dst;
    addEdge({
      id: `network_flow|${srcId}|${dstId}`,
      type: "network_flow",
      source: srcId,
      target: dstId,
      confidence: "high",
      rule: "network-connection",
      basis: `${src} → ${dstLabel}`,
      eventId: e.id,
    });
  }

  // ── ran_on: anchor each process tree to its host (host → root process) ────────────────
  // Run AFTER spawned (need the child set) + lateral (host nodes may already exist; mergeNode
  // dedups). Only tree ROOTS (process nodes that are nobody's spawned child) anchor, so the host
  // gets one edge per tree, not one per process. This is what connects the two halves: a tree on
  // HOST-A and a tree on HOST-B both hang off their host nodes, which lateral_move already links.
  const spawnedChildIds = new Set<string>();
  for (const e of edgeMap.values()) if (e.type === "spawned") spawnedChildIds.add(e.target);
  for (const n of [...nodeMap.values()]) {
    // snapshot: mergeNode may add host nodes
    if (n.kind !== "process" || spawnedChildIds.has(n.id)) continue;
    const host = (n.asset ?? "").trim();
    if (!host) continue; // can't anchor a process with no host
    const hId = hostNodeId(host);
    mergeNode(hId, "host", host, undefined, n.eventIds, n.maxSeverity);
    addEdge({
      id: `ran_on|${hId}|${n.id}`,
      type: "ran_on",
      source: hId,
      target: n.id,
      confidence: "high",
      rule: "process-on-host",
      basis: `${n.label} ran on ${host}`,
      eventId: n.eventIds[0],
    });
  }

  // ── kill-chain phase: tag each node with the dominant tactic of its backing events (#93) ──
  // Derived last, once every node's eventIds are final. Enables the dashboard's optional
  // color-by-kill-chain overlay without a second pass over the timeline per node.
  const eventById = new Map<string, ForensicEvent>(timeline.map((e) => [e.id, e]));
  for (const n of nodeMap.values()) {
    const tac = dominantTactic(n.eventIds, eventById);
    if (tac) n.tactic = tac;
  }

  const nodes = [...nodeMap.values()].sort(
    (a, b) => a.kind.localeCompare(b.kind) || a.id.localeCompare(b.id),
  );
  const edges = [...edgeMap.values()].sort((a, b) => a.id.localeCompare(b.id));
  return markLolbinChains(nodes, edges);
}

// ── Lateral-movement PATH inference (#92, #3085) ──────────────────────────────────────────
// Hops are DIRECTED: each says which host connected to which, read from what the target recorded
// (lateralDirection.ts). Shared-hash / shared-account links have no direction and are never hops —
// chaining them in time order drew fan-out (SRC→A, SRC→B) as A→B — so they are reported apart, as
// hosts that share something (sharedHostLinks.ts). buildLateralPaths stitches the directed hops into
// ordered entry → pivot → ... → target chains by real timestamp. Pure, derived on read, no AI.
//
// COMPLETENESS GUARANTEE (a forensics correctness requirement, not just enumeration): every
// derived hop appears in at least one returned path, so a host the attacker actually reached is
// NEVER dropped. The primary narratives are built greedily from entry points (longest-tail at each
// fork) for readability, then a PATH COVER seeds an additional chain from every hop still uncovered
// — including the onward branch(es) a fork's longest-tail walk discarded. This is bounded (total
// paths ≤ number of hops, no combinatorial blow-up) and identical full chains are de-duplicated.

export interface LateralPath {
  id: string;
  hostIds: string[]; // ordered host node ids: entry host → pivot(s) → target
  hops: LateralHop[]; // per-hop evidence; length = hostIds.length - 1
  confidence: Confidence; // weakest-link confidence across the chain's hops
  startTime: string;
  endTime: string;
}

const CONF_RANK: Record<Confidence, number> = { high: 0, medium: 1, low: 2 };
const weakerConf = (a: Confidence, b: Confidence): Confidence => (CONF_RANK[b] > CONF_RANK[a] ? b : a);

export function buildLateralPaths(state: InvestigationState, window?: TimeWindow): LateralPath[] {
  const fullTimeline = state.forensicTimeline.map(upgradeForensicEvent);
  const hops: LateralHop[] = directedLateralHops(filterTimeline(fullTimeline, window), fullTimeline).map(
    ({ fromHost: _f, toHost: _t, severity: _s, ...hop }) => hop,
  );
  if (hops.length === 0) return [];

  // ── stitch hops into ordered chains ───────────────────────────────────────────────────
  // A chain is a sequence of hops where each hop's target feeds the next hop's source AND time
  // only moves forward (the next hop's arrival ≥ this hop's). At each step the longest available
  // continuation is taken — a fork picks ONE branch for the PRIMARY narrative. The onward branch a
  // fork discards is NOT lost: the path-cover pass below re-seeds it as its own path so its
  // destination host still appears in the output.
  //
  // COST: real cases run many parallel hops between the same hosts (one per shared account/hash),
  // so the hop graph is dense — a 12-host case produced ~1.2k hops. Picking the longest
  // continuation by RECURSIVELY COMPARING EVERY BRANCH is a full simple-path enumeration:
  // exponential, and it pegged a core indefinitely, blocking the event loop and hanging the whole
  // server on that case. Instead, the longest tail reachable from each hop is computed ONCE
  // (memoized, O(hops + edges)) and the chain is then walked greedily using those precomputed
  // lengths — polynomial, with the same "take the longest continuation" intent.
  const hopTime = (h: LateralHop) => timeOf(h.toTimestamp);
  const outByHost = new Map<string, LateralHop[]>();
  for (const hop of hops) {
    const arr = outByHost.get(hop.from) ?? [];
    arr.push(hop);
    outByHost.set(hop.from, arr);
  }
  for (const arr of outByHost.values()) arr.sort((a, b) => hopTime(a) - hopTime(b));

  // Longest tail reachable from each hop, ignoring the per-chain visited set (that constraint is
  // applied during the walk below). Hops sharing a timestamp can point at each other, so an
  // in-progress hop re-entered mid-computation is treated as a dead end rather than recursed into.
  // That makes this a lower bound on such cycles — it ranks candidate branches, it is not itself
  // the emitted chain, so an underestimate can only cost branch preference, never correctness.
  const tailLen = new Map<LateralHop, number>();
  const inProgress = new Set<LateralHop>();
  function bestTailLen(hop: LateralHop): number {
    const memo = tailLen.get(hop);
    if (memo !== undefined) return memo;
    if (inProgress.has(hop)) return 0;
    inProgress.add(hop);
    let best = 0;
    for (const next of outByHost.get(hop.to) ?? []) {
      if (hopTime(next) < hopTime(hop)) continue;
      const len = bestTailLen(next);
      if (len > best) best = len;
    }
    inProgress.delete(hop);
    tailLen.set(hop, 1 + best);
    return 1 + best;
  }

  // Greedy walk: at each step take the time-forward, not-yet-visited continuation with the longest
  // precomputed tail. Successors are pre-sorted by arrival, and the comparison is strict, so ties
  // keep the earliest hop — the same branch the old exhaustive version preferred.
  function extend(hop: LateralHop, visited: Set<string>): LateralHop[] {
    const chain = [hop];
    let current = hop;
    for (;;) {
      let best: LateralHop | undefined;
      let bestLen = -1;
      for (const next of outByHost.get(current.to) ?? []) {
        if (hopTime(next) < hopTime(current)) continue; // must not move backward in time
        if (visited.has(next.to)) continue; // cycle guard — no host twice in one chain
        const len = bestTailLen(next);
        if (len > bestLen) {
          best = next;
          bestLen = len;
        }
      }
      if (!best) return chain;
      chain.push(best);
      visited.add(best.to);
      current = best;
    }
  }

  // A hop is a chain ROOT when no other hop lands on its `from` host at/before this hop's own
  // start — i.e. this host wasn't already reached as a mid-chain pivot, so the chain genuinely
  // begins here rather than being a tail that a root's walk will already cover.
  const arrivalsByHost = new Map<string, number[]>();
  for (const hop of hops) {
    const arr = arrivalsByHost.get(hop.to) ?? [];
    arr.push(hopTime(hop));
    arrivalsByHost.set(hop.to, arr);
  }
  function isRoot(hop: LateralHop): boolean {
    const t = timeOf(hop.fromTimestamp);
    return !(arrivalsByHost.get(hop.from) ?? []).some((arrival) => arrival <= t);
  }

  const paths: LateralPath[] = [];
  const coveredHops = new Set<LateralHop>(); // hop identity — same objects flow through extend()
  const seenChains = new Set<string>(); // de-dup identical full chains (never emitted twice)
  let idx = 0;
  // A chain's identity is its ordered (from→to, rule, backing events) sequence — two chains that
  // trace the same hosts via different evidence are legitimately distinct and both kept.
  const chainKey = (chain: readonly LateralHop[]): string =>
    chain.map((h) => `${h.from}>${h.to}|${h.rule}|${h.eventIds.join(",")}`).join("::");
  function emit(chain: LateralHop[]): void {
    const key = chainKey(chain);
    if (seenChains.has(key)) return;
    seenChains.add(key);
    for (const h of chain) coveredHops.add(h);
    let confidence: Confidence = "high";
    for (const h of chain) confidence = weakerConf(confidence, h.confidence);
    paths.push({
      id: `lateral-path:${idx++}`,
      hostIds: [chain[0].from, ...chain.map((h) => h.to)],
      hops: chain,
      confidence,
      startTime: chain[0].fromTimestamp,
      endTime: chain[chain.length - 1].toTimestamp,
    });
  }

  // 1) Primary narratives: greedy longest-tail chains from each entry point (unchanged).
  for (const hop of hops) {
    if (!isRoot(hop)) continue;
    emit(extend(hop, new Set([hop.from, hop.to])));
  }

  // 2) Path cover: any hop not yet covered — e.g. the onward branch a fork's longest-tail walk
  // discarded, or a hop whose root was suppressed — seeds an ADDITIONAL chain, extended forward
  // with the SAME greedy logic. Each seed marks itself covered, so a single pass covers every hop;
  // total paths stay ≤ number of hops (no exponential blow-up). This is what guarantees no reached
  // host ever disappears from the output.
  for (const hop of hops) {
    if (coveredHops.has(hop)) continue;
    emit(extend(hop, new Set([hop.from, hop.to])));
  }

  // Longest chains first (the most complete reconstructed pivot sequence), then earliest-starting.
  paths.sort((a, b) => b.hops.length - a.hops.length || timeOf(a.startTime) - timeOf(b.startTime));
  return paths;
}

// One connected component of the evidence graph (rabbit-hole detection #13). `nodeIds`/`eventIds` are
// the nodes and their backing forensic events; `critHighCount` is how many of its nodes carry a
// Critical/High max-severity — the signal used to pick the MAIN component (the corroborated attack mass).
export interface GraphComponent {
  nodeIds: Set<string>;
  eventIds: Set<string>;
  nodeCount: number;
  critHighCount: number;
}

// Undirected connected components over the evidence graph's edges. A node with no edge is its own
// singleton component. Pure + deterministic. Union-find, so it's near-linear even on large graphs.
export function connectedComponents(graph: EvidenceGraph): GraphComponent[] {
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    let r = x;
    while (parent.get(r) !== r) r = parent.get(r)!;
    // path-compress
    let c = x;
    while (parent.get(c) !== r) {
      const n = parent.get(c)!;
      parent.set(c, r);
      c = n;
    }
    return r;
  };
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n] as const));
  for (const n of graph.nodes) parent.set(n.id, n.id);
  const union = (a: string, b: string): void => {
    if (!parent.has(a) || !parent.has(b)) return; // ignore an edge to a node that wasn't emitted
    const ra = find(a),
      rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  };
  for (const e of graph.edges) union(e.source, e.target);

  const byRoot = new Map<string, GraphComponent>();
  for (const n of graph.nodes) {
    const root = find(n.id);
    let comp = byRoot.get(root);
    if (!comp) {
      comp = { nodeIds: new Set(), eventIds: new Set(), nodeCount: 0, critHighCount: 0 };
      byRoot.set(root, comp);
    }
    comp.nodeIds.add(n.id);
    comp.nodeCount += 1;
    const sev = nodeById.get(n.id)!.maxSeverity;
    if (sev === "Critical" || sev === "High") comp.critHighCount += 1;
    for (const eid of n.eventIds) comp.eventIds.add(eid);
  }
  return [...byRoot.values()];
}

// The MAIN component (rabbit-hole detection #13): the connected component that holds the corroborated
// Critical/High attack mass — the most Crit/High nodes, tie-broken by most backing events then most
// nodes. This is the "known attack path"; a finding with zero linkage to it is a rabbit-hole candidate.
// Returns null when the graph has no edges/nodes (nothing to anchor relevance against).
export function mainComponent(graph: EvidenceGraph): GraphComponent | null {
  const comps = connectedComponents(graph);
  if (!comps.length) return null;
  return comps
    .slice()
    .sort(
      (a, b) =>
        b.critHighCount - a.critHighCount || b.eventIds.size - a.eventIds.size || b.nodeCount - a.nodeCount,
    )[0];
}

// The host labels in a component, for the "to link it, look for:" discriminator on a disconnected
// finding — the entities that, if they appeared in the finding's evidence, would tie it to the attack.
export function componentHostLabels(graph: EvidenceGraph, comp: GraphComponent, max = 4): string[] {
  const labels = graph.nodes.filter((n) => n.kind === "host" && comp.nodeIds.has(n.id)).map((n) => n.label);
  return [...new Set(labels)].sort().slice(0, max);
}
