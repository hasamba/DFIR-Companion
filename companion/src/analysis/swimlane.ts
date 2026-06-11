import type { ForensicEvent, Severity } from "./stateTypes.js";
import { extractAccounts } from "./assetGraph.js";
import { tacticForTechniques } from "../integrations/iris/mitreTactics.js";

export type SwimlaneGroupBy = "asset" | "severity" | "tactic";

export interface SwimlaneEvent {
  id: string;
  timestamp: string;
  endTimestamp?: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  relatedFindingIds: string[];
  sources?: string[];
  count?: number;
}

export interface SwimlaneLane {
  id: string;       // e.g. "host:win01" | "sev:Critical" | "tac:Execution" | "unassigned"
  label: string;
  type: "host" | "account" | "severity" | "tactic" | "unassigned";
  events: SwimlaneEvent[];
}

export interface SwimlaneData {
  lanes: SwimlaneLane[];
  minTime: string | null;
  maxTime: string | null;
  totalEvents: number;
}

const SEV_ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

const TACTIC_ORDER = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact",
  "Uncategorized",
];

function toSwimlaneEvent(e: ForensicEvent): SwimlaneEvent {
  return {
    id: e.id,
    timestamp: e.timestamp,
    endTimestamp: e.endTimestamp,
    description: e.description,
    severity: e.severity,
    mitreTechniques: e.mitreTechniques,
    relatedFindingIds: e.relatedFindingIds,
    sources: e.sources,
    count: e.count,
  };
}

// Group a filtered forensic timeline into swimlane lanes for chart rendering.
// - groupBy "asset"    (default): one lane per host (event.asset) or account (from description),
//                                 unassigned lane for events with no host and no account.
// - groupBy "severity": one lane per severity level (Critical → Info), only populated ones.
// - groupBy "tactic":  one lane per ATT&CK tactic in kill-chain order, Uncategorized last.
//
// An event's primary lane is determined by the FIRST match:
//   asset mode:    event.asset (host) > first extracted account > "Unassigned"
//   severity mode: event.severity
//   tactic mode:   dominant tactic (tacticForTechniques) || "Uncategorized"
//
// Only events with a valid ISO timestamp participate (undated events are excluded).
export function buildSwimlaneData(
  events: ForensicEvent[],
  groupBy: SwimlaneGroupBy = "asset",
): SwimlaneData {
  const dated = events.filter((e) => !Number.isNaN(Date.parse(e.timestamp)));

  const laneMap = new Map<string, SwimlaneLane>();

  function ensureLane(id: string, label: string, type: SwimlaneLane["type"]): SwimlaneLane {
    let lane = laneMap.get(id);
    if (!lane) {
      lane = { id, label, type, events: [] };
      laneMap.set(id, lane);
    }
    return lane;
  }

  for (const e of dated) {
    const ev = toSwimlaneEvent(e);
    if (groupBy === "severity") {
      ensureLane(`sev:${e.severity}`, e.severity, "severity").events.push(ev);
    } else if (groupBy === "tactic") {
      const tactic = tacticForTechniques(e.mitreTechniques, e.description) ?? "Uncategorized";
      ensureLane(`tac:${tactic}`, tactic, "tactic").events.push(ev);
    } else {
      // asset grouping: host wins over account; if neither, unassigned
      if (e.asset && e.asset.trim()) {
        const name = e.asset.trim();
        ensureLane(`host:${name.toLowerCase()}`, name, "host").events.push(ev);
      } else {
        const accounts = extractAccounts(e.description);
        if (accounts.length > 0) {
          ensureLane(`account:${accounts[0].toLowerCase()}`, accounts[0], "account").events.push(ev);
        } else {
          ensureLane("unassigned", "Unassigned", "unassigned").events.push(ev);
        }
      }
    }
  }

  // Sort lanes into a logical order
  let lanes: SwimlaneLane[];
  if (groupBy === "severity") {
    lanes = SEV_ORDER.map((s) => laneMap.get(`sev:${s}`)).filter((l): l is SwimlaneLane => !!l);
  } else if (groupBy === "tactic") {
    lanes = TACTIC_ORDER.map((t) => laneMap.get(`tac:${t}`)).filter((l): l is SwimlaneLane => !!l);
  } else {
    const hosts = [...laneMap.values()]
      .filter((l) => l.type === "host")
      .sort((a, b) => a.label.localeCompare(b.label));
    const accounts = [...laneMap.values()]
      .filter((l) => l.type === "account")
      .sort((a, b) => a.label.localeCompare(b.label));
    const unassigned = laneMap.get("unassigned");
    lanes = [...hosts, ...accounts, ...(unassigned ? [unassigned] : [])];
  }

  // Time bounds
  let minMs = Infinity, maxMs = -Infinity;
  for (const e of dated) {
    const t = Date.parse(e.timestamp);
    if (t < minMs) minMs = t;
    if (t > maxMs) maxMs = t;
    if (e.endTimestamp) {
      const end = Date.parse(e.endTimestamp);
      if (!Number.isNaN(end) && end > maxMs) maxMs = end;
    }
  }

  return {
    lanes,
    minTime: dated.length > 0 ? new Date(minMs).toISOString() : null,
    maxTime: dated.length > 0 ? new Date(maxMs).toISOString() : null,
    totalEvents: dated.length,
  };
}
