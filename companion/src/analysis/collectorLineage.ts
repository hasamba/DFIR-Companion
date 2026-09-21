// From the collector's spawn to the script blocks that process logged (#1488).
//
// Windows.Forensics.PersistenceSniper makes the Velociraptor client spawn a SYSTEM powershell.exe
// that imports a module from the collector's tool tree. Rule 2c (collectorDeployment.ts) grades
// that launch as the collector's; isDetectionToolScript (veloDetectionNoise.ts) grades the script
// blocks that name the module's path. What neither reaches is a block the same process compiled
// from its COMMAND LINE — `Find-AllPersistence …` — which carries no path at all, and on INC-2026-032
// seven of those stayed Medium ("Powershell Create Scheduled Task") beside a launch graded Info.
//
// The record does carry one more fact the engine wrote: its `Execution ProcessID`, the PowerShell
// host process — the same number Sysmon recorded as `ProcessId` on the spawn. So this ledger keeps
// the (host, pid, time) of every row rule 2c accepted, and answers whether a later SYSTEM script row
// with that pid on that host was logged while the spawned process was alive.
//
// EVERY CLAIM HERE LOWERS A GRADE, so the bound matters more than the match:
//
//   - The spawn must pass rule 2c in full — SYSTEM, parent = the collector exe under its install
//     root, Tools path on the command line — and must not be vetoed by a foreign destination
//     (#1486). A pid alone is a number any process can have.
//   - The claim is bounded by the spawned process's LIFETIME as the file shows it: it starts at the
//     spawn, ends at the first later process creation on the same host that reuses the pid
//     (whatever that process was — Windows recycles pids, and the next holder is somebody else),
//     and is capped at CLAIM_WINDOW_MS regardless, because a file that lacks the reuse row cannot
//     prove the process was still ours. That cap is the load-bearing bound on a Chainsaw HUNT file,
//     which carries matched detections only, so an ordinary pid reuse is usually not in it (Codex,
//     review of #1488); a raw evtx dump routed here carries every creation and ends the claim
//     exactly. PersistenceSniper ran for 30 s on 032; 5 minutes covers a slow run and is a short
//     time for a SYSTEM intruder — who must already be SYSTEM to log the block — to churn the pid
//     back, for a prize bounded at quieting one non-Critical row.
//   - A row with no host, no time, or no valid pid anchors to nothing and is never claimed. Hosts
//     compare on the short name resolveRowHost compares on, so an FQDN and a NetBIOS spelling of
//     one machine meet, and two machines never do on a case difference.
//   - The caller (chainsawImport.ts) still requires the script row to be SYSTEM and PATH-LESS: a row
//     that names a path is judged by that path (isDetectionToolScript), and a path outside the tool
//     tree keeps its grade whatever pid it carries.
//
// Order-independent: `note` and `claims` may interleave in any order, because a directory hunt lists
// the PowerShell log before Sysmon's. The importer therefore holds candidate rows until it has seen
// the whole file, then asks.

import { parsePid, type MappedEvent } from "./siemImport.js";
import {
  isCollectorSpawn,
  isForeignDestination,
  isProcessRow,
  type CollectorInfrastructure,
} from "./collectorDeployment.js";
import { shortHostName } from "./hostIdentity.js";

/** The longest a spawn vouches for its pid when the file shows no later reuse of it. */
export const CLAIM_WINDOW_MS = 5 * 60 * 1000;

export const SPAWNED_SCRIPT_NOTE =
  " [DFIR collector footprint — script block of the process the Velociraptor client spawned]";

// Epoch ms of an importer timestamp, or undefined when it does not parse. A missing time fails closed.
function epoch(timestamp: string): number | undefined {
  const t = Date.parse((timestamp ?? "").trim());
  return Number.isFinite(t) ? t : undefined;
}

function hostKey(host: string): string {
  return shortHostName(host ?? "");
}

export class CollectorSpawnLineage {
  // host|pid → epoch ms of every collector spawn with that pid on that host.
  private readonly spawns = new Map<string, number[]>();
  // host|pid → epoch ms of every process creation with that pid on that host (the spawns included).
  private readonly creations = new Map<string, number[]>();

  constructor(private readonly infra: CollectorInfrastructure) {}

  /** Offer ONE mapped row. Only a process creation with a host, a pid and a time is recorded. */
  note(m: MappedEvent): void {
    if (!isProcessRow(m)) return;
    const pid = parsePid(String(m.pid ?? ""));
    const at = epoch(m.timestamp);
    const host = hostKey(m.asset ?? "");
    if (pid === undefined || at === undefined || !host) return;
    const key = `${host}|${pid}`;
    push(this.creations, key, at);
    if (isCollectorSpawn(m) && !isForeignDestination(m, this.infra)) push(this.spawns, key, at);
  }

  /**
   * Was a script row logged at `timestamp`, by the process `pid` on `host`, while a collector-spawned
   * process held that pid? True only inside [spawn, min(spawn + window, next creation of the pid)).
   */
  claims(host: string, pid: number, timestamp: string): boolean {
    const at = epoch(timestamp);
    const h = hostKey(host);
    if (at === undefined || !h || !Number.isInteger(pid) || pid <= 0) return false;
    const key = `${h}|${pid}`;
    const spawns = this.spawns.get(key);
    if (!spawns) return false;
    const creations = this.creations.get(key) ?? [];
    return spawns.some((spawn) => {
      if (at < spawn || at > spawn + CLAIM_WINDOW_MS) return false;
      // The first creation after the spawn ends its lifetime; a row at or past it is the next holder's.
      return !creations.some((c) => c > spawn && c <= at);
    });
  }
}

function push(map: Map<string, number[]>, key: string, at: number): void {
  const cur = map.get(key);
  if (cur) cur.push(at);
  else map.set(key, [at]);
}
