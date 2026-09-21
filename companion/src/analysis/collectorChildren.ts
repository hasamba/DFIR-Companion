// From the collector's spawn to everything that process did (#1500).
//
// Rule 2c (collectorDeployment.ts) grades the SYSTEM powershell.exe the Velociraptor client spawns
// for Windows.Forensics.PersistenceSniper; isDetectionToolScript grades the script blocks that name
// the module's path; collectorLineage.ts grades the path-less blocks by process id (#1488). What
// none of them reached on INC-2026-033 is what that process then DID: the `Add-Type` compile
// artefacts it wrote to `C:\Windows\SystemTemp\` (Sysmon EID 11, "Potential Binary Or Script
// Dropper"), the `net.exe users` it ran (EID 1, "Local Accounts Discovery") and the `net1.exe`
// under that. Synthesis read them as reflective tooling and a second discovery wave.
//
// This ledger wraps CollectorSpawnLineage and follows the spawn one step further, on facts Sysmon
// wrote about the processes, not strings the processes chose:
//
//   - A Sysmon ProcessGuid is unique per process on a host, so a child whose ParentProcessGuid is a
//     claimed process, or a file whose ProcessGuid is one, belongs to it — no pid-reuse window is
//     needed, only "created at or after its owner". A claimed child's own GUID joins the set, so a
//     grandchild (`net1` under `net`) is reached, to CHILD_DEPTH.
//   - Without GUIDs (a 4688-style export) the claim falls back to the parent PID inside the spawn's
//     LIFETIME as collectorLineage.ts bounds it. That reaches a direct child or file only: a
//     pid-claimed child does not vouch for its own children, because nothing bounds ITS lifetime.
//   - The row must run as SYSTEM (the Sysmon `User` field), the identity the client runs artifacts
//     under and the one an intruder must already hold to forge a parent (rule 2c's argument).
//   - Same host, on the short name; a row before its owner was created; a Critical — all refused.
//
// EVERY CLAIM HERE LOWERS A GRADE. A claimed row goes to Info with `origin: "collector"` (the tagger
// then leaves its grade alone) and gets `|collector` on its aggKey, so a collector `net.exe users`
// never shares a group with an intruder's identical command — the group would otherwise carry
// whichever origin arrived first (eventAggregate.ts).
//
// Order-independent, like collectorLineage: `offer` holds candidates until `resolve`, because a
// hunt lists the PowerShell log before Sysmon. The bulk driver primes the ledger with every
// process creation on its evidence-only pass and then resolves per batch.

import { getCI, parsePid, str, type MappedEvent } from "./siemImport.js";
import { CollectorSpawnLineage, SPAWNED_SCRIPT_NOTE } from "./collectorLineage.js";
import {
  isCollectorSpawn,
  isForeignDestination,
  isProcessRow,
  loadCollectorInfrastructure,
  type CollectorInfrastructure,
} from "./collectorDeployment.js";
import {
  demoteDetectionToolScript,
  engineScriptPath,
  eventData,
  eventId,
  gradeScriptAsCollector,
  isSystemScriptRow,
  scriptHostPid,
} from "./veloDetectionNoise.js";
import { processGuid } from "./processAccess.js";
import { recordComputer, shortHostName } from "./hostIdentity.js";

type Row = Record<string, unknown>;

export const SPAWNED_CHILD_NOTE =
  " [DFIR collector footprint — child process / file of the process the Velociraptor client spawned]";

/** How many generations below the spawn a GUID chain is followed (spawn → net → net1 is two). */
export const CHILD_DEPTH = 4;
const COLLECTOR_AGG_SUFFIX = "|collector";
const SYSMON_PROCESS_CREATE = 1;
const SYSMON_FILE_CREATE = 11;
const SYSTEM_ACCOUNT = /^(?:NT AUTHORITY|WORKGROUP)\\SYSTEM$/i;

interface Candidate {
  kind: "script" | "process" | "file";
  m: MappedEvent;
  host: string; // short host name, as resolved
  hosts: string[]; // the resolved name and the record's own Computer — see hostKeys
  at: number; // epoch ms
  guid: string; // the row's own process GUID ("" when absent)
  parentGuid: string; // EID 1 only
  pid?: number; // the acting process (EID 11) or the script host (4104)
  parentPid?: number; // EID 1 only
}

/** Is this Sysmon record a process creation (EID 1)? The bulk driver's evidence pass keys on it. */
export function isProcessCreateRow(raw: Row): boolean {
  return eventId(raw) === SYSMON_PROCESS_CREATE && !!eventData(raw);
}

function hostKey(m: MappedEvent): string {
  return shortHostName(m.asset ?? "");
}

// The names a row can be filed under: the host the importer resolved AND the name the record itself
// carries. A renamed lab box (#1489) writes its old name into every record until the rename, and a
// bulk import may resolve the spawn before the rename evidence is read and the child after it — so
// a claim is stored and looked up under both, and two spellings of one machine still meet.
function hostKeys(raw: Row, m: MappedEvent): string[] {
  return [...new Set([hostKey(m), shortHostName(recordComputer(raw))].filter(Boolean))];
}

function ownGuid(raw: Row, m: MappedEvent): string {
  return m.canonical?.process?.id || processGuid(str(getCI(eventData(raw) ?? {}, "ProcessGuid")));
}

function ranAsSystem(raw: Row, m: MappedEvent): boolean {
  const user = m.canonical?.actor?.name || str(getCI(eventData(raw) ?? {}, "User"));
  return SYSTEM_ACCOUNT.test(user.trim());
}

// The candidate a row makes, or null when the row is nothing this ledger judges.
function candidate(raw: Row, m: MappedEvent): Candidate | null {
  const host = hostKey(m);
  const hosts = hostKeys(raw, m);
  const at = Date.parse(m.timestamp ?? "");
  if (!host || !Number.isFinite(at)) return null;
  const ed = eventData(raw);
  const eid = eventId(raw);
  if (isSystemScriptRow(raw) && !engineScriptPath(raw))
    return { kind: "script", m, host, hosts, at, guid: "", parentGuid: "", pid: scriptHostPid(raw) };
  if (!ed || !ranAsSystem(raw, m)) return null;
  if (eid === SYSMON_PROCESS_CREATE && isProcessRow(m))
    return {
      kind: "process",
      m,
      host,
      hosts,
      at,
      guid: ownGuid(raw, m),
      parentGuid: processGuid(str(getCI(ed, "ParentProcessGuid"))),
      parentPid: parsePid(str(getCI(ed, "ParentProcessId"))),
    };
  if (eid === SYSMON_FILE_CREATE && str(getCI(ed, "TargetFilename")).trim())
    return {
      kind: "file",
      m,
      host,
      hosts,
      at,
      guid: ownGuid(raw, m),
      parentGuid: "",
      pid: parsePid(str(getCI(ed, "ProcessId"))),
    };
  return null;
}

export class CollectorFootprintLedger {
  private readonly lineage: CollectorSpawnLineage;
  // host|guid → epoch ms the process was created: the spawns, and every child claimed through one.
  private readonly claimed = new Map<string, number>();
  private pending: Candidate[] = [];

  constructor(private readonly infra: CollectorInfrastructure = loadCollectorInfrastructure()) {
    this.lineage = new CollectorSpawnLineage(infra);
  }

  /**
   * The evidence-only pass of the bulk driver: record what a process-creation row proves (a spawn,
   * a pid lifetime) and hold nothing. `offer` on the same row later is harmless.
   */
  prime(raw: Row, events: readonly (MappedEvent | null)[]): void {
    for (const m of events) if (m) this.noteProcess(raw, m);
  }

  /** Offer ONE row's mapped events: grade the tool-tree scripts now, hold the rest for `resolve`. */
  offer(raw: Row, events: readonly (MappedEvent | null)[]): void {
    demoteDetectionToolScript(raw, events);
    for (const m of events) {
      if (!m) continue;
      this.noteProcess(raw, m);
      if (m.origin === "collector") continue;
      const c = candidate(raw, m);
      if (c) this.pending.push(c);
    }
  }

  // A spawn seeds the claimed set — unless it is Critical. Rule 2c refuses to lower a Critical spawn,
  // and a process the pipeline still calls Critical must not vouch for what it went on to do.
  private noteProcess(raw: Row, m: MappedEvent): void {
    this.lineage.note(m);
    if (m.severity === "Critical" || !isProcessRow(m) || !isCollectorSpawn(m)) return;
    if (isForeignDestination(m, this.infra)) return;
    const at = Date.parse(m.timestamp ?? "");
    if (Number.isFinite(at)) this.remember(hostKeys(raw, m), ownGuid(raw, m), at);
  }

  private remember(hosts: readonly string[], guid: string, at: number): void {
    if (guid) for (const h of hosts) this.claimed.set(`${h}|${guid}`, at);
  }

  /** Judge every held candidate. Drains the candidates; the spawns and claims are kept. */
  resolve(): void {
    const pending = this.pending;
    this.pending = [];
    for (const c of pending)
      if (c.kind === "script" && c.pid !== undefined && this.lineage.claims(c.host, c.pid, c.m.timestamp))
        gradeScriptAsCollector(c.m, SPAWNED_SCRIPT_NOTE);
    this.resolveProcesses(pending.filter((c) => c.kind === "process").sort((a, b) => a.at - b.at));
    for (const c of pending) if (c.kind === "file" && this.owns(c, c.guid, c.pid)) claim(c.m);
  }

  // Fixed point over the time-ordered process rows: a claimed child vouches for its own children on
  // the next round, to CHILD_DEPTH generations.
  private resolveProcesses(procs: Candidate[]): void {
    let open = procs;
    for (let depth = 0; depth < CHILD_DEPTH && open.length > 0; depth++) {
      const next: Candidate[] = [];
      for (const c of open) {
        if (!this.owns(c, c.parentGuid, c.parentPid)) {
          next.push(c);
          continue;
        }
        // A GUID chain continues through a claimed child; a pid claim, or a Critical row claim()
        // refused, vouches for nothing below it.
        if (claim(c.m) && c.parentGuid) this.remember(c.hosts, c.guid, c.at);
      }
      if (next.length === open.length) return;
      open = next;
    }
  }

  // Does a claimed process own this candidate? By GUID when the row names one (no fallback — a GUID
  // that is not claimed IS the answer), on any of the row's host names, created at or after the
  // owner; else by the spawn's pid inside its lifetime (collectorLineage.ts).
  private owns(c: Candidate, guid: string, pid: number | undefined): boolean {
    if (guid)
      return c.hosts.some((h) => {
        const born = this.claimed.get(`${h}|${guid}`);
        return born !== undefined && c.at >= born;
      });
    return pid !== undefined && this.lineage.claims(c.host, pid, c.m.timestamp);
  }
}

// Info, the collector origin, the note, never lowering a Critical — and a partition of its own in
// the aggregator, so an intruder's identical command never inherits the collector's grade. True when
// the row was claimed.
function claim(m: MappedEvent): boolean {
  if (m.severity === "Critical") return false;
  gradeScriptAsCollector(m, SPAWNED_CHILD_NOTE);
  if (!m.aggKey.endsWith(COLLECTOR_AGG_SUFFIX)) m.aggKey = `${m.aggKey}${COLLECTOR_AGG_SUFFIX}`;
  return true;
}
