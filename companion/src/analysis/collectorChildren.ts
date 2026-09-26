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
// The same ledger links the collector's RUNSPACE (#1555): a 4103 / 800 of the signed BitsTransfer
// module PersistenceSniper auto-loads, and the session's 400 engine start, carry no Tools-tree path
// but the same engine-written Host ID + Runspace ID as a record isDetectionToolScript already proved.
// Only a proven row seeds a runspace, and a Critical one does not (veloDetectionNoise.ts, "The
// runspace link").
//
// Order-independent, like collectorLineage: `offer` holds candidates until `resolve`, because a
// hunt lists the PowerShell log before Sysmon. The bulk driver primes the ledger with every
// process creation and every Tools-tree script record on its evidence-only pass and then resolves
// per batch.
//
// The same seam carries two cross-row rules about ordinary Windows behaviour, not the collector
// (#1593): a parent's handle to its own child at creation (processParentage.ts) and an AppX package
// update's firewall rule swap (appxFirewallChurn.ts). They run through OsBehaviourLedger
// (osBehaviourRules.ts), which the native Hayabusa and Windows Event XML importers share (#1621).

import { getCI, parsePid, str, type MappedEvent } from "./siemImport.js";
import { CollectorSpawnLineage, SPAWNED_SCRIPT_NOTE } from "./collectorLineage.js";
import {
  isCollectorKlistScript,
  isCollectorSpawn,
  isForeignDestination,
  isKlistSessionCommand,
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
  isDetectionToolScript,
  isRunspaceLinkCandidate,
  isSystemScriptRow,
  scriptHostPid,
  scriptRunspace,
} from "./veloDetectionNoise.js";
import { processGuid } from "./processAccess.js";
import { shortHostName } from "./hostIdentity.js";
import { isInjectionEvidenceRow } from "./processParentage.js";
import { isAppxFirewallRow } from "./appxFirewallChurn.js";
import { ledgerHostKeys as hostKeys, OsBehaviourLedger } from "./osBehaviourRules.js";

type Row = Record<string, unknown>;

export const SPAWNED_CHILD_NOTE =
  " [DFIR collector footprint — child process / file of the process the Velociraptor client spawned]";

export const RUNSPACE_SCRIPT_NOTE =
  " [DFIR collector footprint — PowerShell session the Velociraptor client ran from its tool tree]";

/** How many generations below the spawn a GUID chain is followed (spawn → net → net1 is two). */
export const CHILD_DEPTH = 4;
const COLLECTOR_AGG_SUFFIX = "|collector";
const SYSMON_PROCESS_CREATE = 1;
const SYSMON_FILE_CREATE = 11;
const SYSTEM_ACCOUNT = /^(?:NT AUTHORITY|WORKGROUP)\\SYSTEM$/i;

interface Candidate {
  kind: "script" | "process" | "file" | "runspace";
  m: MappedEvent;
  host: string; // short host name, as resolved
  hosts: string[]; // the resolved name and the record's own Computer — see hostKeys
  at: number; // epoch ms
  guid: string; // the row's own process GUID ("" when absent)
  parentGuid: string; // EID 1 only
  pid?: number; // the acting process (EID 11) or the script host (4104)
  parentPid?: number; // EID 1 only
  runspace?: string; // "runspace" only: hostId|runspaceId (scriptRunspace)
}

/** Is this Sysmon record a process creation (EID 1)? The bulk driver's evidence pass keys on it. */
export function isProcessCreateRow(raw: Row): boolean {
  return eventId(raw) === SYSMON_PROCESS_CREATE && !!eventData(raw);
}

/**
 * Does this row carry evidence the ledger must see before any batch resolves: a process creation
 * (a spawn, or a child whose parent may open it — #1593), a Tools-tree script record (a runspace
 * seed, #1555), a remote thread / tampering record (it keeps a child's handle row, #1593), or an
 * AppX firewall rule change (one half of a package update, #1593)? The bulk
 * evidence pass primes on it.
 */
export function isCollectorEvidenceRow(raw: Row): boolean {
  return (
    isProcessCreateRow(raw) ||
    isDetectionToolScript(raw) ||
    isAppxFirewallRow(raw) ||
    isInjectionEvidenceRow(raw)
  );
}

function hostKey(m: MappedEvent): string {
  return shortHostName(m.asset ?? "");
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
  const runspace = isRunspaceLinkCandidate(raw) ? scriptRunspace(raw) : "";
  if (runspace) return { kind: "runspace", m, host, hosts, at, guid: "", parentGuid: "", runspace };
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
  // host|guid → birth of the client's klist collection script and every klist command claimed under it
  // (#1699). Separate from `claimed`: it vouches only for rows isKlistSessionCommand accepts.
  private readonly klistOwners = new Map<string, number>();
  // host|hostId|runspaceId of every PowerShell session a Tools-tree record proved (#1555).
  private readonly runspaces = new Set<string>();
  private pending: Candidate[] = [];
  private readonly os = new OsBehaviourLedger();

  constructor(private readonly infra: CollectorInfrastructure = loadCollectorInfrastructure()) {
    this.lineage = new CollectorSpawnLineage(infra);
  }

  /**
   * The evidence-only pass of the bulk driver: record what a process-creation row proves (a spawn,
   * a pid lifetime) and hold nothing. `offer` on the same row later is harmless.
   */
  prime(raw: Row, events: readonly (MappedEvent | null)[]): void {
    for (const m of events) if (m) this.noteProcess(raw, m);
    this.noteRunspace(raw, events);
    this.os.note(raw, events); // the OS-behaviour facts (#1593): process creations, firewall changes
  }

  /** Offer ONE row's mapped events: grade the tool-tree scripts now, hold the rest for `resolve`. */
  offer(raw: Row, events: readonly (MappedEvent | null)[]): void {
    demoteDetectionToolScript(raw, events);
    this.noteRunspace(raw, events);
    this.os.note(raw, events);
    this.os.offer(raw, events);
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
    if (m.severity === "Critical" || !isProcessRow(m) || isForeignDestination(m, this.infra)) return;
    const at = Date.parse(m.timestamp ?? "");
    if (!Number.isFinite(at)) return;
    if (isCollectorSpawn(m)) this.remember(hostKeys(raw, m), ownGuid(raw, m), at);
    else if (isCollectorKlistScript(m))
      this.remember(hostKeys(raw, m), ownGuid(raw, m), at, this.klistOwners);
  }

  // A Tools-tree record seeds its runspace — only once it was actually graded the collector's. A
  // Critical keeps its unset origin (gradeScriptAsCollector), and like a Critical spawn it must not
  // vouch for the rest of its session.
  private noteRunspace(raw: Row, events: readonly (MappedEvent | null)[]): void {
    if (!isDetectionToolScript(raw)) return;
    const runspace = scriptRunspace(raw);
    if (!runspace) return;
    for (const m of events)
      if (m?.origin === "collector") for (const h of hostKeys(raw, m)) this.runspaces.add(`${h}|${runspace}`);
  }

  private remember(hosts: readonly string[], guid: string, at: number, into = this.claimed): void {
    if (guid) for (const h of hosts) into.set(`${h}|${guid}`, at);
  }

  /** Judge every held candidate. Drains the candidates; the spawns and claims are kept. */
  resolve(): void {
    const pending = this.pending;
    this.pending = [];
    for (const c of pending)
      if (c.kind === "script" && c.pid !== undefined && this.lineage.claims(c.host, c.pid, c.m.timestamp))
        gradeScriptAsCollector(c.m, SPAWNED_SCRIPT_NOTE);
    for (const c of pending)
      if (c.kind === "runspace" && c.hosts.some((h) => this.runspaces.has(`${h}|${c.runspace}`)))
        claimSession(c.m);
    this.resolveProcesses(pending.filter((c) => c.kind === "process").sort((a, b) => a.at - b.at));
    for (const c of pending) if (c.kind === "file" && this.owns(c, c.guid, c.pid)) claim(c.m);
    this.os.resolve();
  }

  // Fixed point over the time-ordered process rows: a claimed child vouches for its own children on
  // the next round, to CHILD_DEPTH generations.
  private resolveProcesses(procs: Candidate[]): void {
    let open = procs;
    for (let depth = 0; depth < CHILD_DEPTH && open.length > 0; depth++) {
      const next: Candidate[] = [];
      for (const c of open) {
        if (this.ownsKlist(c)) {
          if (claim(c.m)) this.remember(c.hosts, c.guid, c.at, this.klistOwners);
          continue;
        }
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

  // Is this an exact klist command whose parent GUID is the klist collection or a klist command claimed
  // under it (#1699)? GUID only — no pid fallback — and created at or after its owner.
  private ownsKlist(c: Candidate): boolean {
    if (!c.parentGuid || !isKlistSessionCommand(c.m)) return false;
    return c.hosts.some((h) => {
      const born = this.klistOwners.get(`${h}|${c.parentGuid}`);
      return born !== undefined && c.at >= born;
    });
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

// A runspace-linked record: graded like a script, and partitioned like a child. Any script can
// import BitsTransfer, so an intruder's `Start-BitsTransfer` logs the very 4103 / 800 text the
// collector's session did; sharing a group with it would fold the intruder's record into Info.
function claimSession(m: MappedEvent): void {
  gradeScriptAsCollector(m, RUNSPACE_SCRIPT_NOTE);
  if (m.origin === "collector" && !m.aggKey.endsWith(COLLECTOR_AGG_SUFFIX))
    m.aggKey = `${m.aggKey}${COLLECTOR_AGG_SUFFIX}`;
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
