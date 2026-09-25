// A process opening its own child at creation is not process access worth a finding (#1593).
//
// Sysmon EID 10 fires when a handle to a process is created, and CreateProcess itself creates one:
// the parent gets a full handle (0x1fffff) to the child it just started. On INC-2026-005 that single
// fact became 188 "Proc Access" rows graded High (ALL_ACCESS, a call trace with the parent's own
// .NET JIT frame unbacked) — `powershell.exe` opening every `cmd.exe`, `sc.exe` and `net.exe` it ran.
//
// The link is read from facts Sysmon wrote, never from image names: the EID 10's TargetProcessGUID
// must be a process whose own EID 1 names the EID 10's SourceProcessGUID as ParentProcessGuid. A
// Sysmon ProcessGuid is unique per process on a host, so an intruder's tool cannot claim a process
// it did not create, and `powershell.exe` opening `lsass.exe` never matches — lsass is wininit's.
//
// EVERY CLAIM HERE LOWERS A GRADE, so the bounds:
//
//   - The access must fall within CREATION_WINDOW_MS of the child's creation. The creation handle is
//     logged in the same instant (-2 ms … +105 ms on 005); a parent that opens its child AGAIN later
//     is a separate act and keeps its grade.
//   - Every EID 1 seen for the child GUID must name the SAME parent GUID. Conflicting records are
//     ambiguous and fail closed.
//   - Same host, on the short name and the record's own Computer (the collector ledger's host keys).
//   - A child that a remote thread (EID 8) or a tampering record (EID 25) in the same import names as
//     its target keeps the handle row at its grade, as the precursor of that sequence (Codex, review
//     of #1593). Evidence that arrives in a LATER import cannot reach back: the row is Info by then.
//   - A Critical is never lowered.
//
// What this does NOT say: the EID 10 is the handle the parent was always going to hold. A parent that
// then hollows or injects into its child writes through that handle, and the evidence of THAT is the
// child's own rows (EID 8 / EID 25 / the child's command line), each graded on its own. This rule
// only stops the creation handle itself from being read as credential access or injection.
//
// Order-independent like the collector ledger: `note` sees every process creation (the bulk driver
// primes them all before the first batch), `offer` holds EID 10 candidates, `resolve` judges them.

import type { MappedEvent } from "./siemImport.js";
import { getCI, str } from "./siemImport.js";
import { eventData, eventId } from "./veloDetectionNoise.js";
import { processGuid } from "./processAccess.js";
import { appendDerivedNote } from "./derivedNote.js";

type Row = Record<string, unknown>;

/** How far the access may sit from the child's creation and still be the creation handle. */
export const CREATION_WINDOW_MS = 1000;

export const OWN_CHILD_MARKER = "[own-child handle:";
export const OWN_CHILD_NOTE =
  "the parent opened its own child at creation — CreateProcess always returns a full handle to the child";
export const OWN_CHILD_AGG_SUFFIX = "|own-child";

const SYSMON_PROCESS_CREATE = 1;
const SYSMON_REMOTE_THREAD = 8;
const SYSMON_PROCESS_ACCESS = 10;
const SYSMON_PROCESS_TAMPERING = 25;

/** Is this raw record a remote thread or a tampering record — evidence against a child? */
export function isInjectionEvidenceRow(raw: Row): boolean {
  const eid = eventId(raw);
  return (eid === SYSMON_REMOTE_THREAD || eid === SYSMON_PROCESS_TAMPERING) && !!eventData(raw);
}

interface Creation {
  parent: string;
  at: number;
}

interface Candidate {
  m: MappedEvent;
  hosts: readonly string[];
  source: string;
  target: string;
  at: number;
}

function field(ed: Row, key: string): string {
  return processGuid(str(getCI(ed, key)));
}

export class ParentChildAccessLedger {
  // host|childGuid → every creation record seen for that child.
  private readonly creations = new Map<string, Creation[]>();
  // host|guid of every process a remote thread (EID 8) or tampering record (EID 25) names as target.
  private readonly injected = new Set<string>();
  private pending: Candidate[] = [];

  /** Record a Sysmon process creation (EID 1), remote thread (8) or tampering (25). Others are ignored. */
  note(raw: Row, m: MappedEvent, hosts: readonly string[]): void {
    const eid = eventId(raw);
    const ed = eventData(raw);
    if (!ed) return;
    if (eid === SYSMON_REMOTE_THREAD || eid === SYSMON_PROCESS_TAMPERING) {
      const target = field(ed, eid === SYSMON_REMOTE_THREAD ? "TargetProcessGuid" : "ProcessGuid");
      if (target) for (const h of hosts) this.injected.add(`${h}|${target}`);
      return;
    }
    if (eid !== SYSMON_PROCESS_CREATE) return;
    const child = field(ed, "ProcessGuid");
    const parent = field(ed, "ParentProcessGuid");
    const at = Date.parse(m.timestamp ?? "");
    if (!child || !parent || !Number.isFinite(at)) return;
    for (const h of hosts) {
      const key = `${h}|${child}`;
      const list = this.creations.get(key);
      if (list) list.push({ parent, at });
      else this.creations.set(key, [{ parent, at }]);
    }
  }

  /** Hold a Sysmon process access (EID 10) for `resolve`. Any other row is ignored. */
  offer(raw: Row, m: MappedEvent, hosts: readonly string[]): void {
    if (eventId(raw) !== SYSMON_PROCESS_ACCESS || m.origin === "collector") return;
    const ed = eventData(raw);
    if (!ed) return;
    const source = field(ed, "SourceProcessGUID");
    const target = field(ed, "TargetProcessGUID");
    const at = Date.parse(m.timestamp ?? "");
    if (!source || !target || source === target || !Number.isFinite(at) || hosts.length === 0) return;
    this.pending.push({ m, hosts, source, target, at });
  }

  /** Judge every held candidate. Drains the candidates; the creations are kept. */
  resolve(): void {
    const pending = this.pending;
    this.pending = [];
    for (const c of pending) if (c.m.severity !== "Critical" && this.isOwnChildAtCreation(c)) demote(c.m);
  }

  private isOwnChildAtCreation(c: Candidate): boolean {
    // A child something threaded into or tampered with keeps the handle row as its precursor.
    if (c.hosts.some((h) => this.injected.has(`${h}|${c.target}`))) return false;
    const records = c.hosts.flatMap((h) => this.creations.get(`${h}|${c.target}`) ?? []);
    if (records.length === 0) return false;
    if (records.some((r) => r.parent !== c.source)) return false; // ambiguous parentage fails closed
    return records.some((r) => r.parent === c.source && Math.abs(c.at - r.at) <= CREATION_WINDOW_MS);
  }
}

function demote(m: MappedEvent): void {
  m.severity = "Info";
  if (!m.description.includes(OWN_CHILD_MARKER))
    m.description = appendDerivedNote(m.description, OWN_CHILD_MARKER, OWN_CHILD_NOTE);
  if (!m.aggKey.endsWith(OWN_CHILD_AGG_SUFFIX)) m.aggKey = `${m.aggKey}${OWN_CHILD_AGG_SUFFIX}`;
}
