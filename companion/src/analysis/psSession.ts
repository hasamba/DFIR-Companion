import { getPath, str } from "./siemFieldPick.js";
import type { PowerShellBlock } from "./canonicalPowerShell.js";

// The PowerShell session a Windows record ran in (#2078), read at import time from the PowerShell
// host process id the ENGINE stamped on the record (`Execution ProcessID`). See canonicalPowerShell.ts
// for why the process id, not the 4103 Host ID / Runspace ID pair, is the key. Pure.

type Row = Record<string, unknown>;

/**
 * Every spelling of the execution process id a record reaching mapWindows can carry, in read order:
 * the key the EVTX-XML / Chainsaw / Velociraptor flatteners write and NXLog (OTRF/Mordor) emits;
 * Winlogbeat's `winlog.process.pid` and its ECS copy; Chainsaw's flat hunt row; the evtx crate and
 * native System block, with or without an Event wrapper. `ProcessID` last: on a flat NXLog record it
 * is the same System value, and it is read on PowerShell channels only, whose EventData has no pid.
 */
const EXECUTION_PID_KEYS = [
  "ExecutionProcessID",
  "winlog.process.pid",
  "process.pid",
  "SystemData.Execution_attributes.ProcessID",
  "System.Execution.#attributes.ProcessID",
  "System.Execution.ProcessID",
  "Event.System.Execution.#attributes.ProcessID",
  "Event.System.Execution.ProcessID",
  "ProcessID",
] as const;

function positivePid(raw: unknown): number | undefined {
  const s = str(raw).trim();
  if (!/^\d+$/.test(s)) return undefined;
  const n = Number(s);
  return Number.isSafeInteger(n) && n > 0 ? n : undefined;
}

/** The execution process id of a System block (`Execution` in either spelling), raw; for flatteners. */
export function systemExecutionPid(system: Row): unknown {
  return getPath(system, "Execution.#attributes.ProcessID") ?? getPath(system, "Execution.ProcessID");
}

export interface PowerShellSessionRead {
  readonly block: PowerShellBlock;
  /** The record key the process id was read from: the canonical rawFieldMap citation. */
  readonly field: string;
}

/** The session of a PowerShell-channel record, or undefined when it carries no positive pid. */
export function powerShellSessionOf(rec: Row): PowerShellSessionRead | undefined {
  for (const key of EXECUTION_PID_KEYS) {
    const pid = positivePid(getPath(rec, key));
    if (pid === undefined) continue;
    return { block: { sessionId: `pid:${pid}`, processId: pid }, field: key };
  }
  return undefined;
}

export interface PowerShellCanonicalParts {
  fields: { powershell?: PowerShellBlock };
  rawFieldMap: Record<string, string[]>;
  derivationMap: Record<string, string>;
}

/**
 * The canonical-envelope fragments mapWindows spreads into createCanonicalEvent: the block and its
 * provenance. Empty off the PowerShell channel or without a pid.
 */
export function powerShellCanonicalParts(isPowerShellChannel: boolean, rec: Row): PowerShellCanonicalParts {
  const read = isPowerShellChannel ? powerShellSessionOf(rec) : undefined;
  if (!read) return { fields: {}, rawFieldMap: {}, derivationMap: {} };
  return {
    fields: { powershell: read.block },
    rawFieldMap: { "powershell.processId": [read.field] },
    derivationMap: {
      "powershell.sessionId":
        "powershell-session-v1: the PowerShell host process id the engine stamped (Execution ProcessID), as pid:<n>",
    },
  };
}
