// Lateral movement (T1021.001) from the Custom.DFIR.RDPLateralMovementDetection artifact.
//
// That artifact records EID 4648 "explicit credential" logons — an account presenting DIFFERENT
// credentials to reach another machine, the classic RDP/`runas`-then-pivot signature. But it also
// captures the LOCAL boot noise Windows raises as `UMFD-0` / `DWM-*` to `localhost`, so grading every
// row would be almost all false positives. The signal is a REMOTE target with a real initiating
// user: that pair is what an operator moving with stolen credentials leaves, and neither half is a
// name the local machine writes for itself. A local/boot row returns null (stays Info).
//
// Kept out of velociraptorImport (frozen at the size ledger); called from mapGeneric next to the
// ransomware signal, since these rows otherwise land in the generic mapper as Info.

import type { Severity } from "./stateTypes.js";
import { getCI, str } from "./siemImport.js";

type Row = Record<string, unknown>;

export interface RdpLateralSignal {
  severity: Severity;
  mitre: string[];
  note: string;
}

function toEid(v: unknown): number {
  const n = Number(str(v).trim());
  return Number.isFinite(n) ? n : 0;
}

// A target that names the local machine itself (or nothing) is not lateral movement.
function isLocalTarget(target: string, computer: string): boolean {
  const t = target.trim().toLowerCase();
  if (!t) return true;
  if (t === "localhost" || t === "127.0.0.1" || t === "::1" || t === "-") return true;
  const c = computer.trim().toLowerCase();
  return !!c && (t === c || t === c.split(".")[0]);
}

// A machine / service principal (ends in `$`, or a well-known non-interactive session owner) is the
// boot-time noise, not an operator.
function isMachineOrNoiseUser(user: string): boolean {
  const u = user.trim().toLowerCase();
  if (!u || u === "-") return true;
  if (u.endsWith("$")) return true;
  return /^(?:umfd-\d+|dwm-\d+|system|local service|network service|font driver host)$/.test(u);
}

/**
 * Grade a Custom.DFIR.RDPLateralMovementDetection row. Returns a Medium T1021.001 signal for an
 * explicit-credential logon to a REMOTE host by a real user, or null for local / boot rows.
 */
export function rdpLateralSignal(artifact: string, row: Row): RdpLateralSignal | null {
  if (!/rdplateralmovement/i.test(artifact)) return null;
  if (toEid(getCI(row, "EventID")) !== 4648) return null;

  const target = str(getCI(row, "TargetServer"));
  const computer = str(getCI(row, "ComputerName"));
  if (isLocalTarget(target, computer)) return null;

  const initiator = str(getCI(row, "InitiatingUser"));
  if (isMachineOrNoiseUser(initiator)) return null;

  const srcIp = str(getCI(row, "SourceIP")).trim();
  const who = initiator || "a user";
  return {
    severity: "Medium",
    mitre: ["T1021.001"],
    note: `explicit-credential logon (EID 4648) by ${who} to remote ${target}${
      srcIp && srcIp !== "-" ? ` from ${srcIp}` : ""
    } — RDP lateral movement`,
  };
}
