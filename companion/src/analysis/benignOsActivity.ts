// Two shapes of ordinary Windows behaviour that graded as findings on INC-2026-005 (#1593).
//
// EVERY RULE HERE LOWERS A GRADE, so each one is bound to facts the OS wrote, never to a name alone.
//
// 1. dwm.exe → csrss.exe remote thread (Sysmon EID 8). The Desktop Window Manager's win32k callback
//    creates a thread in the session's csrss.exe whose start address is in KERNEL space
//    (0xFFFFF807…). processAccess.ts reads any start outside a user-mode module as "outside any
//    module" and grades it High / T1055. The rule claims only that exact shape: both images
//    path-anchored to \Windows\System32\ (traversal refused), and the start a kernel-space address
//    (at or above 0xFFFF800000000000, parsed exactly with BigInt). A user-mode unbacked start, a
//    module-backed start (`LoadLibraryW` is the DLL-injection shape), or no start at all keeps its
//    grade. Per row, at the shared aggregation seam, so every importer gets it.
//
// The AppX firewall-update pair needs the raw record and a second row, so it lives in
// appxFirewallChurn.ts, in the collector ledger's seam.

import type { MappedEvent } from "./siemImport.js";
import { descriptionField } from "./collectorDeployment.js";
import { appendDerivedNote } from "./derivedNote.js";

export const OS_BEHAVIOUR_MARKER = "[normal OS behaviour:";
export const DWM_THREAD_NOTE =
  "the Desktop Window Manager's kernel callback thread into csrss.exe, not injection";
export const BENIGN_OS_AGG_SUFFIX = "|os-benign";

// ───────────────────────────── 1. dwm → csrss ─────────────────────────────

const PATH_TRAVERSAL = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
const SYSTEM_DWM = /^[a-z]:[\\/]windows[\\/]system32[\\/]dwm\.exe$/i;
const SYSTEM_CSRSS = /^[a-z]:[\\/]windows[\\/]system32[\\/]csrss\.exe$/i;
const UNBACKED_START = /^thread:unbacked:0x([0-9a-f]{1,16})$/i;
const KERNEL_SPACE = 0xffff800000000000n;

export function anchored(path: string, re: RegExp): boolean {
  return !!path && !PATH_TRAVERSAL.test(path) && re.test(path);
}

// processAccess.ts writes `thread:unbacked:<address>` (plus `;source=…` for a system-path source).
function startsInKernelSpace(action: string): boolean {
  const m = UNBACKED_START.exec(action.split(";")[0].trim());
  return !!m && BigInt(`0x${m[1]}`) >= KERNEL_SPACE;
}

/** Is this the Desktop Window Manager's kernel-callback thread into csrss.exe? */
export function isDwmCsrssCallback(m: MappedEvent): boolean {
  const c = m.canonical;
  if (c?.event?.type !== "remote_thread") return false;
  const source = descriptionField(m.description, "SourceImage");
  const target = c.process?.executable?.trim() || descriptionField(m.description, "TargetImage");
  return (
    anchored(source, SYSTEM_DWM) &&
    anchored(target, SYSTEM_CSRSS) &&
    startsInKernelSpace(c.event.action ?? "")
  );
}

/** The per-row rules, applied at the aggregation seam (eventAggregate.ts). Idempotent. */
export function annotateBenignOsActivity(m: MappedEvent): void {
  if (m.severity !== "Critical" && isDwmCsrssCallback(m)) gradeBenign(m, DWM_THREAD_NOTE);
}

export function gradeBenign(m: MappedEvent, note: string): void {
  m.severity = "Info";
  if (!m.description.includes(`${OS_BEHAVIOUR_MARKER} ${note}]`))
    m.description = appendDerivedNote(m.description, OS_BEHAVIOUR_MARKER, note);
  if (!m.aggKey.endsWith(BENIGN_OS_AGG_SUFFIX)) m.aggKey = `${m.aggKey}${BENIGN_OS_AGG_SUFFIX}`;
}
