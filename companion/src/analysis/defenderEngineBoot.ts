// Defender's own engine loading its policy at start-up is not tampering (#2084).
//
// On the public APT29 Day 2 corpus every analysis pass kept a Critical "Defender disabled and broadly
// excluded". The rows were MsMpEng.exe itself writing `DisableRealtimeMonitoring` and `Exclusions\*`
// minutes after the host restarted: the range's own Defender policy loading, not the attacker.
//
// THE ANCHOR. Start-up records (6005 / 6009 / 4608, Kernel-General 12) are graded Info, so they never
// reach the forensic timeline where the finding-level cap runs. The import seam still holds them for
// one step (merge-all → tagger → caps → demote, the same place the build-time and lab-setup caps run),
// so stampEngineBoot reads them THERE and records, on each engine write that follows a start-up on the
// same host within ENGINE_BOOT_WINDOW_MS, the start-up it follows. Nothing reads the super-timeline and
// the model never sees the record; defenderTamperCap.ts reads it when it grades the finding.
//
// THE GUARD. With Tamper Protection on, `Set-MpPreference` reaches the registry THROUGH the Defender
// service, so "MsMpEng.exe wrote it" alone could be an attacker. A write is never stamped, and a stamp
// never caps, when an attacker tool touched Defender on that host inside the same window: a Defender
// cmdlet, reg.exe / sc.exe / a script host naming Defender, MpCmdRun -RemoveDefinitions, or any other
// process writing a Defender key. A wrong answer here falls towards keeping the finding Critical.
//
// The record lives here, not in stateTypes.ts (at its size ledger): `defenderEngineBoot` is the one
// extra field on a row, and the readers below are the only ones that touch it.
//
// PURE — returns new events, never mutates its input.

import type { ForensicEvent } from "./stateTypes.js";
import { assetKey } from "./gapEdgeClass.js";
import { readRegistryKey } from "./genericSysmonRegistry.js";

/** How long after a host starts the Defender engine's own policy writes count as start-up. */
export const ENGINE_BOOT_WINDOW_MS = 10 * 60_000;

export interface EngineBootRecord {
  bootAt: string; // ISO time of the start-up record the write follows
}
export type EngineBootEvent = ForensicEvent & { defenderEngineBoot?: EngineBootRecord };

// "EID 6005", "EventID: 4608", "(6009)". The digit guard keeps 60050 out (gapEdgeClass.ts's matcher).
const eidRe = (ids: string): RegExp =>
  new RegExp(String.raw`\b(?:eid|event\s*id)\s*[:#=]?\s*(?:${ids})(?!\d)|\((?:${ids})\)`, "i");
const STARTUP_EID = eidRe("6005|6009|4608");
const SHUTDOWN_EID = eidRe("6006|6008|1074");
const STARTUP_TEXT = /\boperating system started at system time\b|\bwindows is starting up\b/i;

// The Defender engine, only under the folders Defender itself installs to. A bare `MsMpEng.exe`
// anywhere else is a masquerade.
const ENGINE_IMAGE =
  /^(?:\\\\\?\\)?[a-z]:\\(?:programdata\\microsoft\\windows defender\\platform\\[^\\]+|program files\\windows defender)\\(?:msmpeng|mpdefendercoreservice)\.exe$/;
const DEFENDER_KEY = /\\microsoft\\windows defender(?:\\|$)/i;
const IMAGE_TOKEN = /(?:^|[\s¦-])Image(?:=|:[ \t]*)(.+?)(?= - | @ | ¦ |\r|\n|$)/;

const DEFENDER_CMDLET = /\b(?:Set|Add|Remove)-MpPreference\b/i;
const REMOVE_DEFINITIONS = /\bmpcmdrun(?:\.exe)?\b[^\n]*-removedefinitions\b/i;
const ATTACKER_TOOL =
  /(?:^|[\\\s"'])(?:reg|sc|powershell|pwsh|cmd|wmic|regedit|regini|mshta|wscript|cscript|rundll32)(?:\.exe)?\b/i;
const DEFENDER_TEXT = /windows defender|\bwindefend\b|\bwdfilter\b|\bwdboot\b|\bwdnissvc\b/i;

const rowText = (e: ForensicEvent): string => `${e.description} ${e.message ?? ""} ${e.commandLine ?? ""}`;

/** True for a host start-up record: 6005 / 6009 / 4608, Kernel-General 12. Never a shutdown. */
export function isStartupRow(e: ForensicEvent): boolean {
  const text = rowText(e);
  if (SHUTDOWN_EID.test(text)) return false;
  if (e.canonical?.event?.type === "boot") return true;
  return STARTUP_EID.test(text) || STARTUP_TEXT.test(text);
}

/** The image of the process that wrote the row, normalised, or "". */
function writerImage(e: ForensicEvent): string {
  const fromText = IMAGE_TOKEN.exec(e.description)?.[1] ?? IMAGE_TOKEN.exec(e.message ?? "")?.[1];
  const raw = e.canonical?.process?.executable || fromText || (/\.exe$/i.test(e.path ?? "") ? e.path : "");
  return (raw ?? "").trim().replace(/\//g, "\\").toLowerCase();
}

function defenderKeyOf(e: ForensicEvent): string {
  const key = readRegistryKey(e);
  return key && DEFENDER_KEY.test(key.replace(/\//g, "\\")) ? key : "";
}

/** True when the Defender engine, under its own install folder, wrote a Defender registry key. */
export function isDefenderEngineWrite(e: ForensicEvent): boolean {
  return !!defenderKeyOf(e) && ENGINE_IMAGE.test(writerImage(e));
}

// Defender Operational 5001 (real-time protection disabled) / 5007 (configuration changed): the
// importers write `(EID n)`, `(EID n Defender)` or `(EID n, Microsoft Defender)`; the label or the
// rendered message names Defender. A row with no Defender marker is not read as one.
const STATUS_EID = eidRe("5001|5007");
const DEFENDER_NAME = /\bdefender\b/i;

/** True for a writer-less Defender Operational 5001 / 5007 row (#2104). */
export function isDefenderStatusRow(e: ForensicEvent): boolean {
  const text = rowText(e);
  return STATUS_EID.test(text) && DEFENDER_NAME.test(text) && !writerImage(e);
}

/** True when something other than the engine touched Defender: a cmdlet, a tool, a key write. */
export function isAttackerDefenderTouch(e: ForensicEvent): boolean {
  // Defender's own record of a change names no tool; the change's value may name one (an exclusion).
  if (isDefenderEngineWrite(e) || isDefenderStatusRow(e)) return false;
  const text = rowText(e);
  if (DEFENDER_CMDLET.test(text) || REMOVE_DEFINITIONS.test(text)) return true;
  if (defenderKeyOf(e)) return true;
  const tool = `${e.processName ?? ""} ${e.path ?? ""} ${e.commandLine ?? ""} ${e.description}`;
  return ATTACKER_TOOL.test(tool) && DEFENDER_TEXT.test(text);
}

const OFF_SWITCH = /^disable[a-z]+$/i;
const ZERO_DWORD = /^(?:dword\s*\(0x0+\)|0x0+|0)$/i;
const DETAILS_TOKEN = /(?:^|[\s¦-])Details(?:=|:[ \t]*)(DWORD \(0x[0-9a-f]+\)|\d+)/i;
const SET_PREF = /\bSet-MpPreference\b([\s\S]*)$/i;
const PARAM = /-([A-Za-z]+)(?::|\s+)("?[^\s"]*"?)/g;

function registryTurnsOn(e: ForensicEvent): boolean {
  const key = defenderKeyOf(e);
  const valueName = key.split(/[\\/]/).pop() ?? "";
  if (!key || !OFF_SWITCH.test(valueName)) return false;
  const data = e.canonical?.registry?.valueData ?? DETAILS_TOKEN.exec(rowText(e))?.[1] ?? "";
  return ZERO_DWORD.test(data.trim());
}

function cmdletTurnsOn(e: ForensicEvent): boolean {
  const text = rowText(e);
  if (/\b(?:Add|Remove)-MpPreference\b/i.test(text)) return false;
  const args = SET_PREF.exec(text)?.[1];
  if (!args) return false;
  const params = [...args.matchAll(PARAM)];
  return (
    params.length > 0 &&
    params.every(
      ([, name, value]) => OFF_SWITCH.test(name) && /^(?:\$false|0)$/i.test(value.replace(/"/g, "")),
    )
  );
}

/** True when the row only switches Defender protection ON (a Disable* flag set to 0 / $false). */
export function isProtectionOnRow(e: ForensicEvent): boolean {
  return registryTurnsOn(e) || cmdletTurnsOn(e);
}

/** The row's start-up record, when it carries a valid one. */
export function engineBootOf(e: ForensicEvent): EngineBootRecord | undefined {
  const r = (e as EngineBootEvent).defenderEngineBoot;
  return r && typeof r.bootAt === "string" && Number.isFinite(Date.parse(r.bootAt)) ? r : undefined;
}

/** The row with the record, or the same object when it already carries one or none is given. */
export function withEngineBoot(e: ForensicEvent, rec: EngineBootRecord | undefined): ForensicEvent {
  if (!rec || engineBootOf(e)) return e;
  return { ...e, defenderEngineBoot: rec } as EngineBootEvent;
}

function timesByHost(
  rows: readonly ForensicEvent[],
  pick: (e: ForensicEvent) => boolean,
): Map<string, number[]> {
  const out = new Map<string, number[]>();
  for (const e of rows) {
    const host = assetKey(e);
    const t = Date.parse(e.timestamp);
    if (!host || !Number.isFinite(t) || !pick(e)) continue;
    out.set(host, [...(out.get(host) ?? []), t]);
  }
  return out;
}

const touchedIn = (touches: readonly number[] | undefined, bootAt: number): boolean =>
  (touches ?? []).some((t) => t >= bootAt && t <= bootAt + ENGINE_BOOT_WINDOW_MS);

/**
 * The engine writes in `rows` that follow a start-up on the same host within the window, with no
 * attacker touch of Defender on that host in the window, stamped with that start-up. Only the rows
 * that change are returned; a row already stamped is left alone.
 */
export function stampEngineBoot(rows: readonly ForensicEvent[]): ForensicEvent[] {
  const boots = timesByHost(rows, isStartupRow);
  if (!boots.size) return [];
  const touches = timesByHost(rows, isAttackerDefenderTouch);
  const out: ForensicEvent[] = [];
  for (const e of rows) {
    if (engineBootOf(e) || !isDefenderEngineWrite(e)) continue;
    const host = assetKey(e);
    const t = Date.parse(e.timestamp);
    const before = (boots.get(host) ?? []).filter((b) => b <= t && t - b <= ENGINE_BOOT_WINDOW_MS);
    if (!before.length) continue;
    const bootAt = Math.max(...before);
    if (touchedIn(touches.get(host), bootAt)) continue;
    out.push(withEngineBoot(e, { bootAt: new Date(bootAt).toISOString() }));
  }
  return out;
}

/**
 * True when every row is covered and no row in `context` shows an attacker tool touching Defender
 * on that row's host inside its start-up window (a later import can bring one). Covered: a stamped
 * engine write; or a writer-less 5001 / 5007 row (#2104) that falls inside the start-up window of a
 * clear stamped engine write among `rows` on the same host. 5001 / 5007 rows alone never cap.
 */
export function engineBootOnly(rows: readonly ForensicEvent[], context: readonly ForensicEvent[]): boolean {
  if (!rows.length) return false;
  const touches = timesByHost(context, isAttackerDefenderTouch);
  const clearBoots = new Map<string, number[]>();
  for (const e of rows) {
    const rec = engineBootOf(e);
    if (!rec || !isDefenderEngineWrite(e)) continue;
    const host = assetKey(e);
    const bootAt = Date.parse(rec.bootAt);
    if (!touchedIn(touches.get(host), bootAt))
      clearBoots.set(host, [...(clearBoots.get(host) ?? []), bootAt]);
  }
  return rows.every((e) => {
    const host = assetKey(e);
    const rec = engineBootOf(e);
    if (rec && isDefenderEngineWrite(e)) return (clearBoots.get(host) ?? []).includes(Date.parse(rec.bootAt));
    if (!isDefenderStatusRow(e)) return false;
    const at = [Date.parse(e.timestamp)]; // NaN never falls in a window
    return (clearBoots.get(host) ?? []).some((bootAt) => touchedIn(at, bootAt));
  });
}
