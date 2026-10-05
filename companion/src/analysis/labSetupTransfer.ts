// Lab setup: files the operator copied into the VM (#1946).
//
// In a lab run the operator drags the scenario's files into the guest through the hypervisor's
// drag-and-drop folder. VMware writes them under `%TEMP%\vmware-<user>\VMwareDnD\<id>\`, VirtualBox
// under `%TEMP%\VirtualBox Dropped Files\`. THOR and YARA then grade the copied scripts High, and the
// synthesis reported "attack tooling staged on the host" as a High finding (INC-2026-028).
//
// This pass caps such a row at Medium, writes a `[lab-setup: …]` note the analyst and the model both
// read, and records a `lab-setup` tag on the row. It only LOWERS a grade, and it is reversible: a row
// whose path no longer matches (the setting was narrowed) gets its recorded grade back.
//
// Only the file ARRIVING is lab setup. Running the copied tool is the scenario itself, so a row that
// executes from the folder (an execute action, or its own command line names the folder) keeps its
// grade. A promoted row or a hard attacker signal keeps its grade too (buildTimeWindow.protectedFromCap).
//
// The record lives here, not in stateTypes.ts (at its size ledger): `labSetup` is the one extra
// field on a row and on a finding, and the readers below are the only ones that touch it.

import { appendDerivedNote, DESCRIPTION_BASE_MAX } from "./derivedNote.js";
import { protectedFromCap } from "./buildTimeWindow.js";
import {
  SEVERITY_RANK,
  worstSeverity,
  type Finding,
  type ForensicEvent,
  type Severity,
} from "./stateTypes.js";

export const LAB_SETUP_MARKER = "[lab-setup:";
export const LAB_SETUP_TAG = "lab-setup";
export const LAB_SETUP_SEVERITY_CAP: Severity = "Medium";
export const LAB_SETUP_PATHS_ENV = "DFIR_LAB_SETUP_PATHS";
/** Hypervisor drag-and-drop transfer folders: VMware Tools and VirtualBox Guest Additions. */
export const DEFAULT_LAB_SETUP_PATHS: readonly string[] = ["\\VMwareDnD\\", "\\VirtualBox Dropped Files\\"];
export const LAB_SETUP_FINDING_REASON =
  "capped: every cited event is a file copied into the VM through a lab-setup folder (hypervisor drag-and-drop) — the operator staging the lab, not the intrusion";

export interface LabSetupRecord {
  tag: typeof LAB_SETUP_TAG;
  folder: string;
  cappedFrom?: Severity;
}
export type LabSetupEvent = ForensicEvent & { labSetup?: LabSetupRecord };
export interface FindingLabSetup {
  labSetup?: boolean;
}

const NOTE_RE = /\s*\[lab-setup:[^\]]*\]/gu;
const HAS_NOTE = /\[lab-setup:[^\]]*\]/u;
const DEFAULT_SET = new Set(DEFAULT_LAB_SETUP_PATHS.map((p) => norm(p)));

function norm(p: string): string {
  return p.trim().replace(/\//g, "\\").toLowerCase();
}

/** Bundled folders plus DFIR_LAB_SETUP_PATHS (comma-separated substrings), read at call time. */
export function labSetupPaths(env: NodeJS.ProcessEnv = process.env): string[] {
  const extra = (env[LAB_SETUP_PATHS_ENV] ?? "").split(",").map(norm).filter(Boolean);
  return [...new Set([...DEFAULT_SET, ...extra])];
}

/** The lab-setup folder this row's file sits in, or null. A run from the folder is not setup. */
export function labSetupFolder(e: ForensicEvent, paths: readonly string[]): string | null {
  if (!e.path || e.action === "execute") return null;
  const p = norm(e.path);
  const hit = paths.find((x) => p.includes(x));
  if (!hit) return null;
  if (e.commandLine && norm(e.commandLine).includes(hit)) return null;
  return hit;
}

/** The grade a lab-setup row may carry: never above Medium. */
export function capLabSetupSeverity(s: Severity): Severity {
  return SEVERITY_RANK[s] < SEVERITY_RANK[LAB_SETUP_SEVERITY_CAP] ? LAB_SETUP_SEVERITY_CAP : s; // rank 0 = Critical
}

/** The row's lab-setup record, when it carries one. */
export function labSetupOf(e: ForensicEvent): LabSetupRecord | undefined {
  const r = (e as LabSetupEvent).labSetup;
  return r && r.tag === LAB_SETUP_TAG ? r : undefined;
}

/** True when a row carries any trace of the cap (its record or its note). */
export function hasLabSetupMark(e: ForensicEvent): boolean {
  return !!labSetupOf(e) || HAS_NOTE.test(e.description);
}

function noteFor(folder: string): string {
  const kind = DEFAULT_SET.has(folder) ? "hypervisor drag-and-drop transfer" : "configured lab-setup path";
  return `${kind} (${folder}) — a file the operator copied into the VM, not attacker staging`;
}

function withNote(e: ForensicEvent, folder: string): ForensicEvent {
  const severity = capLabSetupSeverity(e.severity);
  const labSetup: LabSetupRecord = {
    tag: LAB_SETUP_TAG,
    folder,
    ...(severity !== e.severity ? { cappedFrom: e.severity } : {}),
  };
  return {
    ...e,
    severity,
    description: appendDerivedNote(e.description, LAB_SETUP_MARKER, noteFor(folder), DESCRIPTION_BASE_MAX),
    labSetup,
  } as LabSetupEvent;
}

function stripNote(e: ForensicEvent): ForensicEvent {
  return { ...e, description: e.description.replace(NOTE_RE, "").trim() };
}

function withoutNote(e: ForensicEvent): ForensicEvent {
  const { labSetup, ...rest } = e as LabSetupEvent;
  return {
    ...rest,
    severity: labSetup?.cappedFrom ?? e.severity,
    description: e.description.replace(NOTE_RE, "").trim(),
  };
}

/** Cap one row, or lift a cap whose folder no longer matches. The same object back when nothing changes. */
export function capLabSetupRow(e: ForensicEvent, paths: readonly string[]): ForensicEvent {
  const rec = labSetupOf(e);
  // An Info row is not in the record the model reads; leave it alone unless it carries an old mark.
  const eligible = e.severity !== "Info" || !!rec;
  const folder = eligible && !protectedFromCap(e) ? labSetupFolder(e, paths) : null;
  if (folder && !rec) return withNote(HAS_NOTE.test(e.description) ? stripNote(e) : e, folder);
  if (folder && rec && rec.folder !== folder) return withNote(withoutNote(e), folder);
  // A merge raised a capped row: cap it again and keep the worse original grade for a later lift.
  if (folder && rec && capLabSetupSeverity(e.severity) !== e.severity) {
    const cappedFrom = worstSeverity(rec.cappedFrom ?? e.severity, e.severity);
    return {
      ...e,
      severity: capLabSetupSeverity(e.severity),
      labSetup: { ...rec, cappedFrom },
    } as LabSetupEvent;
  }
  if (!folder && rec) return withoutNote(e);
  if (!folder && HAS_NOTE.test(e.description)) return stripNote(e);
  return e;
}

/** True when a finding cites rows and every one of them is lab setup. */
export function labSetupOnly(supporting: readonly ForensicEvent[]): boolean {
  return supporting.length > 0 && supporting.every((e) => !!labSetupOf(e));
}

/** The finding's lab-setup flag. */
export function findingIsLabSetup(f: Finding): boolean {
  return (f as Finding & FindingLabSetup).labSetup === true;
}
