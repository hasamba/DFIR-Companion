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
// executes from the folder keeps its grade: an execute action, a command line that names the folder,
// or an execution artifact (Prefetch, UserAssist, Amcache, BAM, ShimCache with its execution flag, a
// process start — isExecutionRecord). A promoted row or a hard attacker signal keeps its grade too (buildTimeWindow.protectedFromCap).
//
// The record lives here, not in stateTypes.ts (at its size ledger): `labSetup` is the one extra
// field on a row and on a finding, and the readers below are the only ones that touch it.

import { appendDerivedNote, DESCRIPTION_BASE_MAX } from "./derivedNote.js";
import { protectedFromCap } from "./buildTimeWindow.js";
import { veloAction } from "./downloadCorroborationShared.js";
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

// A bundled folder counts only in the shape the hypervisor writes, under a Temp folder. The bare name
// (`\VMwareDnD\`) is attacker-choosable, so it alone must not cap a staged payload (#2002).
// DFIR_LAB_SETUP_PATHS extras stay plain substrings: the operator owns them.
const DEFAULT_SHAPES: ReadonlyMap<string, RegExp> = new Map([
  [norm(DEFAULT_LAB_SETUP_PATHS[0]), /\\temp\\vmware-[^\\]+\\vmwarednd\\/u],
  [norm(DEFAULT_LAB_SETUP_PATHS[1]), /\\temp\\virtualbox dropped files\\/u],
]);

function pathMatches(p: string, entry: string): boolean {
  const shape = DEFAULT_SHAPES.get(entry);
  return shape ? shape.test(p) : p.includes(entry);
}

/** Bundled folders plus DFIR_LAB_SETUP_PATHS (comma-separated substrings), read at call time. */
export function labSetupPaths(env: NodeJS.ProcessEnv = process.env): string[] {
  const extra = (env[LAB_SETUP_PATHS_ENV] ?? "").split(",").map(norm).filter(Boolean);
  return [...new Set([...DEFAULT_SET, ...extra])];
}

// Execution evidence, read from the marks each importer itself writes — never the row's subject text.
// KAPE stamps `sources` with the tool's name; Velociraptor writes `sources: ["Velociraptor"]` and
// its fixed `[<artifact>]: <action>` segment (veloAction). Amcache and BAM are recorded when a
// binary runs, not when a file is copied in; ShimCache counts only with its execution flag.
const EXEC_SOURCES = /^(?:prefetch|userassist|amcache|bam)$/i;
const VELO_EXEC_ACTION = /prefetch|userassist|amcache|shimcache, execution flag set/i;
const VELO_BAM = /^Velociraptor(?: \[[^\]]*\])? BAM: /;
const KAPE_SHIM_EXECUTED = /^ShimCache: .* — present in the cache, execution flag set; time shown/;

/** True when the row records that the binary RAN: a process start or an execution artifact. */
export function isExecutionRecord(e: ForensicEvent): boolean {
  if (e.action === "execute") return true;
  if (e.canonical?.event?.category === "process" && e.canonical.event.type === "start") return true;
  const sources = e.sources ?? [];
  if (sources.some((s) => EXEC_SOURCES.test(s))) return true;
  if (sources.includes("ShimCache") && KAPE_SHIM_EXECUTED.test(e.description)) return true;
  if (!sources.includes("Velociraptor")) return false;
  return VELO_EXEC_ACTION.test(veloAction(e)) || VELO_BAM.test(e.description);
}

/** The lab-setup folder this row's file sits in, or null. A run from the folder is not setup. */
export function labSetupFolder(e: ForensicEvent, paths: readonly string[]): string | null {
  if (!e.path || isExecutionRecord(e)) return null;
  const p = norm(e.path);
  const hit = paths.find((x) => pathMatches(p, x));
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
