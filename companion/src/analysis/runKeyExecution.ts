// A Run / RunOnce value already in the case, then a later process start whose command line IS that
// value, on the same host (#2082). The tagger grades one row at a time, so it can grade the Run
// write (win_run_key) but never "the persistence fired". This pass is that join. It runs at merge
// time, beside the Defender-episode pass and for the same reason: the registry write and the process
// start arrive from different imports, or from one import whose rows the tagger has not seen yet.
//
// WHAT IT ESTABLISHES. That a process-start record (Sysmon 1, Security 4688, an EDR start row) on the
// same host, dated after the Run write by more than the tolerance, ran exactly the command the Run
// value stores — compared after environment-variable contraction on both sides. When the value names
// its image by full path, the full path is compared; only a bare image name (resolved through PATH,
// "rundll32.exe …") is compared by name, and then only with non-empty arguments — a bare name alone
// would claim every start of that system binary.
//
// WHAT IT NEVER CLAIMS. Not a substring match, not a prefix match. Not "the same file" — a path is a
// path. No match against a description, a message or a Run row that carries no typed value (Hayabusa,
// Chainsaw, Velociraptor registry rows): adversary-controlled text must not forge a High. Two stock
// Windows values (the per-user OneDrive /background start and SecurityHealthSystray) are allow-listed
// as exact normalised values only; the same program from another path is not stock.
//
// Severity: High when the value's image is a script or proxy host (from LOLBINS — rundll32, regsvr32,
// mshta, powershell, …), Medium for any other exact match. Adds T1547.001. Only ever raises; its
// notes are recomputed from the current evidence on every merge. It sees only the forensic timeline
// as merged — a row demoted to the super-timeline is never in its input (CLAUDE.md §7).

import type { Severity } from "./stateTypes.js";
import { appendDerivedNote, splitDerivedNotes } from "./derivedNote.js";
import { canonicalHostName } from "./hostAlias.js";

/**
 * The script and proxy hosts among winProcessBaseline.ts LOLBINS — a Run value that launches one is
 * High. Kept here because the timeline domain may not import the ingest one; a test pins it as a
 * subset of LOLBINS.
 */
export const RUN_KEY_PROXY_HOSTS: ReadonlySet<string> = new Set([
  "powershell.exe",
  "pwsh.exe",
  "cmd.exe",
  "wscript.exe",
  "cscript.exe",
  "mshta.exe",
  "rundll32.exe",
  "regsvr32.exe",
  "msiexec.exe",
  "installutil.exe",
  "regasm.exe",
  "regsvcs.exe",
  "msbuild.exe",
  "cmstp.exe",
  "certutil.exe",
  "bitsadmin.exe",
  "wmic.exe",
  "hh.exe",
  "odbcconf.exe",
]);

/** The marker this pass appends. Registered in derivedNote.ts. */
export const RUN_KEY_EXECUTION_MARKER = "[persistence executed:";
/** A start inside this window of the Run write has no established order. */
export const RUN_KEY_EXECUTION_TOLERANCE_MS = 2000;
/** Run values indexed per host — the newest ones; the rest are never read. */
const RUN_ROWS_PER_HOST_MAX = 512;
const NOTE_MAX = 600;
const TECHNIQUE = "T1547.001";

export interface RunKeyTimelineShape {
  id?: string;
  description?: string;
  asset?: string;
  severity?: Severity;
  mitreTechniques?: string[];
  path?: string;
  commandLine?: string;
  timestamp?: string;
  canonical?: {
    event?: { category?: string; type?: string };
    process?: { executable?: string; commandLine?: string };
    registry?: { key?: string; valueName?: string; valueData?: string };
    time?: { normalized?: string };
  };
}

const RANK: Record<string, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

// ───────────────────────────── normalising a command ─────────────────────────────

/** Expanded profile and system paths rewritten to the variable that names them; never expanded. */
const CONTRACTIONS: ReadonlyArray<[RegExp, string]> = [
  [/%systemroot%/g, "%windir%"],
  [/[a-z]:\\users\\[^\\"]+\\appdata\\roaming(?=\\|"|$|\s)/g, "%appdata%"],
  [/[a-z]:\\users\\[^\\"]+\\appdata\\local(?=\\|"|$|\s)/g, "%localappdata%"],
  [/c:\\windows(?=\\|"|$|\s)/g, "%windir%"],
];

const contract = (s: string): string =>
  CONTRACTIONS.reduce((acc, [re, to]) => acc.replace(re, to), s.replace(/\s+/g, " ").trim().toLowerCase());

/** A command split into its image and arguments, both contracted and lowercased. */
interface Command {
  image: string;
  args: string;
}

function splitCommand(raw: string): Command | null {
  const s = contract(raw);
  if (!s) return null;
  if (s[0] === '"') {
    const end = s.indexOf('"', 1);
    if (end === -1) return { image: s.slice(1), args: "" };
    return { image: s.slice(1, end), args: s.slice(end + 1).trim() };
  }
  const sp = s.indexOf(" ");
  return sp === -1 ? { image: s, args: "" } : { image: s.slice(0, sp), args: s.slice(sp + 1).trim() };
}

const hasDir = (image: string): boolean => /[\\/]/.test(image);
const baseName = (image: string): string => image.split(/[\\/]/).pop() ?? image;
const withExe = (name: string): string => (name.includes(".") ? name : `${name}.exe`);

/** The one key a Run value is matched by, or null when the value cannot be matched safely. */
function valueKey(raw: string): { key: string; image: string } | null {
  const c = splitCommand(raw);
  if (!c || !c.image) return null;
  if (hasDir(c.image)) return { key: `path|${c.image}|${c.args}`, image: baseName(c.image) };
  // A bare image name alone would claim every start of that binary.
  if (!c.args) return null;
  const image = withExe(c.image);
  return { key: `bare|${image}|${c.args}`, image };
}

/** Every key a process start can be found by: its full image path, and its bare name with arguments. */
function startKeys(e: RunKeyTimelineShape): string[] {
  const line = e.commandLine?.trim() || e.canonical?.process?.commandLine?.trim();
  if (!line) return [];
  const c = splitCommand(line);
  if (!c || !c.image) return [];
  const imagePath = e.path ?? e.canonical?.process?.executable;
  const full = hasDir(c.image) ? c.image : imagePath ? (splitCommand(`"${imagePath}"`)?.image ?? "") : "";
  const keys = full ? [`path|${full}|${c.args}`] : [];
  if (c.args) keys.push(`bare|${withExe(baseName(c.image))}|${c.args}`);
  return keys;
}

/** Stock Windows values, as exact normalised keys (persistenceStockOs.ts strictness). */
const STOCK_VALUES = new Set([
  "path|%localappdata%\\microsoft\\onedrive\\onedrive.exe|/background",
  "path|%windir%\\system32\\securityhealthsystray.exe|",
]);

// ───────────────────────────── reading rows ─────────────────────────────

const RUN_KEY = /\\currentversion\\(?:policies\\explorer\\)?run(?:once)?(?:\\|$)/i;

const ms = (iso: string | undefined): number | null => {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
};

interface RunValue<T> {
  event: T;
  host: string;
  at: number;
  key: string;
  image: string;
  name: string;
  registryKey: string;
}

function readRunValue<T extends RunKeyTimelineShape>(e: T): RunValue<T> | null {
  const reg = e.canonical?.registry;
  const registryKey = reg?.key?.trim();
  const data = reg?.valueData?.trim();
  if (!registryKey || !data || !RUN_KEY.test(registryKey)) return null;
  const k = valueKey(data);
  if (!k || STOCK_VALUES.has(k.key)) return null;
  const tail = registryKey.split("\\").pop() ?? "";
  const name = reg?.valueName?.trim() || (/^run(?:once)?$/i.test(tail) ? "" : tail);
  const at = ms(e.canonical?.time?.normalized) ?? ms(e.timestamp);
  if (at === null || !e.asset) return null;
  return { event: e, host: canonicalHostName(e.asset), at, ...k, name, registryKey };
}

/** True for a row whose typed registry value is a Run / RunOnce command this pass can match (mergeIndex.ts). */
export function isRunKeyValueRow(e: RunKeyTimelineShape): boolean {
  return readRunValue(e) !== null;
}

const isProcessStart = (e: RunKeyTimelineShape): boolean =>
  e.canonical?.event?.category === "process" && e.canonical.event.type === "start";

/** Run values by host + key, oldest first; per host only the newest RUN_ROWS_PER_HOST_MAX. */
function indexRunValues<T extends RunKeyTimelineShape>(events: readonly T[]): Map<string, RunValue<T>[]> {
  const byHost = new Map<string, RunValue<T>[]>();
  for (const e of events) {
    const r = readRunValue(e);
    if (r) (byHost.get(r.host) ?? byHost.set(r.host, []).get(r.host)!).push(r);
  }
  const index = new Map<string, RunValue<T>[]>();
  for (const values of byHost.values()) {
    values.sort((a, b) => b.at - a.at || String(a.event.id).localeCompare(String(b.event.id)));
    for (const r of values.slice(0, RUN_ROWS_PER_HOST_MAX)) {
      const k = `${r.host}|${r.key}`;
      (index.get(k) ?? index.set(k, []).get(k)!).push(r);
    }
  }
  for (const list of index.values()) list.sort((a, b) => a.at - b.at);
  return index;
}

// ───────────────────────────── words ─────────────────────────────

const neutral = (t: string): string =>
  t
    .replace(/\[/g, "(")
    .replace(/\]/g, ")")
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
const clip = (s: string): string => (s.length > NOTE_MAX ? `${s.slice(0, NOTE_MAX - 1)}…` : s);

const startNote = <T>(r: RunValue<T>): string =>
  clip(
    `runs the Run value${r.name ? ` '${neutral(r.name).slice(0, 80)}'` : ""} at ${neutral(r.registryKey).slice(0, 260)}, written ${new Date(r.at).toISOString()}`,
  );

const runNote = (n: number, first: number): string =>
  `${n} later start${n === 1 ? "" : "s"} ran this value, first at ${new Date(first).toISOString()}`;

// ───────────────────────────── the pass ─────────────────────────────

const OWN_NOTE = /\s*\[persistence executed:[\s\S]{0,900}?\]/gu;

function withoutOwnNotes(description: string | undefined): string {
  const { base, notes } = splitDerivedNotes(description);
  if (!notes) return base;
  return [base, notes.replace(OWN_NOTE, "").trim()].filter(Boolean).join(" ");
}

const raise = (current: Severity | undefined, to: Severity): Severity =>
  RANK[to] > RANK[current ?? "Info"] ? to : (current ?? "Info");

/** For each start, the latest Run value on its host it ran, written before it past the tolerance. */
function matchStarts<T extends RunKeyTimelineShape>(events: readonly T[]): Map<T, RunValue<T>> {
  const index = indexRunValues(events);
  const out = new Map<T, RunValue<T>>();
  if (!index.size) return out;
  for (const e of events) {
    if (!isProcessStart(e) || !e.asset) continue;
    const at = ms(e.canonical?.time?.normalized) ?? ms(e.timestamp);
    if (at === null) continue;
    const host = canonicalHostName(e.asset);
    let best: RunValue<T> | undefined;
    for (const k of startKeys(e))
      for (const r of index.get(`${host}|${k}`) ?? [])
        if (at - r.at > RUN_KEY_EXECUTION_TOLERANCE_MS && (!best || r.at > best.at)) best = r;
    if (best) out.set(e, best);
  }
  return out;
}

/**
 * Raise every start that ran a stored Run / RunOnce value, and note on the Run row how often it ran.
 * Pure; returns the same object for a row it leaves unchanged; idempotent across merges.
 */
export function corroborateRunKeyExecution<T extends RunKeyTimelineShape>(events: readonly T[]): T[] {
  const matches = matchStarts(events);
  const perRun = new Map<T, { n: number; first: number }>();
  for (const [e, r] of matches) {
    const at = ms(e.canonical?.time?.normalized) ?? ms(e.timestamp) ?? r.at;
    const p = perRun.get(r.event);
    perRun.set(r.event, { n: (p?.n ?? 0) + 1, first: Math.min(p?.first ?? at, at) });
  }
  return events.map((e) => {
    const base = withoutOwnNotes(e.description);
    let description = base;
    let severity = e.severity ?? "Info";
    let mitre = e.mitreTechniques;
    const r = matches.get(e);
    if (r) {
      description = appendDerivedNote(description, RUN_KEY_EXECUTION_MARKER, startNote(r));
      severity = raise(severity, RUN_KEY_PROXY_HOSTS.has(r.image) ? "High" : "Medium");
      if (!(mitre ?? []).includes(TECHNIQUE)) mitre = [...(mitre ?? []), TECHNIQUE];
    }
    const run = perRun.get(e);
    if (run)
      description = appendDerivedNote(description, RUN_KEY_EXECUTION_MARKER, runNote(run.n, run.first));
    if (
      description === (e.description ?? "") &&
      severity === (e.severity ?? "Info") &&
      mitre === e.mitreTechniques
    )
      return e;
    return { ...e, description, severity, mitreTechniques: mitre ?? [] };
  });
}
