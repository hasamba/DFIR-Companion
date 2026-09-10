// Memory cross-view discrepancies: psxview process visibility and ldrmodules loader membership
// (#909 item 3).
//
// Both plugins exist for ONE reason: to disagree with themselves. psxview enumerates processes
// several independent ways — the active-process list, a pool scan, thread ownership, the CSRSS
// handle table — and prints a column per method. ldrmodules reports whether a mapped module appears
// in each of the three PEB loader lists (InLoad, InInit, InMem). A row where every column agrees is
// ordinary. A row where they DISAGREE is the finding: something is visible to one kernel structure
// and absent from another, which is what unlinking looks like.
//
// The importer flattened both into generic rows and threw the columns away, so the only thing the
// plugins are collected for never reached the timeline.
//
// ─────────────────────────── WHY THIS GRADES SO CAUTIOUSLY ───────────────────────────
//
// A disagreement is NOT proof of a rootkit, and the benign causes are common:
//
//   • A process that exited between enumeration passes is missing from the later ones. That is a
//     race in the acquisition, not stealth.
//   • Very early boot processes (System, smss.exe) legitimately have no CSRSS handle and no session.
//   • A module mapped as a RESOURCE rather than loaded as code is absent from the init list by
//     design — it was never initialised because it is not code.
//   • WOW64 processes carry a second, 32-bit PEB, so a 64-bit walker sees a different module set.
//   • A field the plugin could not read prints as "-" or "N/A". ABSENT IS NOT FALSE, and treating
//     an unreadable column as "not present in that list" manufactures the exact discrepancy this
//     module is looking for.
//
// So: a single false-or-missing column is never a finding on its own — published Volatility output
// shows ordinary lsass.exe and svchost.exe rows with one column false, and tagging each of those
// would mark routine processes as rootkit leads on every host. TWO independent methods must
// disagree, the description names which, and the benign causes are named with it. Nothing here says
// "rootkit"; it says which views differ and what else produces that.
//
// Correlation is confined to one memory image and one process identity, per the issue: these rows
// describe a single acquisition, and comparing across images would compare different machines'
// states.

import type { Severity } from "./stateTypes.js";

export type Row = Record<string, unknown>;

/** The psxview enumeration methods we understand, in the order they are reported. */
const PSXVIEW_METHODS: { key: string; aliases: string[] }[] = [
  { key: "pslist", aliases: ["pslist", "PsActiveProcessHead", "pslist_present"] },
  { key: "psscan", aliases: ["psscan", "PoolScanner", "psscan_present"] },
  { key: "thrdproc", aliases: ["thrdproc", "thrdscan", "ThreadScan", "thrdproc_present"] },
  // Volatility 2 emits pspcid between thrdproc and csrss. Omitting it did not make a pspcid-only
  // discrepancy "unreadable" — it made it invisible.
  { key: "pspcid", aliases: ["pspcid", "PspCidTable", "pspcid_present"] },
  { key: "csrss", aliases: ["csrss", "CsrssHandles", "csrss_present"] },
  { key: "session", aliases: ["session", "Sessions", "session_present"] },
  { key: "deskthrd", aliases: ["deskthrd", "DesktopThreads", "deskthrd_present"] },
];

/** The three PEB loader lists ldrmodules reports membership in. */
const LDR_LISTS: { key: string; aliases: string[] }[] = [
  { key: "InLoad", aliases: ["InLoad", "InLoadOrderModuleList", "in_load"] },
  { key: "InInit", aliases: ["InInit", "InInitializationOrderModuleList", "in_init"] },
  { key: "InMem", aliases: ["InMem", "InMemoryOrderModuleList", "in_mem"] },
];

// Early-boot processes legitimately fail SPECIFIC views, and only those.
//
// The first version exempted these names from the whole detection, which is a one-line evasion:
// name a process smss.exe, unlink it from pslist, and nothing is reported. Volatility 2's own rules
// are method-specific for exactly this reason — they excuse a missing CSRSS handle or desktop
// thread for a process that starts before those structures exist, and excuse nothing else.
//
// `System` additionally has to BE the System process: PID 4. A user-mode process wearing the name
// gets no exemption at all.
const EARLY_BOOT_EXCEPTIONS: { name: RegExp; pid?: number; excused: string[] }[] = [
  { name: /^system$/i, pid: 4, excused: ["csrss", "session", "deskthrd"] },
  { name: /^smss\.exe$/i, excused: ["csrss", "session", "deskthrd"] },
  { name: /^csrss\.exe$/i, excused: ["csrss", "deskthrd"] },
  { name: /^(?:registry|memory compression)$/i, excused: ["csrss", "session", "deskthrd"] },
];

// A membership row whose path is one of these is DATA, not code. Windows maps resource-only files
// (LOAD_LIBRARY_AS_DATAFILE / AS_IMAGE_RESOURCE) without entering them in any loader list, so a
// localized .mui on a clean host is false in all three — the exact shape the "mapped but never
// loaded" branch was grading as injection.
const RESOURCE_MAPPING = /\.(?:mui|nls|dat|fon|ttf|ttc|otf|ico|cur|ani|msstyles|tlb|winmd)$/i;

export type Tri = true | false | null; // null = the plugin could not report this column

function getCI(row: Row, key: string): unknown {
  for (const k of Object.keys(row)) if (k.toLowerCase() === key.toLowerCase()) return row[k];
  return undefined;
}

/**
 * Read a boolean-ish cell as a tristate.
 *
 * The distinction that matters: an UNREADABLE column is null, not false. Volatility prints "-",
 * "N/A" or an empty cell when a method could not be applied, and reading that as "absent from this
 * list" invents the discrepancy the module is hunting for.
 */
export function triState(v: unknown): Tri {
  if (v === true || v === false) return v;
  const s = String(v ?? "")
    .trim()
    .toLowerCase();
  if (!s || s === "-" || s === "n/a" || s === "na" || s === "unknown" || s === "?") return null;
  // Volatility 2 --apply-rules prints "Okay", not "Ok".
  if (["true", "yes", "y", "1", "ok", "okay", "present"].includes(s)) return true;
  if (["false", "no", "n", "0", "absent", "missing"].includes(s)) return false;
  return null;
}

function readFlags(row: Row, spec: { key: string; aliases: string[] }[]): Record<string, Tri> {
  const out: Record<string, Tri> = {};
  for (const f of spec) {
    let v: unknown;
    for (const a of f.aliases) {
      v = getCI(row, a);
      if (v !== undefined) break;
    }
    out[f.key] = v === undefined ? null : triState(v);
  }
  return out;
}

// True only when the row carries a real, parsable exit timestamp.
function hasExited(row: Row): boolean {
  const raw = String(
    getCI(row, "Exit Time") ??
      getCI(row, "ExitTime") ??
      getCI(row, "process_exit_time") ??
      getCI(row, "exit_time") ??
      "",
  ).trim();
  if (!raw) return false;
  if (/^(?:n\/?a|-|none|unknown|\?)$/i.test(raw)) return false;
  if (/^0+$/.test(raw)) return false;
  // The FILETIME and .NET zero dates both mean "never exited".
  if (/^(?:1601-01-01|0001-01-01|1970-01-01)/.test(raw)) return false;
  return !Number.isNaN(Date.parse(raw));
}

export interface CrossViewSignal {
  severity: Severity;
  mitre: string[];
  note: string; // human-readable, appended to the event description
  present: string[]; // methods/lists that reported it
  absent: string[]; // methods/lists that did not
  unreadable: string[]; // columns the plugin could not report — never counted as absent
}

/** True when the table carries any of the columns this module understands. */
export function hasPsxviewColumns(row: Row): boolean {
  return PSXVIEW_METHODS.some((f) => f.aliases.some((a) => getCI(row, a) !== undefined));
}

export function hasLdrColumns(row: Row): boolean {
  return LDR_LISTS.some((f) => f.aliases.some((a) => getCI(row, a) !== undefined));
}

/**
 * Grade one psxview row.
 *
 * Returns null when the views agree, when too few could be read to compare, or when the process is
 * one that legitimately fails several of them.
 */
export function psxviewSignal(row: Row): CrossViewSignal | null {
  const flags = readFlags(row, PSXVIEW_METHODS);
  const present = Object.keys(flags).filter((k) => flags[k] === true);
  const absent = Object.keys(flags).filter((k) => flags[k] === false);
  const unreadable = Object.keys(flags).filter((k) => flags[k] === null);

  // Nothing to compare: one readable column cannot disagree with anything.
  if (present.length + absent.length < 2) return null;
  if (absent.length === 0) return null;

  const name = String(getCI(row, "Name") ?? getCI(row, "ImageFileName") ?? "").trim();
  const pid = Number(String(getCI(row, "PID") ?? getCI(row, "Pid") ?? "").trim());
  // Drop the methods this process is legitimately allowed to fail, then re-ask the question.
  const excused = EARLY_BOOT_EXCEPTIONS.find(
    (e) => e.name.test(name) && (e.pid === undefined || e.pid === pid),
  )?.excused;
  const realAbsent = excused ? absent.filter((k) => !excused.includes(k)) : absent;
  if (realAbsent.length === 0) return null;

  // A process that has EXITED is expected to be gone from the live list and still findable by a
  // pool scan. That is the acquisition catching a race, not concealment.
  //
  // Volatility 3 spells the column "Exit Time", with a space. Reading only the Volatility 2
  // spelling meant every terminated process in a V3 capture was graded as a hidden one.
  //
  // And only a PARSABLE, non-sentinel date counts. Treating any non-empty value as proof of
  // termination let "N/A", "-" or corrupt text suppress a real finding — an evasion, not a guard.
  if (hasExited(row)) return null;

  // ONE dissenting method is not a finding. Published Volatility output shows ordinary lsass.exe,
  // rundll32.exe and svchost.exe rows with deskthrd alone false; emitting a T1014-tagged event for
  // each would tag routine processes as rootkit leads on every host. The file header always said a
  // single column was insufficient — this is the code finally agreeing with it.
  if (realAbsent.length < 2) return null;

  const severity: Severity = "Medium";
  return {
    severity,
    mitre: ["T1014"],
    note:
      `cross-view: found by ${present.join(", ") || "no method"}; not found by ${realAbsent.join(", ")}` +
      (unreadable.length ? ` (${unreadable.join(", ")} not reported)` : "") +
      ". Hidden-process indicator only — confirm before concluding, and note the benign causes " +
      "(exited process, early boot, unreadable column).",
    present,
    absent: realAbsent,
    unreadable,
  };
}

/**
 * Grade one ldrmodules row.
 *
 * The classic injected-DLL shape is a module mapped in memory but present in NO loader list — it
 * was never loaded through the loader. Absence from InInit alone is routine (resource-only
 * mappings) and is deliberately not a finding.
 */
export function ldrModulesSignal(row: Row): CrossViewSignal | null {
  const flags = readFlags(row, LDR_LISTS);
  const present = Object.keys(flags).filter((k) => flags[k] === true);
  const absent = Object.keys(flags).filter((k) => flags[k] === false);
  const unreadable = Object.keys(flags).filter((k) => flags[k] === null);

  if (present.length + absent.length < 2) return null;
  if (absent.length === 0) return null;

  const path = String(
    getCI(row, "MappedPath") ?? getCI(row, "Path") ?? getCI(row, "FullDllName") ?? "",
  ).trim();

  // A module absent from every readable list, while ldrmodules is nonetheless reporting it, is
  // mapped-but-not-loaded.
  if (present.length === 0) {
    // ...unless it is a RESOURCE mapping, which is the common benign case and was the first
    // version's worst false positive. Windows maps localized .mui files and other data with
    // LOAD_LIBRARY_AS_DATAFILE, entering them in no loader list at all, so a clean host shows rows
    // like `csrss.exe ... False False False \\Windows\\System32\\pt-BR\\winsrv.dll.mui`. Grading
    // those as process injection tags routine localization as an attack.
    if (RESOURCE_MAPPING.test(path)) return null;

    // An UNBACKED region — no path at all — is the strong shape: executable memory that no file
    // explains, which is what a reflectively-loaded module looks like. A row with a real DLL path
    // is weaker, because a resource mapping can also carry a .dll name.
    const unbacked = !path;
    return {
      severity: unbacked ? "Medium" : "Low",
      mitre: ["T1055.001"],
      note:
        `cross-view: ${unbacked ? "mapped with no backing file" : `mapped from ${path}`} but in none ` +
        `of the loader lists (${absent.join(", ")})` +
        (unreadable.length ? ` (${unreadable.join(", ")} not reported)` : "") +
        ". Consistent with a module loaded without the loader; also seen for WOW64 and " +
        "resource-only mappings. Confirm before concluding.",
      present,
      absent,
      unreadable,
    };
  }

  // Absent from InInit alone: routine for a mapping that is data rather than code. And a single
  // dissenting list is not a finding at all, for the same reason one dissenting psxview method
  // is not — see psxviewSignal.
  if (absent.length < 2) return null;

  return {
    severity: "Low",
    mitre: ["T1055.001"],
    note:
      `cross-view: in ${present.join(", ")} but not ${absent.join(", ")}` +
      (unreadable.length ? ` (${unreadable.join(", ")} not reported)` : "") +
      ". Inconsistent loader membership — a lead, not a verdict.",
    present,
    absent,
    unreadable,
  };
}
