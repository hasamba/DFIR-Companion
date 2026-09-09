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
// So: a single false-or-missing column is never a finding on its own. The grade rises only when
// more than one independent method disagrees, and the description always names which methods
// disagreed so the analyst can weigh it. Nothing here says "rootkit"; it says which views differ.
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

// Processes that legitimately fail several views. System has no user-mode CSRSS handle and no
// desktop thread; smss.exe and csrss.exe itself start before the structures that would list them.
const EARLY_BOOT = /^(?:system|smss\.exe|csrss\.exe|registry|memory compression)$/i;

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
  const s = String(v ?? "").trim().toLowerCase();
  if (!s || s === "-" || s === "n/a" || s === "na" || s === "unknown" || s === "?") return null;
  if (["true", "yes", "y", "1", "ok", "present"].includes(s)) return true;
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
  if (EARLY_BOOT.test(name)) return null;

  // A process that has EXITED is expected to be gone from the live list and still findable by a
  // pool scan. That is the acquisition catching a race, not concealment.
  const exited = String(getCI(row, "ExitTime") ?? getCI(row, "process_exit_time") ?? "").trim();
  if (exited && !/^0*$/.test(exited) && !exited.startsWith("1601-01-01")) return null;

  // One dissenting method is weak — a single structure can be stale for ordinary reasons. Two or
  // more independent methods disagreeing is the shape that is worth an analyst's time, and even
  // that is Medium: this is a lead, never a verdict.
  const severity: Severity = absent.length >= 2 ? "Medium" : "Low";
  return {
    severity,
    mitre: ["T1014"],
    note:
      `cross-view: found by ${present.join(", ") || "no method"}; not found by ${absent.join(", ")}` +
      (unreadable.length ? ` (${unreadable.join(", ")} not reported)` : "") +
      ". Hidden-process indicator only — confirm before concluding, and note the benign causes " +
      "(exited process, early boot, unreadable column).",
    present,
    absent,
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

  // A module absent from every readable list, while ldrmodules is nonetheless reporting it, is
  // mapped-but-not-loaded. That is the strongest thing this table can say.
  if (present.length === 0) {
    return {
      severity: "Medium",
      mitre: ["T1055.001"],
      note:
        `cross-view: mapped in memory but in none of the loader lists (${absent.join(", ")})` +
        (unreadable.length ? ` (${unreadable.join(", ")} not reported)` : "") +
        ". Consistent with a module loaded without the loader; also seen for WOW64 and " +
        "resource-only mappings. Confirm before concluding.",
      present,
      absent,
      unreadable,
    };
  }

  // Absent from InInit alone: routine for a mapping that is data rather than code.
  if (absent.length === 1 && absent[0] === "InInit") return null;

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
