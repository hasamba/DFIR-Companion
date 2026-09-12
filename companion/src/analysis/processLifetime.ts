// Process lifetime and sacrificial-process patterns (#909 item 6).
//
// Three shapes that only become visible once a process's START and EXIT are both known:
//
//   • A SACRIFICIAL process — spawned purely to be injected into and then discarded. The classic is
//     an argument-free rundll32.exe: rundll32 exists to run an exported function, so a rundll32
//     with no arguments was never going to do anything, and something injected into it.
//   • REPEATED SHORT LIFETIMES — the same image spawned and gone again, over and over. One is
//     nothing. Twenty in a minute is a loop: a beacon, a spraying tool, a retry.
//   • AN UNEXPECTED PARENT — a process whose parent is not one that starts it in the ordinary
//     course of events.
//
// ─────────────────────────── EMPTY IS NOT THE SAME AS UNKNOWN ───────────────────────────
//
// The rundll32 rule turns entirely on this. "The command line was captured and it was empty" is the
// finding. "The command line was not captured" is the overwhelmingly common case in triage
// collections that record process names and nothing else, and reading it as "empty" would flag
// every rundll32 on the estate — including the dozens Windows itself starts. So the caller must say
// which it has, and an unknown command line produces nothing at all.
//
// ─────────────────────────── PID REUSE, AND WHAT AN ORPHAN MEANS ───────────────────────────
//
// Windows recycles PIDs aggressively. Two records sharing a PID are the same process only if their
// lifetimes overlap and their images agree, so every correlation here is keyed on PID plus image
// plus start time, never PID alone.
//
// And a process whose parent is missing from the collection is NOT an orphan. A snapshot taken
// after the parent exited shows exactly that shape, and so does any partial collection. Missing
// evidence is missing evidence — it is never promoted to a finding.
//
// ─────────────────────────── NOT ATTRIBUTING FROM A NAME ───────────────────────────
//
// A tool family is not identified by the executable name it happened to default to years ago.
// Attackers rename, and defenders inherit the name in unrelated software. Nothing here concludes
// "this is <framework>" from an image name; it reports the observed shape.

import type { Severity } from "./stateTypes.js";
import { appendDerivedNote } from "./derivedNote.js";

/** What the collection actually recorded about one process. */
export interface ProcessRecord {
  image: string; // full path or bare name
  name: string; // lowercased basename
  pid: string;
  ppid: string;
  parentName: string;
  start: string; // ISO, "" when not recorded
  exit: string; // ISO, "" when not recorded
  /**
   * The command line, and — crucially — whether one was CAPTURED at all.
   *
   * "captured and empty" and "never captured" are different facts that look identical in a string
   * field. Conflating them is what would turn every rundll32 on a name-only collection into a
   * finding.
   */
  commandLine: string;
  commandLineCaptured: boolean;
}

export interface LifetimeSignal {
  severity: Severity;
  mitre: string[];
  note: string;
}

// Images whose whole purpose is to run something passed as an argument. Started with none, they had
// no work to do.
const NEEDS_ARGUMENTS = new Set(["rundll32.exe", "regsvr32.exe", "mshta.exe", "msiexec.exe"]);

// How long a process may live and still count as short-lived, and how many are needed before a
// repeat is worth reporting.
export const SHORT_LIFETIME_MS = 5000;
export const REPEAT_THRESHOLD = 10;
/**
 * The executions must fall inside one window to count as a burst.
 *
 * Without it the rule fires as soon as a total is reached, however long it took — and a logon
 * script that runs ten times over three months is not a beacon. A burst is the observation; a total
 * is just a count of executions.
 */
export const REPEAT_WINDOW_MS = 10 * 60 * 1000;

// Parents that legitimately start almost anything, so an "unexpected parent" finding against them
// would be noise: the shell, the service host, the scheduler, the installer.
const PERMISSIVE_PARENTS = new Set([
  "explorer.exe",
  "services.exe",
  "svchost.exe",
  "taskeng.exe",
  "taskhostw.exe",
  "msiexec.exe",
  "userinit.exe",
  "wininit.exe",
  "winlogon.exe",
  "cmd.exe",
  "powershell.exe",
  "pwsh.exe",
]);

// Escape every regex metacharacter, not just the dot. NEEDS_ARGUMENTS holds four safe names today;
// this stops the next name added to it from becoming a pattern.
function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function ms(iso: string): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

/** Lifetime in milliseconds, or null when either end was not recorded. */
export function lifetimeMs(r: Pick<ProcessRecord, "start" | "exit">): number | null {
  const a = ms(r.start);
  const b = ms(r.exit);
  if (a === null || b === null) return null;
  const d = b - a;
  // A negative lifetime means the clocks disagree or the fields were swapped. Either way it is not
  // evidence of anything, so it is discarded rather than reported as an instant exit.
  return d < 0 ? null : d;
}

/**
 * Identity for correlating records across tables.
 *
 * PID alone is not identity: Windows recycles PIDs, so two records sharing one may be two different
 * processes. Image and start time are what make it specific.
 */
export function processIdentity(
  r: Pick<ProcessRecord, "name" | "pid" | "start"> & { image?: string; host?: string },
): string {
  // The full image is part of identity: two binaries with the same basename at different paths are
  // different programs, and one of them being in \Temp\ is usually the point.
  return `${r.host ?? ""}|${(r.image || r.name).toLowerCase()}|${r.pid}|${r.start}`;
}

/**
 * A single process, judged on its own record.
 *
 * `corroborating` is required for the sacrificial-process rule: an argument-free rundll32 alone is a
 * shape, not a finding — Windows starts plenty. It becomes a lead when something else about the
 * same process is already odd.
 */
export function sacrificialSignal(
  r: ProcessRecord,
  corroborating: { shortLived?: boolean; unexpectedParent?: boolean; injectedInto?: boolean } = {},
): LifetimeSignal | null {
  // The importers' baseName helper preserves source case, so a case-sensitive lookup would miss
  // RUNDLL32.EXE — which is exactly how an attacker writes it.
  if (!NEEDS_ARGUMENTS.has(r.name.toLowerCase())) return null;

  // The distinction the whole rule rests on.
  if (!r.commandLineCaptured) return null;
  // A captured command line that merely repeats the image is still argument-free.
  const args = r.commandLine
    .replace(/^\s*"[^"]*"\s*/, "")
    .replace(new RegExp(`^\\s*\\S*${escapeRe(r.name)}\\s*`, "i"), "")
    .trim();
  if (args) return null;

  const also = [
    corroborating.injectedInto ? "memory in it was flagged as executable and private" : "",
    corroborating.shortLived ? "it exited within seconds" : "",
    corroborating.unexpectedParent ? `it was started by ${r.parentName || "an unexpected parent"}` : "",
  ].filter(Boolean);

  // Without a second observation this is a shape, not a lead. Windows itself starts argument-free
  // hosts, and reporting each one buries the one that matters.
  if (also.length === 0) return null;

  return {
    severity: "Medium",
    mitre: ["T1055"],
    note:
      `${r.name} was started with no arguments, which leaves it nothing to do — and ${also.join(", and ")}. ` +
      "That combination is consistent with a process spawned to be injected into. The command line " +
      "was recorded and was empty; this rule does not fire when none was recorded.",
  };
}

export interface RepeatCluster {
  name: string;
  count: number;
  windowMs: number;
  severity: Severity;
  note: string;
}

/**
 * Images spawned and gone again, repeatedly.
 *
 * Only records with BOTH a start and an exit count: without them the lifetime is unknown, and
 * counting unknown-lifetime records here would just count executions.
 */
export function repeatedShortLifetimes(
  records: readonly ProcessRecord[],
  opts: { shortMs?: number; threshold?: number; windowMs?: number } = {},
): RepeatCluster[] {
  const shortMs = opts.shortMs ?? SHORT_LIFETIME_MS;
  const threshold = opts.threshold ?? REPEAT_THRESHOLD;
  const windowMs = opts.windowMs ?? REPEAT_WINDOW_MS;

  const byName = new Map<string, number[]>();
  const seen = new Set<string>();
  for (const r of records) {
    // Deduplicate on full identity: the same process reported by two tables is one process.
    const id = processIdentity(r);
    if (seen.has(id)) continue;
    seen.add(id);
    const life = lifetimeMs(r);
    if (life === null || life > shortMs) continue;
    const started = ms(r.start);
    if (started === null) continue;
    const list = byName.get(r.name) ?? [];
    list.push(started);
    byName.set(r.name, list);
  }

  const out: RepeatCluster[] = [];
  for (const [name, times] of byName) {
    if (times.length < threshold) continue;
    times.sort((a, b) => a - b);
    // The densest run inside one window, not the total. A logon script that runs ten times over
    // three months is not a burst, and counting it as one is how this rule would have become noise.
    let best = { count: 0, span: 0 };
    let lo = 0;
    for (let hi = 0; hi < times.length; hi++) {
      while (times[hi] - times[lo] > windowMs) lo++;
      const count = hi - lo + 1;
      if (count > best.count) best = { count, span: times[hi] - times[lo] };
    }
    if (best.count < threshold) continue;
    out.push({
      name,
      count: best.count,
      windowMs: best.span,
      severity: "Low",
      note:
        `${name} started and exited within ${Math.round(shortMs / 1000)}s, ${best.count} times over ` +
        `${Math.round(best.span / 1000)}s. Repeated short-lived executions of one image are consistent ` +
        "with a loop — a beacon, a retry, or a tool working through a list — and equally with a " +
        "scheduled task or a health check. The pattern is the observation; what ran is the question.",
    });
  }
  return out.sort((a, b) => b.count - a.count);
}

/**
 * A parent that does not ordinarily start this child.
 *
 * Returns null when the parent was not recorded. A process whose parent is absent from the
 * collection is not an orphan — a snapshot taken after the parent exited looks exactly like that,
 * and so does any partial collection.
 */
export function unexpectedParentSignal(
  r: ProcessRecord,
  expectedParents: ReadonlyMap<string, ReadonlySet<string>>,
): LifetimeSignal | null {
  if (!r.parentName) return null; // not recorded — see above
  const expected = expectedParents.get(r.name);
  if (!expected || expected.size === 0) return null;
  const parent = r.parentName.toLowerCase();
  if (expected.has(parent)) return null;
  if (PERMISSIVE_PARENTS.has(parent)) return null;

  return {
    severity: "Low",
    mitre: [],
    note:
      `${r.name} was started by ${r.parentName}, where this image is normally started by ` +
      `${[...expected].join(" or ")}. An unusual parent is a lead; installers, management agents and ` +
      "wrappers legitimately produce unusual parentage.",
  };
}

// ─────────────────────────── the timeline pass ───────────────────────────

/**
 * A forensic event, reduced to the process fields this module needs.
 *
 * Deliberately structural. Reading a start or exit time out of a description string would be
 * guessing, and a guess here becomes a lifetime, which becomes a finding.
 */
export interface TimelineProcessEvent {
  description?: string;
  processName?: string;
  parentName?: string;
  pid?: number;
  commandLine?: string;
  timestamp?: string;
  severity?: Severity;
  mitreTechniques?: string[];
}

// Which images ordinarily start which. Small and specific on purpose: an expectation that is only
// roughly right produces a finding that is only roughly right.
/**
 * The marker this pass appends.
 *
 * Exported because correlate.ts must STRIP it before keying a duplicate: the derived note did not
 * exist before this change, so a stored marked event and a freshly imported unmarked one would key
 * differently and the row would duplicate on re-import.
 */
export const UNEXPECTED_PARENT_MARKER = "[unexpected parent:";

/** Same contract as UNEXPECTED_PARENT_MARKER — correlate.ts must strip it before keying. */
export const SACRIFICIAL_MARKER = "[sacrificial process:";

export const EXPECTED_PARENTS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ["lsass.exe", new Set(["wininit.exe"])],
  ["services.exe", new Set(["wininit.exe"])],
  // The leader SMSS is started by System; it then spawns a transient per-session copy for session 0
  // and for every user session, whose parent is smss.exe itself. Listing only "system" flagged every
  // ordinary session creation on the host.
  ["smss.exe", new Set(["system", "smss.exe"])],
  ["csrss.exe", new Set(["smss.exe"])],
  ["wininit.exe", new Set(["smss.exe"])],
  ["winlogon.exe", new Set(["smss.exe"])],
  ["spoolsv.exe", new Set(["services.exe"])],
  // lsm.exe is legacy: it does not exist as a standalone process on modern Windows, so an entry for
  // it can only produce findings on old builds where the expectation is also least certain.
]);

/**
 * Raise events whose parentage is not the ordinary one.
 *
 * Pure and idempotent: the marker is appended once, and severity uses a floor so re-running over an
 * already-marked timeline changes nothing. It only ever RAISES a grade — a process's parentage
 * cannot make other evidence about it less true.
 */
export function markProcessLifetimeSignals<T extends TimelineProcessEvent>(events: readonly T[]): T[] {
  // Processes the case has already flagged as holding executable private memory. That is the
  // corroboration the sacrificial rule needs: an argument-free host ALONE is a shape Windows
  // produces itself, and only becomes a lead when something else about the same process is odd.
  const injected = new Set<string>();
  for (const e of events) {
    const n = (e.processName ?? "").toLowerCase();
    if (n && /executable memory region flagged|malfind/i.test(e.description ?? "")) injected.add(n);
  }

  const rank: Record<string, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

  return events.map((e) => {
    const name = (e.processName ?? "").toLowerCase();
    if (!name) return e;
    if ((e.description ?? "").includes(UNEXPECTED_PARENT_MARKER)) return e;
    if ((e.description ?? "").includes(SACRIFICIAL_MARKER)) return e;

    const record: ProcessRecord = {
      image: name,
      name,
      pid: String(e.pid ?? ""),
      ppid: "",
      parentName: (e.parentName ?? "").toLowerCase(),
      start: e.timestamp ?? "",
      exit: "",
      commandLine: e.commandLine ?? "",
      // The distinction the sacrificial rule turns on. An event that carries no commandLine field
      // at all is one where none was CAPTURED — not one captured and found empty.
      commandLineCaptured: e.commandLine !== undefined,
    };

    const parentSignal = record.parentName ? unexpectedParentSignal(record, EXPECTED_PARENTS) : null;
    const sacrificial = sacrificialSignal(record, {
      unexpectedParent: !!parentSignal,
      injectedInto: injected.has(name),
    });

    // The sacrificial finding is the stronger statement, so it wins when both apply.
    const signal = sacrificial ?? parentSignal;
    if (!signal) return e;
    const marker = sacrificial ? SACRIFICIAL_MARKER : UNEXPECTED_PARENT_MARKER;

    const severity =
      rank[signal.severity] > rank[e.severity ?? "Info"] ? signal.severity : (e.severity ?? "Info");
    // The marker is appended AFTER clipping the base text, never before: clipping the joined
    // string let a long description push the marker off the end while the severity bump still
    // applied — a raised event with no stated reason. The clip keeps earlier passes' notes
    // (see derivedNote.ts).
    return {
      ...e,
      severity,
      ...(signal.mitre.length
        ? { mitreTechniques: [...new Set([...(e.mitreTechniques ?? []), ...signal.mitre])] }
        : {}),
      description: appendDerivedNote(e.description, marker, signal.note),
    };
  });
}

/** Kept as the previous name so existing callers and tests are unaffected. */
export const markUnexpectedParents = markProcessLifetimeSignals;
