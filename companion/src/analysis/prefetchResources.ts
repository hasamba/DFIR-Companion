// Finding companion payloads through Prefetch resource references (#909 item 10).
//
// A Prefetch file lists every file the executable touched during its first ten seconds — up to a
// thousand of them, with the volume they lived on. The importer kept the executable name and a run
// count and dropped the list, which is the half that answers "what else came with it".
//
// The question this module exists to serve: given one binary you already suspect, WHAT ELSE on this
// host referenced the same unusual files? A dropper and its payload share a staging directory. A
// renamed copy of a tool references the same helper DLL. Two executions of the same framework pull
// the same oddly-named resource. None of that is visible from executable names alone.
//
// ─────────────────────────── WHY COMMON RESOURCES MUST BE EXCLUDED ───────────────────────────
//
// Every process on Windows loads ntdll.dll, kernel32.dll and a hundred more. Scoring similarity
// without excluding them makes every pair of executables look related, which is the same as finding
// nothing — except that it looks like a finding. So only resources that are UNUSUAL in this
// collection count: a file referenced by one or two executables, in a location a shipped program
// does not use.
//
// ─────────────────────────── WHAT A REFERENCE IS AND IS NOT ───────────────────────────
//
//   • It is evidence the file was ACCESSED while that program started.
//   • It is NOT proof the DLL was loaded — Prefetch records what the loader touched, including
//     files it opened and rejected.
//   • It is NOT proof a user opened a document. A shell preview handler touches files nobody opened.
//   • A TRUSTED executable referencing a file does not clear that file. rundll32.exe is signed by
//     Microsoft and is how a great deal of malicious code runs; treating its references as
//     vouched-for would invert the question.
//
// Scoping is per host and per volume, because two hosts' Prefetch tells you nothing about each
// other and the same path on two volumes is two files.

/** One parsed Prefetch entry, with the reference list the artifact carries. */
export interface PrefetchEntry {
  executable: string; // as recorded, e.g. RUNDLL32.EXE
  host: string;
  volumeSerial: string; // distinguishes the same path on two volumes
  runCount: number;
  lastRun: string;
  /** Every file the executable referenced while starting. */
  referenced: string[];
}

/** A resource shared by more than one executable, and rare enough to mean something. */
export interface SharedResource {
  path: string;
  executables: string[];
  /** How many DISTINCT executables in this collection referenced it. */
  breadth: number;
}

// Locations a shipped program's resources live in. A reference under one of these is unremarkable
// however rare it is, because rarity in a small collection is not the same as rarity on the host.
const SYSTEM_LOCATION =
  /\\(?:windows\\(?:system32|syswow64|winsxs|assembly|servicing|microsoft\.net)|program files(?: \(x86\))?|programdata\\microsoft)\\/i;

// Locations a shipped program does NOT execute or stage from. A rare reference here is the shape
// worth reporting.
const USER_WRITABLE =
  /\\(?:users\\[^\\]+\\(?:appdata|downloads|desktop|documents)|windows\\temp|temp|perflogs|users\\public|\$recycle\.bin)\\/i;

/** How many executables may reference a resource before it stops being unusual. */
export const MAX_BREADTH = 3;

function norm(p: string): string {
  return String(p ?? "")
    .trim()
    .toLowerCase()
    .replace(/\//g, "\\")
    .replace(/^\\device\\harddiskvolume\d+/i, "");
}

/**
 * Resources referenced by more than one executable and by few enough to be worth looking at.
 *
 * Scoped to one host and volume by the caller. Common system libraries are excluded outright: every
 * process loads them, so scoring on them makes every pair look related, which looks like a finding
 * and is not one.
 */
export function sharedResources(
  entries: readonly PrefetchEntry[],
  opts: { maxBreadth?: number } = {},
): SharedResource[] {
  const maxBreadth = opts.maxBreadth ?? MAX_BREADTH;
  const byResource = new Map<string, Set<string>>();

  for (const e of entries) {
    for (const raw of e.referenced) {
      const p = norm(raw);
      if (!p) continue;
      // Excluded outright, not merely down-weighted: a shipped library referenced by two programs
      // says nothing about either.
      if (SYSTEM_LOCATION.test(p)) continue;
      const set = byResource.get(p) ?? new Set<string>();
      set.add(e.executable.toLowerCase());
      byResource.set(p, set);
    }
  }

  const out: SharedResource[] = [];
  for (const [path, execs] of byResource) {
    if (execs.size < 2) continue; // shared means more than one
    if (execs.size > maxBreadth) continue; // referenced widely: ordinary, whatever its location
    out.push({ path, executables: [...execs].sort(), breadth: execs.size });
  }
  return out.sort((a, b) => a.breadth - b.breadth || a.path.localeCompare(b.path));
}

export interface CompanionLead {
  suspect: string;
  companion: string;
  via: string[]; // the shared resources that linked them
  inUserWritable: boolean;
  note: string;
}

/**
 * Other executables that referenced the same unusual resources as one you already suspect.
 *
 * `suspect` is an executable name the case already has a reason to care about. This does not decide
 * what is suspicious; it answers "what else touched the same things".
 */
export function companionLeads(
  entries: readonly PrefetchEntry[],
  suspect: string,
  opts: { maxBreadth?: number } = {},
): CompanionLead[] {
  const target = suspect.toLowerCase();
  if (!entries.some((e) => e.executable.toLowerCase() === target)) return [];

  const shared = sharedResources(entries, opts).filter((r) => r.executables.includes(target));

  const byCompanion = new Map<string, string[]>();
  for (const r of shared) {
    for (const exe of r.executables) {
      if (exe === target) continue;
      const list = byCompanion.get(exe) ?? [];
      list.push(r.path);
      byCompanion.set(exe, list);
    }
  }

  const out: CompanionLead[] = [];
  for (const [companion, via] of byCompanion) {
    const inUserWritable = via.some((p) => USER_WRITABLE.test(p));
    out.push({
      suspect: target,
      companion,
      via,
      inUserWritable,
      note:
        `${companion} referenced ${via.length === 1 ? "the same file" : `${via.length} of the same files`} ` +
        `as ${target}: ${via.slice(0, 5).join(", ")}${via.length > 5 ? `, and ${via.length - 5} more` : ""}. ` +
        (inUserWritable
          ? "At least one is in user-writable space, where a shipped program does not keep resources. "
          : "") +
        "A Prefetch reference shows a file was accessed while the program started — not that a DLL " +
        "was loaded, and not that anyone opened a document. It links two executions; it does not " +
        "explain them.",
    });
  }
  return out.sort((a, b) => b.via.length - a.via.length);
}
