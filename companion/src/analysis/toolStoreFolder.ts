// One user-writable folder that holds several attack tools (#1970 part 1).
//
// An operator often drops a whole kit into one folder: in the lab case PsExec, AdFind and WinRAR sat
// together in `C:\Users\Public\Music`. Each file row alone is an Info file-system record, and the
// staging rule in data/tags.yaml grades only a binary that sits directly in a staging folder, so
// every one of them was demoted and the AI never read the folder as one kit.
//
// What the pass establishes: on one named host, TOOL_STORE_MIN_TOOLS or more DIFFERENT tools from
// the curated list below have a record in the same user-writable folder (stagingPaths.ts
// isStagedPath; never under Program Files or the Windows system folders). One row per tool, the
// highest-graded and then the earliest, is raised to Medium and carries a note that names the folder
// and every tool. Medium is "a lead to triage", not a verdict: an administrator's tool folder in
// `C:\Users\Public` trips it too. It does not establish that any tool ran or who put it there.
//
// The curated list is built from the project's own name lists (attackToolNames.ts): the offensive
// tools the Prefetch grader marks High, its remote-execution and bulk-transfer names, the transfer
// tools of transferToolStaging.ts, the AD recon tools, plus portable archivers (rar, WinRAR, 7-Zip).
// LOLBins are left out: every host has them, and nobody brings them.
//
// Only ever raises. Its notes are recomputed on every merge, so a note whose other tools have left
// the case comes off; the severity it earned stays. Runs at merge time over the forensic timeline
// only (stateMerge.ts runTimelineChain), never over the super-timeline. Every row it reads names a
// listed tool in a user-writable folder, which is what mergeIndex.ts mergeLoadAlways keys on, so the
// incremental merge hands it all of its input. Info file rows of a LATER import are already demoted
// before this pass sees them — the same limit transferToolStaging.ts discloses.

import { SEVERITY_RANK, worstSeverity, type ForensicEvent } from "./stateTypes.js";
import { appendDerivedNote } from "./derivedNote.js";
import { filePath } from "./downloadExecution.js";
import { excerpt, hostOf, ms, neutral } from "./downloadCorroborationShared.js";
import { isStagedPath, isVendorRootPath } from "./stagingPaths.js";
import { AD_RECON_TOOLS, DUAL_USE, OFFENSIVE_TOOLS } from "./attackToolNames.js";
import { TRANSFER_TOOL_NAMES } from "./transferToolStaging.js";

export const TOOL_STORE_MARKER = "[attack tool store:";

/** Distinct tools one folder must hold before it is a lead. */
export const TOOL_STORE_MIN_TOOLS = 3;

// Remote execution (T1569.002) and bulk transfer (T1567.002) from the Prefetch grader's list.
const REMOTE_AND_TRANSFER = new Set(["T1569.002", "T1567.002"]);

// Portable archivers. Counted only inside a user-writable folder, like every tool here.
const ARCHIVERS: Readonly<Record<string, string>> = {
  "rar.exe": "winrar",
  "winrar.exe": "winrar",
  "7z.exe": "7-zip",
  "7za.exe": "7-zip",
  "7zr.exe": "7-zip",
  "7zg.exe": "7-zip",
};

// Binaries of one product, counted as one tool.
const ALIASES: Readonly<Record<string, string>> = {
  psexesvc: "psexec",
  megasync: "mega",
  megacmd: "mega",
  megatools: "mega",
  mimilib: "mimikatz",
};

const family = (token: string): string => ALIASES[token] ?? token;

// Exact file names → tool.
const EXACT: ReadonlyMap<string, string> = new Map([
  ...Object.entries(DUAL_USE)
    .filter(([, ids]) => ids.some((t) => REMOTE_AND_TRANSFER.has(t)))
    .map(([n]): [string, string] => [n, family(n.replace(/\.exe$/, ""))]),
  ...TRANSFER_TOOL_NAMES.map((n): [string, string] => [n, family(n.replace(/\.exe$/, ""))]),
  ...Object.entries(ARCHIVERS),
]);

// Name tokens → tool, for a binary or script that carries the token anywhere in its name
// (`mimikatz_x64.exe`, `SharpHound.ps1`).
const TOKEN_RES: readonly RegExp[] = [
  ...OFFENSIVE_TOOLS.map((r) => r.re),
  new RegExp(`(?:${AD_RECON_TOOLS.join("|")})`, "i"),
];
const TOOL_EXT = /\.(?:exe|dll|ps1)$/i;
const DEVICE_PREFIX = /^[\\/]{2}[.?][\\/](?=[A-Za-z]:)/;

const NAMED_MAX = 8;
const NOTE_MAX = 900;
const OWN_NOTE = /\s*\[attack tool store:[^\]]*\]/gu;

const leafOf = (path: string): string => {
  const p = path.replace(/\//g, "\\");
  return p.slice(p.lastIndexOf("\\") + 1).toLowerCase();
};
const parentOf = (path: string): string => {
  const p = path.replace(/\//g, "\\");
  return p.slice(0, Math.max(0, p.lastIndexOf("\\")));
};

/** The tool a file name belongs to, or null when the name is not on the curated list. */
export function toolFamilyOf(name: string): string | null {
  const leaf = leafOf(name);
  const exact = EXACT.get(leaf);
  if (exact) return exact;
  if (!TOOL_EXT.test(leaf)) return null;
  for (const re of TOKEN_RES) {
    const m = re.exec(leaf);
    if (m) return family(m[0].toLowerCase());
  }
  return null;
}

/** Whether a row names a listed tool inside a user-writable folder. */
function userWritable(relative: string): boolean {
  return isStagedPath(`\\${relative}`) && !isVendorRootPath(`c:\\${relative}`);
}

interface Row {
  event: ForensicEvent;
  host: string;
  tool: string;
  folder: string;
  time: number;
}

function rowOf(e: ForensicEvent): Row | null {
  if (!e.path) return null;
  const tool = toolFamilyOf(e.path);
  const host = hostOf(e);
  // A Win32 device prefix (`\\.\C:\…`, `\\?\C:\…`) names the same folder as the plain path.
  const file = filePath(e.path.replace(DEVICE_PREFIX, ""));
  if (!tool || !host || !file || !userWritable(file.relative)) return null;
  const folder = file.relative.slice(0, Math.max(0, file.relative.lastIndexOf("\\")));
  return { event: e, host, tool, folder, time: ms(e.timestamp) ?? Number.MAX_SAFE_INTEGER };
}

/** Whether a row names a listed tool in a user-writable folder on a named host. */
export function isToolStoreRow(e: ForensicEvent): boolean {
  return rowOf(e) !== null;
}

// The row that speaks for one tool: the highest grade, then the earliest, then the lowest id. A raised
// row outranks an Info row of the same tool that a later import adds, so the lead stays put.
const better = (a: Row, b: Row): boolean => {
  const ra = SEVERITY_RANK[a.event.severity ?? "Info"];
  const rb = SEVERITY_RANK[b.event.severity ?? "Info"];
  if (ra !== rb) return ra < rb;
  if (a.time !== b.time) return a.time < b.time;
  return a.event.id < b.event.id;
};

const clip = (s: string): string => (s.length > NOTE_MAX ? `${s.slice(0, NOTE_MAX - 1)}…` : s);

/** The note words for each lead row. */
function findStores(rows: readonly Row[]): Map<ForensicEvent, string> {
  const byFolder = new Map<string, Map<string, Row>>();
  for (const r of rows) {
    const key = `${r.host}|${r.folder}`;
    const tools = byFolder.get(key) ?? new Map<string, Row>();
    const cur = tools.get(r.tool);
    if (!cur || better(r, cur)) tools.set(r.tool, r);
    byFolder.set(key, tools);
  }
  const out = new Map<ForensicEvent, string>();
  for (const tools of byFolder.values()) {
    if (tools.size < TOOL_STORE_MIN_TOOLS) continue;
    const leads = [...tools.values()].sort((a, b) => a.tool.localeCompare(b.tool));
    const first = leads[0];
    const named = leads
      .slice(0, NAMED_MAX)
      .map((r) => `${r.tool} (row ${neutral(r.event.id).slice(0, 60)})`)
      .join(", ");
    const more = leads.length > NAMED_MAX ? `, and ${leads.length - NAMED_MAX} more` : "";
    const words = clip(
      `${leads.length} different attack tools in ${excerpt(parentOf(first.event.path ?? ""))} on ` +
        `${neutral(first.host).slice(0, 80)}: ${named}${more}`,
    );
    for (const r of leads) out.set(r.event, words);
  }
  return out;
}

/**
 * Raise one row per tool to Medium when a user-writable folder on one host holds
 * TOOL_STORE_MIN_TOOLS or more different attack tools. Only ever raises; recomputes its own notes on
 * every merge.
 */
export function linkToolStoreFolders(events: ForensicEvent[]): ForensicEvent[] {
  const rows = events.map(rowOf).filter((r): r is Row => r !== null);
  if (!rows.length) return events;
  const found = findStores(rows);
  const tool = new Set(rows.map((r) => r.event));
  return events.map((e): ForensicEvent => {
    if (!tool.has(e)) return e;
    const base = (e.description ?? "").replace(OWN_NOTE, "");
    const words = found.get(e);
    if (!words) return base === e.description ? e : { ...e, description: base };
    const severity = worstSeverity(e.severity ?? "Info", "Medium");
    // The same note already on the row: leave it where it is, so a re-merge never reorders notes.
    if ((e.description ?? "").includes(`${TOOL_STORE_MARKER} ${words}]`) && severity === e.severity) return e;
    return { ...e, severity, description: appendDerivedNote(base, TOOL_STORE_MARKER, words) };
  });
}
