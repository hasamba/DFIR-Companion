// A bulk-transfer tool staged with its own config in one folder (#1955 part 1).
//
// exfilCorrelate.ts joins archive staging to a later upload. It never sees the kit an operator
// drops before the upload: `rclone.exe` and the `rclone.conf` that holds the remote and its
// credentials, written to one folder (often `C:\Users\Public\Music` or another staging spot) within
// minutes. Each file row alone is an Info file-system record, and the Amcache row for the same
// binary is Info too (kapeImport.ts / velociraptorImport.ts grade no Amcache row), so all of them
// are demoted out of the forensic timeline and the AI never reads them.
//
// What the pass establishes: on one named host, a transfer tool's binary and its config sit in the
// same folder, and the two file records are dated within STAGING_WINDOW_MS of each other. Both rows
// are raised to Medium and tagged T1567.002. A Prefetch, Amcache or process-start record on that
// host that names the tool's full path is raised to High: the staged tool also ran (Amcache is a
// presence record, but a staged kit beside it is the context that makes it worth reading). It does
// not establish that data left the host, what the remote was, or that the config was ever read.
//
// Only ever raises. Its notes are recomputed on every merge, so a note whose partner row has left
// the case comes off; the severity it earned stays. Runs at merge time over the forensic timeline
// only (stateMerge.ts runTimelineChain), never over the super-timeline. Every row it reads names a
// tool or config file by its last path segment, which is what mergeIndex.ts mergeLoadAlways keys
// on, so the incremental merge hands it all of its input.

import { worstSeverity, type ForensicEvent, type Severity } from "./stateTypes.js";
import { appendDerivedNote } from "./derivedNote.js";
import { filePath, sameLocation, type FilePath } from "./downloadExecution.js";
import { excerpt, hostOf, ms, neutral, veloAction } from "./downloadCorroborationShared.js";

export const TRANSFER_TOOL_STAGED_MARKER = "[transfer tool staged:";

/** The two file records must be dated this close to each other. */
export const STAGING_WINDOW_MS = 10 * 60_000;

const MEGA_CONFIGS = [".megarc", "megarc.ini"] as const;

// The tool binary → the config file it reads from its own folder. Restated, not imported:
// prefetchExecution.ts is analysis/ingest and this pass is analysis/timeline. The test pins every
// T1567.002 name there against TRANSFER_TOOL_NAMES below.
const TOOL_CONFIGS: Readonly<Record<string, readonly string[]>> = {
  "rclone.exe": ["rclone.conf"],
  "winscp.exe": ["winscp.ini"],
  "megatools.exe": MEGA_CONFIGS,
  "megacmd.exe": MEGA_CONFIGS,
  "megasync.exe": MEGA_CONFIGS,
};
// Transfer tools with no config file on disk by default: named so the list stays complete, never joined.
const EXECUTION_ONLY = ["restic.exe", "pscp.exe"] as const;

export const TRANSFER_TOOL_NAMES: readonly string[] = [...Object.keys(TOOL_CONFIGS), ...EXECUTION_ONLY];
const CONFIG_NAMES = new Set(Object.values(TOOL_CONFIGS).flat());

const PAIRS_NAMED_MAX = 4;
const NOTE_MAX = 900;
const OWN_NOTE = /\s*\[transfer tool staged:[^\]]*\]/gu;

const baseName = (path: string): string => {
  const p = path.replace(/\//g, "\\");
  return p.slice(p.lastIndexOf("\\") + 1).toLowerCase();
};
const parentOf = (path: string): string => {
  const p = path.replace(/\//g, "\\");
  return p.slice(0, Math.max(0, p.lastIndexOf("\\")));
};

/** Whether a row names a transfer tool or one of their config files by its last path segment. */
export function isTransferToolRow(e: Pick<ForensicEvent, "path">): boolean {
  if (!e.path) return false;
  const name = baseName(e.path);
  return name in TOOL_CONFIGS || CONFIG_NAMES.has(name);
}

const isExecutionRecord = (e: ForensicEvent): boolean =>
  /Prefetch|Amcache/i.test((e.sources ?? []).join(" ")) ||
  /prefetch|amcache/i.test(veloAction(e)) ||
  (e.canonical?.event?.category === "process" && e.canonical.event.type === "start");

const artifactOf = (e: ForensicEvent): string => {
  const words = `${(e.sources ?? []).join(" ")} ${veloAction(e)}`;
  if (/Prefetch/i.test(words)) return "Prefetch";
  if (/Amcache/i.test(words)) return "Amcache";
  return "process start";
};

interface Row {
  event: ForensicEvent;
  host: string;
  name: string;
  file: FilePath;
  folder: FilePath;
  time: number | null;
}

function rowOf(e: ForensicEvent): Row | null {
  if (!e.path || !isTransferToolRow(e)) return null;
  const host = hostOf(e);
  const file = filePath(e.path);
  if (!host || !file) return null;
  const parent = file.relative.slice(0, Math.max(0, file.relative.lastIndexOf("\\")));
  return {
    event: e,
    host,
    name: baseName(e.path),
    file,
    folder: { ...file, relative: parent },
    time: ms(e.timestamp),
  };
}

const push = <K, V>(m: Map<K, V[]>, k: K, v: V): void => {
  const list = m.get(k);
  if (list) list.push(v);
  else m.set(k, [v]);
};

const gap = (a: Row, b: Row): string =>
  `${Math.round(Math.abs((a.time ?? 0) - (b.time ?? 0)) / 1000)} s apart`;
const id = (r: Row): string => neutral(r.event.id).slice(0, 60);
const clip = (s: string): string => (s.length > NOTE_MAX ? `${s.slice(0, NOTE_MAX - 1)}…` : s);

function withoutOwnNote(description: string): string {
  return description.replace(OWN_NOTE, "");
}

/** The pairs and the execution records of the staged tools, as note words per row. */
function findStaging(rows: Row[]): Map<ForensicEvent, { words: string[]; raiseTo: Severity }> {
  const files = rows.filter((r) => !isExecutionRecord(r.event));
  const runs = rows.filter((r) => r.name in TOOL_CONFIGS && isExecutionRecord(r.event));
  const byFolder = new Map<string, Row[]>();
  for (const r of files) push(byFolder, `${r.host}|${r.folder.relative}`, r);
  const runsByPath = new Map<string, Row[]>();
  for (const r of runs) push(runsByPath, `${r.host}|${r.file.relative}`, r);

  const out = new Map<ForensicEvent, { words: string[]; raiseTo: Severity }>();
  const add = (r: Row, words: string, raiseTo: Severity): void => {
    const cur = out.get(r.event) ?? { words: [], raiseTo };
    if (cur.words.length < PAIRS_NAMED_MAX) cur.words.push(words);
    out.set(r.event, { words: cur.words, raiseTo: worstSeverity(cur.raiseTo, raiseTo) });
  };
  for (const group of byFolder.values()) {
    for (const tool of group) {
      const configs = TOOL_CONFIGS[tool.name];
      if (!configs || tool.time === null) continue;
      const partners = group.filter(
        (c) =>
          configs.includes(c.name) &&
          c.time !== null &&
          Math.abs(c.time - tool.time!) <= STAGING_WINDOW_MS &&
          sameLocation(tool.folder, c.folder).same,
      );
      if (!partners.length) continue;
      const ran = (runsByPath.get(`${tool.host}|${tool.file.relative}`) ?? []).filter(
        (x) => sameLocation(tool.file, x.file).same,
      );
      const folder = excerpt(parentOf(tool.event.path ?? ""));
      const where = `in ${folder} on ${neutral(tool.host).slice(0, 80)}`;
      const ranWords = ran.length
        ? `; tool also recorded by: ${ran
            .slice(0, PAIRS_NAMED_MAX)
            .map(
              (x) => `${artifactOf(x.event)} row ${id(x)} ${neutral(x.event.timestamp ?? "").slice(0, 40)}`,
            )
            .join(", ")}`
        : "";
      for (const c of partners) {
        add(
          tool,
          `${tool.name} beside its config ${c.name} (row ${id(c)}, ${gap(tool, c)}) ${where}${ranWords}`,
          "Medium",
        );
        add(c, `config for ${tool.name} (row ${id(tool)}, ${gap(tool, c)}) ${where}${ranWords}`, "Medium");
        for (const x of ran)
          add(
            x,
            `${tool.name} staged with its config ${c.name} ${where} (rows ${id(tool)}, ${id(c)})`,
            "High",
          );
      }
    }
  }
  return out;
}

/**
 * Raise a transfer tool and its config staged in one folder on one host to Medium, and the record
 * that the tool ran to High. Only ever raises; recomputes its own notes on every merge.
 */
export function linkTransferToolStaging(events: ForensicEvent[]): ForensicEvent[] {
  const rows = events.map(rowOf).filter((r): r is Row => r !== null);
  if (!rows.length) return events;
  const found = findStaging(rows);
  return events.map((e): ForensicEvent => {
    if (!isTransferToolRow(e)) return e;
    const base = withoutOwnNote(e.description ?? "");
    const hit = found.get(e);
    if (!hit) return base === e.description ? e : { ...e, description: base };
    const mitre = (e.mitreTechniques ?? []).includes("T1567.002")
      ? e.mitreTechniques
      : [...(e.mitreTechniques ?? []), "T1567.002"];
    const severity = worstSeverity(e.severity ?? "Info", hit.raiseTo);
    const note = `${TRANSFER_TOOL_STAGED_MARKER} ${clip(hit.words.join("; "))}]`;
    // The same note already on the row: leave it where it is, so a re-merge never reorders notes.
    if ((e.description ?? "").includes(note) && severity === e.severity && mitre === e.mitreTechniques)
      return e;
    return {
      ...e,
      severity,
      mitreTechniques: mitre,
      description: appendDerivedNote(base, TRANSFER_TOOL_STAGED_MARKER, clip(hit.words.join("; "))),
    };
  });
}
