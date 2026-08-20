// Mapping for a THOR (Nextron) finding that arrives THROUGH Velociraptor rather than as a THOR file.
//
// `Generic.Scanner.ThorZIP/ThorResultsJson` streams THOR's JSON-Lines log back one row per line, so the
// findings reach the Velociraptor importer as ordinary rows. Left to the generic mapper they came out
// as "Velociraptor [Generic.Scanner.ThorZIP/ThorResultsJson]: Possibly Dangerous file found" — the
// artifact plumbing named, the FINDING not. Which file? Which log entry? Which rule fired? All of it
// sat in the row, unread: the generic mapper looks for `OSPath`/`Exe`/`Image`, and THOR writes `file`,
// `entry`, `process_name`, `parent`, `reason_N`, `rulename_N`.
//
// So the same scan disagreed with itself depending on how it was collected — analysis/thorImport.ts
// reads all of those when the analyst drops the JSON on the import button. This module is the shared
// answer: THOR rows are described, graded and keyed the THOR way on both paths.
//
// Its own module because analysis/velociraptorImport.ts is frozen by the file-size ledger (#384).
import { createHash } from "node:crypto";
import { getCI, isObject, str } from "./siemImport.js";
import type { Severity } from "./stateTypes.js";

type Row = Record<string, unknown>;

// THOR level → severity, identical to thorImport.ts LEVEL_SEVERITY.
const LEVEL: Record<string, Severity> = {
  alert: "Critical",
  warning: "High",
  notice: "Medium",
  info: "Info",
};

// What the finding is ABOUT, most specific first. `entry` beats `file` for a LogScan hit: the log file
// is where it was seen, the entry is what was seen.
const SUBJECT_KEYS = ["process_name", "entry", "file", "image_file", "filename", "path", "command"];

// Of those, the ones whose value is a filesystem path (or a process name), so the title can show just
// the leaf. `entry` and `command` are free text and stay whole.
const PATH_KEYS = new Set(["process_name", "file", "image_file", "filename", "path"]);

// Rendered into the [details] panel, in this order, when present. A curated list — a THOR ProcessCheck
// row carries ~80 columns and dumping them all is how a details panel becomes unreadable.
const DETAIL_KEYS = [
  "entry",
  "file",
  "image_file",
  "command",
  "process_name",
  "pid",
  "parent",
  "ppid",
  "owner",
  "image_owner",
  "type",
  "size",
  "sha256",
  "image_sha256",
  "md5",
  "image_md5",
  "created",
  "modified",
  "log_modified",
  "score",
];

function firstStr(row: Row, keys: readonly string[]): string {
  return firstEntry(row, keys)[1];
}

// The first populated key AND its value — the caller needs to know WHICH field answered, because a
// path and a log entry are shortened differently.
function firstEntry(row: Row, keys: readonly string[]): [string, string] {
  for (const k of keys) {
    const v = str(getCI(row, k)).trim();
    if (v) return [k, v];
  }
  return ["", ""];
}

function clip(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

/** A short, stable fingerprint of the WHOLE value — so a bounded key never loses its tail. */
function digest(s: string): string {
  return createHash("sha1").update(s).digest("hex").slice(0, 16);
}

const baseName = (s: string): string => s.trim().split(/[\\/]/).pop() || s.trim();

export interface ThorFields {
  severity: Severity;
  description: string; // the row TITLE — deliberately free of " - " (see dashboard-text.js splitEventTitle)
  detail: string; // the [details] panel body — rendered from the event's `message`
  aggKey: string;
  mitre: string[];
  path?: string;
  sha256?: string;
  md5?: string;
  processName?: string;
  parentName?: string;
}

/**
 * Read one row as a THOR finding, or `undefined` when it is not one.
 *
 * `module` + `message` + `level` is what importDetect uses to claim a whole FILE for the THOR importer,
 * and for a file that is enough — the analyst chose it. A hunt is a MIXED row stream, so those three
 * common column names alone would relabel any custom artifact that logs `level: "Warning"` as THOR,
 * regrade it on THOR's scale and strip its artifact title. So a row must also prove it is THOR's:
 * either it carries THOR's own scan envelope (`scanid`/`log_version`, present on every line of its JSON
 * log — all 1081 rows of the reference scan have both), or it came from an artifact that names THOR.
 */
export function thorFields(
  row: unknown,
  ctx: { artifact?: string; host?: string } = {},
): ThorFields | undefined {
  if (!isObject(row)) return undefined;
  const r: Row = row;
  const module = str(getCI(r, "module")).trim();
  const message = str(getCI(r, "message")).trim();
  const levelWord = str(getCI(r, "level")).trim();
  if (!module || !message || !levelWord) return undefined;
  const isThorSource =
    !!getCI(r, "scanid") || !!getCI(r, "log_version") || /\bthor\b|thorzip/i.test(ctx.artifact ?? "");
  if (!isThorSource) return undefined;
  const level = LEVEL[levelWord.toLowerCase()];
  if (!level) return undefined;

  const [subjectKey, subject] = firstEntry(r, SUBJECT_KEYS);
  // A PATH shortens to its basename — "mimikatz.exe" identifies the finding better than 90 characters
  // of parent directories. Anything else (a log entry, a command line) is prose and must NOT be
  // basenamed: splitting a Defender log line on its backslashes leaves a fragment starting mid-word.
  // Kept LONG on purpose. Two Defender log lines routinely share a 300-character prefix — the same
  // base64 blob or command line — and differ only near the end, and correlate's exact-duplicate step
  // keys on the DESCRIPTION: clip it short and two distinct findings collapse into one row. The
  // dashboard truncates the title for display at its own limit and shows the rest in [details], so the
  // length costs nothing on screen and is what keeps the findings apart.
  const shortSubject = PATH_KEYS.has(subjectKey) ? baseName(subject) : oneLine(subject);
  const description = clip(
    `THOR ${levelWord} [${module}]: ${message}${shortSubject ? ` — ${shortSubject}` : ""}`.replace(
      / - /g,
      " — ",
    ),
    600,
  );

  // IDENTITY vs CONTEXT. `path`/`sha256`/`md5` are what correlate.ts merges events on — step 1 unions
  // equal hashes, step 2 unions equal paths — so they must describe the SUBJECT of the finding and
  // nothing else. A LogScan row breaks that twice over: its `file` is the LOG the line was read from
  // (every hit in that log shares it) and its `sha256_1` is a file merely NAMED in the line. Handing
  // either over collapsed 18 distinct Defender detections and the mimikatz file finding into ONE
  // timeline row. Both still reach the analyst in `detail`, and the IOC scrape still harvests the
  // hashes — they simply stop being this event's identity.
  const subjectIsEntry = subjectKey === "entry";
  const path = subjectIsEntry
    ? undefined
    : firstStr(r, ["file", "image_file", "filepath", "image_path", "path"]) || undefined;
  const procName = firstStr(r, ["process_name", "image_name"]);
  const parent = firstStr(r, ["parent"]);

  return {
    // The scanner's grade, unmodified. Downgrading the Init/Startup notices (thorImport.ts drops
    // those modules outright) kept two licence banners out of the forensic timeline and cost the
    // reconciliation an analyst actually performs: THOR's summary reports 1 Alert / 40 Warnings /
    // 2 Notices, and the case showed no Medium at all. A timeline that disagrees with the scanner's
    // own totals is worth less than one carrying two banners.
    severity: level,
    description,
    detail: buildDetail(r),
    // Keyed like thorImport.ts's dedup signature — module + message + SUBJECT + rule — plus the HOST,
    // as the generic Velociraptor key has always done. Without the subject, 39 different suspicious log
    // entries collapse into one "×39" row naming none of them; without the host, the same finding on
    // two endpoints collapses into one row attributed to whichever host was read first (aggregateEvents
    // keeps only the first event's asset), and the second machine's compromise vanishes.
    // The subject and rule are HASHED, not truncated, into the key. Slicing a fixed width off the
    // front discards exactly the tail that tells two long log entries apart, and aggregateEvents then
    // collapses them into one counted row — the loss this subject-aware key exists to prevent.
    aggKey:
      `thor|${ctx.host ?? ""}|${module}|${message}|${digest(subject + "|" + firstStr(r, ["rulename_1", "matched_1", "reason_1"]))}`
        .toLowerCase()
        .slice(0, 400),
    mitre: pickTechniques(r),
    ...(path ? { path } : {}),
    ...(subjectIsEntry ? {} : (hash(r, ["sha256", "image_sha256"], 64) ?? {})),
    ...(subjectIsEntry ? {} : (hash(r, ["md5", "image_md5"], 32) ?? {})),
    ...(procName ? { processName: baseName(procName) } : {}),
    ...(parent ? { parentName: baseName(parent) } : {}),
  };
}

function hash(row: Row, keys: string[], len: number): { sha256: string } | { md5: string } | undefined {
  const v = firstStr(row, keys).toLowerCase();
  if (!new RegExp(`^[a-f0-9]{${len}}$`).test(v)) return undefined;
  return len === 64 ? { sha256: v } : { md5: v };
}

function oneLine(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

// MITRE technique ids out of THOR's tag/class fields (e.g. "T1059_001" in `tags_1`, "ATTACK.T1059").
function pickTechniques(row: Row): string[] {
  const blob = ["tags_1", "tags_2", "sigclass_1", "sigclass_2", "ref_1", "ref_2"]
    .map((k) => str(getCI(row, k)))
    .join(" ");
  const ids = new Set<string>();
  for (const m of blob.matchAll(/\bT(\d{4})[._](\d{3})\b|\bT(\d{4})\b/gi))
    ids.add(m[1] ? `T${m[1]}.${m[2]}` : `T${m[3]}`.toUpperCase());
  return [...ids];
}

// The [details] body: what THOR saw, then WHY it flagged it. Each reason keeps its own score and
// reference, because a single finding routinely fires several rules with very different weights.
function buildDetail(row: Row): string {
  const lines: string[] = [];
  for (const k of DETAIL_KEYS) {
    const v = oneLine(str(getCI(row, k)));
    if (v) lines.push(`${k}: ${v.slice(0, 400)}`);
  }
  for (let i = 1; i <= 4; i++) {
    const reason = oneLine(str(getCI(row, `reason_${i}`)));
    if (!reason) continue;
    const extra = [
      str(getCI(row, `rulename_${i}`)),
      str(getCI(row, `ref_${i}`)),
      str(getCI(row, `matched_${i}`)).slice(0, 120),
    ]
      .map((s) => oneLine(s))
      .filter(Boolean)
      .join(" | ");
    const score = str(getCI(row, `subscore_${i}`));
    lines.push(
      `reason ${i}: ${reason.slice(0, 300)}${extra ? ` (${extra})` : ""}${score ? ` [score ${score}]` : ""}`,
    );
  }
  return lines.join("\n");
}
