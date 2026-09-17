// A download mark corroborated by the evidence the same file ran, and a hidden stream by the
// command line that referenced it (#932 item 3, second half — #985).
//
// ntfsStreams.ts (#984) made a download mark say what it establishes — where a file came from,
// not that it ran — and took the execution techniques off it. The evidence that the file ran lives
// in OTHER uploads: Prefetch, UserAssist, Sysmon 1 / Security 4688 / EDR process starts. They meet
// here, in a merge-time pass over the forensic timeline, like the timestomp corroboration (#909
// item 8). UserAssist is partial by design — it only records programs launched through Explorer
// (refutationGate.ts's EVIDENCE_CLASS_SOURCES excludes it for exactly that reason, when deciding
// whether an ABSENCE proves nothing ran) — but that caveat is about absence, not presence; a
// UserAssist row that IS there is as real a "this ran" record as Prefetch.
//
// What the pass establishes: that a process-start, Prefetch, or UserAssist record names the SAME
// file — the same host, the same volume where both say one, the same path below the volume root,
// and the same bytes where both carry a digest — and when that record is dated relative to the
// mark row's own anchor. It does not establish that a user opened the file (no technique is added),
// that a file with no mark is local, that a `.zip`'s mark covers what was extracted, or that a run
// within two seconds of the anchor came after it. Presence records (Amcache, ShimCache) are listed
// as presence and raise nothing. A hash that differs vetoes a path match: a reused path is not the
// same file.
//
// Two import paths name these tools differently. KAPE's importer (kapeImport.ts) stamps `sources`
// with the tool's own name ("Prefetch", "Amcache", "ShimCache"). Velociraptor's importer folds every
// artifact through one generic event shape (`actionEvent()`) that always sets `sources: ["Velociraptor"]`
// — the tool name only survives in `description`, in the fixed `[<artifact>]: <action>` segment the
// importer's own code writes, never in the attacker-influenced subject text that follows. `artifactOf`/
// `classify` below fall back to that segment, bounded so it can't run into the subject (#985).
//
// The boundary's cost, said: "nothing automatic reads the raw record" (ARCHITECTURE.md), so a
// Prefetch row imported BEFORE its mark was demoted to the super-timeline and is out of reach. A
// record that corroborates a mark is itself raised so it survives demote; the manual says which
// order to import in. The notes are recomputed from the current evidence on every merge.
//
// A third join — a mark's own download URL or referrer against a Velociraptor browser-history
// visit that precedes it, the browser-origin half #985 asks for — lives in downloadVisitOrigin.ts
// (split out for the file-size ledger, #384). Same posture: no technique is added, and a mark is
// raised no higher than Medium, below what real execution evidence earns.

import type { Severity } from "./stateTypes.js";
import { appendDerivedNote, splitDerivedNotes } from "./derivedNote.js";
import {
  type TimelineEventShape,
  ORDER_TOLERANCE_MS,
  neutral,
  excerpt,
  ms,
  hostOf,
  veloAction,
} from "./downloadCorroborationShared.js";
import {
  browserVisitCorroboration,
  BROWSER_VISIT_MARKER,
  REFERRER_VISIT_MARKER,
  VISIT_PRECEDES_MARK_MARKER,
} from "./downloadVisitOrigin.js";

// The timeline layer may not import the ingest layer (ARCHITECTURE.md), so the three readings this
// pass shares with ntfsStreams.ts / recordIdentity.ts are restated here and pinned against their
// originals in tests/analysis/downloadExecution.test.ts.

/** The words a mark row carries (ntfsStreams.ts `markWords` + PROVENANCE_NOTE). */
const MARK_WORDS =
  /downloaded from (?:the [A-Za-z ]+ zone|zone \S+)[\s\S]*download provenance, not execution/;

/** `<hostPath>:<stream>` — the stream is what follows the first colon after the last separator (ntfsStreams.ts `splitStream`). */
export function splitStream(path: string): { hostPath: string; stream: string } {
  const sep = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  const name = path.slice(sep + 1);
  const colon = name.indexOf(":");
  if (colon < 0) return { hostPath: path, stream: "" };
  if (sep < 0 && colon === 1 && /^[A-Za-z]$/.test(name[0])) return { hostPath: path, stream: "" };
  const stream = name.slice(colon + 1).replace(/:\$[A-Za-z_]+$/, "");
  return { hostPath: path.slice(0, sep + 1) + name.slice(0, colon), stream };
}

/** The markers this pass appends. Stripped by correlate.ts before a duplicate key is taken. */
export const DOWNLOAD_EXECUTED_MARKER = "[download-marked file executed:";
export const RAN_MARKED_FILE_MARKER = "[ran a download-marked file:";
export const STREAM_REFERENCED_MARKER = "[stream referenced by a command line:";
export const STREAM_REFERENCE_MARKER = "[command line references a stream:";
export const YARA_MATCHES_MARK_MARKER = "[matches a download mark:";

/** Executions named per mark; the rest are counted. */
export const EXECUTIONS_NAMED_MAX = 8;
const COMMAND_LINE_SCAN_MAX = 4096;
/** Records indexed per path or hash bucket; the rest are counted, never read. */
const BUCKET_MAX = 64;
/** Marks named on one corroborating execution row; the rest are counted. */
const MARKS_PER_CORROBORATOR_MAX = 4;
/** Command lines named on one stream row; the rest are counted. */
const COMMANDS_PER_STREAM_MAX = 4;
const REFERENCES_PER_COMMAND_MAX = 4;
const NOTE_MAX = 900;

const RANK: Record<string, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

// ───────────────────────────── paths ─────────────────────────────

export interface FilePath {
  /** The volume as the record spells it: a drive letter (`c`), a `{guid}`, or "" when it names none. */
  volume: string;
  volumeKind: "drive" | "guid" | "none";
  /** Below the volume root, backslashes, case-folded, no leading separator. */
  relative: string;
}

/**
 * The path a record carries, split into the volume it names and the path below the root.
 * MFTECmd writes `.\Users\x\a.exe` (no volume); PECmd `\VOLUME{guid}\USERS\X\A.EXE`; Sysmon
 * `C:\Users\x\a.exe`. Junctions, 8.3 names and `\\?\` device paths are not resolved.
 */
export function filePath(raw: string): FilePath | null {
  let p = raw.trim().replace(/\//g, "\\");
  if (!p) return null;
  let volume = "";
  let volumeKind: FilePath["volumeKind"] = "none";
  const guid = /^\\VOLUME\{([^}]+)\}/i.exec(p);
  const drive = /^([A-Za-z]):/.exec(p);
  if (guid) {
    volume = `{${guid[1].toLowerCase()}}`;
    volumeKind = "guid";
    p = p.slice(guid[0].length);
  } else if (drive) {
    volume = drive[1].toLowerCase();
    volumeKind = "drive";
    p = p.slice(2);
  } else if (p.startsWith(".\\")) p = p.slice(1);
  const relative = p.replace(/^\\+/, "").toLowerCase();
  return relative ? { volume, volumeKind, relative } : null;
}

/** Whether two records name one file's location: the same relative path, and no disagreeing volume. */
export function sameLocation(a: FilePath, b: FilePath): { same: boolean; volumeNote?: string } {
  if (a.relative !== b.relative) return { same: false };
  if (a.volumeKind === "none" || b.volumeKind === "none")
    return { same: true, volumeNote: "volume not compared (one record names none)" };
  if (a.volumeKind !== b.volumeKind)
    return { same: true, volumeNote: "volume not compared (GUID vs drive letter)" };
  return { same: a.volume === b.volume };
}

// ───────────────────────────── time ─────────────────────────────

function gapWords(gapMs: number): string {
  const s = Math.round(Math.abs(gapMs) / 1000);
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86_400) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86_400)} d`;
}

/** What the anchor of a mark row's time IS: a stream's creation (Sysmon 15), or the host file's recorded creation (MFT). */
function anchorWords(mark: TimelineEventShape): string {
  return (mark.sources ?? []).some((s) => /MFT/i.test(s))
    ? "the host file's recorded creation time"
    : "the mark's creation time";
}

/** The order against the anchor named in the note's preface: a gap, or why none is established. */
function orderWords(run: number | null, anchor: number | null): string {
  if (run === null || anchor === null) return "order not established (no readable time)";
  const gap = run - anchor;
  if (Math.abs(gap) <= ORDER_TOLERANCE_MS)
    return `order not established (within ${ORDER_TOLERANCE_MS / 1000} s)`;
  return gap > 0 ? `${gapWords(gap)} after` : `${gapWords(gap)} before`;
}

// ───────────────────────────── records ─────────────────────────────

type Kind = "mark" | "execution" | "presence" | "stream" | "detection";

interface Indexed<T> {
  event: T;
  kind: Kind;
  host: string;
  file: FilePath;
  artifact: string;
  /** Whether this record's own sha256/md5 is real, observed identity of the file it names — false
   * for a CLI YARA row, whose hash comes from the rule author's reference-sample metadata, never a
   * hash the CLI computes of the file it scanned (#985 item 4, design review). Read at both the
   * hash-bucket build/read sites AND the path-bucket veto (a false value must never let this
   * record's hash reject an otherwise-valid path match, nor let it join or be joined by hash). */
  identityHash: boolean;
  /** Whether a match on this record should raise the mark to the record's OWN graded severity,
   * rather than a flat tier — true for THOR and Velociraptor-native YARA (both carry a real,
   * context-graded severity scale: yaraGrade.ts's gradeYaraHit()), false for CLI YARA (its severity
   * floors at Medium regardless of confidence, so it keeps the established flat-High raise). Read
   * instead of comparing the `artifact` label string — a string compare is exactly the fragile
   * pattern that caused a regression when this rule was first added for THOR (#985 item 4, 985-1a-2
   * design review, finding F5). */
  proportionalSeverity: boolean;
}

const isMark = (e: TimelineEventShape): boolean =>
  !!e.path && MARK_WORDS.test(splitDerivedNotes(e.description).base);

const isProcessStart = (e: TimelineEventShape): boolean =>
  e.canonical?.event?.category === "process" && e.canonical.event.type === "start";

// `veloAction` (imported) reads Velociraptor's `[<artifact>]: <action>` segment, gated on
// `sources` naming Velociraptor — see downloadCorroborationShared.ts for the spoof-protection
// reasoning.

// The raw YARA CLI importer's own fixed description prefix (yaraImport.ts's parseYaraOutput):
// "YARA: <rule> matched <file>...". Only the CLI path is recognised here — Velociraptor's own
// native YARA scanning is a documented follow-up (985-1a-2): its description is rewritten by a
// LATER, generic artifact-prefix step this file cannot see at classification time, and its
// self-scan/volatile exclusion signal does not survive that rewrite reliably (see the design doc).
const YARA_CLI_RULE = /^YARA: (\S+) matched/;

// A THOR (Nextron) finding: the standalone importer (`sources: ["THOR"]`, thorImport.ts) or one
// streamed through Velociraptor (`sources: ["Velociraptor"]`, thorRowMap.ts's thorFields() —
// description begins "THOR <level> [<module>]: ...", a prefix Velociraptor's generic artifact-name
// injection explicitly exempts THOR rows from, so it stays stable, unlike CLI YARA's raw text).
// Gated on `sources` first, like every other description-text detector in this file (`veloAction`,
// CLI YARA's own `sources.includes("YARA")`) — an ungated `/^THOR /` test would let an unrelated
// row spoof a match by copying the literal prefix into its own description (#985 item 4, 985-1a-3
// design review, finding F5).
const isThor = (e: TimelineEventShape): boolean =>
  (e.sources ?? []).includes("THOR") ||
  ((e.sources ?? []).includes("Velociraptor") && /^THOR /.test(e.description ?? ""));

// A Velociraptor-native YARA hit (velociraptorImport.ts's mapYara — DetectRaptor.Generic.
// Detection.YaraFile, Windows.Detection.Yara.Glob/Process). mapYara's own description starts
// "Velociraptor YARA: <rule> - ...", which the generic artifact-prefix injection rewrites to
// "Velociraptor [<artifact>] YARA: <rule> - ..." — the injection only touches the literal
// `^Velociraptor` prefix, so the `YARA: ` marker survives shifted, well inside mapYara's own
// 600-char cap. Anchored to the START of the description (not a loose substring test) so a
// coincidental "YARA:" elsewhere in an unrelated row's own text can never match, and gated on
// `sources` first like every other description-text detector in this file (#985 item 4, 985-1a-2
// design review).
const VELO_YARA_RULE = /^Velociraptor(?: \[[^\]]*\])? YARA: (\S+)/;
const isVeloYara = (e: TimelineEventShape): boolean =>
  (e.sources ?? []).includes("Velociraptor") && VELO_YARA_RULE.test(e.description ?? "");

function artifactOf(e: TimelineEventShape): string {
  const src = (e.sources ?? []).join(" ");
  const action = veloAction(e);
  // Checked first (THOR, then Velociraptor-native YARA): both findings' own messages routinely name
  // a Windows artifact they flagged (a Sysmon-sourced log line, an event ID 4688 hit, a rule/hit-
  // context excerpt) — the Sysmon/4688 checks below, run against raw description text, would
  // otherwise mislabel a real row (#985 item 4, 985-1a-3 design review finding F7, reconfirmed for
  // this leg by 985-1a-2's design review).
  if (isThor(e)) return "THOR";
  if (isVeloYara(e)) {
    const rule = VELO_YARA_RULE.exec(e.description ?? "")?.[1];
    return `Velociraptor YARA: ${rule ?? "rule"}`;
  }
  if (/Prefetch/i.test(src) || /prefetch/i.test(action)) return "Prefetch";
  if (/UserAssist/i.test(src) || /UserAssist/i.test(action)) return "UserAssist";
  if (/Amcache/i.test(src) || /Amcache/i.test(action)) return "Amcache";
  if (/ShimCache/i.test(src) || /ShimCache/i.test(action)) return "ShimCache";
  if (/Sysmon/i.test(src) || /Sysmon/i.test(e.description ?? "")) return "Sysmon 1";
  if (/4688/.test(e.description ?? "")) return "Security 4688";
  if ((e.sources ?? []).includes("YARA")) {
    const rule = YARA_CLI_RULE.exec(e.description ?? "")?.[1];
    return `YARA: ${rule ?? "rule"}`;
  }
  return src || "process start";
}

function classify<T extends TimelineEventShape>(e: T): Indexed<T> | null {
  if (!e.path) return null;
  const src = (e.sources ?? []).join(" ");
  const action = veloAction(e);
  const isCliYara = (e.sources ?? []).includes("YARA");
  // Checked before the execution-kind chain, not just for the label reasons above: a memory-only
  // Velociraptor YARA hit carries no observation time to order against, so it must never fall
  // through to "execution" and be treated as a confirmed run — a content match is weaker evidence
  // than a process start, even though mapYara sets no `canonical` field today (#985 item 4,
  // 985-1a-2 design review, finding F3 — defensive against a future change).
  const isVeloYaraRow = isVeloYara(e);
  let kind: Kind | null = null;
  if (isMark(e)) kind = "mark";
  else if (isThor(e) || isVeloYaraRow) kind = "detection";
  else if (
    /Prefetch/i.test(src) ||
    /prefetch/i.test(action) ||
    /UserAssist/i.test(src) ||
    /UserAssist/i.test(action) ||
    isProcessStart(e)
  )
    kind = "execution";
  else if (/Amcache|ShimCache/i.test(src) || /Amcache|ShimCache/i.test(action)) kind = "presence";
  else if (isCliYara) kind = "detection";
  if (!kind) return null;
  const file = filePath(e.path);
  if (!file) return null;
  return {
    event: e,
    kind,
    host: hostOf(e),
    file,
    artifact: artifactOf(e),
    identityHash: !isCliYara,
    proportionalSeverity: isThor(e) || isVeloYaraRow,
  };
}

/** A digest disagreement between two rows that both carry one kind — SHA-256 decides over MD5. */
export function hashVeto(a: TimelineEventShape, b: TimelineEventShape): boolean {
  if (a.sha256 && b.sha256) return a.sha256.toLowerCase() !== b.sha256.toLowerCase();
  if (a.md5 && b.md5) return a.md5.toLowerCase() !== b.md5.toLowerCase();
  return false;
}
export const sameHash = (a: TimelineEventShape, b: TimelineEventShape): boolean =>
  (!!a.sha256 && !!b.sha256 && a.sha256.toLowerCase() === b.sha256.toLowerCase()) ||
  (!!a.md5 && !!b.md5 && a.md5.toLowerCase() === b.md5.toLowerCase());

// ───────────────────────────── the mark → execution pass ─────────────────────────────

interface Match<T> {
  record: Indexed<T>;
  by: "path" | "hash";
  volumeNote?: string;
  hostNote?: string;
}

/** A bounded index bucket: the first BUCKET_MAX records read, the rest counted. */
interface Bucket<T> {
  records: Indexed<T>[];
  beyond: number;
}

function addToBucket<T>(map: Map<string, Bucket<T>>, key: string, r: Indexed<T>): void {
  const b = map.get(key) ?? map.set(key, { records: [], beyond: 0 }).get(key)!;
  if (b.records.length < BUCKET_MAX) b.records.push(r);
  else b.beyond += 1;
}

/**
 * The execution and presence records that name the mark's file. Eligibility first — the same
 * location (or the same bytes), no digest disagreement — then the host rule over the ELIGIBLE
 * records only: two named hosts must agree; an unnamed record attaches only when the eligible
 * records name at most one host.
 */
function candidatesFor<T extends TimelineEventShape>(
  mark: Indexed<T>,
  byPath: Map<string, Bucket<T>>,
  byHash: Map<string, Bucket<T>>,
): { matches: Match<T>[]; unattributed: number; reused: number; beyondIndex: number } {
  const pathBucket = byPath.get(mark.file.relative);
  const hashBuckets = [mark.event.sha256, mark.event.md5]
    .filter((h): h is string => !!h)
    .map((h) => byHash.get(h.toLowerCase()))
    .filter((b): b is Bucket<T> => !!b);
  let reused = 0;
  const eligible: Omit<Match<T>, "hostNote">[] = [];
  const seen = new Set<Indexed<T>>();
  for (const r of pathBucket?.records ?? []) {
    if (r === mark || seen.has(r)) continue;
    const loc = sameLocation(mark.file, r.file);
    if (!loc.same) continue;
    if (r.identityHash && hashVeto(mark.event, r.event)) {
      reused += 1;
      continue;
    }
    seen.add(r);
    eligible.push({ record: r, by: "path", ...(loc.volumeNote ? { volumeNote: loc.volumeNote } : {}) });
  }
  for (const b of hashBuckets)
    for (const r of b.records) {
      // Detection-kind (THOR/YARA) admitted too — only ever reaches this bucket when its own hash
      // is real identity (identityHash: true), which the write side already gates (#985 item 4,
      // 985-1a-3 design review, finding F1: this read-side filter used to drop it silently).
      if (r === mark || seen.has(r) || (r.kind !== "execution" && r.kind !== "detection")) continue;
      // The same bytes — SHA-256 decides when both carry it, so a matching MD5 beside a
      // differing SHA-256 is a disagreement, not a match.
      if (hashVeto(mark.event, r.event) || !sameHash(mark.event, r.event)) continue;
      seen.add(r);
      eligible.push({ record: r, by: "hash" });
    }
  const namedHosts = new Set([mark.host, ...eligible.map((m) => m.record.host)].filter(Boolean));
  const matches: Match<T>[] = [];
  let unattributed = 0;
  for (const m of eligible) {
    const r = m.record;
    if (mark.host && r.host) {
      if (mark.host === r.host) matches.push(m);
      continue;
    }
    if (namedHosts.size > 1) {
      unattributed += 1;
      continue;
    }
    matches.push({
      ...m,
      hostNote:
        namedHosts.size === 1
          ? `host not named on one record — attributed to the case's one named host, ${neutral([...namedHosts][0]).slice(0, 80)}`
          : "host not named on either record",
    });
  }
  matches.sort(
    (a, b) =>
      (a.record.event.timestamp ?? "").localeCompare(b.record.event.timestamp ?? "") ||
      a.record.artifact.localeCompare(b.record.artifact) ||
      a.record.host.localeCompare(b.record.host),
  );
  const beyondIndex = (pathBucket?.beyond ?? 0) + hashBuckets.reduce((n, b) => n + b.beyond, 0);
  return { matches, unattributed, reused, beyondIndex };
}

/** One match's words; the anchor and the host rule are said once in the preface. */
function matchWords<T extends TimelineEventShape>(
  m: Match<T>,
  mark: Indexed<T>,
  anchor: number | null,
): string {
  const r = m.record;
  const when = r.event.timestamp ? neutral(r.event.timestamp).slice(0, 40) : "no time";
  const order = r.kind === "execution" ? `, ${orderWords(ms(r.event.timestamp), anchor)}` : "";
  const EXECUTION_WHAT: Record<string, string> = { Prefetch: "last run", UserAssist: "ran" };
  const DETECTION_WHAT: Record<string, string> = { THOR: "flagged" };
  const what =
    r.kind === "execution"
      ? (EXECUTION_WHAT[r.artifact] ?? "process start")
      : r.kind === "detection"
        ? (DETECTION_WHAT[r.artifact] ?? "content match")
        : "present";
  const notes = [
    r.kind === "presence" ? "not an execution record" : "",
    m.by === "hash" ? `by hash, at ${excerpt(r.event.path ?? "")}` : "",
    m.volumeNote === "volume not compared (GUID vs drive letter)" ? m.volumeNote : "",
  ]
    .filter(Boolean)
    .join("; ");
  return `${neutral(r.artifact).slice(0, 40)} ${what} ${when}${order}${notes ? ` (${notes})` : ""}`;
}

/** What every match in a mark's note is read against: the anchor, and how hosts and volumes were compared. */
function preface<T extends TimelineEventShape>(mark: Indexed<T>, matches: Match<T>[]): string {
  const parts = [`against ${anchorWords(mark.event)}`];
  const hostNote = matches.find((m) => m.hostNote)?.hostNote;
  if (hostNote) parts.push(hostNote);
  if (matches.some((m) => m.volumeNote === "volume not compared (one record names none)"))
    parts.push("volume not compared (one record names none)");
  return parts.join("; ");
}

// ───────────────────────────── the stream → command line pass ─────────────────────────────

// A `file.ext:stream` token: the part before the colon is a path or file name ending in an
// extension — never a lone drive letter — and the part after is a stream name. Linear: each
// class is distinct from its neighbours.
const STREAM_REF =
  /(?:^|[\s"'=,(])((?:[A-Za-z]:\\|\\\\|\.{1,2}\\)?[^\s"'<>|:*?]*?[^\s"'<>|:*?\\]+\.[A-Za-z0-9]{1,8}):([A-Za-z0-9_$.\-{}]{1,255})(?=[\s"',)]|$)/g;

export interface StreamReference {
  file: string;
  stream: string;
  /** Absolute (a drive or UNC path) or bare/relative — only an absolute reference resolves to a row. */
  absolute: boolean;
}

/** The `file:stream` references a command line carries, bounded. */
export function streamReferences(commandLine: string): StreamReference[] {
  const text = commandLine.slice(0, COMMAND_LINE_SCAN_MAX);
  const out: StreamReference[] = [];
  STREAM_REF.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = STREAM_REF.exec(text)) && out.length < REFERENCES_PER_COMMAND_MAX) {
    const file = m[1];
    const stream = m[2].replace(/[.,;]+$/, "");
    if (!stream || /^[A-Za-z]$/.test(file)) continue;
    out.push({ file, stream, absolute: /^(?:[A-Za-z]:\\|\\\\)/.test(file) });
  }
  return out;
}

const isHiddenStream = (e: TimelineEventShape): boolean => {
  if (!e.path || isMark(e)) return false;
  const { stream } = splitStream(e.path);
  return !!stream && RANK[e.severity ?? "Info"] >= RANK.Medium;
};

// ───────────────────────────── the pass ─────────────────────────────

const MARKERS = [
  DOWNLOAD_EXECUTED_MARKER,
  RAN_MARKED_FILE_MARKER,
  STREAM_REFERENCED_MARKER,
  STREAM_REFERENCE_MARKER,
  BROWSER_VISIT_MARKER,
  REFERRER_VISIT_MARKER,
  VISIT_PRECEDES_MARK_MARKER,
  YARA_MATCHES_MARK_MARKER,
];
const NOTE_NAMES = MARKERS.map((m) => m.slice(1, -1));

/** The description with this pass's own notes removed — the notes are recomputed on every merge. */
function withoutOwnNotes(description: string | undefined): string {
  const { base, notes } = splitDerivedNotes(description);
  if (!notes) return base;
  // Drop only our notes; keep other passes' notes in place, in order.
  const kept = notes.replace(
    new RegExp(
      `\\s*\\[(?:${NOTE_NAMES.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")}):[\\s\\S]{0,1200}?\\]`,
      "gu",
    ),
    "",
  );
  return [base, kept.trim()].filter(Boolean).join(" ");
}

function raise<T extends TimelineEventShape>(e: T, to: Severity): Severity {
  return RANK[to] > RANK[e.severity ?? "Info"] ? to : (e.severity ?? "Info");
}

const clipNote = (s: string): string => (s.length > NOTE_MAX ? `${s.slice(0, NOTE_MAX - 1)}…` : s);

/**
 * Corroborate every download mark with the execution and presence records of the same file, and
 * every hidden stream with the command line that referenced it. Only ever raises; recomputes its
 * own notes from the current evidence on every merge.
 */
export function corroborateDownloadExecution<T extends TimelineEventShape>(events: readonly T[]): T[] {
  const anyMark = events.some(isMark);
  const anyStream = events.some(isHiddenStream);
  if (!anyMark && !anyStream)
    // Nothing to corroborate — but a note this pass wrote earlier, on a row whose evidence has
    // since left the case, is stale and comes off. Severity stays: the pass only ever raises.
    return events.map((e) => {
      const description = withoutOwnNotes(e.description);
      return description === (e.description ?? "") ? e : { ...e, description };
    });

  const indexed = events.map(classify);
  const byPath = new Map<string, Bucket<T>>();
  const byHash = new Map<string, Bucket<T>>();
  for (const r of indexed) {
    if (!r || r.kind === "mark") continue;
    addToBucket(byPath, r.file.relative, r);
    // A record whose own hash isn't real identity (a CLI YARA row) must never be findable BY
    // hash either — not just never add itself (#985 item 4, design review).
    if (r.identityHash)
      for (const h of [r.event.sha256, r.event.md5]) if (h) addToBucket(byHash, h.toLowerCase(), r);
  }

  // Mark → execution (and → a THOR/YARA content match): the note per mark, and the corroborating
  // rows. `detectionMatches` (formerly `yaraMatches`) now carries either detection source.
  const markNotes = new Map<T, { note: string; raiseTo: Severity | null }>();
  const corroborating = new Map<T, { marks: string[]; more: number }>();
  const detectionMatches = new Map<T, { marks: string[]; more: number }>();
  for (const r of indexed) {
    if (!r || r.kind !== "mark") continue;
    const { matches, unattributed, reused, beyondIndex } = candidatesFor(r, byPath, byHash);
    if (!matches.length && !unattributed && !reused && !beyondIndex) continue;
    const anchor = ms(r.event.timestamp);
    // The counts are never clipped away: the named executions fill what the tail leaves.
    const tail: string[] = [];
    if (reused)
      tail.push(
        `path reused: ${reused === 1 ? "a process image's hash differs" : `${reused} process images' hashes differ`} from the marked file's — not the same file`,
      );
    if (unattributed)
      tail.push(
        `${unattributed} record${unattributed === 1 ? "" : "s"} not attributed — the case names several hosts with this path`,
      );
    if (beyondIndex)
      tail.push(`${beyondIndex} record${beyondIndex === 1 ? "" : "s"} beyond the index, not read`);
    const named: string[] = [];
    let omitted = 0;
    for (const m of matches) {
      const words = matchWords(m, r, anchor);
      const more = matches.length - named.length - 1;
      const withMore = more > 0 ? `; +${more} more` : "";
      const length =
        preface(r, matches).length +
        2 +
        [...named, words].join("; ").length +
        withMore.length +
        (tail.length ? tail.join("; ").length + 2 : 0);
      if (named.length >= EXECUTIONS_NAMED_MAX || length > NOTE_MAX) {
        omitted = matches.length - named.length;
        break;
      }
      named.push(words);
    }
    const parts = [
      ...(matches.length ? [preface(r, matches)] : []),
      ...named,
      ...(omitted ? [`+${omitted} more`] : []),
      ...tail,
    ];
    // The finding needs an execution record dated AFTER the anchor beyond the tolerance: a run
    // before it, within it, or with no readable time is said and raises nothing.
    const after = (m: Match<T>): boolean => {
      const run = ms(m.record.event.timestamp);
      return (
        m.record.kind === "execution" && run !== null && anchor !== null && run - anchor > ORDER_TOLERANCE_MS
      );
    };
    // A content match has no observation time to order against — neither THOR nor YARA carries
    // one — so it corroborates unconditionally, unlike an execution record's after-the-anchor
    // requirement. An execution match after the anchor raises the mark to a flat High (established,
    // unchanged). A detection match raises the mark to ITS OWN graded severity, not a flat tier —
    // a THOR `notice` and a THOR `alert` are not the same strength of evidence, and CLI YARA's own
    // severityFromMeta already floors at Medium, so this is a no-op change for shipped behaviour
    // (#985 item 4, 985-1a-3 design review, finding F4).
    const isDetection = (m: Match<T>): boolean => m.record.kind === "detection";
    let raiseTo: Severity | null = matches.some(after) ? "High" : null;
    for (const m of matches.filter(isDetection)) {
      // THOR and Velociraptor-native YARA both carry a real graded severity scale and raise the mark
      // proportionally to it. CLI YARA's own severityFromMeta floors every hit at Medium regardless
      // of true confidence, so a CLI YARA content match keeps the established flat High (985-1a)
      // rather than being pulled down to Medium by this rule — verified by running the existing
      // 985-1a tests, which caught this as a real regression before it shipped. Read from the
      // classification-time flag, not the `artifact` label string — a string compare is exactly the
      // fragile pattern that caused that regression in the first place (#985 item 4, 985-1a-2 design
      // review, finding F5).
      const sev = m.record.proportionalSeverity ? (m.record.event.severity ?? "Info") : "High";
      if (raiseTo === null || RANK[sev] > RANK[raiseTo]) raiseTo = sev;
    }
    markNotes.set(r.event, { note: parts.join("; "), raiseTo });
    for (const m of matches.filter(after)) {
      const c =
        corroborating.get(m.record.event) ??
        corroborating.set(m.record.event, { marks: [], more: 0 }).get(m.record.event)!;
      if (c.marks.length < MARKS_PER_CORROBORATOR_MAX)
        c.marks.push(`${excerpt(r.event.path ?? "")}${r.host ? ` on ${neutral(r.host).slice(0, 80)}` : ""}`);
      else c.more += 1;
    }
    for (const m of matches.filter(isDetection)) {
      const c =
        detectionMatches.get(m.record.event) ??
        detectionMatches.set(m.record.event, { marks: [], more: 0 }).get(m.record.event)!;
      if (c.marks.length < MARKS_PER_CORROBORATOR_MAX)
        c.marks.push(`${excerpt(r.event.path ?? "")}${r.host ? ` on ${neutral(r.host).slice(0, 80)}` : ""}`);
      else c.more += 1;
    }
  }

  // Stream → command line: an absolute reference resolved to the stream row at that location on
  // that host. A bare or relative reference resolves to nothing (the working directory is not in
  // the record) and is not a lead either — the same token grammar matches `host:port` arguments.
  const streamRows = events.filter(isHiddenStream);
  const streamByKey = new Map<string, { row: T; file: FilePath; host: string }[]>();
  for (const row of streamRows) {
    const { hostPath, stream } = splitStream(row.path!);
    const file = filePath(hostPath);
    if (!file) continue;
    const k = `${file.relative}:${stream.toLowerCase()}`;
    (streamByKey.get(k) ?? streamByKey.set(k, []).get(k)!).push({ row, file, host: hostOf(row) });
  }
  const streamNotes = new Map<T, { commands: string[]; more: number }>();
  const processNotes = new Map<T, string[]>();
  if (streamRows.length) {
    // Two phases: every reference is located first, so the host rule is judged over ALL the
    // commands that reference one stream — a hostless stream row attaches only when those
    // commands and the row name at most one host between them.
    interface Ref {
      e: T;
      host: string;
      ref: StreamReference;
      located: { row: T; file: FilePath; host: string }[];
    }
    const refs: Ref[] = [];
    const byStream = new Map<T, Ref[]>();
    for (const e of events) {
      if (!e.commandLine || !isProcessStart(e)) continue;
      const host = hostOf(e);
      for (const ref of streamReferences(e.commandLine)) {
        if (!ref.absolute) continue;
        const f = filePath(ref.file);
        if (!f) continue;
        const located = (streamByKey.get(`${f.relative}:${ref.stream.toLowerCase()}`) ?? []).filter(
          (s) => sameLocation(f, s.file).same,
        );
        const r: Ref = { e, host, ref, located };
        refs.push(r);
        for (const s of located) (byStream.get(s.row) ?? byStream.set(s.row, []).get(s.row)!).push(r);
      }
    }
    const attached = new Set<Ref>();
    for (const [row, rs] of byStream) {
      const rowHost = hostOf(row);
      const namedHosts = new Set([rowHost, ...rs.map((r) => r.host)].filter(Boolean));
      const eligible = rs.filter((r) => (rowHost && r.host ? r.host === rowHost : namedHosts.size <= 1));
      for (const r of eligible) {
        attached.add(r);
        const words = `${excerpt(r.e.commandLine ?? "")} (${neutral(artifactOf(r.e)).slice(0, 40)}, ${r.e.timestamp ? neutral(r.e.timestamp).slice(0, 40) : "no time"}${r.host ? `, ${neutral(r.host).slice(0, 80)}` : ""})`;
        const n = streamNotes.get(row) ?? streamNotes.set(row, { commands: [], more: 0 }).get(row)!;
        if (n.commands.length < COMMANDS_PER_STREAM_MAX) n.commands.push(words);
        else n.more += 1;
      }
    }
    for (const r of refs) {
      if (attached.has(r)) continue;
      (processNotes.get(r.e) ?? processNotes.set(r.e, []).get(r.e)!).push(
        `${excerpt(`${r.ref.file}:${r.ref.stream}`)} — ${r.located.length ? "not attributed: the case names several hosts with this stream" : "no stream row at this location carries it"}`,
      );
    }
  }

  // Mark → browser visit (#985) — the matching lives in downloadVisitOrigin.ts; this pass only
  // hands it the classified marks (event + resolved host), the same input shape as the mark →
  // execution join above.
  const markRecords = indexed
    .filter((r): r is Indexed<T> => !!r && r.kind === "mark")
    .map((r) => ({ event: r.event, host: r.host }));
  const { ownVisitNotes, referrerVisitNotes, precededNotes } = browserVisitCorroboration(events, markRecords);

  return events.map((e) => {
    const base = withoutOwnNotes(e.description);
    let description = base;
    let severity = e.severity ?? "Info";
    const mark = markNotes.get(e);
    if (mark) {
      description = appendDerivedNote(description, DOWNLOAD_EXECUTED_MARKER, clipNote(mark.note));
      if (mark.raiseTo) severity = raise(e, mark.raiseTo);
    }
    const ran = corroborating.get(e);
    if (ran) {
      const words = [...ran.marks, ...(ran.more ? [`+${ran.more} more`] : [])].join("; ");
      description = appendDerivedNote(description, RAN_MARKED_FILE_MARKER, clipNote(words));
      severity = raise({ ...e, severity }, "Medium");
    }
    const referenced = streamNotes.get(e);
    if (referenced) {
      const words = [...referenced.commands, ...(referenced.more ? [`+${referenced.more} more`] : [])].join(
        "; ",
      );
      description = appendDerivedNote(description, STREAM_REFERENCED_MARKER, clipNote(words));
      severity = raise({ ...e, severity }, "High");
    }
    const references = processNotes.get(e);
    if (references) {
      description = appendDerivedNote(
        description,
        STREAM_REFERENCE_MARKER,
        clipNote(references.slice(0, 4).join("; ")),
      );
      severity = raise({ ...e, severity }, "Medium");
    }
    const ownVisit = ownVisitNotes.get(e);
    if (ownVisit) {
      description = appendDerivedNote(description, BROWSER_VISIT_MARKER, clipNote(ownVisit));
      severity = raise({ ...e, severity }, "Medium");
    }
    const refVisit = referrerVisitNotes.get(e);
    if (refVisit) {
      description = appendDerivedNote(description, REFERRER_VISIT_MARKER, clipNote(refVisit));
      severity = raise({ ...e, severity }, "Medium");
    }
    const preceded = precededNotes.get(e);
    if (preceded) {
      const words = [...preceded.marks, ...(preceded.more ? [`+${preceded.more} more`] : [])].join("; ");
      description = appendDerivedNote(description, VISIT_PRECEDES_MARK_MARKER, clipNote(words));
      // Raised too, like the corroborating execution row — otherwise an Info-severity visit falls
      // into the super-timeline before the next merge and this join can never re-find it.
      severity = raise({ ...e, severity }, "Medium");
    }
    const detectionMatch = detectionMatches.get(e);
    if (detectionMatch) {
      const words = [
        ...detectionMatch.marks,
        ...(detectionMatch.more ? [`+${detectionMatch.more} more`] : []),
      ].join("; ");
      description = appendDerivedNote(description, YARA_MATCHES_MARK_MARKER, clipNote(words));
      // severityFromMeta floors a CLI YARA row at Medium always, so this is usually a no-op there.
      // A THOR row can be Info (self-scan demoted) — matching a mark doesn't change that THOR
      // itself graded this hit as noise, so the raise is skipped rather than re-promoting it (#985
      // item 4, 985-1a-3 design review, finding F2).
      if ((e.severity ?? "Info") !== "Info") severity = raise({ ...e, severity }, "Medium");
    }
    if (description === (e.description ?? "") && severity === (e.severity ?? "Info")) return e;
    return { ...e, description, severity };
  });
}
