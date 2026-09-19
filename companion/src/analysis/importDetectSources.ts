import { getCI, isObject } from "./siemImport.js";
import { classifyLinuxArtifact, splitCollection } from "./linuxPersistence.js";
import { classifyMacArtifact, isBinaryPlist, isXmlPlist } from "./macosPersistence.js";
import { isRcloneConfig, isRcloneLog, isMegaLog } from "./rcloneImport.js";

// Format detectors for the sources added alongside the identity/mobile/browser importers — Okta,
// Google Workspace, Hindsight, macOS and LEAPP.
//
// They live here rather than in importDetect.ts because that file sits at the 800-line limit, and
// the repo's rule when the size gate fails is to put the new code in its own module rather than
// raise the ceiling (CONTRIBUTING.md, "the file-size ratchet"). importDetect.ts keeps the dispatch
// order — which detector is asked first is a real contract between formats — and imports the
// predicates from here.

type Row = Record<string, unknown>;

// Local copy of importDetect's row picker: exporting it from there just to reach it here would
// widen that module's surface for one three-line helper.
function firstObj(arr: unknown[]): Row | null {
  for (const el of arr) if (isObject(el)) return el;
  return null;
}

// Okta System Log v1: eventType + published is the pair every record carries, and `outcome.result`
// or an `actor` object confirms it against another product that happens to use those two names.
export function isOkta(s: Row): boolean {
  if (!getCI(s, "eventType") || !getCI(s, "published")) return false;
  return !!getCI(s, "actor") || !!getCI(s, "outcome") || !!getCI(s, "legacyEventType");
}

// Google Workspace Admin SDK Reports activity: the id{time,applicationName} envelope plus an
// events array. Checked against the envelope, not `actor`, which other Google products also send.
export function isWorkspaceActivityRow(s: Row): boolean {
  const id = getCI(s, "id");
  if (!isObject(id)) return false;
  const row = id;
  if (!getCI(row, "time") || !getCI(row, "applicationName")) return false;
  return Array.isArray(getCI(s, "events")) || String(getCI(s, "kind") ?? "").includes("reports#activity");
}

// ROOT-AWARE ON PURPOSE. The Reports API wraps its rows in `{ items: [...] }`, and `items` is not in
// CONTAINER_KEYS — widening that list would change how every other format samples. Left unhandled
// the wrapper reads as an object whose values are arrays, which isVelociraptor claims as an artifact
// map, so the check looks at the envelope itself as well as the sampled row.
export function isGoogleWorkspace(s: Row, root: unknown): boolean {
  if (isWorkspaceActivityRow(s)) return true;
  if (!isObject(root)) return false;
  const items = getCI(root, "items");
  if (!Array.isArray(items)) return false;
  const first = firstObj(items);
  return !!first && isWorkspaceActivityRow(first);
}

// Hindsight browser artifacts: the (type + url + timestamp) triple with Hindsight's own
// `interpretation`/`profile folder` columns. Requires one of the Hindsight-specific columns so a
// generic proxy log with a url column is not claimed.
export function isHindsight(s: Row): boolean {
  if (!getCI(s, "url") && !getCI(s, "URL")) return false;
  if (!getCI(s, "timestamp") && !getCI(s, "date")) return false;
  return (
    getCI(s, "interpretation") != null ||
    getCI(s, "profile folder") != null ||
    getCI(s, "profile_folder") != null ||
    (getCI(s, "type") != null && getCI(s, "profile") != null)
  );
}

// macOS unified log (`log show --style json`): eventMessage plus one of the Apple-specific columns.
// traceID/machTimestamp/processImagePath are absent from every other JSON feed here.
export function isMacosUnifiedLog(s: Row): boolean {
  if (!getCI(s, "eventMessage") && !getCI(s, "composedMessage")) return false;
  return (
    getCI(s, "processImagePath") != null ||
    getCI(s, "senderImagePath") != null ||
    getCI(s, "machTimestamp") != null ||
    getCI(s, "traceID") != null
  );
}

// LSQuarantine CSV dump — the column prefix is unmistakable; a file-attribute listing (#1037) by
// the one header no other export carries, `com.apple.quarantine` — `quarantine`, `xattr` and a
// path column are not a signature (a generic inventory carries those too).
export function macosQuarantineCsvSig(h: Set<string>): boolean {
  for (const k of h) if (k.startsWith("lsquarantine") || k === "com.apple.quarantine") return true;
  return false;
}

const MACOS_SAMPLE_MAX = 8;
const CONTAINERS = ["Records", "data", "events", "records", "results", "logs", "value", "alerts"];

/** Up to MACOS_SAMPLE_MAX objects from an array root or a wrapped one — the macOS family is read record by record. */
function sampleObjects(root: unknown): Row[] {
  let arr: unknown[] | undefined;
  if (Array.isArray(root)) arr = root;
  else if (isObject(root)) {
    const hits = root.hits;
    if (isObject(hits) && Array.isArray(hits.hits)) arr = hits.hits as unknown[];
    else for (const k of CONTAINERS) if (Array.isArray(getCI(root, k))) arr = getCI(root, k) as unknown[];
  }
  // Stop at the eighth object: the scan never walks an attacker-sized array.
  const out: Row[] = [];
  for (const el of arr ?? [root]) {
    if (isObject(el)) out.push(el);
    if (out.length >= MACOS_SAMPLE_MAX) break;
  }
  return out;
}

const isQuarantineDbRecord = (s: Row): boolean =>
  Object.keys(s).some((k) => k.trim().toLowerCase().startsWith("lsquarantine"));
const isQuarantineAttrRecord = (s: Row): boolean =>
  Object.keys(s).some((k) => k.trim().toLowerCase() === "com.apple.quarantine");

/**
 * The macOS JSON family, in any record order: a database record, an attribute record or a
 * unified-log record among the first MACOS_SAMPLE_MAX objects — and no Velociraptor stamp on any of
 * them, which keeps a collector's own export on its own route.
 */
export function isMacosFamily(root: unknown): boolean {
  const objs = sampleObjects(root);
  if (objs.some((s) => typeof getCI(s, "_Source") === "string" && !!getCI(s, "_Source"))) return false;
  return objs.some((s) => isQuarantineDbRecord(s) || isQuarantineAttrRecord(s) || isMacosUnifiedLog(s));
}

export function hindsightCsvSig(h: Set<string>): boolean {
  const has = (k: string) => h.has(k);
  if (!has("url") || !(has("timestamp") || has("date"))) return false;
  return (
    has("interpretation") || has("profile folder") || has("profile_folder") || (has("type") && has("profile"))
  );
}

// sqlite-dissect's (DC3) per-table commit-history CSV export (#932 item 8) — its fixed 9-header
// prefix (verified live against csv_export.py's own column-header construction) is not shared by
// any other exporter; "row id" alone would false-positive too broadly, so the full set is required.
export function sqliteRowStateCsvSig(h: Set<string>): boolean {
  return (
    h.has("file source") &&
    h.has("version") &&
    h.has("page version") &&
    h.has("cell source") &&
    h.has("page number") &&
    h.has("location") &&
    h.has("operation") &&
    h.has("file offset") &&
    h.has("row id")
  );
}
// FSEventsParser's (dlcowen/G-C Partners) real All_FSEVENTS.tsv header — the reduced R_COLUMNS
// set the tool's own print_columns() writes, tab-joined (#933 item 9). Full-length and ordered:
// a shorter or reordered match risks claiming an unrelated 9-column TSV export.
const FSEVENTS_TSV_HEADER = [
  "id",
  "node_id",
  "fs_uid",
  "fullpath",
  "type",
  "flags",
  "approx_dates_plus_minus_one_day",
  "source",
  "source_modified_time",
];
export function fsEventsTsvSig(text: string): boolean {
  const firstLine = (text.split(/\r?\n/, 1)[0] ?? "").trim();
  if (!firstLine.includes("\t")) return false;
  const cols = firstLine.split("\t").map((c) => c.trim().toLowerCase());
  return cols.length === FSEVENTS_TSV_HEADER.length && cols.every((c, i) => c === FSEVENTS_TSV_HEADER[i]);
}

// mac_apt's (ydkhatri) Spotlight store-item export: `ID` + `Date_Updated` (every row, per
// ProcessStoreItem()) plus at least one real kMDItem* usage/download attribute column — the sparse
// full column set varies by store version, so only the usage-bearing subset is required (#933 item
// 10). Comma-delimited, goes through the same header set every other CSV detector here uses.
export function spotlightStoreCsvSig(h: Set<string>): boolean {
  if (!h.has("id") || !h.has("date_updated")) return false;
  return (
    h.has("kmditemusecount") ||
    h.has("kmditemlastuseddate") ||
    h.has("kmditemuseddates") ||
    h.has("kmditemdownloadeddate") ||
    h.has("kmditemwherefroms")
  );
}

// ───────────────────────────── auditd (line-oriented) ─────────────────────────────
//
// Moved here from importDetect.ts, which sits at the 800-line limit: the dispatch ORDER is the
// contract that has to stay in that file, the predicate itself does not.

// Linux auditd records ("type=SYSCALL msg=audit(1490451217.272:270): …") — the raw audit.log /
// `ausearch` format. The `type=… msg=audit(secs.millis:serial)` shape is unique to auditd, so one
// matching line anywhere in the head is enough to claim it ahead of the generic log fallback.
const RE_AUDITD = /(?:^|\n)\s*type=\w+\s+msg=audit\(\d+\.\d+:\d+\)/;
// 8 KB was not enough: a real audit.log opens with a boot banner and a run of SYSCALL-less noise,
// and a file whose first `type=… msg=audit(…)` sat past that window sniffed as a plain log and went
// to AI line-triage. 256 KB clears any realistic preamble while still being a cheap slice — the
// regex is anchored per line, so a bigger window costs a scan, not a backtrack.
export function isAuditd(text: string): boolean {
  return RE_AUDITD.test(text.slice(0, 256_000));
}

// ───────────────────────── Linux persistence collection (#908 item 5) ─────────────────────────
//
// Two routes, because analysts hand these over two ways.
//
// A COLLECTION is many small files concatenated under per-file headers — `head`/`tail` banners or a
// script's own. splitCollection only accepts a header that is the whole line and names an absolute
// path, and this claims the file only when at least one of those paths is an artifact class the
// grader reads. A stray header-shaped line inside some other log therefore does not claim it.
//
// A SINGLE artifact is claimed by NAME, and only for names that mean one thing. `authorized_keys`,
// a systemd unit and the shell-profile family qualify. `env` deliberately does not: a `.env` file is
// an application's secrets, not a Linux environment dump, and routing one here would be a mis-route
// with a privacy cost. A collection can still carry /etc/environment, where the header says what it is.
const SINGLE_ARTIFACT_NAME =
  /^(?:authorized_keys2?|crontab|\.?(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile))$|\.(?:service|timer|socket)$|^(?:s[ug]id|setuid)[\w.-]*$/i;

export function looksLikeLinuxPersist(filename: string, text: string): boolean {
  const base = (filename ?? "").split(/[\\/]/).pop() ?? "";
  // A collected artifact is routinely saved with a .txt/.log wrapper extension.
  // A .csv has its own importer and its own detection; a name that merely contains "suid" must not
  // pull one here. `SUID_audit_report.csv` was being claimed.
  if (/\.(?:csv|tsv|json|jsonl|ndjson|xml|evtx)$/i.test(base)) return false;
  const stem = base.replace(/\.(?:txt|log|out)$/i, "");
  if (SINGLE_ARTIFACT_NAME.test(stem) && classifyLinuxArtifact(stem) !== "unknown") return true;

  // 256 KB is enough to see the first headers of any realistic collection without scanning a
  // multi-megabyte upload that is not one.
  const members = splitCollection((text ?? "").slice(0, 256_000));
  return members.some((m) => m.kind !== "unknown");
}

// ───────────────────────── macOS persistence collection (#908 item 6) ─────────────────────────
//
// A property list is self-identifying — `<plist>` or the plist DOCTYPE — so a single collected
// LaunchAgent needs no filename rule at all.
//
// A whole-upload BINARY plist is NOT claimed (#1392). It used to be, so the importer could say the
// file needs converting — but the magic says "bplist", not "launchd", and every other binary plist
// (an MRU .sfl2, an app's .plist) got a launchd "not read" row under the wrong label. The text
// boundary refuses the magic before detection runs (importIngest.ts resolveImportKind), with a hint
// that names the conversion. A binary member INSIDE a collection whose header names a launchd path
// is still graded as unreadable by gradeLaunchd, where the label is the header's, not a guess.
//
// A COLLECTION is claimed only when at least one header names a launchd path. A collection with no
// launchd member is a Linux-shaped collection and belongs to the Linux importer, which grades the
// cron and shell artifacts macOS shares with it.
export function looksLikeMacosPersist(filename: string, text: string): boolean {
  const t = (text ?? "").trimStart();
  if (isBinaryPlist(t)) return false;

  // The plist marker must open the DOCUMENT, not merely appear somewhere in its first 4 KB. The
  // loose test claimed a Velociraptor export whose rows carried plist file CONTENT, an NDJSON whose
  // first record's command line mentioned "<plist", and any JSON preference dump named *.plist —
  // and each of those then produced an empty import, so the whole export was dropped rather than
  // mis-parsed. A property list starts with an XML declaration, a DOCTYPE or the plist element.
  if (/^(?:<\?xml[^>]*\?>\s*)?(?:<!DOCTYPE\s+plist\b|<plist\b)/i.test(t.slice(0, 512))) return true;

  // A .plist NAME with no plist body is not one. It was claimed on the filename alone.
  if (/\.plist$/i.test(filename ?? "") && isXmlPlist(t.slice(0, 4096))) return true;

  return splitCollection(t.slice(0, 256_000), classifyMacArtifact).some((m) => m.kind === "launchd");
}

// ───────────────────────── rclone / MEGAsync evidence (#908 item 9) ─────────────────────────
//
// Three artifacts, one kind: the rclone configuration, the rclone transfer log, and the MEGAsync
// log. Each has a signature of its own, so the filename is never needed and never trusted.
//
// The config check is the fussy one — an rclone.conf is an ordinary INI, and claiming every INI
// would be a mis-route with real cost. It requires a section header AND a `type =` naming a known
// rclone backend, which is the one key every remote has and almost no other INI does.
export function looksLikeRcloneEvidence(text: string): boolean {
  const t = text ?? "";
  return isRcloneConfig(t) || isRcloneLog(t) || isMegaLog(t);
}

// Moved here from importDetect.ts, which sits at the 800-line limit; the dispatch ORDER is the
// contract that has to stay in that file, the predicate does not.
//
// Velociraptor names its JSON exports after the collected artifact, e.g.
// `Velociraptor-Windows.Triage.HighValueMemory.json` or `Generic.System.Pstree.json`. Many
// artifacts (process lists, file listings, memory acquisition) emit rows with no distinctive
// content signature, so they sniff as the generic SIEM fallback. When the FILENAME marks a
// Velociraptor export we route those to the Velociraptor importer instead — it reads each
// artifact's own columns and tags the source, rather than mislabeling rows "SIEM event:".
const VR_ARTIFACT =
  /\b(?:Windows|Linux|MacOS|Generic|Custom|Server|Exchange|Admin|Network)\.[A-Za-z]\w*(?:\.\w+)+/;
export function looksLikeVelociraptorFile(filename: string): boolean {
  const n = filename ?? "";
  return /velociraptor/i.test(n) || VR_ARTIFACT.test(n);
}
