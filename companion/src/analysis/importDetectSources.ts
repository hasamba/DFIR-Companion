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

// Hindsight CSV export: url + timestamp plus one of its own columns.
// LSQuarantine CSV dump — the column prefix is unmistakable.
export function macosQuarantineCsvSig(h: Set<string>): boolean {
  for (const k of h) if (k.startsWith("lsquarantine")) return true;
  return false;
}

export function hindsightCsvSig(h: Set<string>): boolean {
  const has = (k: string) => h.has(k);
  if (!has("url") || !(has("timestamp") || has("date"))) return false;
  return (
    has("interpretation") || has("profile folder") || has("profile_folder") || (has("type") && has("profile"))
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
// LaunchAgent needs no filename rule at all. A binary plist is claimed too, deliberately: the
// importer's job there is to SAY the file needs converting, which is more useful than the generic
// log path silently reading mojibake out of it.
//
// A COLLECTION is claimed only when at least one header names a launchd path. A collection with no
// launchd member is a Linux-shaped collection and belongs to the Linux importer, which grades the
// cron and shell artifacts macOS shares with it.
export function looksLikeMacosPersist(filename: string, text: string): boolean {
  const t = (text ?? "").trimStart();
  if (isBinaryPlist(t)) return true;

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
