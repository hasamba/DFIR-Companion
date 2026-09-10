import { getCI, isObject } from "./siemImport.js";
import { classifyLinuxArtifact, splitCollection } from "./linuxPersistence.js";

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
  /^(?:authorized_keys2?|crontab|\.?(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile))$|\.(?:service|timer|socket)$|suid/i;

export function looksLikeLinuxPersist(filename: string, text: string): boolean {
  const base = (filename ?? "").split(/[\\/]/).pop() ?? "";
  // A collected artifact is routinely saved with a .txt/.log wrapper extension.
  const stem = base.replace(/\.(?:txt|log|out)$/i, "");
  if (SINGLE_ARTIFACT_NAME.test(stem) && classifyLinuxArtifact(stem) !== "unknown") return true;

  // 256 KB is enough to see the first headers of any realistic collection without scanning a
  // multi-megabyte upload that is not one.
  const members = splitCollection((text ?? "").slice(0, 256_000));
  return members.some((m) => m.kind !== "unknown");
}
