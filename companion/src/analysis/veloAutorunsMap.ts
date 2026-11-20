import type { FileIdentity } from "./fileIdentity.js";
import { addIoc, baseName, getCI, oneLine, str, type MappedEvent, type SiemIoc } from "./siemImport.js";
import type { Severity } from "./stateTypes.js";
import { startupAggKey, taskAggKey } from "./veloAggKeys.js";
import { huntCommandTarget, splitCommandLine } from "./veloCommandTarget.js";
import { pickTime } from "./veloRowTime.js";
import { demangleUtf16Noise, withHostSuffix } from "./velociraptorTitle.js";

/**
 * Startup / autorun rows of the Velociraptor importer (#2731). Both artifacts reach the importer's
 * "startup" route (artifact name `startup|autorun`, velociraptorImport.ts classify), and this module
 * picks the mapper by the row's own columns:
 *
 *   Windows.Sysinternals.Autoruns — autorunsc CSV columns. The artifact runs autorunsc with `-c -h`
 *     and, by default, `-s` (verify signatures). Columns read: Time, Entry Location, Entry, Enabled,
 *     Category, Signer, Company, Image Path, Launch String, MD5, SHA-256. Before #2731 these rows went
 *     to the StartupItems mapper, which reads none of them: the event lost the entry, the image path,
 *     the signer and the hashes, and no autorun hunt item was formed.
 *   Windows.Sys.StartupItems and similar — Name / OSPath / Details / Enabled.
 *   Windows.System.TaskScheduler/Analysis — TaskName / Command / Arguments / UserId / RunLevel / OSPath
 *     (its own importer route, "taskscheduler"; moved here from velociraptorImport.ts in #2748).
 *
 * Hunt target (#2748): a StartupItems row and a scheduled task form an autorun hunt item keyed on the
 * program they run, or on the script / DLL a script host or built-in tool runs (veloCommandTarget.ts).
 * It travels as `fileIdentity.autorunTarget`, never as `path` or `processName`: those feed the content
 * tagger, LOLBin grading and correlation, which this does not change. The task row keeps `path` = the
 * task file, so a stored event without the target keeps its old item key. With no reliable target a
 * task falls back to that old key, and a StartupItems row to its entry name.
 *
 * Verified signer: ONLY a Signer value that starts with the literal "(Verified) " records a signer.
 * "(Not verified) …" records a FAILED check; Company and empty values never count. A signer is
 * endpoint-checked Authenticode, unlike Company text, which anyone can write into a binary.
 *
 * Grading (#2731, the user's decision "Low, unsigned only"): an enabled entry that is NOT signed by a
 * verified signer (no Signer, "(Not verified) …", anything else) is Low (T1547); an enabled entry with
 * a "(Verified) " signer is Info, and so is every disabled entry. Info entries still reach the
 * super-timeline and the hunt inventory, and the content tagger can still raise one. The autorunsc `SHA-1` column is a whole-file hash with no recorded size, so it is not used
 * as the Amcache SHA1 (fileIdentity.ts); the SHA-256 is.
 */
type Row = Record<string, unknown>;

const VERIFIED = "(Verified) ";
const SHA256_RE = /^[0-9a-f]{64}$/;
const MD5_RE = /^[0-9a-f]{32}$/;

/** An autorunsc row: its "Entry Location" column with an image path or launch string beside it. */
export function isAutorunsRow(row: Row): boolean {
  return (
    getCI(row, "Entry Location") != null &&
    (getCI(row, "Image Path") != null || getCI(row, "Launch String") != null)
  );
}

/** The Authenticode verdict an autorunsc Signer value states. Only "(Verified) <name>" is a signer. */
export function autorunsSignature(raw: string): FileIdentity | undefined {
  const v = raw.trim();
  if (v.startsWith(VERIFIED)) {
    const signer = v.slice(VERIFIED.length).trim().slice(0, 260);
    return signer ? { signer } : undefined;
  }
  return v ? { signatureUnverified: true } : undefined;
}

const isEnabled = (raw: string): boolean =>
  ["enable", "enabled", "true", "1"].includes(raw.trim().toLowerCase());

const hexCol = (row: Row, key: string, re: RegExp): string | undefined => {
  const v = str(getCI(row, key)).trim().toLowerCase();
  return re.test(v) ? v : undefined;
};

function mapAutoruns(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const entry = str(getCI(row, "Entry")).trim();
  const location = str(getCI(row, "Entry Location")).trim();
  const image = str(getCI(row, "Image Path")).trim();
  const launch = demangleUtf16Noise(str(getCI(row, "Launch String")).trim());
  const enabled = isEnabled(str(getCI(row, "Enabled")));
  const sha256 = hexCol(row, "SHA-256", SHA256_RE) ?? hexCol(row, "SHA256", SHA256_RE);
  const md5 = hexCol(row, "MD5", MD5_RE);
  const identity = autorunsSignature(str(getCI(row, "Signer")));
  const unsigned = enabled && !identity?.signer; // an enabled entry with no verified signer
  if (/^[A-Za-z]:\\/.test(image)) addIoc(sink, "file", image.slice(0, 300));
  if (sha256) addIoc(sink, "hash", sha256);
  else if (md5) addIoc(sink, "hash", md5);
  const what = oneLine(image || launch || location).slice(0, 300);
  const where = location ? ` [${oneLine(location).slice(0, 200)}]` : "";
  const label = `Velociraptor${artifact ? ` [${artifact}]` : ""}: Autorun entry (Autoruns): ${oneLine(entry) || "(entry)"} — ${what}${where} (${enabled ? "enabled" : "disabled"})`;
  return {
    timestamp: pickTime(row),
    description: withHostSuffix(label.slice(0, 600), host).slice(0, 600),
    severity: unsigned ? "Low" : "Info",
    mitre: unsigned ? ["T1547"] : [],
    aggKey: startupAggKey(host, entry, `${location}|${image || launch}`),
    sources: ["Velociraptor"],
    ...(image ? { path: image, processName: baseName(image) } : {}),
    ...(sha256 ? { sha256 } : md5 ? { md5 } : {}),
    ...(identity ? { fileIdentity: identity } : {}),
    ...(host ? { asset: host } : {}),
  };
}

const target = (t: string | undefined): { fileIdentity?: FileIdentity } =>
  t ? { fileIdentity: { autorunTarget: t.slice(0, 600) } } : {};

// Windows.Sys.StartupItems and similar: Name + OSPath + Details + Enabled.
function mapStartupItem(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const name = str(getCI(row, "Name")).trim();
  const ospath = str(getCI(row, "OSPath")).trim();
  const details = demangleUtf16Noise(str(getCI(row, "Details")).trim());
  const enabled = isEnabled(str(getCI(row, "Enabled")));

  // The launched program as a file IOC — the whole quoted path, never cut at its first space (#2748).
  const cmdPath = details ? splitCommandLine(details).program : "";
  if (/^[A-Za-z]:\\/.test(cmdPath)) addIoc(sink, "file", cmdPath.slice(0, 300));
  if (ospath && /^[A-Za-z]:\\/.test(ospath)) addIoc(sink, "file", ospath.slice(0, 300));

  const enabledLabel = enabled ? "enabled" : "disabled";
  const subject = details && details !== name ? oneLine(details).slice(0, 300) : ospath;
  let description = `Velociraptor: Startup [${name || "item"}] — ${subject} (${enabledLabel})`;
  description = withHostSuffix(description, host).slice(0, 600);

  // Active persistence is worth surfacing; disabled items are informational.
  const severity: Severity = enabled ? "Low" : "Info";

  return {
    timestamp: pickTime(row),
    description,
    severity,
    mitre: enabled ? ["T1547"] : [],
    aggKey: startupAggKey(host, name, ospath),
    sources: ["Velociraptor"],
    ...target((details ? huntCommandTarget(details) : undefined) ?? (name || undefined)),
    ...(host ? { asset: host } : {}),
  };
}

const ACCOUNT_LABELS: Record<string, string> = {
  "S-1-5-18": "SYSTEM",
  "S-1-5-19": "LOCAL SERVICE",
  "S-1-5-20": "NETWORK SERVICE",
};

/** Windows.System.TaskScheduler/Analysis. With no reliable target the task file keys the item (#2748). */
export function mapTaskScheduler(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const taskName = str(getCI(row, "TaskName")).trim();
  const command = str(getCI(row, "Command")).trim();
  const args = str(getCI(row, "Arguments")).trim();
  const userId = str(getCI(row, "UserId")).trim();
  const runLevel = str(getCI(row, "RunLevel")).trim();
  const ospath = str(getCI(row, "OSPath")).trim();

  if (ospath) addIoc(sink, "file", ospath);
  if (command && /^[A-Za-z]:\\/.test(command)) addIoc(sink, "file", command.slice(0, 300));

  const cmd = [command, args].filter(Boolean).join(" ");
  const userLabel = ACCOUNT_LABELS[userId] ?? userId;

  let description = `Velociraptor: Scheduled Task [${taskName || "task"}]`;
  if (cmd) description += ` — ${oneLine(cmd).slice(0, 250)}`;
  if (userLabel) description += ` (${userLabel}${runLevel ? `, ${runLevel}` : ""})`;
  description = withHostSuffix(description, host).slice(0, 600);

  return {
    timestamp: pickTime(row),
    description,
    severity: "Info",
    mitre: [],
    aggKey: taskAggKey(host, taskName),
    sources: ["Velociraptor"],
    ...(ospath ? { path: ospath } : {}),
    ...target(command ? huntCommandTarget(command, args) : undefined),
    ...(host ? { asset: host } : {}),
  };
}

/** A row on the importer's startup route: an autorunsc row, else a StartupItems-shaped one. */
export function mapStartupRow(
  row: Row,
  artifact: string,
  host: string,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  return isAutorunsRow(row) ? mapAutoruns(row, artifact, host, sink) : mapStartupItem(row, host, sink);
}
