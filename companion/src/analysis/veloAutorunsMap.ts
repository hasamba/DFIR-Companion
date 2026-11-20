import type { FileIdentity } from "./fileIdentity.js";
import { addIoc, baseName, getCI, oneLine, str, type MappedEvent, type SiemIoc } from "./siemImport.js";
import type { Severity } from "./stateTypes.js";
import { startupAggKey } from "./veloAggKeys.js";
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
 *   Windows.Sys.StartupItems and similar — Name / OSPath / Details / Enabled (unchanged).
 *
 * Verified signer: ONLY a Signer value that starts with the literal "(Verified) " records a signer.
 * "(Not verified) …" records a FAILED check; Company and empty values never count. A signer is
 * endpoint-checked Authenticode, unlike Company text, which anyone can write into a binary.
 *
 * Grading is unchanged from the StartupItems mapper: an enabled entry is Low (T1547), a disabled one
 * Info. The autorunsc `SHA-1` column is a whole-file hash with no recorded size, so it is not used
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
  if (/^[A-Za-z]:\\/.test(image)) addIoc(sink, "file", image.slice(0, 300));
  if (sha256) addIoc(sink, "hash", sha256);
  else if (md5) addIoc(sink, "hash", md5);
  const what = oneLine(image || launch || location).slice(0, 300);
  const where = location ? ` [${oneLine(location).slice(0, 200)}]` : "";
  const label = `Velociraptor${artifact ? ` [${artifact}]` : ""}: Autorun entry (Autoruns): ${oneLine(entry) || "(entry)"} — ${what}${where} (${enabled ? "enabled" : "disabled"})`;
  return {
    timestamp: pickTime(row),
    description: withHostSuffix(label.slice(0, 600), host).slice(0, 600),
    severity: enabled ? "Low" : "Info",
    mitre: enabled ? ["T1547"] : [],
    aggKey: startupAggKey(host, entry, `${location}|${image || launch}`),
    sources: ["Velociraptor"],
    ...(image ? { path: image, processName: baseName(image) } : {}),
    ...(sha256 ? { sha256 } : md5 ? { md5 } : {}),
    ...(identity ? { fileIdentity: identity } : {}),
    ...(host ? { asset: host } : {}),
  };
}

// Windows.Sys.StartupItems and similar: Name + OSPath + Details + Enabled.
function mapStartupItem(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const name = str(getCI(row, "Name")).trim();
  const ospath = str(getCI(row, "OSPath")).trim();
  const details = demangleUtf16Noise(str(getCI(row, "Details")).trim());
  const enabled = isEnabled(str(getCI(row, "Enabled")));

  // Add the executable path or registry path as file/process IOC when it looks like a real path.
  const cmdPath = details.replace(/^["']?([A-Za-z]:\\[^"'\s]+).*$/, "$1");
  if (details && /^[A-Za-z]:\\/.test(cmdPath)) addIoc(sink, "file", cmdPath.slice(0, 300));
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
