// DetectRaptor.Windows.Detection.BinaryRename reports a file whose on-disk name does not match the
// `OriginalFilename` compiled into its version resource — `java.exe` that is really `Cmd.Exe`.
//
// Every row is a detection, but the artifact ships no `Detection` column, so velociraptorImport's
// rowVerdict() finds no verdict and the row falls through to the generic key=value dump at Info. That
// grade is the whole problem: Info never reaches the forensic timeline, so synthesis never sees the
// row at all. In a real case that hid the entire initial-access stage — a `cmd.exe` copied to
// `java.exe` to stand in for an exploited Java broker process — while a competing tool made the same
// artifact its headline finding. (velociraptorImport also floors Info→Medium for any unrecognised row
// from a detection-named artifact, so the next pack with this shape is not invisible while it waits
// for a mapper of its own; this module is what turns the row into something an analyst can act on.)
//
// Kept as its own module rather than inlined into velociraptorImport.ts, which is frozen at its
// current size by the file-size ledger (#384) — see check-file-size.mjs.
import {
  str,
  getCI,
  oneLine,
  addIoc,
  worst,
  isObject,
  normalizeTime,
  type MappedEvent,
  type SiemIoc,
} from "./siemImport.js";
import { type Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { isStagedPath } from "./stagingPaths.js";
import { withHostSuffix } from "./velociraptorTitle.js";

type Row = Record<string, unknown>;

// Windows binaries whose rename is itself the tradecraft: ATT&CK gives it a sub-technique
// (T1036.003 Rename System Utility) precisely because moving a trusted, signed OS tool under a new
// name defeats name-based application control and process-name alerting while keeping the
// signature valid. Matched against the ORIGINAL filename — the binary the file really is — never
// against the name it is wearing, which the attacker chose.
const SYSTEM_UTILITIES =
  /^(cmd|powershell|pwsh|rundll32|regsvr32|mshta|certutil|wscript|cscript|bitsadmin|msiexec|wmic|net|net1|at|schtasks|psexec|psexesvc|reg|sc|installutil|msbuild|regasm|regsvcs|cmstp|forfiles|hh|ieexec|odbcconf|pcalua|presentationhost|scriptrunner|xwizard|conhost|svchost|lsass|winlogon|explorer|taskhostw|dllhost|werfault)\.exe$/i;

// Severity words a rule pack may ship, should a future DetectRaptor release add verdict columns to
// this artifact. Its grade wins over anything inferred here — the importer's contract is to consume
// a tool's verdict, not to re-derive one over the top of it.
const SEV_WORD: Record<string, Severity> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  moderate: "Medium",
  low: "Low",
  informational: "Info",
  info: "Info",
};

/** What the row says about the file, once both name spellings are normalised. */
interface RenameFacts {
  path: string;
  onDisk: string; // the name the file wears on disk
  original: string; // the name compiled into its version resource ("" when there is none)
  vendor: string; // CompanyName, else ProductName
  sha256: string;
  md5: string;
  /** Names differ AND both are known — the only state that proves a rename. */
  renamed: boolean;
  /** No version resource to compare, so a rename can be neither proved nor ruled out. */
  unknownOrigin: boolean;
  systemUtility: boolean;
  staged: boolean;
  /** An explicit Criticality/Severity the rule pack shipped, if any. */
  explicit?: Severity;
}

// Reduce either spelling to a bare lowercase filename so "Cmd.Exe" and "cmd.exe" compare equal and a
// path-bearing OriginalFilename ("C:\build\foo.exe") reduces to its leaf. `split` always returns a
// non-empty array, so the last element here cannot be undefined.
function leafName(value: string): string {
  const parts = value.trim().replace(/["']/g, "").split(/[\\/]/);
  return parts[parts.length - 1].trim().toLowerCase();
}

// Version-resource fields. DetectRaptor nests them under VersionInformation; some collections
// flatten them onto the row, so both shapes are read.
function versionInfo(row: Row): { original: string; vendor: string } {
  const vi = getCI(row, "VersionInformation");
  const src = isObject(vi) ? vi : row;
  return {
    original: str(getCI(src, "OriginalFilename") ?? getCI(src, "OriginalName")).trim(),
    vendor: str(getCI(src, "CompanyName")).trim() || str(getCI(src, "ProductName")).trim(),
  };
}

// Hashes, lowercased and length-checked. Returned as FIELDS on the event (not only as IOCs) because
// `sha256`/`md5` are what cross-tool correlation joins on — a THOR or Amcache row for the same file
// cannot be matched to this one without them.
function rowHashes(row: Row): { sha256: string; md5: string } {
  const h = getCI(row, "Hash");
  const src = isObject(h) ? h : row;
  const pick = (key: string, len: number): string => {
    const v = str(getCI(src, key)).trim().toLowerCase();
    return v.length === len && /^[a-f0-9]+$/.test(v) ? v : "";
  };
  return { sha256: pick("SHA256", 64), md5: pick("MD5", 32) };
}

/** An explicit rule verdict, if a future release of the artifact ships one. */
function explicitSeverity(row: Row): Severity | undefined {
  const d = getCI(row, "Detection");
  const src = isObject(d) ? d : row;
  const word = str(getCI(src, "Criticality") ?? getCI(src, "Severity") ?? getCI(src, "Level"))
    .trim()
    .toLowerCase();
  return word ? SEV_WORD[word] : undefined;
}

function readRow(row: Row): RenameFacts {
  const path = str(getCI(row, "OSPath") ?? getCI(row, "FullPath") ?? getCI(row, "Path")).trim();
  const onDisk = str(getCI(row, "Name")).trim() || (path ? leafName(path) : "");
  const { original, vendor } = versionInfo(row);
  const { sha256, md5 } = rowHashes(row);
  // A rename needs BOTH names. Without an on-disk name there is no claim to make, and asserting one
  // produced an escalated finding whose title named no file at all.
  const comparable = onDisk !== "" && original !== "";
  return {
    path,
    onDisk,
    original,
    vendor,
    sha256,
    md5,
    renamed: comparable && leafName(onDisk) !== leafName(original),
    unknownOrigin: onDisk !== "" && original === "",
    systemUtility: SYSTEM_UTILITIES.test(leafName(original)),
    staged: isStagedPath(path),
    explicit: explicitSeverity(row),
  };
}

// Grade from what the file IS, not what it is called.
//
// Both escalations are deliberately independent of where the file lives. An earlier version
// suppressed the system-utility escalation inside Program Files and System32, reasoning that a
// vendor renaming its own helper there is ordinary. That inverts the signal for the highest-risk
// case: a legitimate cmd.exe in System32 is NAMED cmd.exe, so a renamed one there is more suspicious
// than the same file in an arbitrary folder — and placing it needs admin rights.
//
// A row the detector returned but whose version resource is missing cannot prove a rename, so it is
// not called one; it still gets a Medium floor (High when staged) rather than Info, because a
// resource-stripped binary is the shape most likely to be packed, and Info is invisible to the
// analysis — the exact failure this module exists to remove.
function gradeRename(f: RenameFacts): Severity {
  if (f.explicit) return f.explicit;
  if (!f.renamed && !f.unknownOrigin) return "Info"; // name matches the resource — nothing to report
  let severity: Severity = "Medium";
  if (f.renamed && f.systemUtility) severity = worst(severity, "High");
  if (f.staged) severity = worst(severity, "High");
  return severity;
}

// Lead with the fact an analyst needs and no other field states: the binary this file really is. A
// title naming only the on-disk file repeats the attacker's chosen label back to the reader.
function describeRename(f: RenameFacts): string {
  let out: string;
  if (f.renamed) {
    out = `Velociraptor: Renamed binary — ${oneLine(f.onDisk).slice(0, 120)} is really ${oneLine(f.original).slice(0, 120)}`;
    if (f.vendor) out += ` (${oneLine(f.vendor).slice(0, 80)})`;
  } else if (f.unknownOrigin) {
    out = `Velociraptor: Binary with no version resource — ${oneLine(f.onDisk).slice(0, 120)} carries no OriginalFilename to compare`;
  } else {
    out = `Velociraptor: Renamed binary — ${oneLine(f.onDisk).slice(0, 120)} (name matches OriginalFilename)`;
  }
  if (f.path) out += ` at ${oneLine(f.path).slice(0, 200)}`;
  if (f.renamed && f.systemUtility) out += " [renamed system utility]";
  if (f.staged) out += " [staged: temp/appdata]";
  return out;
}

// The PATH is in the key, and digits are NOT stripped. Both were wrong in the first version: the key
// held only the name pair, so two binaries dropped at different paths under the same pair collapsed
// into one row with a count and a single surviving path, and digit-stripping — copied from
// persistenceSniperImport, where it collapses volatile GUIDs in task paths — folded svchost1.exe and
// svchost2.exe together on top of that. A renamed binary is evidence of a specific file at a specific
// place; nothing about it is volatile enough to normalise away.
//
// THE CAP MUST NOT COST A DISCRIMINATOR, which is why the host leads and the path trails. Two rows
// sharing a key do not merely merge a count: aggregation keeps ONE row and applyEventIdentity
// overwrites its path, hash and description with whichever row landed last, so a collision DELETES
// one binary's evidence rather than miscounting it.
//
// The host used to sit LAST, so it was the first field truncation threw away — and a deep path
// reaches 400 characters on its own. A renamed binary found at the same path on two machines came
// back as one finding on one machine, which is the cross-host merge #659 fixed for Windows events
// arriving again by a different route. Host first puts every short discriminator inside the bound
// by construction.
//
// The path is then the only field that can realistically exhaust what is left, and when it does
// boundedAggKey puts a digest of the FULL key in the tail, so two deep paths sharing a 400-character
// prefix stay two rows. A key short enough to fit is untouched, so nothing that already aggregates
// correctly starts aggregating differently. That bound is shared — the YARA mappers reach it the same
// way — and lives with its reasoning in aggKey.ts.
function renameAggKey(f: RenameFacts, host: string): string {
  return boundedAggKey(
    `vr-rename|${host.toLowerCase()}|${leafName(f.onDisk)}|${leafName(f.original)}|${f.path.toLowerCase()}`,
  );
}

// A masquerading binary is a COPY of the tool it impersonates. A copy carries the SOURCE file's
// Mtime and gets a fresh Btime on this volume, and velociraptorImport's pickTime() prefers Mtime — so
// the event anchors at the build date of the file that was copied, not at the moment the attacker
// dropped it here. In one real collection every renamed binary timestamped eight months before the
// intrusion, off the incident timeline entirely. When Btime is LATER than the picked time, Btime is
// when this file appeared on this host, which is the moment the analyst is looking for.
//
// The value is EMITTED through normalizeTime — the same path pickTime() uses — and parsed only to
// order the two. A Date round-trip would do neither job: it truncates Velociraptor's sub-millisecond
// precision (…12.6207768Z becomes …12.620Z), and it reads a timezone-less Btime in the SERVER's own
// zone, so the same collection would date differently on a UTC host and a UTC+3 host.
function dropTime(row: Row, picked: string): string {
  const btime = normalizeTime(str(getCI(row, "Btime")));
  if (!btime) return picked;
  const btimeMs = Date.parse(btime);
  if (Number.isNaN(btimeMs)) return picked;
  const pickedMs = Date.parse(picked);
  if (!Number.isNaN(pickedMs) && btimeMs <= pickedMs) return picked;
  return btime;
}

export function mapBinaryRename(
  row: Row,
  host: string,
  sink: Map<string, SiemIoc>,
  timestamp: string,
): MappedEvent {
  const f = readRow(row);

  if (f.path) addIoc(sink, "file", f.path.slice(0, 300));
  if (f.sha256) addIoc(sink, "hash", f.sha256);
  else if (f.md5) addIoc(sink, "hash", f.md5);

  return {
    timestamp: dropTime(row, timestamp),
    description: withHostSuffix(describeRename(f), host).slice(0, 600),
    severity: gradeRename(f),
    // T1036.003 Rename System Utility when it is one, else plain T1036 Masquerading. A row that
    // proves no rename carries no masquerading technique.
    mitre: f.renamed ? (f.systemUtility ? ["T1036.003", "T1036"] : ["T1036"]) : [],
    aggKey: renameAggKey(f, host),
    sources: ["Velociraptor"],
    ...(f.path ? { path: f.path } : {}),
    ...(host ? { asset: host } : {}),
    ...(f.sha256 ? { sha256: f.sha256 } : {}),
    ...(f.md5 ? { md5: f.md5 } : {}),
  };
}
