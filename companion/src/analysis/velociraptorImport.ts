// Deterministic importer for Velociraptor native JSON output — the fifth deterministic
// ingest path (THOR, SIEM, Chainsaw, Hayabusa, Velociraptor); no AI call.
//
// Velociraptor is a collection + detection platform: VQL artifacts emit JSON rows whose
// columns vary completely by artifact. Per the Companion's post-detection principle we
// ingest its OUTPUT — we do not run VQL/Sigma/YARA ourselves. The richest rows for the
// timeline are its DETECTION artifacts, so each row is classified and mapped accordingly:
//
//   • Sigma     (`*.Detection.Sigma`, or a `Rule:{Title,Level}` + parsed event) — verdict
//                first: the matched rule's Level drives severity, its Title leads the
//                description, its tags become MITRE; the parsed EVTX event underneath is
//                mapped with the SAME per-EID logic the SIEM/Chainsaw paths use (reused).
//   • YARA      (`*.Detection.Yara.*`, or a string `Rule` + Strings/Meta/Namespace) — a
//                real detection ⇒ High; rule name + scanned file/process + hash → event+IOCs.
//   • EventLog  (a parsed evtx row: `System`+`EventData`) — reuse `mapWindows` per-EID.
//   • Generic   (pslist / netstat / file listing / any other artifact) — auto-detect the
//                artifact's own time (NOT the `_ts` collection time unless nothing better),
//                host, and message; pull IOCs from every column.
//
// Inputs accepted: a JSON array, JSONL/NDJSON (the native collection-results form), a single
// object, an Elastic-style wrapper, or a Velociraptor multi-artifact map { "Artifact.Name":
// [rows], … }. All events are tagged "Velociraptor" for cross-source correlation.

import type { Severity } from "./stateTypes.js";
import { normalizeRow } from "./veloRowNormalize.js";
import { parsedNewProcess, salientFromMessage } from "./veloMessageFields.js";
import { thorFields } from "./thorRowMap.js";
import { consolidateVeloScriptBlocks } from "./scriptBlockFragments.js";
// The expandable full-detail message, and the cap that bounds it — see truncatedRemainder.ts.
import { cappedMessage } from "./truncatedRemainder.js";
import { parseCsv } from "./csvImport.js";
import { scrapeEvidence } from "./veloTextIocs.js";
import {
  extractRecords,
  mapWindows,
  aggregateEvents,
  flatten,
  genericIocs,
  parseHashes,
  cleanIp,
  addIoc,
  mergeRowIocs,
  firstStr,
  baseName,
  oneLine,
  worst,
  str,
  isObject,
  getCI,
  getPath,
  mitreFromText,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";
// A row from a Velociraptor artifact that shells out to Chainsaw and streams its rows back as
// VQL (e.g. a custom "run chainsaw" artifact) carries Chainsaw's flat Sigma-mapping shape
// (Detection/Severity/Rule Group siblings), not Velociraptor's own DetectRaptor {Detection:{Name,
// Criticality}} convention — reuse chainsawImport's shape check + mapper so it isn't misclassified
// as a generic detection() row, which would read no severity from a sibling field and silently
// downgrade a real Critical (e.g. "Security Audit Logs Cleared") to a keyword-guessed Medium.
import { isFlatChainsawRow, mapFlatChainsawRow } from "./chainsawImport.js";
import { mapPersistenceSniper } from "./persistenceSniperImport.js";
import { mapBinaryRename } from "./binaryRenameImport.js";
import { overlayFlatWindowsEid } from "./flatWindowsEvent.js";
import { detectTimestomp } from "./timestompDetect.js";
import { networkTokens } from "./networkTokens.js";
import { gradeMotwDownload, zoneText } from "./motwDownload.js";
import { isAccountUsageRow, mapAccountUsage } from "./accountUsageImport.js";
import { withHostSuffix, titleSafe, demangleUtf16Noise } from "./velociraptorTitle.js";
import {
  isDetectionContentPath,
  isGeneratedModuleScript,
  isDetectionToolLocation,
  isDetectionSampleHost,
} from "./veloDetectionNoise.js";
import { gradeYaraHit, yaraHitAggKey } from "./yaraGrade.js";
import { ransomwareSignal } from "./ransomwareDetect.js";
import { rdpLateralSignal } from "./rdpLateralDetect.js";
import { mapHijackLib } from "./hijackLibImport.js";
import { decodeHitContext } from "./yaraHitContext.js";
import { amcacheMasquerade } from "./amcacheMasquerade.js";
import { MAX_TIME_MS, MIN_TIME_MS, pickTime, vrTime } from "./veloRowTime.js";
import { prefetchSignal } from "./prefetchExecution.js";
import { isSamAccountRow, mapSamAccount } from "./samAccountImport.js";

type Row = Record<string, unknown>;

export interface VelociraptorImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  artifact?: string; // fallback artifact/source label (e.g. the filename) when rows carry no _Source
  hostFallback?: string; // asset to stamp on events whose row carries no host (single-client flow import)
}

export interface VelociraptorParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number; // rows found
  kept: number; // events emitted (after aggregation + cap)
  dropped: number; // rows not represented (below floor / capped)
  groups: number; // distinct event groups before the cap
  detections: number; // Sigma + YARA detection rows seen
  format: string; // "array" | "jsonl" | "artifact-map" | "single" | …
  hostname: string;
}

const IPV4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
// A field whose NAME marks its value as a software / assembly / schema version, not a network
// address. `FileVersion:"11.0.49.0"` and `ProductVersion:"8.0.0.1"` are valid dotted quads, so octet
// validation alone cannot reject them — the key is the only signal that they are not IOCs.
const VERSION_KEY = /version|\bbuild\b|revision|assembly/i;
const HEX_HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;

const SIGMA_LEVEL: Record<string, Severity> = {
  critical: "Critical",
  crit: "Critical",
  high: "High",
  medium: "Medium",
  med: "Medium",
  low: "Low",
  informational: "Info",
  info: "Info",
};
const SEV_WORDS: Record<string, Severity> = {
  ...SIGMA_LEVEL,
  warning: "Medium",
  warn: "Medium",
  error: "High",
  notice: "Low",
  alert: "Critical",
};

const WRAPPER_KEYS = new Set([
  "data",
  "hits",
  "events",
  "records",
  "results",
  "logs",
  "rows",
  "items",
  "alerts",
  "value",
]);

function flatStr(v: unknown): string {
  if (v == null) return "";
  if (Array.isArray(v)) return v.map(flatStr).join(" ");
  if (isObject(v)) return Object.values(v).map(flatStr).join(" ");
  return String(v);
}

// The human-readable message for a row. Velociraptor Sigma/Hayabusa rows put it in `Details`; the
// parsed event (when present) carries its own `Message`. Used for the description AND for keeping
// distinct detections distinct (see msgFingerprint).
function rowMessage(row: Row): string {
  const m = firstStr(row, ["Message", "Details", "message"]);
  if (m) return m;
  const ev = getCI(row, "_Event");
  return isObject(ev) ? str(getCI(ev, "Message")) : "";
}

// A stable djb2 hash → base36, for folding message content into an aggregation key compactly.
function hashStr(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}

// Fingerprint a message for aggregation: normalize away VOLATILE bits (GUIDs, any digits — PIDs,
// thread/record ids, counters) but keep the words AND every network address, then hash the WHOLE
// thing. So two detections that differ only in a PID collapse, while two that name different tools
// (HackTool:Passview vs HackTool:Mimikatz) or different peers stay separate — the message, not just
// the rule title, decides identity. The hash (not a prefix) means a distinguishing token anywhere
// in a long, boilerplate-heavy message still separates the events, and keeps the folded key a fixed
// length however many addresses one message names.
function msgFingerprint(msg: string): string {
  const line = oneLine(msg)
    .toLowerCase()
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "");
  const addrs = networkTokens(line);
  const norm = line
    .replace(/\d+/g, "")
    .replace(/[^a-z]+/g, " ")
    .trim();
  const joined = addrs.length ? `${norm} ${addrs.join(" ")}`.trim() : norm;
  return joined ? hashStr(joined) : "";
}

// ───────────────────────────── detection verdicts ─────────────────────────────

// Many Velociraptor "*.Detection.*" artifacts (DetectRaptor et al.) carry their VERDICT in a
// `Detection` field — a bare string ("Cobalt Strike: trick_ryuk.profile") or an object with a
// rule `Name` (+ optional `Criticality`/`Severity`) — or in `RuleName`/`RuleID`. Per the
// post-detection principle we consume that verdict (we don't re-evaluate the rule): its text
// leads the description, its own criticality drives severity, and any Txxxx ids become MITRE.
interface Verdict {
  title: string;
  critWord: string;
  mitre: string[];
}

function rowVerdict(row: Row): Verdict | null {
  const d = getCI(row, "Detection");
  let title = "";
  let critWord = "";
  if (typeof d === "string") title = d.trim();
  else if (isObject(d)) {
    title = str(getCI(d, "Name") ?? getCI(d, "Title") ?? getCI(d, "Rule") ?? getCI(d, "ID")).trim();
    critWord = str(getCI(d, "Criticality") ?? getCI(d, "Severity") ?? getCI(d, "Level"))
      .trim()
      .toLowerCase();
    // DetectRaptor "keyword scan" detections (e.g. .Detection.MFT) carry the matched string in
    // StringHit/HitString rather than a rule Name — use it as the verdict subject so the row is
    // treated as a detection (severity escalates on a malware/tool keyword) instead of generic noise.
    if (!title) title = str(getCI(d, "StringHit") ?? getCI(d, "HitString") ?? getCI(d, "Hit")).trim();
  }
  if (!title) title = firstStr(row, ["RuleName", "RuleID"]).trim();
  if (!title) return null;
  const mitre = mitreFromText(
    title,
    firstStr(row, ["RuleName"]),
    flatStr(getCI(row, "Tags") ?? getCI(row, "Mitre")),
  );
  return { title, critWord, mitre };
}

// Known malware-family / offensive-tooling keywords in a verdict title → escalate. These read
// the tool's OWN verdict wording, not the raw artifact, so it stays "consume, don't re-detect".
const CRIT_KEYWORDS =
  /ransom|lockbit|\bconti\b|wannacry|black\s*cat|\balphv\b|emotet|trickbot|qakbot|\bhive\b/i;
const HIGH_KEYWORDS =
  /cobalt\s*strike|mimikatz|web\s*shell|webshell|lazagne|rubeus|sharphound|bloodhound|meterpreter|\bbeacon\b|reverse\s*shell|secretsdump|psexec|\bsliver\b|brute\s*ratel|nanodump|seatbelt|\blsass\b|kerberoast|dcsync|impacket/i;

// Severity for a detection verdict: the rule's explicit Criticality/Severity wins; else
// DetectRaptor conventions (a "BAU …" baseline or an "IN DEVELOPMENT" rule → Low); else a
// malware/tool keyword escalates; else Medium (a named detection rule fired — worth surfacing).
function detectionSeverity({ title, critWord }: Verdict): Severity {
  const explicit = critWord ? (SIGMA_LEVEL[critWord] ?? SEV_WORDS[critWord]) : undefined;
  if (explicit) return explicit;
  if (/\bin\s*development\b/i.test(title)) return "Low";
  if (/^\s*bau\b/i.test(title)) return "Low";
  if (CRIT_KEYWORDS.test(title)) return "Critical";
  if (HIGH_KEYWORDS.test(title)) return "High";
  return "Medium";
}

// ───────────────────────────── host ─────────────────────────────
// Row TIMES live in veloRowTime.ts (pickTime / vrTime) — imported above.

const HOST_KEYS = ["Fqdn", "Hostname", "Computer", "ComputerName", "System.Computer", "Host", "ClientName"];
function pickHost(row: Row): string {
  for (const k of HOST_KEYS) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const s = str(v).trim();
    if (s) return s;
  }
  return "";
}

// ───────────────────────────── IOCs / hashes ─────────────────────────────

function vrHashes(row: Row): { sha256?: string; md5?: string } {
  const h = parseHashes(row, row); // "Hashes" string + hashes_ex object
  let { sha256, md5 } = h;
  if (!sha256) {
    const d = firstStr(row, [
      "HashSHA256",
      "SHA256",
      "Sha256",
      "sha256",
      "UploadSHA256",
      "Hash.SHA256",
      "Hash.Sha256",
    ]).toLowerCase();
    if (/^[a-f0-9]{64}$/.test(d)) sha256 = d;
  }
  if (!md5) {
    const d = firstStr(row, ["MD5", "Md5", "md5", "Hash.MD5", "Hash.Md5"]).toLowerCase();
    if (/^[a-f0-9]{32}$/.test(d)) md5 = d;
  }
  return { sha256, md5 };
}

// Extract IOCs from every column of a row (used by generic + YARA rows).
function collectRowIocs(row: Row, sink: Map<string, SiemIoc>): { sha256?: string; md5?: string } {
  const pairs: [string, string][] = [];
  flatten(row, pairs);
  genericIocs(
    pairs.filter(([, v]) => !isDetectionContentPath(v)),
    sink,
  );
  const { sha256, md5 } = vrHashes(row);
  if (sha256) addIoc(sink, "hash", sha256);
  else if (md5) addIoc(sink, "hash", md5);
  for (const [k, v] of pairs) {
    const val = v.trim();
    const ip = cleanIp(val);
    // Treat a bare dotted-quad as an IP only when the KEY is network-ish (ip/addr) or the value is a
    // valid address AND the key is not a version field — otherwise `FileVersion:"11.0.49.0"` becomes
    // a fake IP IOC (it did, in every eval case).
    if (ip && (/ip|addr/i.test(k) || (IPV4.test(val) && !VERSION_KEY.test(k)))) addIoc(sink, "ip", ip);
    if (HEX_HASH.test(val)) addIoc(sink, "hash", val.toLowerCase());
  }
  return { sha256, md5 };
}

// ───────────────────────────── EVTX-row normalization ─────────────────────────────

// A Velociraptor parsed-evtx row carries `System` + `EventData` (sometimes under `Event`), or —
// for artifacts that flatten the event (e.g. DetectRaptor's Windows.Detection.Evtx) — top-level
// `Channel`/`EventID`/`EventData`. Reshape either to the flat record `mapWindows` consumes,
// normalizing the EventID (number or `{ Value }`/`{ #text }`) to a bare value, plus the host.
function winRowToFlat(row: Row): { rec: Row; host: string } | null {
  const sys = isObject(getCI(row, "System"))
    ? (getCI(row, "System") as Row)
    : isObject(getPath(row, "Event.System"))
      ? (getPath(row, "Event.System") as Row)
      : null;
  const edRaw = getCI(row, "EventData") ?? getPath(row, "Event.EventData");

  if (sys) {
    let eid: unknown = getCI(sys, "EventID");
    if (isObject(eid)) eid = getCI(eid, "Value") ?? getCI(eid, "#text");
    const channel =
      str(getCI(sys, "Channel")) ||
      str(getPath(sys, "Provider.Name")) ||
      str(getPath(sys, "Provider.#attributes.Name"));
    return {
      host: str(getCI(sys, "Computer")).trim(),
      rec: {
        event_id: eid,
        channel,
        event_data: isObject(edRaw) ? edRaw : {},
        "@timestamp": vrTime(getCI(sys, "TimeCreated")),
        message: str(getCI(row, "Message")),
      },
    };
  }

  // Flat shape: top-level Channel/EventID/EventData with no System wrapper.
  let eidFlat: unknown = getCI(row, "EventID") ?? getCI(row, "EventId");
  if (eidFlat == null && !isObject(edRaw)) return null;
  if (isObject(eidFlat)) eidFlat = getCI(eidFlat, "Value") ?? getCI(eidFlat, "#text");
  return {
    host: str(getCI(row, "Computer")).trim(),
    rec: {
      event_id: eidFlat,
      channel: str(getCI(row, "Channel")),
      event_data: isObject(edRaw) ? edRaw : {},
      "@timestamp": pickTime(row),
      message: str(getCI(row, "Message")),
    },
  };
}

// ───────────────────────────── per-row mapping ─────────────────────────────

type Kind =
  | "sigma"
  | "yara"
  | "chainsaw"
  | "detection"
  | "eventlog"
  | "pslist"
  | "netstat"
  | "download"
  | "startup"
  | "taskscheduler"
  | "persistenceSniper"
  | "binaryRename"
  | "accountUsage"
  | "usn"
  | "mft"
  | "browser"
  | "prefetch"
  | "userassist"
  | "shimcache"
  | "shellbags"
  | "amcacheApp"
  | "samAccount"
  | "amcacheFile"
  | "lnk"
  | "hijacklib"
  | "generic";

function artifactName(row: Row): string {
  return firstStr(row, ["_Source", "Artifact", "_Artifact", "artifact", "Source", "ArtifactName"]);
}

function classify(row: Row, artifact: string): Kind {
  const a = artifact.toLowerCase();
  if (/yara/.test(a)) return "yara";
  if (/sigma/.test(a)) return "sigma";
  // Artifact-name fast-paths for the most common telemetry artifacts (column detection is the fallback)
  if (/netstat/.test(a)) return "netstat";
  if (/pslist|pstree|psscan/.test(a)) return "pslist";
  if (/browserdownload|evidence.*download/i.test(a)) return "download";
  if (/startup|autorun/i.test(a)) return "startup";
  if (/taskscheduler/i.test(a)) return "taskscheduler";
  if (/persistencesniper/i.test(a)) return "persistenceSniper";
  if (/binaryrename/i.test(a)) return "binaryRename";
  if (/condensedaccountusage/i.test(a)) return "accountUsage";
  // Both prefetch artifacts by name: Windows.Forensics.Prefetch AND Windows.Timeline.Prefetch.
  // Improved, whose per-run-time rows do not always carry the Executable+RunCount pair the
  // column fallback below looks for — so half the execution evidence reached the generic mapper.
  // Excludes a DETECTION pack's own prefetch rules (DetectRaptor.…Detection.Prefetch): those rows
  // carry a verdict, and the verdict must lead — the fast paths here all run before rowVerdict().
  if (/prefetch/i.test(a) && !isDetectionArtifact(a)) return "prefetch";
  // Generic.Forensic.SQLiteHunter collects every SQLite store on the box under ONE artifact name
  // with a per-source suffix ("…/Chromium Browser History_Visits", "…/IE or Edge WebCacheV01_All
  // Data"). Its browsing sources carry the same visited-URL columns Chrome/Edge.History does, so
  // route them to the same mapper instead of letting a visit render as a key=value dump.
  if (/sqlitehunter/i.test(a) && /histor|webcache|visit|urls?\b/i.test(a)) return "browser";
  // DetectRaptor.Windows.Detection.HijackLibsMFT: a hijackable DLL located on disk. Distinctive
  // `HijackLibInfo` shape, no `Detection` verdict — so rowVerdict skips it and, before this, it fell
  // to the generic mapper (a flat file dump graded Medium by the detection floor, no T1574 mapping).
  if (isObject(getCI(row, "HijackLibInfo"))) return "hijacklib";

  const rule = getCI(row, "Rule");
  if (
    typeof rule === "string" &&
    rule.trim() &&
    (getCI(row, "Strings") || getCI(row, "Meta") || getCI(row, "Namespace") || getCI(row, "Rules"))
  )
    return "yara";
  if (isObject(rule) && (getCI(rule, "Title") || getCI(rule, "Level"))) return "sigma";

  // Chainsaw's flat Sigma-mapping row (Detection/Severity/Rule Group siblings) — BEFORE the
  // generic rowVerdict() check below, which would otherwise treat the bare `Detection` string
  // as a DetectRaptor verdict and never read the sibling `Severity`/`Rule Group` fields.
  if (isFlatChainsawRow(row)) return "chainsaw";

  // A `Detection`/`RuleName` verdict → verdict-first, BEFORE the eventlog branch so a detection
  // that also carries a parsed Windows event (DetectRaptor's Evtx) is overlaid, not flattened.
  if (rowVerdict(row)) return "detection";

  if (getCI(row, "System") || getCI(row, "EventData") || getPath(row, "Event.System")) {
    if (firstStr(row, ["Level"]) && firstStr(row, ["Title", "SigmaTitle", "RuleTitle"])) return "sigma";
    return "eventlog";
  }
  // Column-based fallbacks for files without _Source markers
  if (getCI(row, "CallChain") != null && getCI(row, "Pid") != null && getCI(row, "Name") != null)
    return "pslist";
  if (getCI(row, "Laddr") != null && getCI(row, "Lport") != null && getCI(row, "Status") != null)
    return "netstat";
  // Evidence-of-download rows: Zone.Identifier ADS data (DownloadedFilePath + HostUrl)
  if (getCI(row, "DownloadedFilePath") != null && getCI(row, "HostUrl") != null) return "download";
  // Startup/autorun rows: Name + OSPath + Enabled (Windows.Sys.StartupItems and similar)
  if (getCI(row, "Enabled") != null && getCI(row, "OSPath") != null && getCI(row, "Name") != null)
    return "startup";
  // Scheduled task rows (Windows.System.TaskScheduler/Analysis): TaskName is unique to this artifact
  if (getCI(row, "TaskName") != null && (getCI(row, "Mtime") != null || getCI(row, "OSPath") != null))
    return "taskscheduler";
  // Windows.EventLogs.CondensedAccountUsage — an authentication event already condensed to flat
  // columns, with no System/EventData to reach the eventlog branch. Checked BEFORE that branch's
  // column fallbacks so it never lands in the generic mapper, which drops every column but the verb.
  if (isAccountUsageRow(row)) return "accountUsage";
  // Windows.Forensics.SAM — the local account database. Checked before the generic fallthrough so
  // the account (and its RID) leads, instead of the decoded ParsedV hash blob the flattener emits.
  if (isSamAccountRow(row)) return "samAccount";
  // Windows.Forensics.PersistenceSniper wraps the PersistenceSniper PowerShell module verbatim —
  // Technique + Classification + "Access Gained" is that module's own column set and isn't reused
  // by any other artifact, so it's a safe signature even without a recognisable _Source.
  if (
    getCI(row, "Technique") != null &&
    getCI(row, "Classification") != null &&
    getCI(row, "Access Gained") != null
  )
    return "persistenceSniper";
  // DetectRaptor.Windows.Detection.BinaryRename — a file stat plus its version resource, with no
  // Detection column of its own. `OriginalFilename` under VersionInformation alongside an OSPath is
  // that artifact's signature; no other artifact pairs the two.
  {
    const vi = getCI(row, "VersionInformation");
    if (isObject(vi) && getCI(vi, "OriginalFilename") != null && getCI(row, "OSPath") != null)
      return "binaryRename";
  }
  // Windows.Forensics.Usn — the USN change-journal row: a `Reason` (the filesystem operation:
  // FILE_CREATE / FILE_DELETE / DATA_EXTEND / RENAME_* …) alongside a Usn/MFTId. Mapped specially so
  // the operation lands in the description + agg key (mapGeneric drops it → path-only events).
  if (getCI(row, "Reason") != null && (getCI(row, "Usn") != null || getCI(row, "MFTId") != null))
    return "usn";
  // Windows.NTFS.MFT — an $MFT entry carrying the bare MACB timestamp columns. Expanded to one
  // labeled event per distinct $SI/$FN timestamp so a file's modification/access (not just its
  // creation) shows on the timeline.
  if (
    getCI(row, "EntryNumber") != null &&
    (getCI(row, "Created0x10") != null || getCI(row, "LastModified0x10") != null)
  )
    return "mft";
  // Forensic artifacts whose row carries an implicit ACTION (visited / executed / browsed / installed)
  // — each detected by a field unique to that artifact, and mapped to lead with the verb + real subject
  // instead of the raw registry key / DB-file path the generic mapper would surface.
  if (getCI(row, "visited_url") != null) return "browser"; // browser history → visited URL
  if (
    getCI(row, "PrefetchFileName") != null ||
    (getCI(row, "Executable") != null && getCI(row, "RunCount") != null)
  )
    return "prefetch"; // → executed
  if (getCI(row, "NumberOfExecutions") != null) return "userassist"; // UserAssist → ran (count)
  if (getCI(row, "ExecutionFlag") != null && getCI(row, "Path") != null) return "shimcache"; // AppCompatCache → execution evidence
  if (getCI(row, "_RawData") != null && getCI(row, "FullPath") != null) return "shellbags"; // Shellbags → folder browsed
  if (getCI(row, "InstallDate") != null && getCI(row, "Publisher") != null) return "amcacheApp"; // Amcache app → installed
  if (
    getCI(row, "BinaryType") != null ||
    (getCI(row, "SHA1") != null && getCI(row, "OriginalFileName") != null)
  )
    return "amcacheFile"; // Amcache file → present
  if (getCI(row, "ShellLinkHeader") != null || getCI(row, "LinkTarget") != null) return "lnk"; // LNK → shortcut to target
  return "generic";
}

function mapYara(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const rule = getCI(row, "Rule");
  const ruleName =
    typeof rule === "string" && rule.trim()
      ? rule.trim()
      : str(getPath(row, "Rule.id")) ||
        str(getPath(row, "Rule.Name")) ||
        firstStr(row, ["RuleName", "Namespace"]) ||
        "match";
  // A YARA hit's only OBSERVED indicator is the matched file (+ its hash / owning process). The rule's
  // Meta (reference/source_url/author/sample hashes), Strings, and the binary HitContext are detection
  // LOGIC — flattening the whole row (collectRowIocs) scrapes the rule's GitHub links and match-context
  // bytes as bogus IOCs (a pagefile scan produced 700+ junk hashes / 360+ junk URLs). Extract
  // selectively: structured file hash only. (#102)
  const { sha256, md5 } = vrHashes(row);
  if (sha256) addIoc(sink, "hash", sha256);
  else if (md5) addIoc(sink, "hash", md5);

  const path = firstStr(row, ["OSPath", "FullPath", "_FullPath", "File", "FilePath", "Path"]);
  const procName = firstStr(row, ["Exe", "ProcessName", "ImageName"]);
  const pid = firstStr(row, ["Pid", "ProcessId"]);

  // Grade by context, not a flat High (self-scan → Info, volatile string → Low, heuristic → Medium,
  // named malware on a real path → High). See yaraGrade.ts.
  const grade = gradeYaraHit(ruleName, path, procName);

  // The matched file is a real IOC only when it is a real dropped file — never the collector's own
  // tooling, a rule-content file, or a volatile container (a page-file hit names no file to block).
  if (path && !isDetectionContentPath(path) && grade.reason !== "self-scan" && !grade.volatile)
    addIoc(sink, "file", path);
  if (procName && grade.reason !== "self-scan") addIoc(sink, "process", baseName(procName));

  const mitre = mitreFromText(flatStr(getCI(row, "Meta")), flatStr(getCI(row, "Tags")), ruleName);

  let description = `Velociraptor YARA: ${titleSafe(ruleName)}`;
  if (grade.volatile) {
    // A string in a volatile container is not tied to one file — collapse every such hit on a host
    // into ONE aggregated row so hundreds of page-file matches never crowd the timeline.
    description += ` in a volatile memory container (page file / crash dump — string present, not proof of execution)`;
  } else {
    if (procName) description += ` - ${baseName(procName)}${pid ? ` (pid ${pid})` : ""}`;
    else if (path) description += ` - ${path}`;
    // WHY the rule fired. Description only, never the IOC sink — see yaraHitContext.
    const hit = decodeHitContext(str(getCI(row, "HitContext")));
    if (hit) description += ` [Hit: ${hit}]`;
  }
  if (grade.reason === "self-scan") description += ` [detection tooling / sample corpus]`;
  else if (grade.reason === "heuristic-trusted") description += ` [heuristic rule on a signed OS binary]`;
  else if (grade.reason === "heuristic") description += ` [heuristic rule — needs corroboration]`;
  description = withHostSuffix(description, host).slice(0, 600);

  const aggKey = yaraHitAggKey(grade, host, ruleName, path || procName);

  return {
    timestamp: pickTime(row),
    description,
    severity: grade.severity,
    mitre,
    aggKey,
    sources: ["Velociraptor"],
    ...(sha256 ? { sha256 } : {}),
    ...(md5 && !sha256 ? { md5 } : {}),
    ...(path ? { path } : {}),
    ...(host ? { asset: host } : {}),
    ...(procName ? { processName: baseName(procName) } : {}),
  };
}

function mapSigma(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const ruleObj = isObject(getCI(row, "Rule")) ? (getCI(row, "Rule") as Row) : undefined;
  const title =
    (ruleObj ? str(getCI(ruleObj, "Title")) : "") ||
    firstStr(row, ["Title", "SigmaTitle", "RuleTitle"]) ||
    "detection";
  const level = (ruleObj ? str(getCI(ruleObj, "Level")) : "") || firstStr(row, ["Level"]);
  const sev = SIGMA_LEVEL[level.toLowerCase()];
  const tags = mitreFromText(
    flatStr(ruleObj ? getCI(ruleObj, "Tags") : getCI(row, "Tags")),
    flatStr(getCI(row, "MitreTags")),
    title,
  );

  const flat = winRowToFlat(row);
  const win = flat ? mapWindows(flat.rec, flat.host || host, sink) : null;
  if (win) {
    if (sev) win.severity = worst(win.severity, sev);
    for (const m of tags) if (!win.mitre.includes(m)) win.mitre.push(m);
    win.description = `Velociraptor Sigma: ${titleSafe(title)} - ${win.description}`.slice(0, 600);
    win.aggKey = `vr-sigma|${title.toLowerCase()}|${win.aggKey}`;
    win.sources = ["Velociraptor"];
    if (!win.timestamp) win.timestamp = pickTime(row);
    return win;
  }
  // No parsed event underneath (e.g. a Windows.Sigma.Base row whose event sits in `Details`/`_Event`)
  // — lead with the verdict, then the message so the analyst sees WHAT fired, not just the rule name.
  collectRowIocs(row, sink);
  scrapeEvidence(row, sink);
  const message = rowMessage(row);
  const detail = salientFromMessage(message) || (message ? oneLine(message).slice(0, 400) : "");
  let description = `Velociraptor Sigma: ${titleSafe(title)}`;
  if (detail) description += ` - ${detail}`;
  description = withHostSuffix(description, host);
  return {
    timestamp: pickTime(row),
    description: description.slice(0, 600),
    severity: sev ?? "Medium",
    mitre: tags,
    aggKey: `vr-sigma|${title.toLowerCase()}|${host.toLowerCase()}`.slice(0, 400),
    sources: ["Velociraptor"],
    ...(host ? { asset: host } : {}),
  };
}

// DetectRaptor ships many distinct "*.Detection.*" rule packs (MFT, Amcache, LolDrivers,
// PSReadline, ...) that all flow through rowVerdict()/mapDetection() — folding them all under the
// generic "Velociraptor detection" bucket hides WHICH rule pack actually fired. When the artifact
// names a DetectRaptor pack, lead with its specific technique name instead (e.g. "DetectRaptor MFT
// detection"); any other Velociraptor-hosted rule pack (Custom.*, Chainsaw, etc.) keeps the
// generic "Velociraptor detection" label.
function detectionLabel(artifact: string): string {
  const a = artifact.trim();
  if (/^DetectRaptor\./i.test(a)) {
    const last = a.split(".").pop();
    if (last) return `DetectRaptor ${last} detection`;
  }
  return "Velociraptor detection";
}

// Does the ARTIFACT name mark a rule pack whose rows are detections by construction (DetectRaptor's
// `*.Detection.*` families and anything self-labelled "detection")? Used only to keep an unrecognised
// row from such a pack out of Info; it never lowers a grade.
function isDetectionArtifact(artifact: string): boolean {
  return /detectraptor|\.detection\.|detection$/i.test(artifact.trim());
}

// A DetectRaptor-style detection: the `Detection`/`RuleName` verdict leads. If a parsed Windows
// event sits underneath (Evtx), overlay the verdict onto the per-EID mapping (like Sigma);
// otherwise build the event from the row's file/process/pipe/path + hashes.
function mapDetection(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const v = rowVerdict(row)!; // guaranteed by classify()
  let severity = detectionSeverity(v);
  // The rule pack graded WHAT the program is; it never compared the two names the row carries.
  const masq = amcacheMasquerade(row);
  if (masq) {
    severity = worst(severity, "High");
    if (!v.mitre.includes("T1036.005")) v.mitre.push("T1036.005");
  }
  scrapeEvidence(row, sink); // pull URLs/IPs/hashes out of the matched command line / file content
  const label = detectionLabel(artifact);

  const flat = winRowToFlat(row);
  const win = flat ? mapWindows(flat.rec, flat.host || host, sink) : null;
  if (win) {
    win.severity = worst(win.severity, severity);
    for (const m of v.mitre) if (!win.mitre.includes(m)) win.mitre.push(m);
    const winEd = flat && isObject(flat.rec.event_data) ? flat.rec.event_data : {};
    const winImage = firstStr(winEd, ["Image", "NewProcessName", "TargetImage", "TargetFilename"]);
    const winTag = baseName(winImage);
    win.description =
      `${label}: ${titleSafe(v.title)}${winTag ? ` — ${winTag}` : ""} - ${win.description}`.slice(0, 600);
    win.aggKey = `vr-det|${v.title.toLowerCase()}|${win.aggKey}`.slice(0, 400);
    win.sources = ["Velociraptor"];
    if (!win.timestamp) win.timestamp = pickTime(row);
    return win;
  }

  // Non-event detection (file / registry / named-pipe / history-line hit, or a flattened EVTX
  // detection whose event sits only in the rendered Message).
  const inUse = getCI(row, "InUse");
  const fileDeleted = inUse === false || str(inUse).toLowerCase() === "false";
  const { sha256, md5 } = collectRowIocs(row, sink);
  const message = rowMessage(row);
  const salient = salientFromMessage(message); // LOLBIN + command line out of a 4688-style message
  // The triggering FILE: include the Amcache/driver/registry path fields (EntryPath/EntryName/
  // Detection.PathName) and the nested FileInfo.OSPath (DetectRaptor ISEAutoSave/PSReadline shape)
  // so a verdict names the file that fired it even when OSPath is nested one level down.
  const path =
    firstStr(row, [
      "OSPath",
      "FullPath",
      "_FullPath",
      "File",
      "FilePath",
      "Path",
      "KeyPath",
      "EntryPath",
      "EntryName",
    ]) ||
    str(getPath(row, "FileInfo.OSPath")).trim() ||
    str(getPath(row, "Detection.PathName"));
  // The matched file IS detection content — a Sigma/YARA rule, or a sample log a rule was written
  // against. The "hit" is a keyword match against the rule's own text (tool names, MITRE ids) or
  // against the name of a captured attack log, not against attacker-controlled content on this
  // host. Treat as Info regardless of what keyword tripped detectionSeverity, so running detection
  // tooling does not itself read as a Critical/High finding. See veloDetectionNoise.
  if (isDetectionContentPath(path)) severity = "Info";
  // The matched CONTENT/evidence: the full matched line/Content the analyst needs to read, falling
  // back to the rule's own HitString (the substring it matched). Track the source field name so
  // it can be shown as a label (Line: / Content: / CommandLine: / etc.). NOT Detection.Regex /
  // KeywordRegex (the rule pattern itself, which stays out of the description).
  const EVIDENCE_FIELD_KEYS = ["Line", "Content", "CommandLine", "StringHit", "HitString"] as const;
  let evidenceKey = "";
  let evidence = "";
  for (const k of EVIDENCE_FIELD_KEYS) {
    const v = str(getCI(row, k)).trim();
    if (v) {
      evidenceKey = k;
      evidence = v;
      break;
    }
  }
  if (!evidence) {
    const hit = str(getPath(row, "Detection.HitString")).trim();
    if (hit) {
      evidenceKey = "HitString";
      evidence = hit;
    }
  }
  const procRaw =
    firstStr(row, ["Exe", "Image", "ProcessName", "ProcName", "NewProcessName"]) || parsedNewProcess(message);
  const parentRaw = firstStr(row, ["ParentName", "ParentImage", "ParentProcessName"]);
  const processName = procRaw ? baseName(procRaw) : undefined;
  const parentName = parentRaw ? baseName(parentRaw) : undefined;
  const pipe = firstStr(row, ["PipeName"]);
  if (processName) addIoc(sink, "process", processName);
  if (path && !isDetectionContentPath(path)) addIoc(sink, "file", path);

  // Subject priority: the rendered event's high-signal fields (the actual LOLBIN/command line) win
  // over structured process/path, which win over the matched content/line. Every field is labeled
  // with its source key (ProcName: / PipeName: / Path: / Line: / Content: / …) and joined with
  // " - " so the analyst can read them at a glance without knowing the artifact's column layout.
  // Content-centric detections (ISEAutoSave, PSReadline) get both the filename AND the evidence.
  let subject: string;
  let titleTag = ""; // most specific identifier (process/pipe/file), promoted into the TITLE itself
  if (salient) {
    subject = salient;
  } else {
    const parts: string[] = [];
    if (processName) parts.push(`ProcName: ${processName}`);
    if (pipe) parts.push(`PipeName: ${pipe}`);
    if (path) parts.push(`Path: ${baseName(path)}`);
    if (parts.length === 0) {
      // No structured fields — fall back to the labeled evidence or plain message.
      if (evidence) {
        parts.push(`${evidenceKey}: ${oneLine(evidence)}`);
      } else {
        parts.push(oneLine(message));
      }
    } else if (!processName && !pipe && evidence) {
      // Content-centric detection (ISEAutoSave / PSReadline): path found but the evidence IS the
      // main signal — include it labeled so the analyst sees what the rule matched.
      parts.push(`${evidenceKey}: ${oneLine(evidence)}`);
    }
    titleTag = processName || pipe || (path && !isDetectionContentPath(path) ? baseName(path) : "");
    subject = parts.join(" - ");
  }

  let description = `${label}: ${titleSafe(v.title)}`;
  if (titleTag) description += ` — ${titleTag}`;
  if (subject) description += ` - ${subject}`;
  if (masq) description += ` [masquerade: ${masq.onDisk} claims ${masq.original}]`;
  if (fileDeleted) description += ` [deleted]`;
  description = withHostSuffix(description, host).slice(0, 4000);

  const aggKey =
    `vr-det|${v.title.toLowerCase()}|${(path || processName || pipe || subject).toLowerCase()}|${host.toLowerCase()}`
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<guid>")
      .replace(/\d+/g, "#")
      .slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity,
    mitre: v.mitre,
    aggKey,
    sources: ["Velociraptor"],
    ...(sha256 ? { sha256 } : {}),
    ...(md5 && !sha256 ? { md5 } : {}),
    ...(path ? { path } : {}),
    ...(host ? { asset: host } : {}),
    ...(processName ? { processName } : {}),
    ...(parentName ? { parentName } : {}),
  };
}

function mapEventlog(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent | null {
  const flat = winRowToFlat(row);
  if (!flat) return null;
  const win = mapWindows(flat.rec, flat.host || host, sink);
  if (!win) return null;
  win.sources = ["Velociraptor"];
  if (!win.timestamp) win.timestamp = pickTime(row);
  return win;
}

const GENERIC_MSG_KEYS = [
  "Message",
  "Details",
  "message",
  "Description",
  "Category",
  "DisplayName",
  "Line",
  "Stdout",
  "CommandLine",
  "PipeName",
  "KeyPath",
  "OSPath",
  "FullPath",
  "Name",
];
// Keys whose values are big/structured (rule regexes, PE internals, raw file content) — useful
// for IOC scanning but noise in a one-line description, so they're skipped in the key=value fallback.
const NOISE_KEY =
  /regex|ignore|imports|exports|sections|resources|directories|versioninformation|dllinfo|hitcontext|\bmeta\b|content|reference|url|license/i;
// Collection-metadata keys (the artifact id surfaced in the "[artifact]" prefix, the _ts collection
// time) — skipped in the key=value fallback so they don't duplicate the prefix / add noise.
const META_KEY = /^(_ts|_Source|_Artifact|ArtifactName)$/i;

// NTFS timestomp check for an MFT row (Windows.NTFS.MFT). Windows.NTFS.MFT emits both $SI and $FN
// creation on the SAME row — Created0x10 ($SI) and Created0x30 ($FN), either top-level or nested under
// SITimestamps/FNTimestamps — so we compare them inline (no cross-event grouping). On a hit: bump the
// row's severity to Medium, add T1070.006, and append the reason. Reads the RAW strings (not pickTime,
// which drops the sub-second precision the truncation signal needs). Directories are skipped (noise).
function applyTimestomp(row: Row, m: MappedEvent): void {
  const isDir = getCI(row, "IsDir");
  if (isDir === true || str(isDir).toLowerCase() === "true") return;
  const si = str(getCI(row, "Created0x10")) || str(getPath(row, "SITimestamps.Created0x10"));
  const fn = str(getCI(row, "Created0x30")) || str(getPath(row, "FNTimestamps.Created0x30"));
  if (!si || !fn) return;
  const v = detectTimestomp(si, fn);
  if (!v) return;
  m.severity = worst(m.severity, v.severity);
  for (const id of v.mitre) if (!m.mitre.includes(id)) m.mitre.push(id);
  m.description = `${m.description} — ${v.note}`.slice(0, 1200);
}

function mapGeneric(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  // A THOR finding streamed through an artifact — read it the THOR way. Artifact + host are what let
  // it prove it is really THOR's, and keep one endpoint's findings apart from another's.
  const thor = thorFields(row, { artifact, host });
  const { sha256, md5 } = collectRowIocs(row, sink);
  scrapeEvidence(row, sink); // URLs/IPs/hashes embedded in Message/Line/Content (key-driven extractors miss these)
  const msg = firstStr(row, GENERIC_MSG_KEYS);
  const pairs: [string, string][] = [];
  flatten(row, pairs);
  const base = msg
    ? oneLine(msg)
    : pairs
        .filter(([k, v]) => !META_KEY.test(k) && !NOISE_KEY.test(k) && v.length <= 200)
        .slice(0, 8)
        .map(([k, v]) => `${k}=${v}`)
        .join(" - ");

  const sevWord = firstStr(row, ["Severity", "Level", "Risk", "Priority"]).toLowerCase();
  let severity: Severity = thor?.severity ?? SEV_WORDS[sevWord] ?? "Info";

  const procName = thor?.processName || firstStr(row, ["Exe", "Image", "ProcessName"]);
  const parentName =
    thor?.parentName || firstStr(row, ["ParentName", "ParentImage", "ParentExe", "ParentProcessName"]);
  // A recognised THOR row uses THOR's identity or NONE. thorRowMap withholds the hash and path of a
  // log-entry finding on purpose (they name the surrounding log and a file merely mentioned in the
  // line, and correlate merges on both); letting the generic lookups below supply them anyway hands
  // the collapse straight back.
  const path = thor ? (thor.path ?? "") : firstStr(row, ["OSPath", "FullPath", "_FullPath", "FilePath"]);

  // Self-scan: a THOR finding streamed through Velociraptor (the ThorZIP artifact) flags the
  // collector binary itself and the cached simulation corpus, exactly as the standalone THOR importer
  // does — demote on a detection-tooling LOCATION (never a bare filename). Same predicate as mapYara
  // and thorImport, so the three ingest paths agree on what "the tool found itself" means.
  if (severity !== "Info" && (isDetectionToolLocation(procName) || isDetectionToolLocation(path))) {
    severity = "Info";
  }

  // Raises on a generic row: ransomware impact (T1486 — encrypted file / ransom note, not a
  // self-scan hit) and RDP lateral movement (T1021.001 — an explicit-cred 4648 to a remote host).
  const genRansom = severity !== "Info" || !isDetectionToolLocation(path) ? ransomwareSignal(path) : null;
  const rdp = rdpLateralSignal(artifact, row);
  const ransomMitre = [...(genRansom?.mitre ?? []), ...(rdp?.mitre ?? [])];
  if (genRansom) severity = worst(severity, genRansom.severity);
  if (rdp) severity = worst(severity, rdp.severity);

  // A THOR row names its own finding; the generic form would name the artifact plumbing instead.
  let description = thor?.description ?? `Velociraptor${artifact ? ` [${artifact}]` : ""}: ${base}`;
  if (genRansom) description = `${description} — ${genRansom.note} (T1486)`.slice(0, 600);
  else if (rdp) description = `${description} — ${rdp.note} (T1021.001)`.slice(0, 600);
  description = withHostSuffix(description.slice(0, 600), host).slice(0, 600);

  const aggKey =
    thor?.aggKey ??
    `vr|${artifact.toLowerCase()}|${host.toLowerCase()}|${base.toLowerCase()}`
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<guid>")
      .replace(/\d+/g, "#")
      .slice(0, 400);

  const m: MappedEvent = {
    timestamp: pickTime(row),
    description,
    severity,
    mitre: [],
    aggKey,
    sources: ["Velociraptor"],
    ...(() => {
      // Same rule for the hashes: THOR's own, or none at all for a THOR row.
      const sha = thor ? thor.sha256 : sha256;
      const m5 = thor ? thor.md5 : md5;
      return { ...(sha ? { sha256: sha } : {}), ...(m5 && !sha ? { md5: m5 } : {}) };
    })(),
    ...(path ? { path } : {}),
    ...(host ? { asset: host } : {}),
    ...(procName ? { processName: baseName(procName) } : {}),
    ...(parentName ? { parentName: baseName(parentName) } : {}),
    ...(thor?.detail ? { message: thor.detail } : {}), // the dashboard's [details] panel body
  };
  if (thor?.mitre.length) m.mitre = [...thor.mitre];
  for (const id of ransomMitre) if (!m.mitre.includes(id)) m.mitre.push(id);
  applyTimestomp(row, m); // MFT rows: flag $SI/$FN timestomping (T1070.006, → Medium)
  return m;
}

// The USN `Reason` (the filesystem operation) as a normalized "FILE_CREATE, DATA_EXTEND" string.
// Velociraptor emits it as an array on most versions, a bare string on a few — handle both.
function usnReason(row: Row): string {
  const r = getCI(row, "Reason");
  if (Array.isArray(r))
    return r
      .map((x) => str(x).trim())
      .filter(Boolean)
      .join(", ");
  return str(r).trim();
}

// Windows.Forensics.Usn — the USN journal is a change log, so the `Reason` (FILE_CREATE / FILE_DELETE /
// DATA_EXTEND / RENAME_NEW_NAME …) is the single most important field: it's the "what happened". The
// generic mapper drops it (falls back to OSPath), producing path-only events, and — because Reason
// isn't in the agg key either — collapses a CREATE and a DELETE on the same path into one event. Here
// the operation drives both the description AND the agg key so distinct operations stay distinct.
function mapUsn(row: Row, artifact: string, host: string): MappedEvent {
  const path =
    firstStr(row, ["OSPath", "FullPath", "_FullPath", "FilePath"]) || str(getCI(row, "Filename")).trim();
  const reason = usnReason(row);
  const label = reason || "change";
  let description = `Velociraptor${artifact ? ` [${artifact}]` : ""}: ${label} — ${oneLine(path)}`.slice(
    0,
    600,
  );
  description = withHostSuffix(description, host).slice(0, 600);
  // Ransomware impact (T1486) hides in the USN journal (encrypted-file renames + the ransom note):
  // grade it High so it survives the most-severe-first cap, and collapse every "encrypted with .X"
  // row on a host into ONE counted finding by the signal note. See ransomwareDetect.
  const ransom = ransomwareSignal(path);
  const aggKey = ransom
    ? `vr|ransomware|${host.toLowerCase()}|${ransom.note.toLowerCase()}`
    : `vr|usn|${host.toLowerCase()}|${reason.toLowerCase()}|${path.toLowerCase()}`
        .replace(/\d+/g, "#")
        .slice(0, 400);
  return {
    timestamp: pickTime(row),
    description: ransom ? `${description} — ${ransom.note} (T1486)`.slice(0, 600) : description,
    severity: ransom ? ransom.severity : "Info",
    mitre: ransom ? [...ransom.mitre] : [],
    aggKey,
    sources: ["Velociraptor"],
    ...(path ? { path } : {}),
    ...(host ? { asset: host } : {}),
  };
}

// The MACB timestamp columns, grouped by NTFS attribute stream: $STANDARD_INFORMATION (0x10, the
// commonly-referenced set) and $FILE_NAME (0x30, harder to timestomp). Letters follow the standard
// bodyfile convention — M=modified, A=accessed, C=MFT-record changed, B=born (created).
const MFT_SI: [string, string][] = [
  ["M", "LastModified0x10"],
  ["A", "LastAccess0x10"],
  ["C", "LastRecordChange0x10"],
  ["B", "Created0x10"],
];
const MFT_FN: [string, string][] = [
  ["M", "LastModified0x30"],
  ["A", "LastAccess0x30"],
  ["C", "LastRecordChange0x30"],
  ["B", "Created0x30"],
];

// Render the present letters of a stream as the fixed-position "macb" token (dots for absent), e.g. a
// timestamp that is both the modified and born time → "m..b".
function macbToken(present: Set<string>): string {
  return ["M", "A", "C", "B"].map((c) => (present.has(c) ? c.toLowerCase() : ".")).join("");
}

// Windows.NTFS.MFT — one $MFT entry carries up to 8 timestamps (MACB × $SI/$FN). The old behavior
// emitted a SINGLE event dated at the creation time only, unlabeled, so a file created long ago but
// MODIFIED during the incident showed only its (irrelevant) birth time — the modification was invisible.
// Expand to one event per DISTINCT timestamp value, labeled with which attributes share it. Files whose
// timestamps are all equal (the common case) collapse back to one event, so this doesn't blow up unless
// the times genuinely differ (which is exactly the forensically-interesting case).
function mapMft(row: Row, artifact: string, host: string): MappedEvent[] {
  const path =
    firstStr(row, ["OSPath", "FullPath", "_FullPath", "FilePath"]) || str(getCI(row, "FileName")).trim();
  // Ransomware impact (T1486): an encrypted file (family extension) or a ransom note recorded in the
  // MFT. Graded High so it survives the most-severe-first cap over hundreds of thousands of Info rows.
  const ransom = ransomwareSignal(path);
  // distinct timestamp value → { si: letters, fn: letters }
  const byTime = new Map<string, { si: Set<string>; fn: Set<string> }>();
  const add = (stream: "si" | "fn", letter: string, key: string): void => {
    const t = vrTime(getCI(row, key));
    if (!t) return;
    const ms = Date.parse(t);
    if (!(ms >= MIN_TIME_MS && ms <= MAX_TIME_MS)) return; // skip 1601/epoch "unset" sentinels
    const slot = byTime.get(t) ?? { si: new Set<string>(), fn: new Set<string>() };
    slot[stream].add(letter);
    byTime.set(t, slot);
  };
  for (const [letter, key] of MFT_SI) add("si", letter, key);
  for (const [letter, key] of MFT_FN) add("fn", letter, key);

  const events: MappedEvent[] = [];
  for (const [t, { si, fn }] of byTime) {
    const parts: string[] = [];
    if (si.size) parts.push(`$SI:${macbToken(si)}`);
    if (fn.size) parts.push(`$FN:${macbToken(fn)}`);
    const macb = parts.join(" ");
    let description = `Velociraptor${artifact ? ` [${artifact}]` : ""}: ${macb} — ${oneLine(path)}`.slice(
      0,
      600,
    );
    description = withHostSuffix(description, host).slice(0, 600);
    // A ransomware sweep touches thousands of MFT records — collapse per host + impact type (see mapUsn).
    const aggKey = ransom
      ? `vr|ransomware|${host.toLowerCase()}|${ransom.note.toLowerCase()}`
      : `vr|mft|${host.toLowerCase()}|${macb.toLowerCase()}|${path.toLowerCase()}`
          .replace(/\d+/g, "#")
          .slice(0, 400);
    events.push({
      timestamp: t,
      description: ransom ? `${description} — ${ransom.note} (T1486)`.slice(0, 600) : description,
      severity: ransom ? ransom.severity : "Info",
      mitre: ransom ? [...ransom.mitre] : [],
      aggKey,
      sources: ["Velociraptor"],
      ...(path ? { path } : {}),
      ...(host ? { asset: host } : {}),
    });
  }
  return events;
}

// ───────────────────────────── forensic-artifact action mappers ─────────────────────────────
// Each artifact records an ACTION (executed / visited / browsed / installed …). The generic mapper
// leads with the first populated field — which for these is the raw registry key, the browser's DB
// file, or the artifact's own path — so the timeline read as a bare filename with no "what happened".
// These mappers lead with the action verb and the RIGHT subject (the URL, the target folder, the
// executable), so a super-timeline row states what occurred, not just which file the row came from.

// The first parseable timestamp among `keys` (dotted paths allowed; arrays take [0]), else "" so the
// caller can fall back to pickTime(row).
function firstTime(row: Row, keys: string[]): string {
  for (const k of keys) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const t = vrTime(Array.isArray(v) ? v[0] : v);
    if (t) return t;
  }
  return "";
}

// Shared "<action> (N×): <subject> @ host" shape. `aggSubject` overrides the agg-key subject when the
// visible subject is too volatile to group on (a URL with a cache-buster, a versioned path).
function actionEvent(o: {
  artifact: string;
  host: string;
  action: string;
  subject: string;
  time: string;
  count?: unknown;
  severity?: Severity;
  path?: string;
  processName?: string;
  aggSubject?: string;
}): MappedEvent {
  const n = Number(o.count);
  const cnt = Number.isFinite(n) && n > 1 ? ` (${n}×)` : "";
  let description =
    `Velociraptor${o.artifact ? ` [${o.artifact}]` : ""}: ${o.action}${cnt}: ${oneLine(o.subject)}`.slice(
      0,
      600,
    );
  description = withHostSuffix(description, o.host).slice(0, 600);
  const aggKey =
    `vr|${o.artifact.toLowerCase()}|${o.host.toLowerCase()}|${o.action.toLowerCase()}|${(o.aggSubject ?? o.subject).toLowerCase()}`
      .replace(/\d+/g, "#")
      .slice(0, 400);
  return {
    timestamp: o.time,
    description,
    severity: o.severity ?? "Info",
    mitre: [],
    aggKey,
    sources: ["Velociraptor"],
    ...(o.path ? { path: o.path } : {}),
    ...(o.host ? { asset: o.host } : {}),
    ...(o.processName ? { processName: baseName(o.processName) } : {}),
  };
}

// Windows.Applications.Chrome/Edge.History — a browsing VISIT. The generic mapper showed the History
// DB file path (OSPath); the actual visited URL + title live in dedicated columns.
function mapBrowserHistory(
  row: Row,
  artifact: string,
  host: string,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  collectRowIocs(row, sink);
  // SQLiteHunter names the same two fields differently per source (Chromium visits, the Edge/IE
  // WebCacheV01 container, the Windows Activities cache), so every spelling is accepted here.
  const url = firstStr(row, ["visited_url", "url", "URL", "Url", "EntryURL", "Uri", "AccessedURL"]);
  const title = firstStr(row, ["title", "Title", "page_title", "PageTitle", "DisplayText"]);
  if (url) addIoc(sink, "url", url.slice(0, 300));
  const subject = title ? `"${title}" — ${url}` : url;
  return actionEvent({
    artifact,
    host,
    action: "Visited",
    subject: subject || "(url)",
    aggSubject: url,
    time:
      firstTime(row, ["visit_time", "last_visit_time", "VisitTime", "AccessedTime", "LastAccessTime"]) ||
      pickTime(row),
    count: getCI(row, "visit_count") ?? getCI(row, "AccessCount"),
  });
}

// Windows.Forensics.Shellbags — a FOLDER the user browsed in Explorer. The generic mapper showed the
// raw BagMRU registry key; the decoded folder is FullPath / Description.LongName.
function mapShellbag(row: Row, artifact: string, host: string): MappedEvent {
  const folder =
    firstStr(row, ["FullPath"]) ||
    str(getPath(row, "Description.LongName")).trim() ||
    firstStr(row, ["KeyPath"]);
  return actionEvent({
    artifact,
    host,
    action: "Folder browsed (shellbag)",
    subject: folder || "(folder)",
    time: firstTime(row, ["ModTime", "ModificationTime"]) || pickTime(row),
    path: folder || undefined,
  });
}

// Windows.Registry.UserAssist — a GUI program RUN (with a run count). The generic mapper showed the
// raw value name (e.g. UEME_CTLSESSION); the program is in Name.
function mapUserAssist(row: Row, artifact: string, host: string): MappedEvent {
  const prog = firstStr(row, ["Name"]) || str(getCI(row, "_KeyPath")).trim();
  return actionEvent({
    artifact,
    host,
    action: "Ran (UserAssist)",
    subject: prog || "(program)",
    count: getCI(row, "NumberOfExecutions"),
    time: firstTime(row, ["LastExecution", "LastExecutionTS", "LastExecutionTime"]) || pickTime(row),
    path: prog || undefined,
  });
}

// Windows.Registry.AppCompatCache (Shimcache) — EXECUTION/presence evidence for a binary. The generic
// mapper dumped Position=/ModificationTime=/Path= as a field blob; the binary is in Path.
function mapShimcache(row: Row, artifact: string, host: string): MappedEvent {
  const path = firstStr(row, ["Path", "OSPath"]);
  return actionEvent({
    artifact,
    host,
    action: "Execution evidence (Shimcache)",
    subject: path || "(path)",
    time: firstTime(row, ["ModificationTime"]) || pickTime(row),
    path: path || undefined,
    processName: path || undefined,
  });
}

// Windows.Forensics.Amcache/InventoryApplication — an INSTALLED program.
function mapAmcacheApp(row: Row, artifact: string, host: string): MappedEvent {
  const name = firstStr(row, ["Name"]);
  const ver = str(getCI(row, "Version")).trim();
  const pub = str(getCI(row, "Publisher")).trim();
  const subject = [name, ver && `v${ver}`, pub && `(${pub})`].filter(Boolean).join(" ");
  return actionEvent({
    // Prefer the ISO Amcache key time over InstallDate (US MM/DD/YYYY, which won't sort on the timeline).
    artifact,
    host,
    action: "Installed program (Amcache)",
    subject: subject || name || "(program)",
    aggSubject: name,
    time: firstTime(row, ["Timestamp", "InstallDate"]) || pickTime(row),
  });
}

// Windows.Forensics.Amcache/InventoryApplicationFile — a binary PRESENT on disk (execution/presence
// evidence), with its SHA1. The generic mapper showed the path alone with no verb.
function mapAmcacheFile(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  collectRowIocs(row, sink);
  const path = firstStr(row, ["FullPath", "OSPath"]) || firstStr(row, ["Name", "OriginalFileName"]);
  const sha1 = str(getCI(row, "SHA1")).trim();
  if (/^[0-9a-f]{40}$/i.test(sha1)) addIoc(sink, "hash", sha1.toLowerCase());
  return actionEvent({
    artifact,
    host,
    action: "Program file present (Amcache)",
    subject: path || "(file)",
    time: firstTime(row, ["Timestamp"]) || pickTime(row),
    path: path || undefined,
    processName: path || undefined,
  });
}

// Windows.Forensics.Prefetch — a program EXECUTION (with a run count). The generic mapper showed the
// .pf file path; the executable that actually ran is in Executable / ExecutablePath.
function mapPrefetch(row: Row, artifact: string, host: string): MappedEvent {
  const exe = firstStr(row, ["Executable"]);
  const exePath = firstStr(row, ["ExecutablePath", "ExecutableDosPath"]);
  const subject = exePath && exe ? `${exe} (${exePath})` : exe || exePath || firstStr(row, ["OSPath"]);
  const event = actionEvent({
    artifact,
    host,
    action: "Executed (prefetch)",
    subject: subject || "(executable)",
    count: getCI(row, "RunCount"),
    time: firstTime(row, ["LastRunTimes", "CreationTime", "ModificationTime"]) || pickTime(row),
    path: exePath || undefined,
    processName: exe || undefined,
    aggSubject: exe || exePath,
  });
  // Prefetch carries no command line, so the binary's NAME is the only thing there is to grade — and
  // ungraded it stays at Info, below the forensic floor, where synthesis never reads it. See
  // prefetchExecution.ts for what earns Medium (dual-use) versus High (named offensive tooling).
  const signal = prefetchSignal(exe, exePath);
  if (signal) {
    event.severity = signal.severity;
    event.mitre = signal.mitre;
  }
  return event;
}

// Windows.Forensics.Lnk — a shortcut whose existence is evidence a TARGET was opened. The generic
// mapper dumped the nested LNK structure; the target is in StringData.TargetPath / LinkTarget.
function mapLnk(row: Row, artifact: string, host: string): MappedEvent {
  const target =
    str(getPath(row, "StringData.TargetPath")).trim() ||
    str(getPath(row, "LinkTarget.LinkTarget")).trim() ||
    str(getPath(row, "LinkInfo.Target.Path")).trim();
  const lnkFile = str(getPath(row, "SourceFile.OSPath")).trim();
  return actionEvent({
    artifact,
    host,
    action: "Shortcut (LNK) →",
    subject: target || lnkFile || "(target)",
    time: pickTime(row),
    path: target || undefined,
  });
}

function mapPslist(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const name = str(getCI(row, "Name")).trim();
  const exe = firstStr(row, ["Exe", "Image"]);
  const cmdline = str(getCI(row, "CommandLine")).trim();
  const pid = str(getCI(row, "Pid")).trim();
  const ppid = str(getCI(row, "Ppid")).trim();
  const callChain = str(getCI(row, "CallChain")).trim();

  if (exe) addIoc(sink, "process", baseName(exe));
  else if (name) addIoc(sink, "process", name);

  // "svchost.exe (1004) ← ppid 592 [chain: ...]: C:\Windows\... @ WIN11"
  let description = `${name || "process"}${pid ? ` (pid ${pid})` : ""}`;
  if (ppid && ppid !== "0") description += ` ← ppid ${ppid}`;
  if (callChain && callChain !== name) description += ` [${callChain}]`;
  const subject = cmdline || exe;
  if (subject) description += `: ${oneLine(subject).slice(0, 300)}`;
  description = withHostSuffix(description, host).slice(0, 600);

  const aggKey =
    `vr-pslist|${name.toLowerCase()}|${ppid}|${host.toLowerCase()}|${(cmdline || exe || name).toLowerCase()}`
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<guid>")
      .replace(/\d+/g, "#")
      .slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["Velociraptor"],
    ...(exe ? { path: exe } : {}),
    ...(host ? { asset: host } : {}),
    ...(name ? { processName: name } : {}),
  };
}

function mapNetstat(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const { sha256, md5 } = collectRowIocs(row, sink);

  const laddr = str(getCI(row, "Laddr")).trim();
  const lport = str(getCI(row, "Lport")).trim();
  const raddr = str(getCI(row, "Raddr")).trim();
  const rport = str(getCI(row, "Rport")).trim();
  const status = str(getCI(row, "Status")).trim();
  const proto = firstStr(row, ["Type", "Proto", "Family"]);
  const name = str(getCI(row, "Name")).trim();
  const pid = str(getCI(row, "Pid")).trim();
  const path = firstStr(row, ["Path", "Exe"]);

  // Remote IP as IOC for non-zero, non-loopback addresses
  const rAddrIsReal =
    raddr && raddr !== "0.0.0.0" && raddr !== "::" && raddr !== "::1" && raddr !== "127.0.0.1";
  if (rAddrIsReal) addIoc(sink, "ip", raddr);
  if (name) addIoc(sink, "process", name);

  // ESTABLISHED connections to non-RFC-1918 remote IPs are Low (worth reviewing)
  const isExternal = rAddrIsReal && !/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(raddr);
  const severity: Severity = status === "ESTABLISHED" && isExternal ? "Low" : "Info";

  // "svchost.exe (pid 896) - TCP - LISTEN - 0.0.0.0:135 → 0.0.0.0"
  const src = lport ? `${laddr}:${lport}` : laddr;
  const dst = rport && rport !== "0" ? `${raddr}:${rport}` : raddr;
  let description = `${name || "process"}${pid ? ` (pid ${pid})` : ""}`;
  if (proto) description += ` - ${proto}`;
  if (status) description += ` - ${status}`;
  description += ` - ${src} → ${dst}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  const aggKey =
    `vr-netstat|${name.toLowerCase()}|${status.toLowerCase()}|${lport}|${raddr.toLowerCase()}|${rport}|${host.toLowerCase()}`
      .replace(/\d+/g, "#")
      .slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity,
    mitre: [],
    aggKey,
    sources: ["Velociraptor"],
    ...(sha256 ? { sha256 } : {}),
    ...(md5 && !sha256 ? { md5 } : {}),
    ...(path ? { path } : {}),
    ...(host ? { asset: host } : {}),
    ...(name ? { processName: name } : {}),
  };
}

function mapDownload(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  // Velociraptor renders NTFS device paths with a leading \\.\  — strip it for readability.
  const raw = str(getCI(row, "DownloadedFilePath"));
  const rawPath = (raw.startsWith("\\\\.\\") ? raw.slice(4) : raw).trim();
  // The Zone.Identifier ADS is NUL-terminated — zoneText strips that (and any other control
  // character) so the URL reaching the description AND the url indicator is comparable to the same
  // URL seen in a proxy log or browser history. Left raw, the trailing NUL breaks every match.
  const hostUrl = zoneText(str(getCI(row, "HostUrl")));
  const referrerUrl = zoneText(str(getCI(row, "ReferrerUrl")));
  const name = rawPath ? baseName(rawPath) : "";
  // The mark's whole point: which zone the file came from, and whether it is runnable.
  const grade = gradeMotwDownload(str(getCI(row, "ZoneId")), name || rawPath);

  if (hostUrl && /^https?:\/\//i.test(hostUrl)) addIoc(sink, "url", hostUrl.slice(0, 300));
  if (referrerUrl && /^https?:\/\//i.test(referrerUrl)) addIoc(sink, "url", referrerUrl.slice(0, 300));
  if (rawPath) addIoc(sink, "file", rawPath);

  // FileHash is a nested object {MD5, SHA1, SHA256} in the Velociraptor artifact
  const hashObj = getCI(row, "FileHash");
  const { sha256, md5 } = isObject(hashObj) ? vrHashes(hashObj) : vrHashes(row);
  if (sha256) addIoc(sink, "hash", sha256);
  else if (md5) addIoc(sink, "hash", md5);

  // A Zone.Identifier stream routinely records the zone with no URL (the browser wrote only
  // ZoneId). Naming the zone beats "unknown source", which reads as "we know nothing".
  const urlDisplay = hostUrl || (grade.zoneLabel ? `the ${grade.zoneLabel}` : "unknown source");
  // Prefix with "Velociraptor:" so the artifact-name injection in the main loop can insert
  // [_Source] right after "Velociraptor" (consistent with every other mapper).
  let description = `Velociraptor: Downloaded ${name || rawPath || "file"} from ${urlDisplay}`;
  if (hostUrl && grade.zoneLabel) description += ` (${grade.zoneLabel})`;
  description = withHostSuffix(description, host).slice(0, 600);

  const aggKey = `vr-download|${name.toLowerCase()}|${urlDisplay.toLowerCase()}|${host.toLowerCase()}`
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity: grade.severity,
    mitre: grade.mitre,
    aggKey,
    sources: ["Velociraptor"],
    ...(sha256 ? { sha256 } : {}),
    ...(md5 && !sha256 ? { md5 } : {}),
    ...(rawPath ? { path: rawPath } : {}),
    ...(host ? { asset: host } : {}),
  };
}

function mapStartup(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const name = str(getCI(row, "Name")).trim();
  const ospath = str(getCI(row, "OSPath")).trim();
  const details = demangleUtf16Noise(str(getCI(row, "Details")).trim());
  const enabledRaw = str(getCI(row, "Enabled")).trim().toLowerCase();
  const enabled =
    enabledRaw === "enable" || enabledRaw === "enabled" || enabledRaw === "true" || enabledRaw === "1";

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

  const aggKey = `vr-startup|${name.toLowerCase()}|${ospath.toLowerCase()}`
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity,
    mitre: enabled ? ["T1547"] : [],
    aggKey,
    sources: ["Velociraptor"],
    ...(host ? { asset: host } : {}),
  };
}

function mapTaskScheduler(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const taskName = str(getCI(row, "TaskName")).trim();
  const command = str(getCI(row, "Command")).trim();
  const args = str(getCI(row, "Arguments")).trim();
  const userId = str(getCI(row, "UserId")).trim();
  const runLevel = str(getCI(row, "RunLevel")).trim();
  const ospath = str(getCI(row, "OSPath")).trim();

  if (ospath) addIoc(sink, "file", ospath);
  if (command && /^[A-Za-z]:\\/.test(command)) addIoc(sink, "file", command.slice(0, 300));

  const cmd = [command, args].filter(Boolean).join(" ");
  const userLabel =
    userId === "S-1-5-18"
      ? "SYSTEM"
      : userId === "S-1-5-19"
        ? "LOCAL SERVICE"
        : userId === "S-1-5-20"
          ? "NETWORK SERVICE"
          : userId;

  let description = `Velociraptor: Scheduled Task [${taskName || "task"}]`;
  if (cmd) description += ` — ${oneLine(cmd).slice(0, 250)}`;
  if (userLabel) description += ` (${userLabel}${runLevel ? `, ${runLevel}` : ""})`;
  description = withHostSuffix(description, host).slice(0, 600);

  const aggKey = `vr-task|${taskName.toLowerCase()}|${host.toLowerCase()}`.replace(/\d+/g, "#").slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["Velociraptor"],
    ...(ospath ? { path: ospath } : {}),
    ...(host ? { asset: host } : {}),
  };
}

// ───────────────────────────── row extraction ─────────────────────────────

// Returns the flat row list. Handles a Velociraptor multi-artifact map { "Artifact": [rows] }
// (tagging each row's _Source), else delegates to the shared extractor (array/jsonl/wrapped).
// Parse a CSV export (Elastic Discover "Download CSV") into flat row objects keyed by header,
// dropping Kibana's "-" empty-cell placeholder. Returns null when it doesn't look tabular.
function csvToRows(text: string): { rows: Row[]; format: string } | null {
  const { headers, rows } = parseCsv(text);
  if (headers.length < 2 || rows.length === 0) return null;
  const out: Row[] = rows.map((cells) => {
    const o: Row = {};
    headers.forEach((h, i) => {
      const v = cells[i];
      if (v != null && v !== "" && v !== "-") o[h] = v;
    });
    return o;
  });
  return { rows: out, format: "csv" };
}

function extractRows(text: string): { rows: Row[]; format: string } {
  const trimmed = text.trim();
  if (!trimmed) return { rows: [], format: "empty" };

  // CSV export from Elastic Discover (Velociraptor data indexed into Elastic) — not JSON/NDJSON.
  // Each row becomes a flat object keyed by header; "-" (Kibana's empty-cell placeholder) is dropped.
  // normalizeRow (in the per-row loop) then un-flattens the dotted/.keyword columns.
  if (trimmed[0] !== "{" && trimmed[0] !== "[") {
    const csv = csvToRows(trimmed);
    if (csv) return csv;
  }

  let root: unknown = null;
  try {
    root = JSON.parse(trimmed);
  } catch {
    /* NDJSON path below */
  }

  if (root && isObject(root) && !Array.isArray(root)) {
    const entries = Object.entries(root);
    const isArtifactMap =
      entries.length > 0 &&
      entries.every(([k, v]) => Array.isArray(v) && !WRAPPER_KEYS.has(k.toLowerCase())) &&
      entries.some(([, v]) => (v as unknown[]).some((x) => isObject(x)));
    if (isArtifactMap) {
      const rows: Row[] = [];
      for (const [artifact, arr] of entries) {
        for (const r of arr as unknown[]) {
          if (isObject(r))
            rows.push(getCI(r, "_Source") || getCI(r, "Artifact") ? r : { ...r, _Source: artifact });
        }
      }
      return { rows, format: "artifact-map" };
    }
  }

  const { records, format } = extractRecords(trimmed);
  return { rows: records, format: format === "ndjson" ? "jsonl" : format };
}

// ───────────────────────────── top-level parse ─────────────────────────────

// Shared mutable accumulators + fallbacks for one parse run. Threaded into mapRowToEvents so the
// per-row dispatch is identical whether the driver is the synchronous loop or the chunked async one.
interface VrParseCtx {
  fallbackArtifact: string;
  fallbackHost: string;
  iocSink: Map<string, SiemIoc>;
  hostTally: Map<string, number>;
}

// Map ONE raw row to its forensic event(s). Most rows yield a single event; an MFT row yields one per
// distinct MACB timestamp. Returns the events plus how many detections it produced (so the driver can
// tally). Pure w.r.t. control flow — no yielding — so both parse drivers share this exact logic.
function mapRowToEvents(row: Row, ctx: VrParseCtx): { events: MappedEvent[]; detections: number } {
  // `row` is ALREADY normalized (`Line` payload unwrap + ES-indexed push reshape) — see prepareRows,
  // which both drivers run first. Normalizing again here is not free: an Elastic row keeps its
  // `artifact_` index, so the gate re-opens and the whole collapse/un-flatten walk runs a second
  // time on every row of the import.
  const artifact = artifactName(row) || ctx.fallbackArtifact;
  const host = pickHost(row) || ctx.fallbackHost; // a row's own host always wins; fallback only fills the gap
  if (host) ctx.hostTally.set(host, (ctx.hostTally.get(host) ?? 0) + 1);

  const rowSink = new Map<string, SiemIoc>();
  let detections = 0;
  const out: MappedEvent[] = [];
  {
    const kind = classify(row, artifact);
    // Most mappers yield one event per row; MFT yields one per DISTINCT MACB timestamp, so the
    // dispatch produces an array (usually length 1). An empty array = the row produced nothing.
    let ms: MappedEvent[];
    if (kind === "yara") {
      const m = mapYara(row, artifact, host, rowSink);
      detections++;
      ms = [m];
    } else if (kind === "sigma") {
      const m = mapSigma(row, host, rowSink);
      detections++;
      ms = [m];
    } else if (kind === "chainsaw") {
      const m = mapFlatChainsawRow(row, host, rowSink);
      detections++;
      ms = [m];
    } else if (kind === "detection") {
      const m = mapDetection(row, artifact, host, rowSink);
      detections++;
      ms = [m];
    } else if (kind === "eventlog") {
      ms = [mapEventlog(row, host, rowSink) ?? mapGeneric(row, artifact, host, rowSink)];
    } else if (kind === "pslist") {
      ms = [mapPslist(row, host, rowSink)];
    } else if (kind === "netstat") {
      ms = [mapNetstat(row, host, rowSink)];
    } else if (kind === "download") {
      ms = [mapDownload(row, host, rowSink)];
    } else if (kind === "startup") {
      ms = [mapStartup(row, host, rowSink)];
    } else if (kind === "taskscheduler") {
      ms = [mapTaskScheduler(row, host, rowSink)];
    } else if (kind === "persistenceSniper") {
      ms = [mapPersistenceSniper(row, host, rowSink, pickTime(row))];
    } else if (kind === "binaryRename") {
      ms = [mapBinaryRename(row, host, rowSink, pickTime(row))];
    } else if (kind === "accountUsage") {
      ms = [mapAccountUsage(row, artifact, host, rowSink)];
    } else if (kind === "usn") {
      ms = [mapUsn(row, artifact, host)];
    } else if (kind === "mft") {
      ms = mapMft(row, artifact, host);
    } else if (kind === "hijacklib") {
      ms = [mapHijackLib(row, artifact, host, rowSink)];
    } else if (kind === "browser") {
      ms = [mapBrowserHistory(row, artifact, host, rowSink)];
    } else if (kind === "prefetch") {
      ms = [mapPrefetch(row, artifact, host)];
    } else if (kind === "userassist") {
      ms = [mapUserAssist(row, artifact, host)];
    } else if (kind === "shimcache") {
      ms = [mapShimcache(row, artifact, host)];
    } else if (kind === "shellbags") {
      ms = [mapShellbag(row, artifact, host)];
    } else if (kind === "samAccount") {
      ms = [mapSamAccount(row, artifact, host)];
    } else if (kind === "amcacheApp") {
      ms = [mapAmcacheApp(row, artifact, host)];
    } else if (kind === "amcacheFile") {
      ms = [mapAmcacheFile(row, artifact, host, rowSink)];
    } else if (kind === "lnk") {
      ms = [mapLnk(row, artifact, host)];
    } else {
      ms = [mapGeneric(row, artifact, host, rowSink)];
      // mapGeneric graded the RDP-lateral artifact authoritatively (remote 4648 → T1021, boot → Info);
      // its name ends in "Detection" and its rows are bare 4648s, so the floor + flat-EID overlay below
      // would re-raise the SUPPRESSED boot rows to Medium/T1078. Skip both for it. (#codex)
      const rdpArt = /rdplateralmovement/i.test(artifact);
      // A DETECTION rule pack row that matched no signature lands in the generic key=value dump at
      // Info, invisible to synthesis; floor it to Medium ("a named rule fired"), only ever raising.
      if (!rdpArt && isDetectionArtifact(artifact)) {
        for (const m of ms) if (m && m.severity === "Info") m.severity = "Medium";
      }
      // A FLAT Windows row (bare EventID, no wrapper) also lands here — see overlayFlatWindowsEid.
      if (!rdpArt) for (const m of ms) if (m) overlayFlatWindowsEid(row, m);
    }

    // A 4104 script block that is generated or signed module scaffolding is detection content, not
    // attacker content — the rule matched the shape of compiled PowerShell. Applied after the
    // detection-pack floor above, so it wins over it, but NEVER above Medium: the markers live in a
    // comment or a variable name, so an attacker can put them in a script, and a rule that named a
    // technique (High/Critical) must survive whatever its payload is wrapped in. The broad
    // "this PowerShell looks odd" verdicts this exists to quiet are Medium and below by nature.
    if (isGeneratedModuleScript(row))
      for (const m of ms) if (m && m.severity !== "High" && m.severity !== "Critical") m.severity = "Info";

    // Row-level values shared by every event this row produced (computed once, not per MACB event).
    const realArtifact = artifactName(row);
    const fp = msgFingerprint(rowMessage(row));
    for (const m of ms) {
      if (!m) continue;
      // Stamp the produced event with the VQL artifact that emitted it. Done once here (rather than in
      // each map* function) because `artifact` is already resolved in this dispatch loop and every
      // mapper's result flows through — so downstream (dwell-time window, evidence graph) can tell
      // "from the MFT" apart from "a Sigma detection". Uses the resolved `artifact` (the row's
      // _Source/_Artifact, or the filename fallback) so telemetry rows without _Source still carry it.
      if (artifact) m.artifactName = artifact;
      // Carry the FULL untruncated event message so the super-timeline row can reveal it expandably,
      // when it adds detail beyond the truncated `description`. Stamped here (like artifactName) so
      // every mapper's result benefits. Set only if the mapper didn't already provide one.
      if (!m.message) {
        const full = cappedMessage(rowMessage(row), m.description);
        if (full) m.message = full;
      }
      // Tag every event with the SOURCE artifact (from the row's _Source/_Artifact — stamped by the
      // browser push, or carried by an artifact-map import) so the analyst can navigate back to it.
      // Place it consistently right after "Velociraptor" (the same spot mapGeneric already uses), so
      // detection/sigma/yara read "Velociraptor [artifact] detection: …" not "… [artifact]" at the
      // end. Only a REAL artifact name (from _Source) is shown — never the filename fallback.
      // Skip when mapDetection already led with a DetectRaptor-specific label (detectionLabel()) —
      // that already names the rule pack, so bracketing the full dotted artifact too is redundant.
      // A THOR row is exempt for the same reason: thorRowMap.ts already leads with "THOR <level>
      // [<module>]", which names the tool AND the scanner module that fired. Bracketing
      // "Generic.Scanner.ThorZIP/ThorResultsJson" in front of that names the plumbing twice and pushes
      // the finding off the visible title. The artifact stays on `artifactName` for the origin facet.
      if (
        realArtifact &&
        !m.description.includes(realArtifact) &&
        !m.description.startsWith("DetectRaptor ") &&
        !m.description.startsWith("THOR ")
      ) {
        m.description = (
          m.description.startsWith("Velociraptor")
            ? m.description.replace(/^Velociraptor/, `Velociraptor [${realArtifact}]`)
            : `[${realArtifact}] ${m.description}`
        ).slice(0, 1200);
      }
      // Forensic distinctness: detections sharing a rule title/EID but describing different
      // artifacts (HackTool:Passview vs HackTool:Mimikatz) are SEPARATE events. Fold the message
      // fingerprint into the agg key so they don't collapse on title alone — while truly identical
      // repeats (differing only in volatile ids) still merge. See msgFingerprint.
      if (fp) m.aggKey = `${m.aggKey}|m:${fp}`.slice(0, 440);
      mergeRowIocs(ctx.iocSink, rowSink, m.aggKey);
      out.push(m);
    }
  }
  return { events: out, detections };
}

// Aggregate the accumulated mapped events (collapse repeats, apply the severity floor + event cap),
// then compute represented/dropped counts and the dominant host. Shared tail for both parse drivers.
function finalizeVrParse(
  mapped: MappedEvent[],
  ctx: VrParseCtx,
  total: number,
  format: string,
  detections: number,
  opts: VelociraptorImportOptions,
): VelociraptorParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  // Self-scan: Sigma/Hayabusa run through Velociraptor also scan the bundled EVTX-ATTACK-SAMPLES
  // corpus, whose events carry the sample author's computer name — demote to Info. See chainsawImport.
  for (const ev of mapped) {
    if (ev.severity !== "Info" && isDetectionSampleHost(ev.asset ?? "")) {
      ev.severity = "Info";
      ev.description =
        `${ev.description} [detection sample corpus — ${ev.asset} not in this collection]`.slice(0, 600);
    }
  }
  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const hostname = [...ctx.hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";
  return {
    events,
    iocs: [...ctx.iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    detections,
    format,
    hostname,
  };
}

function emptyVrResult(): VelociraptorParseResult {
  return {
    events: [],
    iocs: [],
    total: 0,
    kept: 0,
    dropped: 0,
    groups: 0,
    detections: 0,
    format: "empty",
    hostname: "",
  };
}

function newVrCtx(opts: VelociraptorImportOptions): VrParseCtx {
  return {
    fallbackArtifact: (opts.artifact ?? "").trim(),
    // A single-client FLOW export has no per-row host column — the whole collection is implicitly for one
    // client — so the resolved hostname is threaded in here to attribute rows that carry no host.
    fallbackHost: (opts.hostFallback ?? "").trim(),
    iocSink: new Map<string, SiemIoc>(),
    hostTally: new Map<string, number>(),
  };
}

// Normalize every row, then rejoin any PowerShell 4104 script block that Windows split across
// several events. Shared by both parse drivers so they stay byte-for-byte identical. Normalizing
// here (rather than only per-row inside mapRowToEvents) is what lets the fragment reader see the
// native nested `EventData`; mapRowToEvents still normalizes, which is a no-op on these rows.
function prepareRows(rows: Row[]): Row[] {
  return consolidateVeloScriptBlocks(rows.map(normalizeRow));
}

// Rows per event-loop turn — big enough that the per-chunk yield overhead is negligible.
const CHUNK = 5000;

// The async twin of prepareRows. Normalization is the expensive half and is per-row, so it is
// chunked and yields between chunks; consolidation needs the whole file at once (fragments of one
// block can sit anywhere in it) but only scans rows, which is cheap next to normalizing them.
// Without this the "streams progress instead of freezing" contract broke on the FIRST call: every
// row was normalized up front with no yield and no progress report.
async function prepareRowsAsync(rows: Row[]): Promise<Row[]> {
  const normalized: Row[] = [];
  for (let i = 0; i < rows.length; i++) {
    normalized.push(normalizeRow(rows[i]));
    if ((i + 1) % CHUNK === 0) await new Promise<void>((resolve) => setImmediate(resolve));
  }
  return consolidateVeloScriptBlocks(normalized);
}

// Synchronous parse (unchanged behaviour) — used by the many callers that need a result inline (import
// preview, detection routing, tests). For a large import prefer parseVelociraptorJsonProgress.
export function parseVelociraptorJson(
  text: string,
  opts: VelociraptorImportOptions = {},
): VelociraptorParseResult {
  const { rows: rawRows, format } = extractRows(text);
  const rows = prepareRows(rawRows);
  if (rows.length === 0) return emptyVrResult();
  const ctx = newVrCtx(opts);
  const mapped: MappedEvent[] = [];
  let detections = 0;
  for (const rawRow of rows) {
    const r = mapRowToEvents(rawRow, ctx);
    for (const m of r.events) mapped.push(m);
    detections += r.detections;
  }
  return finalizeVrParse(mapped, ctx, rows.length, format, detections, opts);
}

// Async parse for large imports: byte-for-byte the same result as parseVelociraptorJson, but it maps
// rows in chunks, reports (rowsDone, rowsTotal) after each chunk, and yields to the event loop between
// chunks — so a multi-hundred-thousand-row parse streams live progress instead of freezing the server.
export async function parseVelociraptorJsonProgress(
  text: string,
  opts: VelociraptorImportOptions = {},
  onProgress?: (done: number, total: number) => void,
): Promise<VelociraptorParseResult> {
  const { rows: rawRows, format } = extractRows(text);
  if (rawRows.length === 0) {
    onProgress?.(0, 0);
    return emptyVrResult();
  }
  const rows = await prepareRowsAsync(rawRows);
  const total = rows.length;
  const ctx = newVrCtx(opts);
  const mapped: MappedEvent[] = [];
  let detections = 0;
  for (let i = 0; i < total; i++) {
    const r = mapRowToEvents(rows[i], ctx);
    for (const m of r.events) mapped.push(m);
    detections += r.detections;
    if ((i + 1) % CHUNK === 0) {
      onProgress?.(i + 1, total);
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  }
  onProgress?.(total, total);
  return finalizeVrParse(mapped, ctx, total, format, detections, opts);
}
