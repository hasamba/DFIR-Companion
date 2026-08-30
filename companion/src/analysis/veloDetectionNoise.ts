// Two shapes where a detection fires on the DETECTION STACK rather than on the host.
//
// Both are the same mistake seen from different angles: a rule pack sweeping a machine finds its own
// reflection — the signatures it ships, the sample logs it was written against, the Windows modules
// it inspects — and reports them as if an attacker had put them there. Neither row is dropped. Both
// are demoted to Info, which is what velociraptorImport already does for a `.yms` hit: the row still
// accounts for itself in `total`, an analyst who goes looking can still find it, and it stops
// crowding out the findings that are about the host.
//
// EVERY PREDICATE HERE LOWERS A GRADE, so every one of them is a place an attacker would like to
// reach. That shapes the whole design: nothing demotes on a signal the attacker chooses (a filename,
// a pasted comment), the callers cap how far a demotion can reach, and where a cheap signal and a
// costly one disagree the costly one wins.

import { getCI, getPath, isObject, str } from "./siemImport.js";
import { tradecraftSignal } from "./tradecraftRules.js";

type Row = Record<string, unknown>;

// `.yms` is Velociraptor's own compiled-Sigma format. Nothing else on a Windows host carries it, so
// the extension alone identifies the file — an attacker who renamed a payload to `.yms` would be
// choosing an extension that exists nowhere but inside Velociraptor's unpacked tool directory.
const VELOCIRAPTOR_SIGNATURE_EXT = /\.yms$/i;

// These extensions are NOT self-identifying. `.yml` is the most common configuration format there
// is, and `.evtx` is a live Windows log; an attacker's `C:\Users\Public\payload.yml` ends the same
// way a Sigma rule does. So the extension only narrows the field — the path has to place the file
// inside detection tooling before anything is demoted.
const SHARED_CONTENT_EXT = /\.(?:ya?ml|evtx|etl)$/i;

// Where detection content actually lives, in the two forms a filesystem sweep reports it.
//
//   the directory   Velociraptor unpacks a signature tree into
//                   `\Program Files\Velociraptor\Tools\tmp*\signatures\sigma\…` for the duration of
//                   a hunt; Hayabusa, Chainsaw and Sigma trees have their own equivalents.
//   the ABSENCE of  …and Velociraptor deletes that tree when the hunt ends, so the MFT keeps the
//   a directory     entries with no resolvable parent and reports them as `<Err>\<Parent N-M need K>`.
//                   That placeholder is written by the MFT parser, not by anything on disk, so it
//                   cannot be forged by naming a file — and on a real collection it was where every
//                   single one of these rows landed.
const DETECTION_CONTENT_LOCATION =
  /<Err>|<Parent |\\Velociraptor\\Tools\\|\\signatures\\|\\sigma\\|\\rules\\|\\hayabusa\\|\\chainsaw\\|EVTX-ATTACK/i;

/**
 * A file whose CONTENT is detection logic or detection test data, matched by a rule pack that only
 * looked at the filename.
 *
 * On a real collection this covered 47 of the 48 High findings the MFT rule pack produced. The 48th
 * was a ransomware binary in ProgramData — which is the point: an analyst reading 48 High findings
 * does not see it, and reading one does.
 *
 * Scoped deliberately to the keyword-detection path in velociraptorImport. It is a statement about
 * what a FILENAME MATCH proves, not a claim that these extensions are harmless — a `.yml` carrying
 * an attacker's configuration is still ingested, still timelined, and still graded by everything
 * that reads content rather than names.
 */
export function isDetectionContentPath(value: string): boolean {
  const path = value.trim();
  if (VELOCIRAPTOR_SIGNATURE_EXT.test(path)) return true;
  return SHARED_CONTENT_EXT.test(path) && DETECTION_CONTENT_LOCATION.test(path);
}

// A file or process that lives inside the DETECTION TOOLING itself, matched regardless of extension.
// isDetectionContentPath is deliberately narrow — it only demotes rule-CONTENT files (.yml/.evtx …)
// so a real payload dropped in an odd place is never lost. This one is broader on purpose, for a
// different caller: a YARA/THOR SCAN that walks the collector's own working tree, its unpacked
// sample corpus, the collector binary itself, or a cached copy of a simulation repo, and reports
// them as host findings. The markers are NOT equally trustworthy, so they do not carry equal weight:
// only the collector's install tree is a location an intruder cannot supply, and only that one lets
// a caller drop an IOC. A corpus directory name is a name anyone can create, so it drops the hit to
// Info and stops there — see isCollectorOwnedLocation, and #720 for what the flat list cost.
//
//   [/\]Velociraptor[/\]  the collector's own install / unpacked-tool tree
//                          (`C:\Program Files\Velociraptor\…`, incl. `\Tools\tmp*\chainsaw\…`)
//   EVTX-ATTACK-SAMPLES    the Sigma test corpus bundled with those tools
//   Digital-Forensic-      the eval / training simulation corpus, downloaded to the host as a repo
//     Artifacts               (its cached copy is not the intrusion under investigation)
//
// CAUTION (why this is narrow): every marker must be a signal the ATTACKER CANNOT CHOOSE. A bare
// `velociraptor.exe`, or a lone `\sigma\` / `\chainsaw\` / `\signatures\` / `\Tools\tmp` directory
// component, is attacker-controllable — a real payload dropped in `C:\Users\x\sigma\evil.dll` would
// be hidden from the forensic view. So we require the collector ROOT context (`\Velociraptor\`,
// which the real THOR row carries as `image_file: C:\Program Files\Velociraptor\Velociraptor.exe`),
// or the published corpus name as a WHOLE path component — never a substring that can appear
// anywhere. Anchoring is not proof: a corpus name IS choosable, which is why it may not delete.

// The collector's own tree. This is the one marker here the attacker cannot supply, so it is also
// the only one that lets a caller DROP an indicator rather than merely lower a grade.
const COLLECTOR_INSTALL_ROOT = /[/\\]Velociraptor[/\\]/i;

// The two published corpus names, each as a WHOLE path component. They were bare substrings until
// #720, which let `EVTX-ATTACK` match `C:\Users\public\EVTX-ATTACKER-kit\evil.exe` — a path any
// intruder can create, and one that suppressed the finding. The trailing class admits the forms a
// real download takes (a directory, the GitHub zip's `-master` suffix, an archive extension)
// without admitting a longer word. Anchoring narrows the accident; it cannot stop a deliberately
// named folder, which is why a corpus match now grades DOWN without deleting evidence — see
// isCollectorOwnedLocation and mapYara.
const SAMPLE_CORPUS_DIR = /[/\\](?:EVTX-ATTACK-SAMPLES|Digital-Forensic-Artifacts)(?:[-_./\\]|$)/i;

const DETECTION_TOOL_LOCATION = new RegExp(
  `${COLLECTOR_INSTALL_ROOT.source}|${SAMPLE_CORPUS_DIR.source}`,
  "i",
);

export function isDetectionToolLocation(value: string): boolean {
  const v = (value || "").trim();
  if (!v) return false;
  return DETECTION_TOOL_LOCATION.test(v);
}

/**
 * The subset of isDetectionToolLocation that is NOT a name an intruder can pick: the collector's own
 * install tree. A hit here is not host evidence at all, so the caller may drop its IOCs. A hit in a
 * sample-corpus directory only LOOKS like tooling — the directory name is attacker-choosable — so it
 * leaves the timeline (Info) but keeps its indicators. See mapYara (#720).
 */
export function isCollectorOwnedLocation(value: string): boolean {
  const v = (value || "").trim();
  if (!v) return false;
  return COLLECTOR_INSTALL_ROOT.test(v);
}

// A volatile memory-backed container: the page/hibernation/swap files, a crash or process memory
// dump, or the NTFS metadata streams a full-volume YARA scan walks. A rule string found HERE proves
// only that the bytes existed in memory or metadata once — not that a named file executed. Kept
// (Low, and aggregated by the caller) rather than dropped, because a family's strings in the page
// file can still corroborate a finding built on stronger evidence.
const VOLATILE_CONTAINER =
  /\\pagefile\.sys$|\\hiberfil\.sys$|\\swapfile\.sys$|MEMORY\.DMP$|\.dmp$|\\\$(?:MFT|MFTMirr|LogFile|UsnJrnl|Extend|Secure|BadClus)\b|\bunallocated\b/i;

export function isVolatileContainer(value: string): boolean {
  const v = (value || "").trim();
  if (!v) return false;
  return VOLATILE_CONTAINER.test(v);
}

// Hostnames that belong to a public detection SAMPLE corpus, not to any real endpoint. When a
// Velociraptor artifact shells out to Chainsaw/Hayabusa, the tool scans the EVTX-ATTACK-SAMPLES set
// it unpacked next to its own binaries alongside the host's real logs — and those sample events
// carry the sample author's computer name, not the collection host's. Across the four eval
// collections this one host supplied ~110 detections per case (22-76% of all Chainsaw hits),
// including a Critical "Security Audit Logs Cleared", every one of them on a machine that was never
// part of the investigation.
//
// WIN-UK1GV882OK6 is the canonical EVTX-ATTACK-SAMPLES computer name — a fixed, published identifier,
// so matching it is not a demotion on a signal an intruder picks (renaming a victim host to the
// public sample name would be self-defeating). Kept as a set so the list is easy to extend as other
// well-known sample hosts surface; the value can be widened by DFIR_SAMPLE_HOSTS (comma-separated).
const KNOWN_SAMPLE_HOSTS = new Set(
  ["WIN-UK1GV882OK6", ...(process.env.DFIR_SAMPLE_HOSTS ?? "").split(",")]
    .map((h) => h.trim().toUpperCase())
    .filter(Boolean),
);

export function isDetectionSampleHost(host: string): boolean {
  const h = (host || "").trim().toUpperCase();
  if (!h) return false;
  return KNOWN_SAMPLE_HOSTS.has(h);
}

// Windows compiles a cdxml module (NetSecurity, NetTCPIP, DnsClient, Defender, …) into PowerShell
// when it is imported, and logs the generated body to EID 4104 like any other script. The generated
// code is dense with the punctuation, dynamic invocation and alias forms that broad "suspicious
// PowerShell" rules key on — so importing a firewall module lights up the same rule a real obfuscated
// payload does.
//
// Every marker is structural: something a compiler or a signing tool emits, never a word an attacker
// picks. The signature block is the one that needs care — it is a COMMENT, so anybody can type it —
// which is why the closing marker is required too. A begin-marker on its own says only that somebody
// wrote seven words, and is not evidence of anything.
const GENERATED_MARKERS: RegExp[] = [
  /\$__cmdletization_/, // cdxml-generated cmdlet body
  /Microsoft\.PowerShell\.Cmdletization/i, // its supporting types
  /Microsoft\.PowerShell\.Core\\Set-StrictMode\s+-Off/i, // the cdxml preamble
  /\\chocolatey\\helpers\\[^\n]*\.psm1/i, // Chocolatey's own helper modules
  // A CLOSED Authenticode block. Still forgeable — which is why callers never let this reach a
  // High/Critical verdict — but a pasted opener alone no longer reaches the demotion at all.
  /#\s*SIG\s*#\s*Begin signature block[\s\S]*#\s*SIG\s*#\s*End signature block/i,
];

const SCRIPT_BLOCK_EID = 4104;
const EVENT_WRAPPERS = ["Event", "_Event"] as const;

// An EventID as Windows/Velociraptor variously writes it: a bare number, a numeric string, or an
// object with a `Value`.
function toEventId(value: unknown): number {
  if (typeof value === "number") return value;
  if (isObject(value)) return toEventId(getCI(value, "Value"));
  const n = Number(str(value).trim());
  return Number.isFinite(n) ? n : 0;
}

// The row's EID, from every shape this importer already accepts: flat (`EID`, Hayabusa), the native
// parsed-EVTX `System.EventID`, and the same under an `Event`/`_Event` wrapper.
function eventId(row: Row): number {
  const flat = toEventId(getCI(row, "EID") ?? getCI(row, "EventID"));
  if (flat) return flat;
  const native = toEventId(getPath(row, "System.EventID"));
  if (native) return native;
  for (const w of EVENT_WRAPPERS) {
    const id = toEventId(getPath(row, `${w}.System.EventID`));
    if (id) return id;
  }
  return 0;
}

// The compiled script text. Read from EventData first — scriptBlockFragments has already reassembled
// a multi-part block there, so a marker split across two fragments is still visible. The rendered
// message is the fallback for a row that carries no EventData at all.
function scriptText(row: Row): string {
  let ed = getCI(row, "EventData");
  for (const w of EVENT_WRAPPERS) {
    if (isObject(ed)) break;
    ed = getPath(row, `${w}.EventData`);
  }
  if (isObject(ed)) {
    const t = str(getCI(ed, "ScriptBlockText")).trim();
    if (t) return t;
  }
  return str(getCI(row, "Details") ?? getCI(row, "Message")).trim();
}

/**
 * Is this row a 4104 script block whose text is generated or signed module scaffolding?
 *
 * The tradecraft check is a filter, NOT the safety argument. It catches a payload that happens to
 * name something tradecraftRules knows; plenty of real tradecraft (`Invoke-Mimikatz -DumpCreds`, for
 * one) matches no rule there and passes straight through. Treating it as protection would be a
 * mistake — it narrows the input, nothing more.
 *
 * The safety argument lives at the call site, which refuses to apply this demotion to a High or
 * Critical verdict. That bounds the worst case to what it should be: a specific rule that named a
 * technique keeps its grade whatever the script is wrapped in, and only the broad
 * "this PowerShell looks odd" verdicts — the ones that fire on generated code in the first place —
 * are ever lowered.
 */
export function isGeneratedModuleScript(row: Row): boolean {
  if (eventId(row) !== SCRIPT_BLOCK_EID) return false;
  const text = scriptText(row);
  if (!text) return false;
  if (!GENERATED_MARKERS.some((re) => re.test(text))) return false;
  return tradecraftSignal("", text)?.weight !== "strong";
}

// The script FILE a 4104 event was compiled from. PowerShell writes it into `EventData.Path` from
// the engine's own view of what it loaded, so unlike the script text it is not a string the script
// can talk about — a payload cannot claim to live somewhere it does not.
function scriptPath(row: Row): string {
  let ed = getCI(row, "EventData");
  for (const w of EVENT_WRAPPERS) {
    if (isObject(ed)) break;
    ed = getPath(row, `${w}.EventData`);
  }
  return isObject(ed) ? str(getCI(ed, "Path")).trim() : "";
}

/**
 * Is this a script block the COLLECTOR ran, out of its own tool tree?
 *
 * Velociraptor artifacts shell out to PowerShell modules unpacked under
 * `\Program Files\Velociraptor\Tools\tmp*\` — Windows.Forensics.PersistenceSniper runs
 * PersistenceSniper.psm1 there as SYSTEM. That module opens tokens via AdjustTokenPrivileges and
 * sweeps local accounts because those are the persistence techniques it DETECTS, and broad Sigma
 * rules grade it "Potential WinAPI Calls Via PowerShell Scripts" (High) and "Powershell LocalAccount
 * Manipulation" (Medium) exactly as they would an intruder's. On a real eval collection synthesis
 * read those rows as a WinPwn/Mimikatz credential-access burst and made it the case's only Critical
 * finding: the collector, reported as the intruder, ranked above the tool the analyst was hunting.
 *
 * Unlike isGeneratedModuleScript this one is allowed to lower a High or Critical, and it has to be —
 * the finding it exists to kill was High. That is why it does NOT reuse isDetectionToolLocation.
 * That predicate matches a bare `\Velociraptor\` component, which is right for the THOR and YARA
 * callers (their hits come from sweeping the collector's actual install) and wrong here: a 4104
 * EventData.Path is wherever the ATTACKER put their script, so `C:\Users\v\Velociraptor\evil.ps1`
 * would let them suppress their own Critical by choosing a directory name — the same weakness #720
 * records for the EVTX-ATTACK / Digital-Forensic-Artifacts markers.
 *
 * What makes that safe is NOT the path. Three review passes established that a path string cannot
 * carry this claim: the attacker chooses where their script lives, and every attempt to price that
 * in failed. `\Velociraptor\` is a directory anyone can create. Pinning a drive letter does not help
 * either — `subst Z: C:\Users\v\evil` and `net use Y: \\attacker\share` cost no privilege, and no
 * hard-coded letter can tell you the EVIDENCE host's system drive, so "Program Files is admin-only"
 * is an assumption about a filesystem this process never sees.
 *
 * The identity is the control. PowerShell records the account the ENGINE ran under, and a script is
 * logged as SYSTEM only if it actually ran as SYSTEM — which the attacker must already have. It also
 * closes the drive-letter hole without guessing anything: `subst` and `net use` mappings are
 * per-logon-session, so a SYSTEM process never sees the volume an unprivileged user mapped. The
 * collector tool tree is then corroboration, not the load-bearing part, and traversal is refused
 * because a prefix match on a path holding `..` describes nothing.
 *
 * This is still evidence rather than proof — an attacker already at SYSTEM can satisfy both. The
 * call site supplies the last bound for that case: it will not lower a Critical, so the most a
 * bypass buys is quieting a High, which an attacker at SYSTEM has far better ways to achieve.
 *
 * A claim about WHO ran the script and WHERE it lived, never about what it contains: the identical
 * body run from a user's Desktop keeps whatever grade it earned.
 */
const COLLECTOR_TOOL_TREE = /^[a-z]:[\\/]program files(?: \(x86\))?[\\/]velociraptor[\\/]tools[\\/]/i;
const PATH_TRAVERSAL = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
const SYSTEM_SID = "S-1-5-18";

// The account the PowerShell engine logged the script under, across the shapes this importer sees:
// DetectRaptor Evtx's flat `UserSID`, Chainsaw's parsed `SystemData.Security_attributes.UserID`, and
// the native EVTX `System.Security.UserID` with or without an Event wrapper.
function logonSid(row: Row): string {
  const flat = str(getCI(row, "UserSID")).trim();
  if (flat) return flat;
  const paths = [
    "SystemData.Security_attributes.UserID",
    "System.Security.UserID",
    "System.Security_attributes.UserID",
  ];
  for (const w of ["", ...EVENT_WRAPPERS]) {
    for (const path of paths) {
      const v = str(getPath(row, w ? `${w}.${path}` : path)).trim();
      if (v) return v;
    }
  }
  return "";
}

export function isDetectionToolScript(row: Row): boolean {
  if (eventId(row) !== SCRIPT_BLOCK_EID) return false;
  if (logonSid(row) !== SYSTEM_SID) return false;
  const path = scriptPath(row);
  return COLLECTOR_TOOL_TREE.test(path) && !PATH_TRAVERSAL.test(path);
}
