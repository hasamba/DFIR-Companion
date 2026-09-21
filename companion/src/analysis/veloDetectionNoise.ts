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
//
// The predicates that read a PATH now live in detectionStackPaths.ts and are re-exported below; the
// ones that read a Velociraptor ROW stay here. That line is where the layering falls: a path test
// needs nothing, a row test needs the importer.

import { getCI, getPath, isObject, str, type MappedEvent } from "./siemImport.js";
import { tradecraftSignal } from "./tradecraftRules.js";

type Row = Record<string, unknown>;

// The path predicates now live in detectionStackPaths.ts — the detect tier needs them and may not
// import this module. Re-exported here so every caller and the reasoning above stay put.
export {
  isDetectionContentPath,
  isDetectionToolLocation,
  isCollectorOwnedLocation,
  isCollectorToolTreePath,
  isVolatileContainer,
} from "./detectionStackPaths.js";

// Hostnames that belong to a public SAMPLE corpus or a stock lab image, not to any endpoint in the
// case. When a Velociraptor artifact shells out to Chainsaw/Hayabusa, the tool may scan a sample set
// it unpacked next to its own binaries alongside the host's real logs — and those events carry the
// sample author's computer name, not the collection host's. Across the four eval collections this
// one host supplied ~110 detections per case (22-76% of all Chainsaw hits), including a Critical
// "Security Audit Logs Cleared".
//
// WIN-UK1GV882OK6 is the hostname baked into the public Vagrant Windows box — a fixed, published
// identifier — so it shows up on every lab built from that box, and every such lab is renamed by
// its provisioner. That cuts both ways (#1417): the name is never a real case host, but a renamed
// lab's OWN event logs carry it on every record written before the rename (Chocolatey installs,
// profile loads, a firewall change — real, benign provisioning). This predicate only says "this is
// not a case host's name". The CALLER decides whether the row is a renamed host's history or a
// foreign corpus: hostIdentity.ts demotes only when the row names no collector (Fqdn/ClientId) at
// all. Matching a fixed public name is not a demotion on a signal an intruder picks (renaming a
// victim host to it would be self-defeating). Kept as a set so the list is easy to extend as other
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
// The other two records the engine writes for the SAME running script: module logging (4103) and
// legacy pipeline execution details (800). PersistenceSniper's `Add-Type … AdjPriv` lands in both.
const MODULE_LOGGING_EID = 4103;
const PIPELINE_EID = 800;
const COLLECTOR_SCRIPT_EIDS = new Set([SCRIPT_BLOCK_EID, MODULE_LOGGING_EID, PIPELINE_EID]);
const EVENT_WRAPPERS = ["Event", "_Event"] as const;

// An EventID as Windows/Velociraptor variously writes it: a bare number, a numeric string, an
// object with a `Value`, or the evtx crate's `{ "#text": N }` a nested Chainsaw document carries.
function toEventId(value: unknown): number {
  if (typeof value === "number") return value;
  if (isObject(value)) return toEventId(getCI(value, "Value") ?? getCI(value, "#text"));
  const n = Number(str(value).trim());
  return Number.isFinite(n) ? n : 0;
}

// The row's EID, from every shape this importer already accepts: flat (`EID`, Hayabusa), the native
// parsed-EVTX `System.EventID`, and the same under an `Event`/`_Event` wrapper. Exported for
// collectorChildren.ts, which reads the same row shapes.
export function eventId(row: Row): number {
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

// The script FILE a PowerShell record was compiled from, as the ENGINE wrote it — so unlike the
// script text it is not a string the script can talk about; a payload cannot claim to live somewhere
// it does not. Per event id (#1477): 4104 logs it as `EventData.Path`; 4103 (module logging) as the
// `Script Name = …` line of `ContextInfo`; 800 (pipeline execution) as `ScriptName=…` inside `Data`,
// which the rendered Message repeats. NEVER `Host Application` / `HostApplication` — that is the host
// PROCESS's command line, a string whoever launched PowerShell chose, and an intruder who starts
// `powershell -c "'<tools path>'; <payload>"` puts the genuine path there on every record.
const SCRIPT_NAME_4103 = /^\s*Script Name\s*=\s*(.*?)\s*$/im;
const SCRIPT_NAME_800 = /^\t?ScriptName=(.*?)\s*$/im;
export function eventData(row: Row): Row | null {
  let ed = getCI(row, "EventData");
  for (const w of EVENT_WRAPPERS) {
    if (isObject(ed)) break;
    ed = getPath(row, `${w}.EventData`);
  }
  return isObject(ed) ? ed : null;
}
// An 800 record's `Data` is three <Data> elements: [0] the command line, [1] the engine's context
// block, [2] the pipeline details/payload. ONLY [1] is read, and only when it has the shape the
// engine writes — every line `\t<Key>=<value>`, one UserId and one ScriptName. [0] and [2] are the
// script's own text; a multi-line command can carry a forged `UserId=WORKGROUP\SYSTEM` line, and
// searching a joined blob would find it (Codex, review of #1477). A flattened export (one string) or
// a row whose EventData is gone leaves nothing that separates the context from the command, so it is
// not read at all — the row keeps its grade, which is the direction a wrong answer must fall.
const CONTEXT_LINE = /^\t?[A-Za-z]+=.*$/;
function pipelineContext(row: Row): string {
  const data = eventData(row)?.Data;
  if (!Array.isArray(data) || data.length < 2 || typeof data[1] !== "string") return "";
  const lines = data[1].split(/\r?\n/).filter((l) => l.trim() !== "");
  if (lines.length === 0 || !lines.every((l) => CONTEXT_LINE.test(l))) return "";
  const count = (key: string) => lines.filter((l) => new RegExp(`^\\t?${key}=`).test(l)).length;
  return count("UserId") === 1 && count("ScriptName") === 1 ? data[1] : "";
}
export function engineScriptPath(row: Row): string {
  const ed = eventData(row);
  switch (eventId(row)) {
    case SCRIPT_BLOCK_EID:
      return ed ? str(getCI(ed, "Path")).trim() : "";
    case MODULE_LOGGING_EID:
      return (ed && SCRIPT_NAME_4103.exec(str(getCI(ed, "ContextInfo")))?.[1]) ?? "";
    case PIPELINE_EID:
      return SCRIPT_NAME_800.exec(pipelineContext(row))?.[1] ?? "";
    default:
      return "";
  }
}

// The classic "Windows PowerShell" channel an 800 lands on records NO Security.UserID, so the SID
// reader below finds nothing for it. The engine writes the identity it ran under into the record's
// own context block instead — `UserId=WORKGROUP\SYSTEM` on a workgroup host, `NT AUTHORITY\SYSTEM`
// on a domain-joined one — the same engine-recorded fact the SID is, and the only spelling of SYSTEM
// the token can produce (SYSTEM is a reserved account name; no user or domain account can be given
// it). Read from the validated context block only, never from the command or payload elements.
const PIPELINE_SYSTEM_USER = /^\t?UserId=(?:NT AUTHORITY|WORKGROUP)\\SYSTEM\s*$/im;
function ranAsSystem(row: Row): boolean {
  const sid = logonSid(row);
  if (sid) return sid === SYSTEM_SID;
  return eventId(row) === PIPELINE_EID && PIPELINE_SYSTEM_USER.test(pipelineContext(row));
}

/**
 * Is this a script block — or the 4103 / 800 record of the same running script (#1477) — the
 * COLLECTOR ran, out of its own tool tree?
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
// Never the `(x86)` folder (#1486): the fleet ships only the 64-bit MSI, so a tool tree there belongs
// to a second copy someone else installed.
const COLLECTOR_TOOL_TREE = /^[a-z]:[\\/]program files[\\/]velociraptor[\\/]tools[\\/]/i;
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
    "System.Security.#attributes.UserID", // the evtx crate's spelling in a nested Chainsaw document
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
  if (!COLLECTOR_SCRIPT_EIDS.has(eventId(row))) return false;
  if (!ranAsSystem(row)) return false;
  const path = engineScriptPath(row);
  return COLLECTOR_TOOL_TREE.test(path) && !PATH_TRAVERSAL.test(path);
}

/**
 * Apply isDetectionToolScript to the events one row produced, in place: Info, never lowering a
 * Critical (the bound the header above argues for), and `origin: "collector"` beside it (#1477). The
 * origin is the part the rest of the pipeline reads. The post-import tagger matches the retained raw
 * message — PersistenceSniper's `Add-Type … AdjPriv` is exactly what the bundled token-manipulation
 * rule looks for — and used to raise the forensic copy of a row this had just graded Info back to
 * High; with the origin set the tagger tags the row and leaves its grade alone (tagger.ts).
 */
export function demoteDetectionToolScript(row: Row, events: readonly (MappedEvent | null)[]): void {
  if (!isDetectionToolScript(row)) return;
  for (const m of events) gradeScriptAsCollector(m, TOOL_TREE_SCRIPT_NOTE);
}

// Why the row reads Info, in the row itself — the same courtesy every other collector demotion
// pays (collectorDeployment.ts). Without it an analyst sees a High-looking script block at Info and
// nothing that says the collector ran it.
export const TOOL_TREE_SCRIPT_NOTE =
  " [DFIR collector footprint — script the Velociraptor client ran from its tool tree]";

/** Info + the collector origin + the note, never lowering a Critical. Idempotent. */
export function gradeScriptAsCollector(m: MappedEvent | null, note: string): void {
  if (!m || m.severity === "Critical") return;
  m.severity = "Info";
  m.origin = "collector";
  if (!m.description.endsWith(note)) m.description = `${m.description}${note}`;
}

/**
 * Is this a script record (4104 / 4103 / 800) the engine logged under SYSTEM? The first two facts
 * isDetectionToolScript rests on, without the path — for a caller that has another fact tying the
 * record to the collector (its process id, collectorLineage.ts, #1488).
 */
export function isSystemScriptRow(row: Row): boolean {
  return COLLECTOR_SCRIPT_EIDS.has(eventId(row)) && ranAsSystem(row);
}

// The process id the ENGINE wrote into the record's System block (`Execution ProcessID`): the
// PowerShell host process that compiled the script. Like the SID and the path, a fact about the
// process, not a string the script controls. The three spellings the importers see: Chainsaw's flat
// `SystemData.Execution_attributes`, the evtx crate's `System.Execution.#attributes`, and the native
// `System.Execution`, the last two with or without an Event wrapper. Undefined when absent or not a
// positive integer.
const EXECUTION_PID_PATHS = [
  "SystemData.Execution_attributes.ProcessID",
  "System.Execution.#attributes.ProcessID",
  "System.Execution.ProcessID",
];
export function scriptHostPid(row: Row): number | undefined {
  for (const w of ["", ...EVENT_WRAPPERS]) {
    for (const path of EXECUTION_PID_PATHS) {
      const raw = getPath(row, w ? `${w}.${path}` : path);
      if (raw === undefined || raw === null || raw === "") continue;
      const n = Number(raw);
      return Number.isInteger(n) && n > 0 ? n : undefined;
    }
  }
  return undefined;
}
