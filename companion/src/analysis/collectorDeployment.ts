// The collector's own deployment on the case host is not evidence (#1460).
//
// INC-2026-028 finding f31 (High, T1070.006) was built from three rows that describe the Companion's
// OWN Velociraptor client arriving on the host: `Velociraptor.exe` fetched from the Velociraptor
// server this Companion is configured against, the `msiexec` install, and the Sysmon EID 2 (file
// creation time changed) an MSI install leaves on the file it wrote. Nothing told the pipeline that
// this is the case's own DFIR infrastructure, so the rows graded like any other download + install +
// timestamp change and synthesis read them as an intrusion.
//
// This is the same mistake veloDetectionNoise.ts exists for — a detection stack finding its own
// reflection — seen from the deployment side rather than the scanning side, and it follows the same
// discipline. EVERY PREDICATE HERE LOWERS A GRADE OR STRIPS A TECHNIQUE, so every one is a place an
// intruder would like to reach:
//
//   - Known infrastructure comes from CONFIG ONLY (the GUI URL and the api_client config the
//     Velociraptor integration already reads), never from event content. A row cannot declare its
//     own destination to be the DFIR server. A LOOPBACK or unspecified address in that config is
//     dropped (#1471): from a client's point of view loopback is itself, never the server, so a
//     `127.0.0.1:8001` api_connection_string (Velociraptor's default when the Companion runs on the
//     server) would otherwise demote every local connection on every host — a High 4104 cradle from
//     `http://127.0.0.1:8080/stage.ps1` and a Medium EID 3 from `%TEMP%\x.exe` to `127.0.0.1:4444`
//     both came out Info. A loopback-only configuration leaves rule 1 inert, by design.
//   - The server address is matched only where a row NAMES A DESTINATION — the DestinationIp /
//     DestinationHostname fields the Windows mapper renders, the structured dstIp, or the host of a
//     URL — never as free text. A row whose message merely mentions the address is untouched.
//   - The collector binary is recognised only under its INSTALL ROOT (`\Program Files\Velociraptor\`),
//     the one location an intruder cannot supply — the reasoning isDetectionToolLocation records. A
//     bare `velociraptor.exe` in `C:\Users\Public\` is exactly the masquerade an attacker would pick,
//     and it keeps whatever grade it earned.
//   - The EID 2 rule reads the CREATING PROCESS, and only the system `msiexec.exe`. Windows Installer
//     rewrites the creation time of every file it lays down, so an EID 2 whose Image is msiexec.exe
//     is the installer's ordinary footprint, not T1070.006. The row is kept at its grade; only the
//     timestomp claim goes, on any MSI, whether or not Velociraptor is configured.
//   - The rendered fields are read in the shape each importer produces: the Windows mapper's
//     ` - Key=value` and Hayabusa's `— Proc=value Cmdline=value … @ host` under Hayabusa's own key
//     names (#1471). The command line and destination of a Hayabusa row come from the STRUCTURED
//     fields its importer sets, so the 120-character cut on its rendered subject cannot hide the MSI
//     name or the address. Accepted residual risk: the ACTING IMAGE still comes from the rendered
//     subject, which keeps only the first six detail fields — Proc/SrcProc is the first or second
//     field in every Hayabusa default profile for EID 1/2/3/10/11/22/4688/7045, so the cap does not
//     reach it.
//
//   - A process the client itself SPAWNED (rule 2c, #1477) needs both the collector exe as its parent
//     — a path Sysmon recorded, not one the child chose — and a Tools-tree file on its command line.
//     Either alone keeps the grade. Children of that process are not covered.
//   - Every demotion here also sets `origin: "collector"`, the structured mark the post-import tagger
//     honours (tagger.ts): the tagger matches the retained raw message, so without it a row graded
//     Info here came back High when PersistenceSniper's `Add-Type … AdjPriv` met the bundled rule.
//
// Runs once per mapped row at the shared aggregation seam (eventAggregate.ts), in place like the
// other mapper overlays, BEFORE the severity floor so a demoted row is floored as Info.

import { readFileSync } from "node:fs";
import type { MappedEvent } from "./siemImport.js";

export interface CollectorInfrastructure {
  /** Lower-cased hostnames / IPs of the configured Velociraptor server(s). Empty ⇒ rule 1 is inert. */
  servers: ReadonlySet<string>;
}

const DEPLOYMENT_DOWNLOAD_NOTE =
  " [DFIR collector deployment — download from the configured Velociraptor server]";
const DEPLOYMENT_INSTALL_NOTE = " [DFIR collector deployment — Velociraptor client install]";
const FOOTPRINT_NOTE = " [DFIR collector footprint — tool run by the Velociraptor client]";
const SPAWN_NOTE = " [DFIR collector footprint — spawned by the Velociraptor client]";
const MSI_TIME_CHANGE_NOTE =
  " [MSI install artifact — creation-time change by msiexec.exe is not timestomping]";
const TIMESTOMP_TECHNIQUE = "T1070.006";

// The Windows mapper renders `(EID N)`; Hayabusa renders `(EID N <channel>)`. Both end the number.
const CREATION_TIME_CHANGED_EID = /\(EID 2[\s)]/;
// The system installer, under either bitness. Anchored to \Windows\ so a copy an intruder dropped
// elsewhere and named msiexec.exe is not the installer.
const SYSTEM_MSIEXEC = /^[a-z]:[\\/]windows[\\/](?:system32|syswow64)[\\/]msiexec\.exe$/i;
// The collector's own install root — the path component an intruder cannot supply — holding the
// client exe. Traversal is refused separately: a prefix match on a path holding `..` proves nothing.
const COLLECTOR_INSTALL_ROOT = /^[a-z]:[\\/]program files(?: \(x86\))?[\\/]velociraptor[\\/]/i;
const COLLECTOR_INSTALL_EXE = new RegExp(`${COLLECTOR_INSTALL_ROOT.source}velociraptor\\.exe$`, "i");
// The tree the client unpacks an artifact's tools into (`\Tools\tmp<digits>\…`), as a token INSIDE a
// command line: preceded by a quote, a space or the start, so `import-module "C:\Program Files\
// Velociraptor\Tools\tmp…\PersistenceSniper.psm1"` is found and `C:\ProgramData\Velociraptor\Tools\`
// is not (rule 2c). Runs to the closing quote / whitespace so traversal inside the token is visible.
const COLLECTOR_TOOLS_ARG =
  /(?:^|[\s"'])([a-z]:[\\/]program files(?: \(x86\))?[\\/]velociraptor[\\/]tools[\\/][^"'\s]*)/gi;
const PATH_TRAVERSAL = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
// The identity the client runs its artifacts under, as Sysmon renders the token's account: the only
// two spellings LocalSystem produces (SYSTEM is a reserved name no user or domain account can take).
const SYSTEM_ACCOUNT = /^(?:NT AUTHORITY|WORKGROUP)\\SYSTEM$/i;
// The client MSI as Velociraptor publishes it: `velociraptor-<version>[-suffix].msi`, or the bare
// `velociraptor.msi` an analyst renamed it to.
const COLLECTOR_MSI = /(?:^|[\\/\s"'])velociraptor(?:-[^\s"'\\/]*)?\.msi(?=$|[\s"'])/i;
const URL_HOST = /\bhttps?:\/\/(?:[^\s/?#@"']*@)?(\[[^\]\s]+\]|[^\s/?#:"']+)/gi;
// The api_client.yaml line the Velociraptor integration connects with. A YAML scalar; quotes optional.
const API_CONNECTION_STRING = /^\s*api_connection_string:\s*["']?([^\s"'#]+)/m;
// Addresses that name the host itself or no host at all. `new URL` has already canonicalised the
// configured spelling (`127.1` → 127.0.0.1, `[0:0:0:0:0:0:0:1]` → ::1, `[::ffff:127.0.0.1]` →
// ::ffff:7f00:1); the raw IPv4-mapped form is listed as well for a caller that skipped that step.
const LOCAL_HOST_NAMES = new Set(["localhost", "localhost.", "::1", "::", "0.0.0.0", "::ffff:7f00:1"]);
// Both spellings of IPv4-mapped 127/8: dotted, and the hex form `new URL` canonicalises it to (`::ffff:7f00:2`).
const LOOPBACK_V4 = /^(?:::ffff:)?127\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}$/i;
// Hayabusa's key for each Windows-mapper key this file reads (hayabusaImport.ts renders the detail
// fields under Hayabusa's own aliases). A key with no entry is looked up under its own name.
const HAYABUSA_PREFIX = /^Hayabusa: /;
const HAYABUSA_KEY: Readonly<Record<string, readonly string[]>> = {
  Image: ["Proc"],
  NewProcessName: ["Proc"],
  SourceImage: ["SrcProc"],
  CommandLine: ["Cmdline"],
  ImagePath: ["Path"],
  ServiceFileName: ["Path"],
  DestinationIp: ["TgtIP", "DstIP"],
  DestinationHostname: ["TgtHost", "DstHost"],
};

// ───────────────────────────── configuration ─────────────────────────────

// The host of a URL as configured or written, lower-cased, brackets off an IPv6 literal. A value
// without a scheme (`velo:8889`) is read as a host:port. Returns "" for anything unparseable.
function urlHost(value: string): string {
  const s = value.trim();
  if (!s) return "";
  for (const candidate of [s, `https://${s}`]) {
    try {
      const host = new URL(candidate).hostname.toLowerCase();
      if (host) return host.replace(/^\[|\]$/g, "");
    } catch {
      /* try the next spelling */
    }
  }
  return "";
}

// api_connection_string from the api_client config, when the file is named and readable. A missing
// or unreadable file is not an error here — the integration reports that on its own surface.
function apiConfigHost(path: string): string {
  if (!path.trim()) return "";
  try {
    const text = readFileSync(path.trim(), "utf8");
    const m = API_CONNECTION_STRING.exec(text);
    return m ? urlHost(m[1]) : "";
  } catch {
    return "";
  }
}

/**
 * Is this host the machine itself (loopback) or no machine at all (unspecified)? Such an address in
 * the configuration names where the Companion runs, not where the clients connect, so it is never
 * the collector server (#1471). Brackets and case are ignored.
 */
export function isLocalOrUnspecifiedHost(host: string): boolean {
  const h = host
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, "");
  return LOCAL_HOST_NAMES.has(h) || LOOPBACK_V4.test(h);
}

/**
 * The configured Velociraptor server host(s), from `DFIR_VELOCIRAPTOR_GUI_URL` and the
 * `api_connection_string` in the file `DFIR_VELOCIRAPTOR_API_CONFIG` names. Read at call time, so a
 * settings reload (or a test's stubbed env) is seen without a restart. Lower-cased, de-duplicated,
 * and never loopback: a `localhost` GUI URL or a `127.0.0.1:8001` api_connection_string yields
 * nothing, so rule 1 stays inert instead of matching every host's own loopback traffic.
 */
export function configuredCollectorServers(env: NodeJS.ProcessEnv = process.env): string[] {
  const hosts = [
    urlHost(env.DFIR_VELOCIRAPTOR_GUI_URL ?? ""),
    apiConfigHost(env.DFIR_VELOCIRAPTOR_API_CONFIG ?? ""),
  ];
  return [...new Set(hosts.filter((h) => h && !isLocalOrUnspecifiedHost(h)))];
}

export function loadCollectorInfrastructure(env: NodeJS.ProcessEnv = process.env): CollectorInfrastructure {
  return { servers: new Set(configuredCollectorServers(env)) };
}

// ───────────────────────────── description fields ─────────────────────────────

// One `Key=value` field as the Windows mapper renders it: fields joined by " - ", the value running
// to the next ` - Key=` field or to the ` @ host` tail. Case-insensitive on the key. A `foo=bar`
// inside a command line is not a field boundary — only the " - " join is.
function mapperField(description: string, key: string): string {
  const re = new RegExp(`(?:^|\\s-\\s)${key}=(.*?)(?=\\s-\\s[A-Z][A-Za-z]*=|\\s@\\s\\S+$|$)`, "i");
  const m = re.exec(description);
  return m ? m[1].trim() : "";
}

// The same field as Hayabusa renders it (#1471): `— Key=value Key=value … @ host`, joined by ONE
// space under Hayabusa's own key names, so the value runs to the next ` Key=` token or the tail. A
// `Key=` token inside a value does cut it, which is why rules 1 and 2 prefer the structured
// commandLine / dstIp the Hayabusa importer sets; the acting image is a path and holds no such token.
function hayabusaField(description: string, key: string): string {
  for (const alias of HAYABUSA_KEY[key] ?? [key]) {
    const re = new RegExp(`(?:^|\\s)${alias}=(.*?)(?=\\s[A-Za-z]+=|\\s@\\s\\S+$|$)`, "i");
    const m = re.exec(description);
    if (m) return m[1].trim();
  }
  return "";
}

// A rendered field by its Windows-mapper key, read in the shape the row's importer produced.
function descriptionField(description: string, key: string): string {
  return HAYABUSA_PREFIX.test(description) ? hayabusaField(description, key) : mapperField(description, key);
}

// The process a row is about, by its two spellings (Sysmon Image, Security 4688 NewProcessName).
function imagePath(m: MappedEvent): string {
  return descriptionField(m.description, "Image") || descriptionField(m.description, "NewProcessName");
}

// A process-creation row: the mapper sets commandLine / processName only for a process row; a row
// from another importer shows the same fact by rendering a CommandLine field or the process EID
// (Sysmon 1, Security 4688).
const PROCESS_CREATE_EID = /\(EID (?:1|4688)[\s)]/;
function isProcessRow(m: MappedEvent): boolean {
  return (
    Boolean(m.commandLine || m.processName) ||
    /(?:^|\s-\s)CommandLine=/i.test(m.description) ||
    PROCESS_CREATE_EID.test(m.description)
  );
}

// A process-SHAPED row — one whose Image is the process that acted: process create (1 / 4688),
// network connection (3), process access (10), file create (11). The Image of a file or registry
// event is still the acting process, but those are read by other overlays; this list is what the
// real collection showed graded High.
const PROCESS_SHAPED_EID = /\(EID (?:1|3|10|11|22|4688)[\s)]/;
function isProcessShapedRow(m: MappedEvent): boolean {
  return isProcessRow(m) || PROCESS_SHAPED_EID.test(m.description);
}

// The ACTING process of a process-shaped row: Image (Sysmon 1/3/11/22), SourceImage (Sysmon 10) or
// NewProcessName (4688). Never TargetImage — that is the process acted UPON, and an intruder's tool
// opening lsass is not the collector because lsass is not under the collector's root either way.
function actingImagePath(m: MappedEvent): string {
  return imagePath(m) || descriptionField(m.description, "SourceImage");
}

// ───────────────────────────── rules ─────────────────────────────

/**
 * Rule 1 — does this row's DESTINATION name the configured Velociraptor server?
 *
 * Destinations: the structured `dstIp`, the rendered `DestinationIp` / `DestinationHostname` fields,
 * and the host of any URL in the description (the download command names the server there). Never
 * the address as free text — the same digits in a message body are not a destination claim.
 */
export function isCollectorServerDestination(m: MappedEvent, infra: CollectorInfrastructure): boolean {
  if (infra.servers.size === 0) return false;
  const candidates = [
    m.dstIp ?? "",
    descriptionField(m.description, "DestinationIp"),
    descriptionField(m.description, "DestinationHostname"),
  ];
  for (const u of m.description.matchAll(URL_HOST)) candidates.push(u[1]);
  return candidates.some((c) => {
    const host = c
      .trim()
      .toLowerCase()
      .replace(/^\[|\]$/g, "");
    return host !== "" && infra.servers.has(host);
  });
}

/**
 * Rule 2 — is this a process-creation row for the collector's own install?
 *
 * Either the client exe under its install root (the service start the MSI performs, the client
 * itself), or the SYSTEM `msiexec.exe` — under \Windows\System32 or \SysWOW64, the same anchor rule 3
 * uses — installing a `velociraptor*.msi`. A `velociraptor.exe` anywhere else is a name an intruder
 * picks, and so is an `msiexec.exe` anywhere else (#1471): a copy in `C:\Users\Public\` installing
 * its own `velociraptor.msi` is T1218.007, not the collector arriving. The MSI path itself is not
 * anchored — an analyst downloads it anywhere; the installer is what an intruder cannot supply.
 */
export function isCollectorInstallBinary(m: MappedEvent): boolean {
  if (isCollectorServiceInstall(m)) return true;
  if (!isProcessRow(m)) return false;
  const image = imagePath(m);
  if (PATH_TRAVERSAL.test(image)) return false;
  if (COLLECTOR_INSTALL_EXE.test(image)) return true;
  if (!SYSTEM_MSIEXEC.test(image)) return false;
  const cmd = m.commandLine || descriptionField(m.description, "CommandLine");
  return COLLECTOR_MSI.test(cmd);
}

// The MSI registers the client as a service, which Windows logs as System 7045 (or Security 4697)
// with the binary in ImagePath — quoted, as the installer writes it. The PATH is the test, never the
// service name: "Velociraptor Service" is a string anyone can register.
const SERVICE_INSTALL_EID = /\(EID (?:7045|4697)[\s)]/;
function isCollectorServiceInstall(m: MappedEvent): boolean {
  if (!SERVICE_INSTALL_EID.test(m.description)) return false;
  const raw =
    descriptionField(m.description, "ImagePath") || descriptionField(m.description, "ServiceFileName");
  const image = raw.replace(/^"([^"]*)".*$/, "$1").trim();
  return !PATH_TRAVERSAL.test(image) && COLLECTOR_INSTALL_EXE.test(image);
}

/**
 * Rule 2b — is this the collector's own FOOTPRINT: a tool the Velociraptor client ran out of its
 * install root?
 *
 * Velociraptor unpacks the tools an artifact needs under `\Program Files\Velociraptor\Tools\tmp*\`
 * and runs them as SYSTEM — THOR opens every process including lsass (Sysmon EID 10, SeDebugPrivilege),
 * Hayabusa reads every log, both connect out. On a real collection 24 of those rows graded High and
 * became an "LSASS access" lead the AI later had to dismiss. The ACTING image is what is tested,
 * root-anchored like isDetectionToolLocation and with traversal refused: `thor64-lite.exe` under
 * `C:\Users\Public\` is a name an intruder picks, and so is a `\Velociraptor\` directory anywhere
 * but Program Files. The client exe's own process-create and service registration are rule 2's
 * (install note, applied first); its other rows — the DNS query for its server (EID 22), its
 * connections, the files it writes — land here with everything else under the root.
 */
export function isCollectorFootprint(m: MappedEvent): boolean {
  if (!isProcessShapedRow(m)) return false;
  const image = actingImagePath(m);
  if (!image || PATH_TRAVERSAL.test(image)) return false;
  return COLLECTOR_INSTALL_ROOT.test(image);
}

/**
 * Rule 2c — is this a process the Velociraptor client ITSELF started to run one of its artifacts?
 *
 * Windows.Forensics.PersistenceSniper makes the client spawn the SYSTEM `powershell.exe` with
 * `import-module "<install root>\Tools\tmp…\PersistenceSniper\PersistenceSniper.psm1"`. The
 * acting image is System32\powershell.exe, so rule 2b never sees it, and on a real collection the
 * Sigma "Change PowerShell Policies" / "Non Interactive PowerShell" hits on that one launch became a
 * High finding that the collector had been hijacked (#1477). Two facts, BOTH required:
 *
 *   - the PARENT executable is the collector exe under its install root — Sysmon recorded that path
 *     from the parent's own image, so the child could not choose it (read from the canonical
 *     envelope the Windows mapper builds, else the rendered ParentImage field); and
 *   - the COMMAND LINE names a file under the collector's Tools tree, root-anchored like rule 2b and
 *     with traversal refused.
 *
 * Parent alone is provenance, not enough: an artifact the analyst did not intend, or a server that
 * is not theirs, can make the client run anything, so a collector child with an ordinary command
 * line keeps its grade (the ParentProc negative in the tests). A Tools path alone is a string anyone
 * can type. And a parent can be CHOSEN: Windows lets a creator name another process as the parent
 * (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) and Sysmon records the chosen one — but naming the
 * collector's SYSTEM process as parent needs a handle to it, which needs SYSTEM. So the row must
 * also run as SYSTEM (the Sysmon `User` field, read from the canonical actor), the identity the
 * client runs its artifacts under — the same bound isDetectionToolScript rests on: an intruder
 * already at SYSTEM can satisfy every predicate, and has better ways to be quiet than this.
 * Children of the spawned process are NOT covered — that needs process-GUID lineage across rows,
 * which this per-row seam does not have. Never lowers a Critical, the bound isDetectionToolScript
 * keeps for the same module's script blocks.
 */
export function isCollectorSpawn(m: MappedEvent): boolean {
  if (!isProcessRow(m)) return false;
  if (!SYSTEM_ACCOUNT.test(m.canonical?.actor?.name ?? descriptionField(m.description, "User"))) return false;
  const parent =
    m.canonical?.process?.parent?.executable?.trim() || descriptionField(m.description, "ParentImage");
  if (!parent || PATH_TRAVERSAL.test(parent) || !COLLECTOR_INSTALL_EXE.test(parent)) return false;
  const cmd = m.commandLine || descriptionField(m.description, "CommandLine");
  for (const hit of cmd.matchAll(COLLECTOR_TOOLS_ARG)) if (!PATH_TRAVERSAL.test(hit[1])) return true;
  return false;
}

/**
 * Rule 3 — is this a Sysmon EID 2 (file creation time changed) written by the system msiexec.exe?
 *
 * Windows Installer sets the creation time of every file it lays down to the time recorded in the
 * package, so this event is the installer's ordinary footprint on ANY MSI install — not timestomping.
 * Independent of Velociraptor being configured. The creating process is the whole test: the same
 * event from powershell.exe, or from an msiexec.exe outside \Windows\System32\, is untouched.
 */
export function isMsiexecCreationTimeChange(m: MappedEvent): boolean {
  if (!CREATION_TIME_CHANGED_EID.test(m.description)) return false;
  return SYSTEM_MSIEXEC.test(imagePath(m));
}

// ───────────────────────────── application ─────────────────────────────

function appendNote(m: MappedEvent, note: string): void {
  if (!m.description.endsWith(note)) m.description = `${m.description}${note}`;
}

/** Apply the rules to ONE mapped row, in place. Idempotent. */
export function annotateCollectorDeployment(m: MappedEvent, infra: CollectorInfrastructure): void {
  if (isMsiexecCreationTimeChange(m)) {
    m.mitre = m.mitre.filter((t) => t !== TIMESTOMP_TECHNIQUE);
    appendNote(m, MSI_TIME_CHANGE_NOTE);
    return;
  }
  if (isCollectorInstallBinary(m)) return gradeAsCollector(m, DEPLOYMENT_INSTALL_NOTE);
  if (isCollectorSpawn(m)) {
    if (m.severity !== "Critical") gradeAsCollector(m, SPAWN_NOTE);
    return;
  }
  if (isCollectorFootprint(m)) return gradeAsCollector(m, FOOTPRINT_NOTE);
  if (isCollectorServerDestination(m, infra)) gradeAsCollector(m, DEPLOYMENT_DOWNLOAD_NOTE);
}

// Info, the note, and the structured origin the rest of the pipeline reads (#1477): the post-import
// tagger never raises a collector-origin row, so a demotion made here survives the tagger's own
// match on the same message — which is how THOR's lsass access and this file's other demotions
// used to come back as High.
function gradeAsCollector(m: MappedEvent, note: string): void {
  m.severity = "Info";
  m.origin = "collector";
  appendNote(m, note);
}

/** Apply the rules to every row, in place, reading the configuration once. */
export function applyCollectorDeployment(
  events: MappedEvent[],
  infra: CollectorInfrastructure = loadCollectorInfrastructure(),
): void {
  for (const m of events) annotateCollectorDeployment(m, infra);
}
