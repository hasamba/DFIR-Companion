// The reviewed allowlists for VQL that Watson may launch on endpoints (vqlAllowed.ts). Watson's VQL
// can be steered by adversary-controlled evidence, so only READ-ONLY names belong here: nothing
// that runs a program, writes or deletes, uploads or sends over the network, changes client or
// server state, or evaluates a string as VQL (lambdas, query strings, computed names).
//
// To extend a list: add one entry, check the Velociraptor reference for every argument it takes
// (an argument that uploads, runs, or evaluates a string disqualifies it), and add a test.
// Names are compared case-insensitively.

import { BUILT_IN_BUNDLES } from "../../../artifactBundleStore.js";

/** Read-only VQL plugins and functions. */
export const ALLOWED_CALLS: readonly string[] = [
  // endpoint state (read-only)
  "pslist",
  "netstat",
  "users",
  "info",
  "wmi", // one literal WQL SELECT from a class on WMI_CLASSES; no namespace argument (vqlArgs.ts)
  // file system reads (an accessor argument must be a literal from ALLOWED_ACCESSORS)
  "glob",
  "stat",
  "read_file",
  "hash",
  "yara",
  "authenticode",
  "parse_pe",
  // parsers
  "parse_csv",
  "parse_json",
  "parse_xml",
  "parse_evtx",
  "parse_lines",
  "split_records",
  // pure value helpers
  "timestamp",
  "format",
  "count",
  "now",
  "lowcase",
  "upcase",
  "regex_replace", // its replace_lambda argument is refused (vqlAllowed.ts)
  "if",
  "dict",
  "array",
  "len",
  "str",
  "int",
  "atoi",
  "basename",
  "dirname",
  "path_join",
  "enumerate",
];

/** The individually reviewed read-only artifacts. */
const REVIEWED_ARTIFACTS: readonly string[] = [
  "Windows.System.Pslist",
  "Windows.Network.Netstat",
  "Windows.EventLogs.EvtxHunter",
  "Windows.Search.FileFinder", // its Upload_File argument is refused (any argument named *upload*)
  "Generic.Client.Info",
  "Linux.Sys.Pslist",
];

/**
 * The built-in bundle whose artifacts are safe for Watson (user decision of 2026-11-15). This is a
 * product decision, not a per-artifact review: some of these run a bundled tool on the endpoint
 * (Hayabusa, Autoruns). Read from the shipped bundle, so the two lists cannot drift. An analyst's edit of that bundle does not change
 * this list. The "best-practice-big-hogs" bundle (slow full-disk scans) is deliberately not included.
 * Many of these fetch and run a tool and take tool overrides, so one of them is safe ONLY in its default
 * run, `Artifact.<Name>()` with no arguments (controller ruling of 2026-11-15, Codex review #1). Any
 * argument makes the query risky: the analyst can approve it, and Auto never launches it.
 */
export const SAFE_BUNDLE_ID = "best-practice";

const bundleArtifacts = (id: string): readonly string[] =>
  BUILT_IN_BUNDLES.find((b) => b.id === id)?.artifacts ?? [];

/** Read-only artifacts Watson may call as `Artifact.<Name>(…)`. */
export const ALLOWED_ARTIFACTS: readonly string[] = [
  ...new Set([...REVIEWED_ARTIFACTS, ...bundleArtifacts(SAFE_BUNDLE_ID)]),
];

const REVIEWED_LC = new Set(REVIEWED_ARTIFACTS.map((a) => a.toLowerCase()));

/** True for an allowed artifact that is safe only with no arguments (Best Practice, not individually reviewed). */
export function isDefaultRunOnly(name: string): boolean {
  const n = name.toLowerCase();
  return !REVIEWED_LC.has(n) && bundleArtifacts(SAFE_BUNDLE_ID).some((a) => a.toLowerCase() === n);
}

/**
 * A Tool_* override (Velociraptor's tool name, file name, hash or URL): it can change the tool an
 * artifact runs. Risky on every artifact, the reviewed ones included (amended ruling 2026-11-15); the
 * reviewed six fetch no tool, so their other arguments keep their usual rules.
 */
export const TOOL_OVERRIDE_ARG = /^tool_/i;

/**
 * Local accessors an `accessor=` argument may name. Network accessors (smb, s3, …) are refused, and
 * so is raw_reg: it takes a JSON "delegate" pathspec that can chain to any other accessor, smb
 * included. String literals that name a delegate or open a JSON object are refused too.
 */
export const ALLOWED_ACCESSORS: readonly string[] = ["auto", "file", "ntfs", "reg", "registry", "data"];

/** VQL keywords that may be followed by `(` without being a call. */
export const VQL_KEYWORDS: readonly string[] = [
  "select",
  "from",
  "where",
  "let",
  "and",
  "or",
  "not",
  "in",
  "as",
  "limit",
  "order",
  "group",
  "by",
  "desc",
  "asc",
  "explain",
  "null",
  "true",
  "false",
];

/** Calls that evaluate a string or a computed name as VQL — named "dynamic invocation" in reasons. */
export const DYNAMIC_CALLS: readonly string[] = [
  "call_function",
  "query",
  "eval",
  "chain",
  "foreach",
  "cache",
  "memoize",
  "filter",
  "map",
  "get",
];

/**
 * Known risky built-in names. Not the safety check (that is the allowlist) — a LET may not define
 * one of these, so a LET cannot shadow a built-in whose lookup might ignore case.
 */
export const DENIED_NAMES: readonly string[] = [
  "execve",
  "shell",
  "rm",
  "copy",
  "upload",
  "upload_directory",
  "write_csv",
  "write_jsonl",
  "write_file",
  "mail",
  "http_client",
  "elastic_upload",
  "splunk_upload",
  "collect_client",
  "hunt",
  "hunt_add",
  "artifact_set",
  "artifact_delete",
  "user_create",
  "user_delete",
  "server_set_metadata",
  "client_set_metadata",
  "label",
  "killkillkill",
  "quarantine",
  "proc_dump",
  "mkdir",
  ...DYNAMIC_CALLS,
];

/** Argument names refused on any call: uploads, dumps, and lambdas (strings evaluated as VQL). */
export const BLOCKED_ARG = /upload|dump|lambda|^func$/i;

/**
 * WMI classes a `wmi(query=…)` may select from: read-only inventory, no side-effecting classes
 * (Win32_PingStatus pings; Win32_Product is left out because enumerating it runs a Windows
 * Installer consistency check that can repair packages).
 */
export const WMI_CLASSES: readonly string[] = [
  "Win32_Process",
  "Win32_Service",
  "Win32_StartupCommand",
  "Win32_LogicalDisk",
  "Win32_OperatingSystem",
  "Win32_ComputerSystem",
  "Win32_UserAccount",
  "Win32_NetworkAdapterConfiguration",
  "Win32_QuickFixEngineering",
  "Win32_ScheduledJob",
];

/** File-reading calls whose path arguments must be plain string literals (no runtime-built paths). */
export const FILE_READ_CALLS: readonly string[] = [
  "glob",
  "stat",
  "read_file",
  "hash",
  "yara",
  "authenticode",
  "parse_pe",
  "parse_csv",
  "parse_xml",
  "parse_evtx",
  "parse_lines",
  "split_records",
];

/** Path-carrying argument names on FILE_READ_CALLS (`rules` only for yara). */
export const PATH_ARGS: readonly string[] = [
  "globs",
  "glob",
  "filename",
  "filenames",
  "file",
  "path",
  "paths",
  "files",
  "root",
];

/** Arguments a call may compile as a query: a string value is refused (only `{…}` or a LET name). */
export const QUERY_ARGS: readonly string[] = ["then", "else", "query", "items", "row"];

/** LET names that would set a Velociraptor config or credential variable. */
export function isCredentialName(name: string): boolean {
  if (/credential|_CONFIG$|^SSH_/i.test(name)) return true;
  return name === name.toUpperCase() && /CRED|KEY|TOKEN|PASS|SECRET/.test(name);
}
