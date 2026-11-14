// The reviewed allowlists for VQL that Watson may launch on endpoints (vqlAllowed.ts). Watson's VQL
// can be steered by adversary-controlled evidence, so only READ-ONLY names belong here: nothing
// that runs a program, writes or deletes, uploads or sends over the network, changes client or
// server state, or evaluates a string as VQL (lambdas, query strings, computed names).
//
// To extend a list: add one entry, check the Velociraptor reference for every argument it takes
// (an argument that uploads, runs, or evaluates a string disqualifies it), and add a test.
// Names are compared case-insensitively.

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

/** Read-only artifacts Watson may call as `Artifact.<Name>(…)`. */
export const ALLOWED_ARTIFACTS: readonly string[] = [
  "Windows.System.Pslist",
  "Windows.Network.Netstat",
  "Windows.EventLogs.EvtxHunter",
  "Windows.Search.FileFinder", // its Upload_File argument is refused (any argument named *upload*)
  "Generic.Client.Info",
  "Linux.Sys.Pslist",
];

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
