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
  "wmi", // WQL SELECT only; the namespace argument must be a local root namespace (vqlAllowed.ts)
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

/** Local accessors an `accessor=` argument may name. Network accessors (smb, s3, …) are refused. */
export const ALLOWED_ACCESSORS: readonly string[] = [
  "auto",
  "file",
  "ntfs",
  "reg",
  "registry",
  "raw_reg",
  "data",
];

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
