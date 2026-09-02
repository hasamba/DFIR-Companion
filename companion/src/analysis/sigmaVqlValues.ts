// Value rendering for the Sigma → VQL compiler (#797): every byte that reaches a VQL literal goes
// through this file. Two rules, one place:
//
//  1. Sigma string matches are case-insensitive, and Sigma `*` / `?` are wildcards. Every string
//     comparison therefore becomes an RE2 regex with `(?i)`, with every other metacharacter escaped.
//  2. A VQL double-quoted string processes backslash escapes, so `\` and `"` are escaped on the way
//     in, and a control character is refused rather than smuggled through.

export type SigmaMatchMode = "exact" | "contains" | "startswith" | "endswith";

export const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/;

/** A VQL double-quoted string literal. */
export function vqlString(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** A VQL list literal of strings. */
export function vqlStringList(values: readonly string[]): string {
  return `[${values.map(vqlString).join(", ")}]`;
}

/** A Sigma value as a regex body: metacharacters escaped, `*` → `.*`, `?` → `.`. */
export function sigmaRegexBody(value: string): string {
  let out = "";
  for (const ch of value) {
    if (ch === "*") out += ".*";
    else if (ch === "?") out += ".";
    else if (/[.+^${}()|[\]\\]/.test(ch)) out += "\\" + ch;
    else out += ch;
  }
  return out;
}

/** The full case-insensitive regex for a Sigma string match in the given mode. */
export function sigmaRegex(value: string, mode: SigmaMatchMode): string {
  const body = sigmaRegexBody(value);
  switch (mode) {
    case "exact":
      return `(?i)^${body}$`;
    case "contains":
      return `(?i)${body}`;
    case "startswith":
      return `(?i)^${body}`;
    case "endswith":
      return `(?i)${body}$`;
  }
}

/**
 * Why a `re` value cannot run on the endpoint, or null when it can. Velociraptor's `=~` is Go RE2,
 * which has no lookarounds and no backreferences; a rule using them would fail quietly in the
 * client's VQL log, which the hunt UI never shows.
 */
export function re2Objection(pattern: string): string | null {
  if (/\(\?<?[=!]/.test(pattern))
    return "the regular expression uses a lookaround, which RE2 on the endpoint does not support";
  if (/\\[1-9]/.test(pattern))
    return "the regular expression uses a backreference, which RE2 on the endpoint does not support";
  return null;
}

// ── Paths and globs ───────────────────────────────────────────────────────────────────────────

/** A Sigma path value as a Velociraptor glob: forward slashes, Sigma wildcards kept as glob wildcards. */
export function fileGlob(value: string, mode: SigmaMatchMode): string {
  const p = value.replace(/\\/g, "/");
  switch (mode) {
    case "exact":
      return p;
    case "startswith":
      return p + "**";
    case "contains":
      return "C:/**/*" + p + "*";
    case "endswith":
      return "C:/**/*" + p;
  }
}

/** The glob that walks the whole disk, so the header can admit it. */
export const WHOLE_DISK_GLOB = "C:/**";

const HIVES: ReadonlyArray<{ names: string[]; glob: string; regex: string }> = [
  { names: ["hklm", "hkey_local_machine"], glob: "HKEY_LOCAL_MACHINE", regex: "HKEY_LOCAL_MACHINE" },
  // The registry accessor sees every loaded user hive under HKEY_USERS; HKCU is one of them.
  { names: ["hkcu", "hkey_current_user"], glob: "HKEY_USERS/*", regex: "HKEY_USERS\\\\[^\\\\]+" },
  { names: ["hku", "hkey_users"], glob: "HKEY_USERS", regex: "HKEY_USERS" },
  { names: ["hkcr", "hkey_classes_root"], glob: "HKEY_CLASSES_ROOT", regex: "HKEY_CLASSES_ROOT" },
];

export interface RegistryPath {
  glob: string;
  /** Regex body (already escaped) matching what the registry accessor reports as OSPath. */
  regexBody: string;
}

/**
 * Split a Sigma registry key path into its hive and the rest, or null when it is not rooted in a
 * hive. A path without a hive would make the hunt walk the whole registry, so it is refused.
 */
export function registryPath(value: string, mode: "exact" | "startswith"): RegistryPath | null {
  const m = /^([A-Za-z_]+)(?:[\\/](.*))?$/.exec(value);
  if (!m) return null;
  const hive = HIVES.find((h) => h.names.includes(m[1].toLowerCase()));
  if (!hive) return null;
  const rest = m[2] ?? "";
  const glob = hive.glob + (rest ? "/" + rest.replace(/\\/g, "/") : "") + (mode === "startswith" ? "**" : "");
  const regexBody = hive.regex + (rest ? "\\\\" + sigmaRegexBody(rest.replace(/\//g, "\\")) : "");
  return { glob, regexBody };
}
