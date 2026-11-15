import type { ForensicEvent } from "../../stateTypes.js";
import { COMMON_WORDS, withShortLabel } from "./hostLabel.js";
import { descriptionHostNames } from "./rowTextHosts.js";

// The masking roster for Watson's super-timeline rows (D2d). These rows are raw-only, so the case
// anonymizer has never seen their names: every name superRow prints in clear must be listed here so
// masking can replace it. IPs are listed too, although the anonymizer also matches them by pattern.

/** Names the shown rows carry, handed to masking as known entities. */
export interface WatsonMaskRoster {
  hosts: string[];
  users: string[];
  ips: string[];
}

// When unsure, a name is NOT listed: roster names are masked as whole words in every later Watson
// prompt of the chat, so a wrongly listed evidence term (mimikatz, cmd.exe) would hide the evidence.

const NAME_MAX = 64;
// The path field's `\Users\<name>\` or `/home/<name>/`: a profile name there may hold spaces.
const PATH_USER = new RegExp(
  `[\\\\/](?:users|home)[\\\\/]([^\\\\/"'|:<>\\r\\n]{1,${NAME_MAX}})[\\\\/]`,
  "gi",
);
// Free text: only a space-free name that ends at a separator, or a spaced one inside a quoted path.
const TEXT_USER = new RegExp(`[\\\\/](?:users|home)[\\\\/]([^\\\\/"'|:<>\\s]{1,${NAME_MAX}})[\\\\/]`, "gi");
const QUOTED_PATH = /"([^"\r\n]*)"/g;
// `\\host\share`, `psexec \\dc02`. Device paths (`\\?\`, `\\.\`) start with no letter or digit.
const UNC_HOST = /\\\\([a-z0-9][a-z0-9.-]*[a-z0-9]|[a-z0-9])/gi;
const ACCOUNT_FLAG = /(?:^|\s)(?:\/user:|-u\s+|--user(?:\s+|=))(?:"([^"]+)"|([^\s"]+))/gi;
const DOMAIN_USER = /(?<![\\\w:.$/-])([\w.-]{1,15})\\([\w.$-]{2,64})(?![\\\w])/g;
const EMAIL_USER = /(?<![\w.-])([\w.-]+)@[\w-]+(?:\.[\w-]+)+/gi;
const HAS_EXTENSION = /\.[a-z0-9]{1,5}$/i;
const UPPER_DOMAIN = /^[A-Z][A-Z0-9-]{0,14}$/;
const DOTTED_DOMAIN = /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i;
/** Programs whose -u / --user / /user: value is an account. Anything else (python -u, sort -u) is not. */
const ACCOUNT_PROGRAMS = new Set([
  "runas",
  "net",
  "net1",
  "psexec",
  "psexec64",
  "paexec",
  "wmic",
  "schtasks",
  "sc",
  "ssh",
  "smbclient",
  "mount",
  "curl",
  "sqlcmd",
  "mysql",
  "psql",
]);
/** Folder names that sit before a backslash and are not a Windows domain. */
const KNOWN_FOLDERS = new Set([
  "desktop",
  "documents",
  "downloads",
  "windows",
  "users",
  "temp",
  "tmp",
  "appdata",
  "local",
  "roaming",
  "programdata",
  "system32",
  "syswow64",
  "public",
  "default",
  "music",
  "pictures",
  "videos",
]);
/** Registry roots and the last word of built-in account prefixes (NT AUTHORITY, IIS APPPOOL, …). */
const NOT_A_DOMAIN =
  /^(?:hklm|hkcu|hkcr|hku|hkcc|hkey_[a-z_]+|authority|builtin|service|apppool|manager|host)$/i;
const BUILTIN_PREFIX = /^(?:nt authority|builtin|nt service|iis apppool|window manager|font driver host)$/i;
/** Built-in principals and shared profile folders. Administrator is a real account and stays. */
const WELL_KNOWN = new Set([
  "system",
  "local service",
  "localservice",
  "network service",
  "networkservice",
  "administrators",
  "users",
  "everyone",
  "authenticated users",
  "trustedinstaller",
  "public",
  "default",
  "default user",
  "all users",
]);
/** Registry hive names: dropped when a pattern only inferred them, kept from an explicit account. */
const HIVE_NAMES = new Set(["sam", "security", "software"]);

const groups = (text: string, re: RegExp): string[] =>
  [...text.matchAll(re)].map((m) => (m[1] ?? m[2] ?? "").trim()).filter(Boolean);

/** A spaced profile name from the path field: whole, plus each real name word (≥ 3, not common). */
const withNameWords = (name: string): string[] => [
  name,
  ...name
    .split(/\s+/)
    .filter((w) => w !== name && w.length >= 3 && /^\p{L}[\p{L}'-]*$/u.test(w))
    .filter((w) => !COMMON_WORDS.has(w.toLowerCase()) && !HAS_EXTENSION.test(w)),
];

function folderUsers(e: ForensicEvent): string[] {
  const shared = (n: string) => WELL_KNOWN.has(n.toLowerCase()); // never split "All Users"
  const fromPath = e.path
    ? groups(e.path, PATH_USER)
        .filter((n) => !shared(n))
        .flatMap(withNameWords)
    : [];
  const text = [e.commandLine, e.description].filter((s): s is string => !!s);
  const quoted = text.flatMap((s) => groups(s, QUOTED_PATH)).flatMap((q) => groups(q, PATH_USER));
  return [...fromPath, ...quoted, ...text.flatMap((s) => groups(s, TEXT_USER))];
}

/** A command word as a program name: quotes, directory and extension dropped (`"C:\\T\\PsExec.exe"`). */
const programName = (word: string): string =>
  word
    .replace(/^["']+|["']+$/g, "")
    .replace(/^.*[\\/]/, "")
    .replace(/\.[a-z0-9]{1,4}$/i, "")
    .toLowerCase();

/** The last account program among the words before `at`, so `cmd /c net use … /user:x` counts. */
const accountProgramBefore = (part: string, at: number): string | undefined =>
  part
    .slice(0, at)
    .split(/\s+/)
    .map(programName)
    .filter((w) => ACCOUNT_PROGRAMS.has(w))
    .pop();

const looksLikeAccount = (v: string): boolean => v.length > 1 && !v.startsWith("-") && !HAS_EXTENSION.test(v);

/** `DOMAIN\user` as the whole spelling plus the bare user; curl's `user:password` keeps the user. */
function accountForms(raw: string, program: string): string[] {
  const v = program === "curl" ? raw.split(":")[0] : raw;
  if (!looksLikeAccount(v)) return [];
  const cut = v.lastIndexOf("\\");
  if (cut <= 0 || cut >= v.length - 1) return [v];
  const user = v.slice(cut + 1);
  return looksLikeAccount(user) ? [v, user] : [];
}

const isDomain = (d: string): boolean =>
  (UPPER_DOMAIN.test(d) || DOTTED_DOMAIN.test(d)) &&
  !KNOWN_FOLDERS.has(d.toLowerCase()) &&
  !NOT_A_DOMAIN.test(d);

/** A built-in principal, a shared profile folder, or a name under a built-in prefix: not a person. */
function isPerson(name: string, explicit = false): boolean {
  const lower = name.toLowerCase();
  if (WELL_KNOWN.has(lower) || (!explicit && HIVE_NAMES.has(lower))) return false;
  const cut = name.lastIndexOf("\\");
  if (cut < 0) return true;
  const domain = name.slice(0, cut).trim();
  const last = domain.split(/\s+/).pop() ?? "";
  const user = name.slice(cut + 1);
  return !NOT_A_DOMAIN.test(last) && !BUILTIN_PREFIX.test(domain) && isPerson(user, explicit);
}

function domainUsers(cmd: string): string[] {
  return [...cmd.matchAll(DOMAIN_USER)]
    .filter((m) => isDomain(m[1]) && looksLikeAccount(m[2]))
    .flatMap((m) => [`${m[1]}\\${m[2]}`, m[2]]);
}

/** Accounts a command names explicitly: account flags of known programs and `DOMAIN\user`. */
function commandAccounts(cmd: string | undefined): string[] {
  if (!cmd) return [];
  const flagged = cmd.split(/[&|;]+/).flatMap((part) =>
    [...part.matchAll(ACCOUNT_FLAG)].flatMap((m) => {
      const program = accountProgramBefore(part, m.index);
      const value = (m[1] ?? m[2] ?? "").trim();
      return program && value ? accountForms(value, program) : [];
    }),
  );
  return [...flagged, ...domainUsers(cmd)];
}

const printed = (e: ForensicEvent): string[] =>
  [e.path, e.commandLine, e.description].filter((s): s is string => !!s);

const uncHosts = (e: ForensicEvent): string[] => printed(e).flatMap((s) => groups(s, UNC_HOST));

const distinct = (xs: readonly (string | undefined)[]): string[] => [
  ...new Set(xs.filter((x): x is string => !!x && !!x.trim()).map((x) => x.trim())),
];

/**
 * An account field's forms, as the forensic path masks them: the whole value, the user, and the domain
 * (for the host list) when it is a real one. A built-in principal gives nothing beyond the value, which
 * the person check then drops.
 */
function fieldAccountForms(raw: string | undefined): { users: string[]; domains: string[] } {
  const v = raw?.trim();
  if (!v) return { users: [], domains: [] };
  const slash = v.lastIndexOf("\\");
  const at = slash < 0 ? v.indexOf("@") : -1;
  const cut = slash >= 0 ? slash : at;
  if (cut <= 0 || cut >= v.length - 1 || !isPerson(v, true)) return { users: [v], domains: [] };
  const [domain, user] =
    slash >= 0 ? [v.slice(0, cut), v.slice(cut + 1)] : [v.slice(cut + 1), v.slice(0, cut)];
  return { users: [v, user], domains: isOwnDomain(domain) ? [domain] : [] };
}

/** Public mail providers: the user of `kate@gmail.com` is the person, the domain names nobody. */
const PUBLIC_MAIL_DOMAINS = new Set([
  "gmail.com",
  "googlemail.com",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "yahoo.com",
  "icloud.com",
  "proton.me",
  "protonmail.com",
  "aol.com",
  "gmx.com",
  "mail.com",
]);

/** An account's domain worth masking: a real domain, not the default WORKGROUP or a public mail host. */
const isOwnDomain = (d: string): boolean =>
  isDomain(d) && !/^workgroup$/i.test(d) && !PUBLIC_MAIL_DOMAINS.has(d.toLowerCase());

const accountFields = (e: ForensicEvent) => [e.canonical?.account?.name, e.callerName].map(fieldAccountForms);

/** Names an account source states outright: the account field, the caller, account flags, DOMAIN\user. */
const explicitUsers = (e: ForensicEvent): string[] => [
  ...accountFields(e).flatMap((f) => f.users),
  ...commandAccounts(e.commandLine),
];

export { IP_LIKE } from "./hostLabel.js";

/**
 * Hosts the row states in a host field. The case's own machines (asset, asset record) give their short
 * label too; a network peer (login.mega.example) is listed whole only, so "login" or "www" is never a
 * token.
 */
const explicitHosts = (e: ForensicEvent): (string | undefined)[] => [
  ...[e.asset, e.assetRecord].flatMap(withShortLabel),
  e.canonical?.network?.source?.hostname,
  e.canonical?.network?.destination?.hostname,
];

/** Names only a pattern suggests: user folders and `user@domain`. */
const inferredUsers = (e: ForensicEvent): string[] => [
  ...folderUsers(e),
  ...(e.commandLine ? groups(e.commandLine, EMAIL_USER) : []),
];

/** Every host, account, user-folder name and IP the shown rows print. */
export function rosterOf(shown: readonly ForensicEvent[]): WatsonMaskRoster {
  const net = (e: ForensicEvent) => e.canonical?.network;
  return {
    hosts: distinct(
      shown.flatMap((e) => [
        ...explicitHosts(e),
        ...accountFields(e).flatMap((f) => f.domains),
        ...uncHosts(e),
        ...descriptionHostNames(e.description),
        ...descriptionHostNames(e.commandLine),
      ]),
    ),
    users: distinct([
      ...distinct(shown.flatMap(explicitUsers)).filter((n) => isPerson(n, true)),
      ...distinct(shown.flatMap(inferredUsers)).filter((n) => isPerson(n)),
    ]),
    ips: distinct(
      shown.flatMap((e) => [e.srcIp, e.dstIp, net(e)?.source?.address, net(e)?.destination?.address]),
    ),
  };
}

/**
 * The most hosts, and the most users, a chat's roster may hold (D2d). Controller ruling H5: a name is
 * NEVER evicted, because memory, chat history and case items may still carry it in clear. When a
 * search would need more names than this, the search is refused instead (roundHop.ts).
 */
export const WATSON_MASK_ROSTER_MAX = 500;

/**
 * One roster list: lower-cased, deduped, a name seen again counts as newest. Hosts and users drop
 * nothing; `keep` (IPs only, which the anonymizer also masks by pattern) drops the oldest past it.
 */
function mergeList(older: readonly string[], newer: readonly string[], keep = Infinity): string[] {
  const seen = new Set<string>();
  return [...older, ...newer]
    .map((n) => (typeof n === "string" ? n.trim().toLowerCase() : ""))
    .reverse()
    .filter((n) => n !== "" && !seen.has(n) && !!seen.add(n))
    .slice(0, keep)
    .reverse();
}

/** A new roster: `older` with `newer` folded in. Neither input is changed. */
export function mergeMaskRoster(
  older: Partial<WatsonMaskRoster> | undefined,
  newer: Partial<WatsonMaskRoster> | undefined,
): WatsonMaskRoster {
  const list = (r: Partial<WatsonMaskRoster> | undefined, k: keyof WatsonMaskRoster): string[] => {
    const v = r?.[k];
    return Array.isArray(v) ? v : [];
  };
  return {
    hosts: mergeList(list(older, "hosts"), list(newer, "hosts")),
    users: mergeList(list(older, "users"), list(newer, "users")),
    ips: mergeList(list(older, "ips"), list(newer, "ips"), WATSON_MASK_ROSTER_MAX),
  };
}

/**
 * True when folding `newer` into `older` would put more than WATSON_MASK_ROSTER_MAX hosts or users on
 * the roster. IPs are not counted: the anonymizer also masks them by pattern.
 */
export function maskRosterFull(
  older: Partial<WatsonMaskRoster> | undefined,
  newer: Partial<WatsonMaskRoster> | undefined,
): boolean {
  const merged = mergeMaskRoster(older, newer);
  return merged.hosts.length > WATSON_MASK_ROSTER_MAX || merged.users.length > WATSON_MASK_ROSTER_MAX;
}
