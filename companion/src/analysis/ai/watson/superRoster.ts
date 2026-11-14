import type { ForensicEvent } from "../../stateTypes.js";

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
/** Words a multi-word profile name is not split into. */
const COMMON_WORDS = new Set([
  "the",
  "and",
  "for",
  "admin",
  "user",
  "users",
  "local",
  "default",
  "public",
  "test",
  "temp",
  "new",
  "old",
  "backup",
  "service",
  "system",
  "owner",
  "guest",
  "home",
]);

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
  const fromPath = e.path ? groups(e.path, PATH_USER).flatMap(withNameWords) : [];
  const text = [e.commandLine, e.description].filter((s): s is string => !!s);
  const quoted = text.flatMap((s) => groups(s, QUOTED_PATH)).flatMap((q) => groups(q, PATH_USER));
  return [...fromPath, ...quoted, ...text.flatMap((s) => groups(s, TEXT_USER))];
}

const programOf = (part: string): string =>
  (part.trim().split(/\s+/)[0] ?? "")
    .replace(/^.*[\\/]/, "")
    .replace(/\.exe$/i, "")
    .toLowerCase();

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
  (UPPER_DOMAIN.test(d) || DOTTED_DOMAIN.test(d)) && !KNOWN_FOLDERS.has(d.toLowerCase());

function domainUsers(cmd: string): string[] {
  return [...cmd.matchAll(DOMAIN_USER)]
    .filter((m) => isDomain(m[1]) && looksLikeAccount(m[2]))
    .flatMap((m) => [`${m[1]}\\${m[2]}`, m[2]]);
}

/** Accounts a command names: account flags of known programs, `DOMAIN\user`, `user@domain`. */
function commandUsers(cmd: string | undefined): string[] {
  if (!cmd) return [];
  const flagged = cmd.split(/[&|;]+/).flatMap((part) => {
    const program = programOf(part);
    return ACCOUNT_PROGRAMS.has(program)
      ? groups(part, ACCOUNT_FLAG).flatMap((v) => accountForms(v, program))
      : [];
  });
  return [...flagged, ...domainUsers(cmd), ...groups(cmd, EMAIL_USER)];
}

const printed = (e: ForensicEvent): string[] =>
  [e.path, e.commandLine, e.description].filter((s): s is string => !!s);

const uncHosts = (e: ForensicEvent): string[] => printed(e).flatMap((s) => groups(s, UNC_HOST));

const distinct = (xs: readonly (string | undefined)[]): string[] => [
  ...new Set(xs.filter((x): x is string => !!x && !!x.trim()).map((x) => x.trim())),
];

/** Every host, account, user-folder name and IP the shown rows print. */
export function rosterOf(shown: readonly ForensicEvent[]): WatsonMaskRoster {
  const net = (e: ForensicEvent) => e.canonical?.network;
  return {
    hosts: distinct(
      shown.flatMap((e) => [
        e.asset,
        e.assetRecord,
        net(e)?.source?.hostname,
        net(e)?.destination?.hostname,
        ...uncHosts(e),
      ]),
    ),
    users: distinct(
      shown.flatMap((e) => [
        e.canonical?.account?.name,
        e.callerName,
        ...folderUsers(e),
        ...commandUsers(e.commandLine),
      ]),
    ),
    ips: distinct(
      shown.flatMap((e) => [e.srcIp, e.dstIp, net(e)?.source?.address, net(e)?.destination?.address]),
    ),
  };
}
