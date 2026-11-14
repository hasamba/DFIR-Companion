import type { ForensicEvent } from "../../stateTypes.js";

// The masking roster for Watson's super-timeline rows (D2d). These rows are raw-only, so the case
// anonymizer has never seen their names: every name superRow prints in clear must be listed here so
// masking can replace it. IPs are listed too, although the anonymizer also matches them by pattern.
// Over-listing costs a masked token; under-listing sends a real name to the model.

/** Names the shown rows carry, handed to masking as known entities. */
export interface WatsonMaskRoster {
  hosts: string[];
  users: string[];
  ips: string[];
}

// `\Users\<name>\` or `/home/<name>/`: a name ended by a separator may hold spaces ("John Smith");
// one at the end of the text is taken up to the first whitespace (a command's next argument).
const USER_SEGMENT = /[\\/](?:users|home)[\\/](?:([^\\/"'|:<>\r\n]+?)(?=[\\/])|([^\\/"'|:<>\s]+))/gi;
// `\\host\share`, `psexec \\dc02`. Device paths (`\\?\`, `\\.\`) start with no letter or digit.
const UNC_HOST = /\\\\([a-z0-9][a-z0-9.-]*[a-z0-9]|[a-z0-9])/gi;
const SLASH_USER = /\/user:(?:"([^"]+)"|([^\s"]+))/gi;
const DASH_USER = /(?:^|\s)(?:-u\s+|--user(?:\s+|=))(?:"([^"]+)"|([^\s"]+))/gi;
const DOMAIN_USER = /(?<![\\\w:.$/-])([a-z][\w-]{0,14})\\([a-z][\w.$-]{0,63})(?![\\\w])/gi;
const EMAIL_USER = /(?<![\w.-])([\w.-]+)@[\w-]+(?:\.[\w-]+)+/gi;
const FILE_LIKE = /\.(exe|dll|sys|ps1|psm1|bat|cmd|vbs|js|hta|txt|log|dat|tmp|zip|7z|rar|ini|lnk|msi)$/i;
const WORD = /^[\p{L}\p{N}._$-]{2,}$/u;

const groups = (text: string, re: RegExp): string[] =>
  [...text.matchAll(re)].map((m) => (m[1] ?? m[2] ?? "").trim()).filter(Boolean);

/** A name and each of its words, so a multi-word name is masked whole and in pieces. */
const withWords = (name: string): string[] => [
  name,
  ...name.split(/\s+/).filter((w) => w !== name && WORD.test(w) && !w.startsWith("-")),
];

/** `DOMAIN\user` as the whole spelling plus the bare user; anything else as it is. */
const withBareUser = (name: string): string[] => {
  const cut = name.lastIndexOf("\\");
  return cut > 0 && cut < name.length - 1 ? [name, name.slice(cut + 1)] : [name];
};

function domainUsers(cmd: string): string[] {
  return [...cmd.matchAll(DOMAIN_USER)]
    .filter((m) => !FILE_LIKE.test(m[2]))
    .flatMap((m) => [`${m[1]}\\${m[2]}`, m[2]]);
}

/** Accounts a command names: `/user:X`, `-u X`, `--user X`, `DOMAIN\user`, `user@domain`. */
function commandUsers(cmd: string | undefined): string[] {
  if (!cmd) return [];
  const flagged = [...groups(cmd, SLASH_USER), ...groups(cmd, DASH_USER)].flatMap(withBareUser);
  return [...flagged, ...domainUsers(cmd), ...groups(cmd, EMAIL_USER)];
}

const printed = (e: ForensicEvent): string[] =>
  [e.path, e.commandLine, e.description].filter((s): s is string => !!s);

const pathUsers = (e: ForensicEvent): string[] =>
  printed(e).flatMap((s) => groups(s, USER_SEGMENT).flatMap(withWords));

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
        ...pathUsers(e),
        ...commandUsers(e.commandLine),
      ]),
    ),
    ips: distinct(
      shown.flatMap((e) => [e.srcIp, e.dstIp, net(e)?.source?.address, net(e)?.destination?.address]),
    ),
  };
}
