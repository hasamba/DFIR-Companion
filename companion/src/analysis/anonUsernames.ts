import { isIPv4, isIPv6 } from "node:net";
import { escapeRegExp } from "./regexEscape.js";
import { MAX_LITERAL, compileLong, nextLong, valuesCanOverlap } from "./anonChunkedMatch.js";

// Username handling for the anonymizer (#1780). A victim account appears in three qualified shapes
// — DOMAIN\user, user@internal.domain and the profile segment of C:\Users\user or /home/user — and
// also BARE, in prose an analyst or the AI wrote ("the account jdoe then ran scp"). The qualified
// detectors found the first three and minted a different token for each shape, and nothing found
// the bare name, so the redacted package, the AI wire and the support bundle all carried it in
// cleartext. This module holds what the anonymizer needs to close that: the shared detector
// patterns, the guard list of ordinary words that must never be replaced globally, and the one
// matcher that finds every known username as a whole word.

// DOMAIN\user — guarded so it doesn't match path segments (C:\Users\srv). Mirrors assetGraph.ts,
// except that a match may not start after "-" either: in \\DC-QA-01\C$ it started at "QA-01" and
// leaked the "DC-" prefix of the host name (#2073). The user half has no length cap and reads Unicode
// letters (#3049): a cap of 20 left a longer user in clear whole or its tail in clear, and an `é` ended
// the user. A qualifier may still start right after a non-ASCII letter, as before, but it is read back
// to the start of its word (replaceNetbiosAccounts): `dave élan\x` read the bogus qualifier `lan`.
export const NETBIOS_ACCT =
  /(?<![\\/:.\w-])(\p{L}[\p{L}\p{N}.-]{1,14})\\([\p{L}\p{N}._$-]{2,})(?![\\/\p{L}\p{N}_])/gu;
const WORD_BEFORE = /[\p{L}\p{N}]+$/u; // the letters and digits the pattern started behind
// The qualifier the pattern read before #3049, when it took ASCII letters only (`lan` of `élan`).
const ASCII_TAIL = /(?<![\w.-])[A-Za-z][A-Za-z0-9.-]{1,14}$/;
const QUALIFIER_TAIL = /(?<![\\/:.\w-])\p{L}[\p{L}\p{N}.-]{1,14}$/u;

// The user half the pattern read before #3049: at most 20 ASCII characters, cut where a non-word
// character followed (`bob` of `bobélan`).
const ASCII_USER = /^[A-Za-z0-9._$-]{2,20}/;
// An e-mail local part glued in front of the qualifier (`<user>@<domain><QUALIFIER>\\<user>`, #3049).
const LOCAL_BEFORE = /(?<![\w.%+@-])[A-Za-z0-9._%+-]{2,}@$/;

/** Where a qualifier that starts at `at` really starts: the start of the word it was cut from. */
function wordStart(text: string, at: number, floor: number): number {
  const run = WORD_BEFORE.exec(text.slice(Math.max(floor, at - 256), at))?.[0].length ?? 0;
  return at - run;
}

/** How the pattern read an account before #3049: the qualifier and user half it took, or null. */
export interface LegacyReading {
  qualifier: string;
  user: string | null;
}
export function legacyReading(qualifier: string, user: string): LegacyReading {
  const ascii = ASCII_USER.exec(user)?.[0] ?? "";
  let len = ascii.length;
  while (len >= 2 && len < user.length && /[\w\\/]/.test(user[len] ?? "")) len--;
  return {
    qualifier: ASCII_TAIL.exec(qualifier)?.[0] ?? qualifier,
    user: len >= 2 ? user.slice(0, len) : null,
  };
}

export interface NetbiosMatch {
  account: string; // the qualifier read whole, `\\`, the user half
  qualifier: string;
  user: string;
  local: string; // an e-mail local part glued in front, without its `@`, or ""
  after: string; // the character after the account
  cut?: boolean; // its qualifier is masked in place and never saved (a JSON-doubled account, #3067)
}
/** Replace each DOMAIN\\user account (and an e-mail local part glued in front) with `mint(match)`. */
export function replaceNetbiosAccounts(text: string, mint: (m: NetbiosMatch) => string): string {
  let out = "";
  let last = 0;
  for (const m of text.matchAll(NETBIOS_ACCT)) {
    const start = wordStart(text, m.index, last);
    const local = LOCAL_BEFORE.exec(text.slice(Math.max(last, start - 256), start))?.[0] ?? "";
    const account = text.slice(start, m.index + m[0].length);
    const slash = account.lastIndexOf("\\");
    const end = m.index + m[0].length;
    const hit = {
      account,
      qualifier: account.slice(0, slash),
      user: account.slice(slash + 1),
      after: text[end] ?? "",
    };
    out += text.slice(last, start - local.length) + mint({ ...hit, local: local.slice(0, -1) });
    last = end;
  }
  return out + text.slice(last);
}

/** The qualifier the account pattern reads at the end of `before` (the text before a `\\`), or null. */
export function freshQualifier(before: string): { qualifier: string; cut: string } | null {
  const m = QUALIFIER_TAIL.exec(before);
  const qualifier = m ? before.slice(wordStart(before, m.index, 0)) : "";
  return m ? { qualifier, cut: legacyReading(qualifier, "").qualifier } : null;
}
// A domain SID glued into a user half (`jdoe-S-1-5-21-…-1001`): the SID pass cannot read it once the
// user is a token, so the account pass gives it its own token (#3049). Text after the SID is left to
// the later passes, as the 20-character pattern left it, unless the old pattern read it all (≤ 20).
const GLUED_SID = /^(.+?)([.$-])(S-1-5-21(?:-\d{1,10}){4})(?!\d)(.*)$/is;
const OLD_USER_MAX = 20;

/** Split a user half at a glued domain SID: the user, the separator, the SID and the text after it. */
export function splitGluedSid(
  user: string,
  length = user.length,
): { user: string; sep: string; sid: string; rest: string } | null {
  const m = GLUED_SID.exec(user);
  const rest = m?.[4] ?? "";
  if (!m || (rest !== "" && length <= OLD_USER_MAX)) return null;
  return { user: m[1] ?? "", sep: m[2] ?? "", sid: m[3] ?? "", rest };
}

// The server of a UNC path (\\SERVER\share) when it is a single label — a NetBIOS name, which is
// internal naming. Dotted servers (FQDNs, IPs) are left to the host, domain and IP passes, because a
// dotted UNC server can be adversary WebDAV infrastructure that the anonymizer preserves on purpose.
// \\?\ and \\.\ device paths never match: the label must start with a letter or digit (#2073).
const UNC_SERVER_RE = /(?<![\\\w:])\\\\([A-Za-z0-9][A-Za-z0-9-]{0,62})(?=\\)/g;
const UNC_SERVER_SKIP = /^(?:localhost|tsclient|wsl|\d+)$/i;

/** Replace each single-label UNC server name with `mint(server)`, keeping the leading `\\`. */
export function replaceUncServers(text: string, mint: (server: string) => string): string {
  return text.replace(UNC_SERVER_RE, (m, server: string) =>
    UNC_SERVER_SKIP.test(server) ? m : `\\\\${mint(server)}`,
  );
}
export const UPN_ACCT = /\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/g;
export const PATH_DOMAINS =
  /^(Users|Windows|Program|ProgramData|ProgramFiles|System|System32|AppData|Device|Temp|Documents|Desktop|Downloads)$/i;
// Capture the profile-dir prefix + the username segment; tokenize only the username. The name stops
// at , the character that opens the anonymizer's IPv6 placeholder: the profile pass runs while
// each address is held aside, and a name that ran on into the placeholder broke it, so the address
// was lost and a USER value holding the private character was stored (#3000).
export const USER_PATH_RE =
  /([A-Za-z]:\\Users\\|\\Users\\|\/home\/|\/Users\/|\/root\/)([^\\/\r\n"'<>|:*?]+)/g;
export const WELL_KNOWN_PROFILE =
  /^(public|default|default user|all users|administrator|admin|guest|system|systemprofile|localservice|networkservice)$/i;
const IPV6_PLACEHOLDER_START = "";
// The anonymizer's one-way secret sentinel (SECRET_SENTINEL in anonymize.ts). It stays in the name
// class on purpose: stopping the name there put the text after the secret in clear (#3002).
const SECRET_MARK = "\uE001";
const EDGE_SPACE = /^(\s*)([\s\S]*?)(\s*)$/;

/** How a profile name is minted: a `saved` name is learned and saved as a discovery, others never. */
export type ProfileNameMint = (name: string, saved: boolean) => string;

/**
 * Replace the username of every profile path with `mint(...)`, keeping the prefix. A name an IPv6
 * placeholder cuts short ran on into it before #3000 and was tokenized whole, as a value holding the
 * private character that never matched again. So it stays a USER token even when it is a built-in
 * profile (Public, Default, …), and it is never learned or saved: a saved fragment such as "5" came
 * back as a custom value on a later call and cut a SID or an address apart. A built-in profile name
 * the path ends normally stays in clear.
 *
 * A secret inside the name ends the username there (#3002), and each part around a secret gets
 * its own USER token. No part is learned or saved: before the fix the value held the secret
 * sentinel and never matched, and a saved part could cut other text on a later call (a "5" cut a
 * SID, a ",end" masked ",end" everywhere). The sentinel stays between the parts and shows as
 * [REDACTED_SECRET]. The built-in-name check is skipped for the parts, so "Public" stays masked.
 *
 * A very short or digit-only name ("5", "12", "ab") is masked in place but never learned or saved
 * either (#3014): as a saved value it came back on a later call and cut SIDs and addresses apart.
 */
export function replaceUserPaths(
  text: string,
  mint: ProfileNameMint,
  carve?: (name: string, saved: boolean) => string | null,
): string {
  return text.replace(USER_PATH_RE, (m, prefix: string, name: string, at: number, w: string) => {
    if (name.includes(SECRET_MARK)) {
      const parts = name.split(SECRET_MARK).map((p) => mintTrimmed(p, (v) => mint(v, false)));
      return prefix + parts.join(SECRET_MARK);
    }
    const cut = w[at + m.length] === IPV6_PLACEHOLDER_START;
    if (!cut && WELL_KNOWN_PROFILE.test(name)) return m;
    const saved = !cut && !isFragmentName(name);
    return prefix + (carve?.(name, saved) ?? mint(name, saved)); // values get their own tokens (#3047)
  });
}
/** Mint a part of a split profile name, keeping its edge spaces outside the token. */
function mintTrimmed(part: string, mint: (value: string) => string): string {
  const [, lead = "", core = "", trail = ""] = EDGE_SPACE.exec(part) ?? [];
  return core ? lead + mint(core) + trail : part;
}

/** Shorter names are never replaced as bare words: "al" or "jo" would shred ordinary prose. */
export const MIN_BARE_USERNAME_LENGTH = 3;

// Account names that are also ordinary words, product names or built-in principals. A victim may
// really log on as "admin" or "backup", and the qualified forms (CORP\admin, C:\Users\backup) are
// still tokenized, but replacing the bare word everywhere would rewrite "the admin share", "test
// run" and "system log" throughout the report — the same failure NON_VICTIM_DOMAINS prevents for
// domains. "anon" and "ipv6" are here because they are fragments of the anonymizer's own tokens and
// placeholders.
export const COMMON_USERNAME_WORDS: ReadonlySet<string> = new Set([
  "admin",
  "administrator",
  "administrators",
  "root",
  "user",
  "users",
  "guest",
  "test",
  "tester",
  "testuser",
  "system",
  "service",
  "services",
  "default",
  "public",
  "backup",
  "support",
  "owner",
  "local",
  "localservice",
  "networkservice",
  "operator",
  "nobody",
  "daemon",
  "bin",
  "sys",
  "www",
  "web",
  "ftp",
  "mail",
  "sql",
  "oracle",
  "postgres",
  "mysql",
  "ubuntu",
  "debian",
  "centos",
  "vagrant",
  "docker",
  "git",
  "dev",
  "demo",
  "temp",
  "tmp",
  "sa",
  "krbtgt",
  "anonymous",
  "everyone",
  "authority",
  "builtin",
  "domain",
  "workgroup",
  "server",
  "client",
  "desktop",
  "home",
  "office",
  "info",
  "sales",
  "security",
  "helpdesk",
  "scanner",
  "printer",
  "anon",
  "ipv6",
]);

/** True for a name too short or all digits: it would match inside SIDs, addresses and numbers. */
export function isFragmentName(name: string): boolean {
  const n = name.trim();
  return n.length < MIN_BARE_USERNAME_LENGTH || /^\d+$/.test(n);
}

/** True for a name that must never be replaced as a bare word (common word, too short, numeric). */
export function isGuardedUsername(name: string): boolean {
  const n = name.trim().toLowerCase();
  if (isFragmentName(n)) return true;
  if (/^[._$-]|[._-]$/.test(n)) return true; // an edge of punctuation cannot anchor a whole-word match
  return COMMON_USERNAME_WORDS.has(n);
}

/**
 * #2056: the first label of every dotted host (DC-QA-01 from DC-QA-01.sub.example), so the short
 * name, the machine account (DC-QA-01$) and a truncated FQDN are tokenized like the FQDN itself.
 * A label the username guard rejects (server, www, numeric — an IPv4 asset) or one equal to an
 * internal domain is skipped: tokenizing it would mask common words or fight the domain pass.
 */
export function shortHostLabels(hosts: Iterable<string>, internalDomains: Iterable<string>): string[] {
  const domains = new Set([...internalDomains].map((d) => d.toLowerCase()));
  const out = new Set<string>();
  for (const h of hosts) {
    const dot = h.indexOf(".");
    if (dot <= 0) continue;
    const label = h.slice(0, dot);
    if (isGuardedUsername(label) || domains.has(label.toLowerCase())) continue;
    out.add(label);
  }
  return [...out];
}

/** The user half of "DOMAIN\user" or "user@domain"; the value itself when neither. */
export function bareUsername(account: string): string {
  const slash = account.lastIndexOf("\\");
  if (slash >= 0) return account.slice(slash + 1);
  const at = account.indexOf("@");
  return at > 0 ? account.slice(0, at) : account;
}

/** Every non-well-known profile-path username in the text (C:\Users\x, /home/x, /Users/x, /root/x). */
export function profilePathUsernames(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(USER_PATH_RE)) {
    const name = m[2].trim();
    if (name && !WELL_KNOWN_PROFILE.test(name)) out.push(name);
  }
  return out;
}

export interface UsernameSources {
  /** Free text to scan: event descriptions and paths, finding text, IOC values. */
  texts: Iterable<string>;
  /** The account extractor (assetGraph.extractAccounts) — injected so this module stays a leaf. */
  accountsOf: (text: string) => string[];
  /** The case's internal domains. Only a UPN on one of these names a victim user. */
  internalDomains: readonly string[];
}

/**
 * The victim usernames the case names in a qualified shape, for the bare-name pass. A UPN on a
 * third-party domain (attacker@evil.example) is an email address, not a victim account, so its local
 * part is not collected. Guarded words are dropped. Lowercased, deduplicated, sorted longest-first.
 */
export function collectUsernames(src: UsernameSources): string[] {
  const internal = src.internalDomains.map((d) => d.toLowerCase());
  const isInternal = (d: string) => internal.some((kd) => d === kd || d.endsWith("." + kd));
  const names = new Set<string>();
  const add = (n: string) => {
    if (!isGuardedUsername(n)) names.add(n.trim().toLowerCase());
  };
  for (const text of src.texts) {
    if (typeof text !== "string" || !text) continue;
    for (const acct of src.accountsOf(text)) {
      if (isNoiseAccount(acct)) continue; // registry hive / Windows principal / tactic folder
      const at = acct.indexOf("@");
      if (!acct.includes("\\") && at > 0 && !isInternal(acct.slice(at + 1).toLowerCase())) continue;
      add(bareUsername(acct));
    }
    for (const n of profilePathUsernames(text)) add(n);
  }
  return [...names].sort((a, b) => b.length - a.length || a.localeCompare(b));
}

// Same boundary rule as anonymize.ts exactValueRegExp: the neighbour must not be a letter, number
// or "_" in any script, so "jdoe" never fires inside "jdoes", "xjdoe" or an ANON_USER_n token.
const UNICODE_WORD = "\\p{L}\\p{N}_";

/**
 * `joined` is set when the span joins overlapping learned names (#3010): those are what is saved.
 * Returning null for a joined span refuses the join: the first name is replaced alone and the scan
 * goes on after it, as it did before #3010.
 */
export type NameReplacer = (m: string, offset: number, whole: string, joined?: string[]) => string | null;
/** Usable as the first argument of String.replace, like the RegExp it stands in for. */
export interface UsernameMatcher {
  [Symbol.replace](text: string, fn: NameReplacer): string;
}
type Span = [number, number];
const WORD_CHAR = /[\p{L}\p{N}_]/u;

// #3070: a name glued to an address that starts with a digit and is never masked ("jdoe0::2") was no
// whole word, so it went out in clear. A digit may follow a name when what starts there is a whole
// address (IPv6, or a dotted-quad IPv4) and no letter, digit or "_" follows it. Any other digit after
// a name (a year, a version, a time, "jdoe0") still leaves it alone: it may be another account.
const ADDRESS_RUN = /[0-9A-Fa-f:.]+/y;
const IPV4_HEAD = /(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9]|\.[0-9])/y;

/** True when a name ending at text[end] ends there: no word character, or a whole glued address. */
function endsName(text: string, end: number): boolean {
  if (!/[0-9]/.test(text[end] ?? "")) return true; // the matcher's boundary held already
  IPV4_HEAD.lastIndex = end;
  const v4 = IPV4_HEAD.exec(text)?.[0];
  if (v4 && isIPv4(v4) && !WORD_CHAR.test(text[end + v4.length] ?? "")) return true;
  ADDRESS_RUN.lastIndex = end;
  const run = ADDRESS_RUN.exec(text)?.[0] ?? "";
  const v6 = isIPv6(run) ? run : run.replace(/[.:]+$/, "");
  return isIPv6(v6) && !WORD_CHAR.test(text[end + v6.length] ?? "");
}

/** A case-insensitive, whole-word, longest-first matcher of the names; null when none. */
export function usernameMatcher(names: Iterable<string>): UsernameMatcher | null {
  const list = [...new Set([...names].map((n) => n.trim()).filter((n) => n && !isGuardedUsername(n)))];
  if (list.length === 0) return null;
  list.sort((a, b) => b.length - a.length || a.localeCompare(b));
  const short = list.filter((n) => n.length <= MAX_LITERAL);
  const long = list.filter((n) => n.length > MAX_LITERAL).map(compileLong); // #3007
  const re = short.length
    ? new RegExp(
        `(?<![${UNICODE_WORD}])(?:${short.map(escapeRegExp).join("|")})(?:(?![${UNICODE_WORD}])|(?=[0-9]))`,
        "giu",
      )
    : null;
  if (re && long.length === 0 && !valuesCanOverlap(list))
    return {
      [Symbol.replace]: (text, fn) =>
        text.replace(re, (m: string, at: number) =>
          endsName(text, at + m.length) ? (fn(m, at, text) ?? m) : m,
        ),
    };
  // The leftmost match wins, the longest on a tie, and the scan resumes at its end: what the single
  // alternation did before a long name had to leave it.
  const next = (text: string, from: number): Span | null => {
    let best: Span | null = null;
    const offer = (c: Span | null) => {
      if (c && (!best || c[0] < best[0] || (c[0] === best[0] && c[1] > best[1]))) best = c;
    };
    if (re) {
      re.lastIndex = from;
      let m = re.exec(text);
      while (m && !endsName(text, m.index + m[0].length)) ((re.lastIndex = m.index + 1), (m = re.exec(text)));
      offer(m ? [m.index, m.index + m[0].length] : null);
    }
    for (const ln of long) offer(nextLong(text, ln, from));
    return best;
  };
  // True when the part of `o` past `end` holds no letter, digit or "_" that the next match (which the
  // scan emits anyway) leaves out: then the span is not widened and the tokens stay what they were.
  const tailCovered = (text: string, o: Span, end: number): boolean => {
    if (o[1] <= end) return true;
    const w = text.slice(end, o[1]).search(WORD_CHAR);
    const n = w < 0 ? null : next(text, end);
    return w < 0 || (!!n && n[0] <= end + w && n[1] >= o[1]);
  };
  return {
    [Symbol.replace](text: string, fn: NameReplacer): string {
      let out = "";
      let at = 0;
      for (let m = next(text, 0); m;) {
        // #3010: a learned name that starts inside this match and runs past it joins the span, or its
        // tail would go out in clear ("ann bob" + "bob carol dave" in "ann bob carol dave").
        const span: Span = [m[0], m[1]];
        const joined = [m];
        let o = next(text, m[0] + 1);
        for (; o && o[0] < span[1]; o = next(text, o[0] + 1)) {
          if (tailCovered(text, o, span[1])) continue;
          span[1] = o[1];
          joined.push(o);
        }
        const names = joined.length > 1 ? joined.map(([s, e]) => text.slice(s, e)) : undefined;
        const run = names ? fn(text.slice(span[0], span[1]), span[0], text, names) : null;
        const end = run === null ? m[1] : span[1];
        out +=
          text.slice(at, m[0]) + (run ?? fn(text.slice(m[0], m[1]), m[0], text) ?? text.slice(m[0], m[1]));
        at = end;
        m = run === null && names ? next(text, end) : o; // the first match at or after the span's end
      }
      return out + text.slice(at);
    },
  };
}

/**
 * Mint every bare-name match, except the user half of a suppressed account and a label inside an
 * untokenized URL or dotted host. `mint` gets the names a joined run is made of (#3010).
 */
export function replaceBareNames(
  text: string,
  matcher: UsernameMatcher,
  suppressed: ReadonlySet<string>,
  mint: (m: string, joined?: string[]) => string,
  ended: (result: string, value: string, at: number, end: number, text: string) => string = (r) => r,
): string {
  let spans: Span[] | undefined; // computed once, only when a name matches
  return matcher[Symbol.replace](text, (m, offset, whole, joined) => {
    // A joined run that would stay text is not joined: the first name alone gets these checks.
    if (joined && suppressed.has(m.toLowerCase())) return null;
    spans ??= preservedSpans(whole);
    const keep =
      insideSuppressedAccount(whole, offset, joined?.[0] ?? m, suppressed) ||
      strictlyInside(spans, offset, m.length);
    // A token before a glued address's digit keeps a delimiter, or it reads back as another (#3070, #2992).
    return !keep ? ended(mint(m, joined), m, offset, offset + m.length, whole) : joined ? null : m;
  });
}

// A URL or a dotted host name that no earlier pass tokenized is not a known victim value, so it is
// most likely adversary infrastructure — which the redacted export promises to keep intact. A
// victim username that happens to be one label of it ("jdoe.evil.example", ".../u/jdoe/payload")
// must not be rewritten, or the recipient receives an indicator that blocks nothing.
const URL_SPAN = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()]+/gi;
const HOST_SPAN = /(?<![\p{L}\p{N}_.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z][A-Za-z0-9-]{1,62}(?![\p{L}\p{N}_-])/gu;
const ANY_TOKEN = /ANON_[A-Z]+_\d+/;

/** The [start, end) spans of untokenized URLs and dotted host names in the text. */
export function preservedSpans(text: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  for (const re of [URL_SPAN, HOST_SPAN]) {
    for (const m of text.matchAll(re)) {
      if (!ANY_TOKEN.test(m[0])) spans.push([m.index, m.index + m[0].length]);
    }
  }
  return spans;
}

/** True when [offset, offset+length) sits strictly inside one span (a label, not the whole span). */
export function strictlyInside(spans: Array<[number, number]>, offset: number, length: number): boolean {
  return spans.some(([s, e]) => offset >= s && offset + length <= e && e - s > length);
}

/**
 * True when the bare name at `offset` is the user half of a qualified account the analyst suppressed
 * ("CORP\jdoe" or "jdoe@corp.example" in the suppressed list). The whole account was left verbatim
 * by the account pass, and the bare-name pass must not reach inside it and tokenize half of it.
 */
export function insideSuppressedAccount(
  text: string,
  offset: number,
  name: string,
  suppressed: ReadonlySet<string>,
): boolean {
  if (suppressed.size === 0) return false;
  const before = /([A-Za-z][A-Za-z0-9.-]{1,14})\\$/.exec(text.slice(Math.max(0, offset - 16), offset));
  if (before && suppressed.has(`${before[1]}\\${name}`.toLowerCase())) return true;
  const after = /^@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/.exec(text.slice(offset + name.length));
  return !!after && suppressed.has(`${name}@${after[1]}`.toLowerCase());
}

// Tokens that LOOK like a "DOMAIN\user" or "host.domain" but are NEVER a victim/customer
// domain. extractAccounts()'s DOMAIN\user regex has three big false-positive sources, and
// deriveKnownEntities() would otherwise promote each to an "internal domain": registry hives
// (HKU\Software), Windows well-known principals (BUILTIN\…, NT AUTHORITY\…, FONT DRIVER HOST\…),
// and EVTX-ATTACK-SAMPLES-style tactic folders (Execution\…, Persistence\…). Promoting them is
// doubly harmful: it pollutes the analyst's anonymization list AND, because anonDomains() does a
// word-boundary replace, it tokenizes these ultra-common words ("access", "code", "files",
// "execution") throughout the timeline — wrecking the text the model reads. All single-label,
// lowercase. A dotted FQDN (windomain.local) is always treated as a real domain and kept.
export const NON_VICTIM_DOMAINS: ReadonlySet<string> = new Set([
  // Windows well-known principals / NETBIOS authorities (the DOMAIN half of e.g. BUILTIN\Administrators)
  "nt",
  "authority",
  "service",
  "builtin",
  "workgroup",
  "virtual",
  "machine",
  "iis",
  "apppool",
  "window",
  "manager",
  "font",
  "driver",
  "host",
  "dwm",
  "umfd",
  "everyone",
  "system",
  "owner",
  "creator",
  // Registry hives (HKU\Software → "hku")
  "hku",
  "hklm",
  "hkcu",
  "hkcr",
  "hkcc",
  "hkey_users",
  "hkey_local_machine",
  "hkey_current_user",
  "hkey_classes_root",
  "hkey_current_config",
  // Bare single-label LAN suffixes (a 2-label host like dc.local would otherwise add "local")
  "local",
  "localdomain",
  "lan",
  "home",
  // MITRE ATT&CK tactics — the EVTX-ATTACK-SAMPLES folder names that keep getting mis-parsed
  "reconnaissance",
  "resource",
  "development",
  "initial",
  "access",
  "execution",
  "persistence",
  "privilege",
  "escalation",
  "defense",
  "evasion",
  "credential",
  "discovery",
  "lateral",
  "movement",
  "collection",
  "command",
  "control",
  "exfiltration",
  "impact",
  "tactics",
  "techniques",
  "mitre",
  "attack",
  // Common tool / process / generic folder names that get mis-parsed as a DOMAIN
  "defender",
  "explorer",
  "vgauth",
  "ransomware",
  "malware",
  "samples",
  "results",
  "tools",
  "setup",
  "files",
  "hours",
  "global",
  "launch",
  "layers",
  "code",
  "jobs",
  "lite",
  "csv",
  "zip",
  "logs",
  "temp",
  "data",
  "output",
  "report",
  "reports",
  "evidence",
  "downloads",
  "desktop",
  "documents",
  "users",
  "public",
  "default",
  "windows",
  "programdata",
  "program",
  "system32",
  "appdata",
]);

// A single-label token is "noise" when it's a known non-victim word; a dotted FQDN is kept.
export function isNoiseDomain(domain: string): boolean {
  const d = domain.toLowerCase().trim();
  if (!d) return true;
  if (d.includes(".")) return false; // real FQDN (windomain.local) — always keep
  return NON_VICTIM_DOMAINS.has(d);
}

/** Noise as the account pattern read it before #3049, too: `élan\\x` is noise because `lan\\x` was. */
export function isLegacyNoiseAccount(account: string): boolean {
  const slash = account.lastIndexOf("\\");
  const cut = slash > 0 ? legacyReading(account.slice(0, slash), "").qualifier : "";
  return isNoiseAccount(account) || (cut !== "" && isNoiseDomain(cut));
}

// An extracted account is noise when its domain part is a non-victim word — e.g.
// HKU\Software, BUILTIN\Administrators, NT AUTHORITY\SYSTEM, Execution\evil.exe.
export function isNoiseAccount(account: string): boolean {
  const slash = account.indexOf("\\");
  if (slash > 0) return isNoiseDomain(account.slice(0, slash));
  const at = account.indexOf("@");
  if (at > 0) return isNoiseDomain(account.slice(at + 1));
  return false;
}
