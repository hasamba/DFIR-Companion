import { escapeRegExp } from "./regexEscape.js";

// Username handling for the anonymizer (#1780). A victim account appears in three qualified shapes
// — DOMAIN\user, user@internal.domain and the profile segment of C:\Users\user or /home/user — and
// also BARE, in prose an analyst or the AI wrote ("the account jdoe then ran scp"). The qualified
// detectors found the first three and minted a different token for each shape, and nothing found
// the bare name, so the redacted package, the AI wire and the support bundle all carried it in
// cleartext. This module holds what the anonymizer needs to close that: the shared detector
// patterns, the guard list of ordinary words that must never be replaced globally, and the one
// regex that finds every known username as a whole word.

// DOMAIN\user — guarded so it doesn't match path segments (C:\Users\srv). Mirrors assetGraph.ts.
export const NETBIOS_ACCT =
  /(?<![\\/:.\w])([A-Za-z][A-Za-z0-9.-]{1,14})\\([A-Za-z0-9._$-]{2,20})(?![\\/\w])/g;
export const UPN_ACCT = /\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/g;
export const PATH_DOMAINS =
  /^(Users|Windows|Program|ProgramData|ProgramFiles|System|System32|AppData|Device|Temp|Documents|Desktop|Downloads)$/i;
// Capture the profile-dir prefix + the username segment; tokenize only the username.
export const USER_PATH_RE =
  /([A-Za-z]:\\Users\\|\\Users\\|\/home\/|\/Users\/|\/root\/)([^\\/\r\n"'<>|:*?]+)/g;
export const WELL_KNOWN_PROFILE =
  /^(public|default|default user|all users|administrator|admin|guest|system|systemprofile|localservice|networkservice)$/i;

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

/** True for a name that must never be replaced as a bare word (common word, too short, numeric). */
export function isGuardedUsername(name: string): boolean {
  const n = name.trim().toLowerCase();
  if (n.length < MIN_BARE_USERNAME_LENGTH) return true;
  if (/^\d+$/.test(n)) return true;
  if (/^[._$-]|[._-]$/.test(n)) return true; // an edge of punctuation cannot anchor a whole-word match
  return COMMON_USERNAME_WORDS.has(n);
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

/** One case-insensitive, whole-word, longest-first alternation of the names; null when none. */
export function usernameRegExp(names: Iterable<string>): RegExp | null {
  const list = [...new Set([...names].map((n) => n.trim()).filter((n) => n && !isGuardedUsername(n)))];
  if (list.length === 0) return null;
  list.sort((a, b) => b.length - a.length || a.localeCompare(b));
  const alternation = list.map(escapeRegExp).join("|");
  return new RegExp(`(?<![${UNICODE_WORD}])(?:${alternation})(?![${UNICODE_WORD}])`, "giu");
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

// An extracted account is noise when its domain part is a non-victim word — e.g.
// HKU\Software, BUILTIN\Administrators, NT AUTHORITY\SYSTEM, Execution\evil.exe.
export function isNoiseAccount(account: string): boolean {
  const slash = account.indexOf("\\");
  if (slash > 0) return isNoiseDomain(account.slice(0, slash));
  const at = account.indexOf("@");
  if (at > 0) return isNoiseDomain(account.slice(at + 1));
  return false;
}
