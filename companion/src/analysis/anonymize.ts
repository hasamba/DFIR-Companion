import type { InvestigationState } from "./stateTypes.js";
import { extractAccounts } from "./assetGraph.js";
import { embeddedIpv4 } from "./iocValue.js";

// Reversible anonymization of the TEXT sent to the LLM. Real values stay in state; only the
// wire is tokenized. Typed numbered tokens keep the model's semantic understanding (it still
// knows ANON_HOST_1 is a host) and within-call correlation (same value → same token). Restore
// walks the model's PARSED JSON response (not the raw string) so real values containing JSON
// metacharacters — e.g. a Windows path's backslashes — never corrupt parsing.

export type AnonCategory = "IP" | "EMAIL" | "USER" | "HOST" | "DOMAIN" | "PATH" | "CMD" | "REG";

// OTHER and EXTIP are token-only: they never appear in the per-case `categories` toggle map.
// EXTIP is produced by the IP detector when maskPublicIps is on, so a public address stays
// distinguishable from an internal one in the token the model reads.
export type AnonTokenCategory = AnonCategory | "OTHER" | "EXTIP";

// The single source of truth for every category assign() can mint. Declaring it as a
// Record<AnonTokenCategory, true> makes TypeScript reject any new union member that is not
// listed here — which is what stops a new category from silently failing to restore.
const TOKEN_CATEGORY_KEYS: Record<AnonTokenCategory, true> = {
  IP: true, EXTIP: true, EMAIL: true, USER: true, HOST: true,
  DOMAIN: true, PATH: true, CMD: true, REG: true, OTHER: true,
};

export const ALL_TOKEN_CATEGORIES = Object.keys(TOKEN_CATEGORY_KEYS) as readonly AnonTokenCategory[];

// Longest-first so no category can be shadowed by another that is a prefix of it.
const TOKEN_ALTERNATION = [...ALL_TOKEN_CATEGORIES].sort((a, b) => b.length - a.length).join("|");
const TOKEN_RE = new RegExp(`ANON_(?:${TOKEN_ALTERNATION})_\\d+`, "gi");

/** True when the whole string is a single anonymization token. Used to drop Presidio findings
 *  that fired on a token rather than on real text. Builds a fresh non-global regex per call so
 *  it never shares lastIndex state with TOKEN_RE. */
export function isAnonToken(s: string): boolean {
  return new RegExp(`^ANON_(?:${TOKEN_ALTERNATION})_\\d+$`, "i").test(s.trim());
}

export interface CustomEntity {
  value: string;
  category: AnonTokenCategory;
}

export interface AnonPolicy {
  enabled: boolean;
  categories: Record<AnonCategory, boolean>;
  redactSecrets: boolean;
  // When true, PUBLIC addresses are tokenized as ANON_EXTIP_n as well. True on the AI wire
  // (nothing about an address is asked of the model, and restore() puts it back). False for
  // the redacted export, where the recipient needs adversary infrastructure to stay actionable.
  maskPublicIps: boolean;
}

// Known victim entities derived from the case, used for high-precision exact-match tokenizing
// of things regex can't reliably find (usernames, hostnames) and to decide which domains/UPNs
// are "internal" (tokenize) vs third-party/adversary (preserve).
export interface KnownEntities {
  hosts: string[];          // victim hostnames / FQDNs (longest-first)
  accounts: string[];       // DOMAIN\user or user@domain
  internalDomains: string[]; // AD/email domains to tokenize (lowercased, longest-first)
  custom?: CustomEntity[];   // analyst-added + auto-discovered exact-match entities (tokenized when enabled)
  // Values the analyst REMOVED from auto-discovery (lowercased). Never tokenized — even when a
  // pattern would match — so removing a false positive (e.g. a mis-matched path) actually stops it
  // being redacted. Checked at the single assign() chokepoint, so it covers every matcher.
  suppressed?: string[];
}

export interface Anonymizer {
  apply(text: string): string;
  restore(text: string): string;
  restoreDeep<T>(value: T): T;
  // The entities this anonymizer tokenized so far (across apply() calls), with their category —
  // used to feed OCR-discovered entities back into the case's auto-discovery list. Never includes
  // one-way secrets (those are redacted to a placeholder, not minted as a reversible token).
  discoveries(): CustomEntity[];
}

export const SECRET_PLACEHOLDER = "[REDACTED_SECRET]";

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// RFC1918 + loopback + link-local + CGNAT = "internal/victim" IPv4s we tokenize as ANON_IP_n.
// A public IP is frequently adversary C2 — classification here is unchanged by maskPublicIps;
// it's the CALLER (anonIps in createAnonymizer) that decides whether a non-internal address is
// tokenized as ANON_EXTIP_n (AI wire) or left visible (redacted export), never this function.
export function isInternalIp(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if ([a, b, Number(m[3]), Number(m[4])].some((n) => n > 255)) return false;
  if (a === 10 || a === 127) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  return false;
}

// IPV4_RE is a DETECTOR, not a validator — \d{1,3} happily matches 999. Before treating a
// non-internal match as an address worth masking, require four in-range octets and exclude
// ranges that are never adversary infrastructure. This also spares the most common collision:
// four-part software version strings such as "1.0.0.0" still match the regex, so anything we
// can rule out structurally is worth ruling out.
export function isMaskableIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  if (nums[0] === 0) return false;     // 0.0.0.0/8 "this network"
  if (nums[0] >= 224) return false;    // 224/4 multicast, 240/4 reserved, 255.255.255.255 broadcast
  return true;
}

// IPv6: loopback, unique-local (fc00::/7), link-local (fe80::/10), IPv4-mapped/compatible
// (::ffff:x.x.x.x or its hex-canonicalized form). As with isInternalIp(), classification here is
// unchanged by maskPublicIps — the caller decides whether a non-internal address becomes
// ANON_EXTIP_n or stays visible. The mapped/compatible check delegates extraction to iocValue.ts's
// embeddedIpv4() rather than re-deriving it here: a naive dotted-decimal-only regex misses the
// hex-canonical spelling (e.g. "::ffff:127.0.0.1" as "::ffff:7f00:1") — a check that only
// recognizes the dotted form would let a victim's internal IPv6 address in that spelling reach
// the external AI provider unredacted. Classification still uses isInternalIp() (not
// iocValue.ts's isPrivateIpv4) so the CGNAT range stays covered here.
export function isInternalIpv6(ip: string): boolean {
  const lower = ip.toLowerCase().replace(/^\[|\]$/g, "");
  if (lower === "::1" || lower === "::") return true;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique-local fc00::/7
  if (/^fe[89ab][0-9a-f]?:/i.test(lower)) return true;               // link-local fe80::/10
  const mapped = embeddedIpv4(lower);
  if (mapped && isInternalIp(mapped)) return true;
  return false;
}

// Match full and compressed IPv6 addresses. Not a validator — a detector for anonymization.
// Handles full (a:b:c:d:e:f:g:h), compressed (::), and IPv4-mapped (::ffff:x.x.x.x).
// Trailing \b (mirroring IPV4_RE's own boundary on both ends) matters now that a non-internal
// match can be REPLACED rather than returned unchanged: without it, this alternation's bare
// "::" + trailing-hex-group branch can run right into the start of an already-minted ANON_IP_n
// token left behind by the IPV4 pass (e.g. "::ffff:ANON_IP_1" — "ffff:A" reads as valid hex),
// silently corrupting that token. \b after the match forbids stopping mid-word like that.
const IPV6_RE = /(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,6}::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}?|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,5}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,6}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,7}|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}|::ffff(?::\d{1,3}){3}|::ffff:\d{1,3}(?:\.\d{1,3}){3})\b/gi;

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
// DOMAIN\user — guarded so it doesn't match path segments (C:\Users\srv). Mirrors assetGraph.ts.
const NETBIOS_ACCT = /(?<![\\/:.\w])([A-Za-z][A-Za-z0-9.-]{1,14})\\([A-Za-z0-9._$-]{2,20})(?![\\/\w])/g;
const UPN_ACCT = /\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/g;
const PATH_DOMAINS = /^(Users|Windows|Program|ProgramData|ProgramFiles|System|System32|AppData|Device|Temp|Documents|Desktop|Downloads)$/i;

// Private-key blocks in every armor this is likely to meet: PEM (RSA / EC / DSA / OPENSSH /
// ENCRYPTED PKCS#8 / bare PKCS#8), the PGP form (which ends "PRIVATE KEY BLOCK", not "PRIVATE KEY"),
// and the SSH2 export form ("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----" — four dashes, inner spaces).
//
// The trailing alternation is the point. A key spilled into a log is exactly where the tail gets
// TRUNCATED, and demanding a matching END delimiter would then redact NOTHING at all — the whole
// body would go to the model in cleartext. When no END is found we fall back to the base64 body, so
// the key material still goes. Both branches are length-bounded (a 4096-bit RSA PEM is ~3.2 KB):
// that bounds the over-redaction a stray header can cause, and it keeps the scan linear, since an
// unbounded lazy scan re-walks the rest of the input for EVERY begin marker.
const PEM_PRIVATE_KEY =
  /-{4,5} ?BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)? ?-{4,5}(?:[\s\S]{0,8192}?-{4,5} ?END [A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)? ?-{4,5}|[A-Za-z0-9+/=\s]{0,8192})/g;

export function createAnonymizer(policy: AnonPolicy, known: KnownEntities): Anonymizer {
  const toToken = new Map<string, string>();  // "CAT:reallower" -> token
  const toReal = new Map<string, string>();   // token (UPPER) -> real value
  const counters: Record<string, number> = {};
  // Values the analyst removed from auto-discovery — never tokenize them (leave as-is), even when
  // a pattern matches. The check sits in assign(), the single point every matcher funnels through.
  const suppressed = new Set((known.suppressed ?? []).map((s) => s.toLowerCase()));

  function assign(category: AnonTokenCategory, real: string): string {
    if (suppressed.has(real.toLowerCase())) return real; // suppressed → keep the real value verbatim
    const key = `${category}:${real.toLowerCase()}`;
    const existing = toToken.get(key);
    if (existing) return existing;
    counters[category] = (counters[category] ?? 0) + 1;
    const token = `ANON_${category}_${counters[category]}`;
    toToken.set(key, token);
    toReal.set(token, real);
    return token;
  }

  // Every (real value, category) this anonymizer minted a token for. Secrets never appear here —
  // redactSecrets() replaces them with a placeholder rather than calling assign().
  function discoveries(): CustomEntity[] {
    const out: CustomEntity[] = [];
    const seen = new Set<string>();
    for (const [token, real] of toReal) {
      const cat = (/^ANON_([A-Z]+)_\d+$/.exec(token)?.[1] ?? "OTHER") as AnonTokenCategory;
      const key = `${cat}:${real.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ value: real, category: cat });
    }
    return out;
  }

  // ── detectors (filled in across later tasks; order is fixed in apply()) ──
  function redactSecrets(t: string): string {
    let out = t;
    // key/value credentials: keep the key name, redact the value.
    out = out.replace(
      /\b(password|passwd|pwd|secret|api[_-]?key|apikey|token|authorization|bearer)\b(\s*[:=]\s*)(?:bearer\s+|basic\s+)?["']?([^\s"'<>,;]{3,})/gi,
      (_m, k: string, sep: string) => `${k}${sep}${SECRET_PLACEHOLDER}`,
    );
    // URL userinfo password (scheme://user:pass@host) — redact just the password.
    out = out.replace(/([a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)([^\s:@/]+)(@)/gi, (_m, a: string, _pw: string, c: string) => `${a}${SECRET_PLACEHOLDER}${c}`);
    // Distinctive fixed-shape secrets. NOTE: deliberately NO generic high-entropy rule — it
    // would clobber hashes (which we must keep as IOCs).
    const fixed: RegExp[] = [
      /\bAKIA[0-9A-Z]{16}\b/g,                                                   // AWS access key id
      /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b/g,         // JWT
      /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,                                         // GitHub tokens
      /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,                                       // Slack tokens
      PEM_PRIVATE_KEY,                                                           // PEM/PGP/SSH2 private keys
    ];
    for (const re of fixed) out = out.replace(re, SECRET_PLACEHOLDER);
    return out;
  }
  function isInternalDomain(domain: string): boolean {
    const d = domain.toLowerCase();
    return known.internalDomains.some((kd) => d === kd || d.endsWith("." + kd));
  }
  function anonAccounts(t: string): string {
    let out = t.replace(NETBIOS_ACCT, (m, dom: string, user: string) =>
      PATH_DOMAINS.test(dom) ? m : assign("USER", `${dom}\\${user}`));
    // Only UPNs on an internal domain are AD accounts → USER. Others stay for anonEmails.
    out = out.replace(UPN_ACCT, (m) => {
      const domain = m.split("@")[1] ?? "";
      return isInternalDomain(domain) ? assign("USER", m) : m;
    });
    return out;
  }
  const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+(?:\.[A-Za-z]{2,}|\.xn--[A-Za-z0-9-]+)\b/g;
  function anonEmails(t: string): string {
    return t.replace(EMAIL_RE, (m) => assign("EMAIL", m));
  }
  // Capture the profile-dir prefix + the username segment; tokenize only the username.
  const USER_PATH_RE = /([A-Za-z]:\\Users\\|\\Users\\|\/home\/|\/Users\/|\/root\/)([^\\/\r\n"'<>|:*?]+)/g;
  const WELL_KNOWN_PROFILE = /^(public|default|default user|all users|administrator|admin|guest|system|systemprofile|localservice|networkservice)$/i;
  function anonUserPaths(t: string): string {
    return t.replace(USER_PATH_RE, (m, prefix: string, name: string) =>
      WELL_KNOWN_PROFILE.test(name) ? m : prefix + assign("USER", name));
  }
  // Encoded command-line blobs: the base64 after PowerShell -e/-ec/-enc/-EncodedCommand and inside
  // FromBase64String('…'). Tokenize ONLY the blob — the command verb + flag stay visible as
  // tradecraft signal (the model still sees that an encoded command ran), and victim data embedded
  // in the encoded payload never reaches the wire. The `=` padding is matched outside the class.
  const ENC_CMD_RE = /(?<![A-Za-z0-9])(-(?:e|ec|enc|encodedcommand)\s+)([A-Za-z0-9+\/_-]{16,}={0,2})/gi;
  const FROM_B64_RE = /(FromBase64String\(\s*["'])([A-Za-z0-9+\/_-]{16,}={0,2})(["'])/gi;
  function anonEncodedCmd(t: string): string {
    let out = t.replace(ENC_CMD_RE, (_m, flag: string, blob: string) => flag + assign("CMD", blob));
    out = out.replace(FROM_B64_RE, (_m, a: string, blob: string, c: string) => a + assign("CMD", blob) + c);
    return out;
  }
  // Machine/domain-issued user SIDs (S-1-5-21-…-RID) are victim-identifying. Well-known SIDs
  // (S-1-5-18, S-1-5-19/20, S-1-5-32-*) lack the S-1-5-21 prefix and are preserved.
  const SID_RE = /\bS-1-5-21(?:-\d{1,10}){4}\b/gi;
  function anonSids(t: string): string {
    return t.replace(SID_RE, (m) => assign("REG", m));
  }
  function anonHosts(t: string): string {
    let out = t;
    for (const h of known.hosts) {
      if (h.length < 2) continue;
      out = out.replace(new RegExp(`\\b${escapeRegExp(h)}\\b`, "gi"), (m) => assign("HOST", m));
    }
    return out;
  }
  function anonDomains(t: string): string {
    let out = t;
    for (const d of known.internalDomains) {
      if (d.length < 2) continue;
      out = out.replace(new RegExp(`\\b${escapeRegExp(d)}\\b`, "gi"), (m) => assign("DOMAIN", m));
    }
    return out;
  }
  function anonIps(t: string): string {
    let out = t.replace(IPV4_RE, (ip) => {
      if (isInternalIp(ip)) return assign("IP", ip);
      if (!policy.maskPublicIps || !isMaskableIpv4(ip)) return ip;
      return assign("EXTIP", ip);
    });
    out = out.replace(IPV6_RE, (ip) => {
      if (isInternalIpv6(ip)) return assign("IP", ip);
      return policy.maskPublicIps ? assign("EXTIP", ip) : ip;
    });
    return out;
  }

  function anonCustom(t: string): string {
    const custom = known.custom ?? [];
    if (custom.length === 0) return t;
    let out = t;
    for (const { value, category } of [...custom].sort((a, b) => b.value.length - a.value.length)) {
      if (!value || value.length < 1) continue;
      out = out.replace(new RegExp(`\\b${escapeRegExp(value)}\\b`, "gi"), (m) => assign(category, m));
    }
    return out;
  }

  function apply(text: string): string {
    let t = text;
    t = anonCustom(t);                       // analyst-added entities always win
    if (policy.redactSecrets) t = redactSecrets(t);
    if (policy.categories.USER) t = anonAccounts(t);
    if (policy.categories.EMAIL) t = anonEmails(t);
    if (policy.categories.PATH) t = anonUserPaths(t);
    if (policy.categories.CMD) t = anonEncodedCmd(t);
    if (policy.categories.REG) t = anonSids(t);
    if (policy.categories.HOST) t = anonHosts(t);
    if (policy.categories.DOMAIN) t = anonDomains(t);
    if (policy.categories.IP) t = anonIps(t);
    return t;
  }

  function restore(text: string): string {
    return text.replace(TOKEN_RE, (m) => toReal.get(m.toUpperCase()) ?? m);
  }

  function restoreDeep<T>(value: T): T {
    if (typeof value === "string") return restore(value) as unknown as T;
    if (Array.isArray(value)) return value.map((v) => restoreDeep(v)) as unknown as T;
    if (value && typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = restoreDeep(v);
      return out as unknown as T;
    }
    return value;
  }

  return { apply, restore, restoreDeep, discoveries };
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
  "nt", "authority", "service", "builtin", "workgroup", "virtual", "machine",
  "iis", "apppool", "window", "manager", "font", "driver", "host", "dwm", "umfd",
  "everyone", "system", "owner", "creator",
  // Registry hives (HKU\Software → "hku")
  "hku", "hklm", "hkcu", "hkcr", "hkcc",
  "hkey_users", "hkey_local_machine", "hkey_current_user", "hkey_classes_root", "hkey_current_config",
  // Bare single-label LAN suffixes (a 2-label host like dc.local would otherwise add "local")
  "local", "localdomain", "lan", "home",
  // MITRE ATT&CK tactics — the EVTX-ATTACK-SAMPLES folder names that keep getting mis-parsed
  "reconnaissance", "resource", "development", "initial", "access", "execution",
  "persistence", "privilege", "escalation", "defense", "evasion", "credential",
  "discovery", "lateral", "movement", "collection", "command", "control",
  "exfiltration", "impact", "tactics", "techniques", "mitre", "attack",
  // Common tool / process / generic folder names that get mis-parsed as a DOMAIN
  "defender", "explorer", "vgauth", "ransomware", "malware", "samples", "results",
  "tools", "setup", "files", "hours", "global", "launch", "layers", "code", "jobs",
  "lite", "csv", "zip", "logs", "temp", "data", "output", "report", "reports",
  "evidence", "downloads", "desktop", "documents", "users", "public", "default",
  "windows", "programdata", "program", "system32", "appdata",
]);

// A single-label token is "noise" when it's a known non-victim word; a dotted FQDN is kept.
export function isNoiseDomain(domain: string): boolean {
  const d = domain.toLowerCase().trim();
  if (!d) return true;
  if (d.includes(".")) return false;          // real FQDN (windomain.local) — always keep
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

// Derive the victim entities to tokenize from the case state: hosts (event.asset), accounts
// (DOMAIN\user / UPN in event text) and the internal domains those imply (NETBIOS name, UPN
// domain, and the parent domain of any FQDN host). Pure + deterministic. Noise accounts/domains
// (registry hives, Windows principals, ATT&CK tactic folders, generic words) are filtered out so
// they neither pollute the analyst's list nor get tokenized as common words across the timeline.
export function deriveKnownEntities(state: InvestigationState): KnownEntities {
  const hosts = new Set<string>();
  const accounts = new Set<string>();
  const internalDomains = new Set<string>();
  for (const e of state.forensicTimeline) {
    if (e.asset && e.asset.trim()) hosts.add(e.asset.trim());
    for (const acct of extractAccounts(e.description)) {
      if (isNoiseAccount(acct)) continue;       // registry hive / Windows principal / tactic folder, not a victim account
      accounts.add(acct);
      if (acct.includes("\\")) internalDomains.add(acct.split("\\")[0]);
      else if (acct.includes("@")) internalDomains.add(acct.split("@")[1]);
    }
  }
  for (const h of hosts) {
    const i = h.indexOf(".");
    if (i > 0) internalDomains.add(h.slice(i + 1)); // FQDN → parent domain is internal
  }
  const byLenDesc = (a: string, b: string) => b.length - a.length || a.localeCompare(b);
  return {
    hosts: [...hosts].sort(byLenDesc),
    accounts: [...accounts],
    internalDomains: [...internalDomains]
      .map((d) => d.toLowerCase())
      .filter((d) => !isNoiseDomain(d))         // belt-and-suspenders: also drops noisy FQDN-parent labels (dc.local → "local")
      .sort(byLenDesc),
  };
}

// Is the configured AI provider on-box (so screenshots sent to it don't leave the machine)?
// Used to decide whether to warn that screenshots are NOT anonymized.
export function isLocalAiProvider(name: string | undefined, baseUrl: string | undefined): boolean {
  if ((name ?? "").toLowerCase() === "ollama") return true;
  const u = (baseUrl ?? "").toLowerCase();
  return /(?:\/\/|@)(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?::|\/|$)/.test(u);
}
