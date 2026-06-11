import type { InvestigationState } from "./stateTypes.js";
import { extractAccounts } from "./assetGraph.js";

// Reversible anonymization of the TEXT sent to the LLM. Real values stay in state; only the
// wire is tokenized. Typed numbered tokens keep the model's semantic understanding (it still
// knows ANON_HOST_1 is a host) and within-call correlation (same value → same token). Restore
// walks the model's PARSED JSON response (not the raw string) so real values containing JSON
// metacharacters — e.g. a Windows path's backslashes — never corrupt parsing.

export type AnonCategory = "IP" | "EMAIL" | "USER" | "HOST" | "DOMAIN" | "PATH";

// Token categories include OTHER (free-form analyst term). AnonCategory stays the 6 pattern
// categories that drive the per-case `categories` toggle map; OTHER is token-only.
export type AnonTokenCategory = AnonCategory | "OTHER";

export interface CustomEntity {
  value: string;
  category: AnonTokenCategory;
}

export interface AnonPolicy {
  enabled: boolean;
  categories: Record<AnonCategory, boolean>;
  redactSecrets: boolean;
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
const TOKEN_RE = /ANON_(?:IP|EMAIL|USER|HOST|DOMAIN|PATH|OTHER)_\d+/gi;

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// RFC1918 + loopback + link-local + CGNAT = "internal/victim" IPs we tokenize. Public IPs are
// PRESERVED — a public IP is frequently adversary C2 we must keep (and enrich), not hide.
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

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
// DOMAIN\user — guarded so it doesn't match path segments (C:\Users\srv). Mirrors assetGraph.ts.
const NETBIOS_ACCT = /(?<![\\/:.\w])([A-Za-z][A-Za-z0-9.-]{1,14})\\([A-Za-z0-9._$-]{2,20})(?![\\/\w])/g;
const UPN_ACCT = /\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/g;
const PATH_DOMAINS = /^(Users|Windows|Program|ProgramData|ProgramFiles|System|System32|AppData|Device|Temp|Documents|Desktop|Downloads)$/i;

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
  const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  function anonEmails(t: string): string {
    return t.replace(EMAIL_RE, (m) => assign("EMAIL", m));
  }
  // Capture the profile-dir prefix + the username segment; tokenize only the username.
  const USER_PATH_RE = /([A-Za-z]:\\Users\\|\\Users\\|\/home\/|\/Users\/)([^\\/\r\n"'<>|:*?]+)/g;
  const WELL_KNOWN_PROFILE = /^(public|default|default user|all users|administrator|admin|guest|system|systemprofile|localservice|networkservice)$/i;
  function anonUserPaths(t: string): string {
    return t.replace(USER_PATH_RE, (m, prefix: string, name: string) =>
      WELL_KNOWN_PROFILE.test(name) ? m : prefix + assign("USER", name));
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
  function anonInternalIps(t: string): string {
    return t.replace(IPV4_RE, (ip) => (isInternalIp(ip) ? assign("IP", ip) : ip));
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
    if (policy.categories.HOST) t = anonHosts(t);
    if (policy.categories.DOMAIN) t = anonDomains(t);
    if (policy.categories.IP) t = anonInternalIps(t);
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
