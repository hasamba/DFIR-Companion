// Reversible anonymization of the TEXT sent to the LLM. Real values stay in state; only the
// wire is tokenized. Typed numbered tokens keep the model's semantic understanding (it still
// knows ANON_HOST_1 is a host) and within-call correlation (same value → same token). Restore
// walks the model's PARSED JSON response (not the raw string) so real values containing JSON
// metacharacters — e.g. a Windows path's backslashes — never corrupt parsing.

export type AnonCategory = "IP" | "EMAIL" | "USER" | "HOST" | "DOMAIN" | "PATH";

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
}

export interface Anonymizer {
  apply(text: string): string;
  restore(text: string): string;
  restoreDeep<T>(value: T): T;
}

export const SECRET_PLACEHOLDER = "[REDACTED_SECRET]";
const TOKEN_RE = /ANON_(?:IP|EMAIL|USER|HOST|DOMAIN|PATH)_\d+/gi;

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

export function createAnonymizer(policy: AnonPolicy, known: KnownEntities): Anonymizer {
  const toToken = new Map<string, string>();  // "CAT:reallower" -> token
  const toReal = new Map<string, string>();   // token (UPPER) -> real value
  const counters: Record<string, number> = {};

  function assign(category: AnonCategory, real: string): string {
    const key = `${category}:${real.toLowerCase()}`;
    const existing = toToken.get(key);
    if (existing) return existing;
    counters[category] = (counters[category] ?? 0) + 1;
    const token = `ANON_${category}_${counters[category]}`;
    toToken.set(key, token);
    toReal.set(token, real);
    return token;
  }

  // ── detectors (filled in across later tasks; order is fixed in apply()) ──
  function redactSecrets(t: string): string { return t; }
  function anonAccounts(t: string): string { return t; }
  function anonEmails(t: string): string { return t; }
  function anonUserPaths(t: string): string { return t; }
  function anonHosts(t: string): string { return t; }
  function anonDomains(t: string): string { return t; }
  function anonInternalIps(t: string): string {
    return t.replace(IPV4_RE, (ip) => (isInternalIp(ip) ? assign("IP", ip) : ip));
  }
  void escapeRegExp; void known; // referenced by detectors added later

  function apply(text: string): string {
    let t = text;
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

  return { apply, restore, restoreDeep };
}
