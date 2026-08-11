// Validation for AI provider and enrichment base URLs.
//
// SCOPE: this closes the ACCIDENTAL/cleartext case only — http:// to a host outside the operator's
// own loopback/private network, where the key and case prompts travel in the clear and are
// interceptable by anyone on that path. It does NOT and CANNOT stop a base URL deliberately pointed
// at an attacker-controlled host over https://: a self-hosted LiteLLM/Ollama proxy (loopback OR
// elsewhere on the operator's LAN — see isPrivateNetworkHost) or a third-party OpenAI-compatible
// cloud endpoint is a legitimate, supported configuration, and there is no way to distinguish "the
// operator's own proxy" from "attacker.example.com with a free TLS cert" by URL shape alone — both
// are ordinary https:// URLs to an arbitrary host. If the base URL can be set by an untrusted or
// insufficiently authenticated caller (e.g. POST /settings/env — see that route's own
// writable-key allowlist), THAT is the actual control point for the deliberate-redirection threat;
// this module only ever sees the URL after it's already been written, and by then rejecting it
// just breaks legitimate self-hosted setups instead of stopping anything an attacker with write
// access couldn't route around by using https:// instead of http://.

// Strip a trailing ":port" from a URL-style host, WITHOUT touching a bare (unbracketed) IPv6
// address — those have 2+ colons and no port suffix can appear on them outside brackets. Bracketed
// IPv6 ([::1]:port or [::1]) is unwrapped first.
function hostWithoutPort(host: string): string {
  let lower = host.toLowerCase();
  if (lower.startsWith("[")) {
    const close = lower.indexOf("]");
    if (close > 0) lower = lower.slice(1, close);
    return lower;
  }
  if (
    !lower.includes(":") ||
    (lower.indexOf(":") === lower.lastIndexOf(":") && /^\d+$/.test(lower.slice(lower.lastIndexOf(":") + 1)))
  ) {
    const lastColon = lower.lastIndexOf(":");
    if (lastColon > 0) lower = lower.slice(0, lastColon);
  }
  return lower;
}

/** Returns true when the host is a loopback / localhost address (any port). */
export function isLoopbackHost(host: string): boolean {
  const lower = hostWithoutPort(host);
  if (lower === "localhost") return true;
  if (lower === "127.0.0.1" || /^127\.\d+\.\d+\.\d+$/.test(lower)) return true;
  if (lower === "::1") return true;
  if (lower === "0.0.0.0") return true;
  return false;
}

// RFC1918 + CGNAT + link-local IPv4, and unique-local/link-local IPv6 — an address that never
// leaves the operator's own network even when it isn't the SAME host. Mirrors the internal-IP
// ranges anonymize.ts/iocValue.ts already treat as "internal" elsewhere in this codebase.
function isPrivateNetworkHost(host: string): boolean {
  const lower = hostWithoutPort(host);
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(lower);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    if ([a, b, Number(v4[3]), Number(v4[4])].some((n) => n > 255)) return false;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true; // link-local
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
    return false;
  }
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique-local fc00::/7
  if (/^fe[89ab][0-9a-f]?:/i.test(lower)) return true; // link-local fe80::/10
  return false;
}

/** Validate a base URL scheme. Returns an error message string when unsafe, null when ok.
 *  - https:// to any host is always ok
 *  - http:// to a loopback OR private-network host is ok (local/LAN Ollama/LiteLLM — see
 *    isPrivateNetworkHost; this is deliberately broader than "the same host" because a remote
 *    LiteLLM box on the operator's own LAN, reached over plain HTTP, is a supported deployment)
 *  - http:// to any other (public-internet) host is flagged (cleartext key + prompt exfiltration
 *    risk to anyone on that path — see this module's top-of-file note on what this can and can't
 *    prevent)
 */
export function validateBaseUrl(url: string | undefined): string | null {
  if (!url || !url.trim()) return null; // empty = use provider default (always https)
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return `base URL "${url}" is not a valid URL`;
  }
  const scheme = parsed.protocol.toLowerCase();
  if (scheme !== "https:" && scheme !== "http:") {
    return `base URL "${url}" must use http: or https: scheme (got ${scheme})`;
  }
  if (scheme === "http:" && !isLoopbackHost(parsed.host) && !isPrivateNetworkHost(parsed.host)) {
    return `base URL "${url}" uses http:// to a public host — the API key and case prompts will be sent in cleartext and are interceptable. Use https:// or a loopback/private-network host.`;
  }
  return null;
}
