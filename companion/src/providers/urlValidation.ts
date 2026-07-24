// Validation for AI provider and enrichment base URLs to prevent API key exfiltration
// and MITM attacks via misconfigured base URLs.

/** Returns true when the host is a loopback / localhost address (any port). */
export function isLoopbackHost(host: string): boolean {
  let lower = host.toLowerCase();
  // Handle bracketed IPv6: [::1]:port or [::1]
  if (lower.startsWith("[")) {
    const close = lower.indexOf("]");
    if (close > 0) lower = lower.slice(1, close);
  } else if (!lower.includes(":") || (lower.indexOf(":") === lower.lastIndexOf(":") && /^\d+$/.test(lower.slice(lower.lastIndexOf(":") + 1)))) {
    // IPv4 or bare hostname with optional port — strip the port only when there's exactly one colon
    // and what follows is all digits. IPv6 (2+ colons) is NOT port-stripped.
    const lastColon = lower.lastIndexOf(":");
    if (lastColon > 0) lower = lower.slice(0, lastColon);
  }
  if (lower === "localhost") return true;
  if (lower === "127.0.0.1" || /^127\.\d+\.\d+\.\d+$/.test(lower)) return true;
  if (lower === "::1") return true;
  if (lower === "0.0.0.0") return true;
  return false;
}

/** Validate a base URL scheme. Returns an error message string when unsafe, null when ok.
 *  - https:// to any host is always ok
 *  - http:// to a loopback host is ok (local Ollama/LiteLLM)
 *  - http:// to a non-loopback host is flagged (cleartext key + prompt exfiltration risk)
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
  if (scheme === "http:" && !isLoopbackHost(parsed.host)) {
    return `base URL "${url}" uses http:// to a non-loopback host — the API key and case prompts will be sent in cleartext and are interceptable. Use https:// or a loopback host.`;
  }
  return null;
}