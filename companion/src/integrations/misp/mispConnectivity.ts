// Diagnostics for the MISP connectivity check (GET /servers/getVersion).
//
// That ping is the FIRST call both the push path and the enrichment probe make, so a
// misconfigured DFIR_MISP_URL is the most likely MISP error an operator ever meets — and it used
// to be the least informative one: "MISP HTTP 400 on /servers/getVersion" named neither the URL
// nor the setting at fault, and every transport failure (refused, DNS, TLS) collapsed into
// undici's useless "fetch failed" because the real reason hides on `err.cause`.
//
// Same class of fix as #168 (which stopped blaming API-key permissions for malformed values):
// name the LIKELY cause, and only when the evidence actually supports it. A 5xx means the URL
// reached MISP, so it must NOT send the operator editing DFIR_MISP_URL.

export const MISP_PING_PATH = "/servers/getVersion";

// undici rejects with TypeError("fetch failed") and puts the actionable reason on `cause` —
// occasionally one level deeper still. AbortSignal.timeout is the exception: it rejects with a
// DOMException carrying a `name` but no `code`, so match on that too. "" when nothing is known.
export function mispCauseCode(err: unknown): string {
  let cur: unknown = err;
  for (let depth = 0; cur && depth < 5; depth++) {
    const e = cur as { code?: unknown; name?: unknown; cause?: unknown };
    if (typeof e.code === "string" && e.code) return e.code;
    if (e.name === "TimeoutError" || e.name === "AbortError") return "ETIMEDOUT";
    cur = e.cause;
  }
  return "";
}

// Node surfaces certificate problems as a family of OpenSSL codes rather than one value.
function isCertFailure(code: string): boolean {
  return code.includes("CERT") || code.includes("SELF_SIGNED") || code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE";
}

// Plain-words, actionable reason for a transport-level failure — "" when the code is unfamiliar
// (better to quote the original error than to invent a confident wrong cause).
function transportReason(code: string, url: string): string {
  if (code === "ECONNREFUSED") {
    return `connection refused by ${url} — nothing is listening on that host/port (MISP is down, or DFIR_MISP_URL has the wrong port)`;
  }
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") {
    return `cannot resolve the hostname in ${url} — check the host in DFIR_MISP_URL`;
  }
  if (code === "ETIMEDOUT" || code === "UND_ERR_CONNECT_TIMEOUT" || code === "UND_ERR_HEADERS_TIMEOUT") {
    return `timed out contacting ${url} — the host/port may be firewalled or unreachable (check DFIR_MISP_URL)`;
  }
  if (code === "EPROTO" || code === "ERR_SSL_WRONG_VERSION_NUMBER") {
    return `TLS handshake failed with ${url} — this usually means DFIR_MISP_URL uses https:// against a plain-http port`;
  }
  if (isCertFailure(code)) {
    return `TLS certificate rejected for ${url} (${code}) — set DFIR_MISP_CA to a PEM CA bundle to trust a private CA, or DFIR_MISP_INSECURE=1 to skip verification (lab only)`;
  }
  return "";
}

// Message for a MISP request that never got a response. Falls back to the original error text
// (plus the code, when there is one) so an unrecognised failure still says more than before.
export function mispTransportMessage(err: unknown, url: string): string {
  const code = mispCauseCode(err);
  const reason = transportReason(code, url);
  if (reason) return `MISP connectivity check failed: ${reason}`;
  const original = err instanceof Error ? err.message : String(err);
  return `MISP request failed: ${original}${code ? ` (${code})` : ""}`;
}

// The ping answered 2xx, but the body wasn't MISP JSON at all — a reverse proxy or an unrelated
// app on that port serving an HTML page. Parsing it raises a bare "Unexpected token '<'", which
// names neither the URL nor the setting.
export function mispPingBodyMessage(url: string, err: unknown): string {
  const original = err instanceof Error ? err.message : String(err);
  return `MISP connectivity check failed: ${url} answered, but not with MISP JSON (${original}) — DFIR_MISP_URL probably points at another service (a proxy or web app) rather than a MISP API. Check DFIR_MISP_URL.`;
}

// Message for a ping that DID get a response, but not a usable one.
//
// 400/404/405 on this endpoint means we're almost certainly not talking to a MISP API at all:
// every MISP serves /servers/getVersion, so the base URL is the suspect. Any other status (5xx,
// 429, …) means we DID reach MISP — name the URL for context but never blame the setting.
export function mispPingStatusMessage(status: number, url: string): string {
  if (status === 400 || status === 404 || status === 405) {
    return `MISP connectivity check failed: HTTP ${status} from ${url} — every MISP serves that endpoint, so this usually means DFIR_MISP_URL has the wrong scheme (an https-only instance reached over http://), an extra path suffix, or points at something that isn't MISP. Check DFIR_MISP_URL.`;
  }
  return `MISP connectivity check failed: HTTP ${status} from ${url}`;
}
