// Why a CrowdStrike NG-SIEM request never got an HTTP answer (#2685), in one analyst sentence.
//
// Node's fetch (undici) rejects every low-level failure with `TypeError: fetch failed` and puts the
// real reason on `cause` — sometimes one level deeper, sometimes inside an AggregateError when
// several addresses were tried. The search used to answer all of them with "Could not reach
// CrowdStrike NG-SIEM.", which named nothing to check. This module finds the error code and says
// what it points at: DNS, the network path, the certificate, or the base URL setting.
//
// Nothing here sees the secret by construction (undici errors carry no request body, and the base
// URL is validated to hold no userinfo), but every output still passes through `redact` — an
// injected fetch or an upstream message is not ours to trust.

const MAX_DEPTH = 6;
const LOG_MAX = 1_000;

const DNS_CODES = new Set(["ENOTFOUND", "EAI_AGAIN", "EAI_NONAME", "EAI_FAIL", "EAI_NODATA"]);
const NETWORK_CODES = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "EPIPE",
  "ECONNABORTED",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_SOCKET",
  "UND_ERR_CLOSED",
  "UND_ERR_HEADERS_TIMEOUT",
]);
/** The chain could not be built to a trusted root: the case a CA bundle fixes. */
const TRUST_CODES = new Set([
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_GET_ISSUER_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
]);
const EXPIRY_CODES = new Set(["CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID"]);
const NAME_CODES = new Set(["ERR_TLS_CERT_ALTNAME_INVALID", "HOSTNAME_MISMATCH"]);

export type FailureKind = "dns" | "network" | "trust" | "expiry" | "name" | "tls" | "url" | "other";

/** Every error in the chain (cause and AggregateError.errors), bounded and cycle-safe. */
function chainOf(err: unknown): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  const seen = new Set<unknown>();
  const walk = (e: unknown, depth: number): void => {
    if (!e || typeof e !== "object" || seen.has(e) || depth > MAX_DEPTH || out.length > 20) return;
    seen.add(e);
    const rec = e as Record<string, unknown>;
    out.push(rec);
    walk(rec.cause, depth + 1);
    if (Array.isArray(rec.errors)) for (const sub of rec.errors.slice(0, 8)) walk(sub, depth + 1);
  };
  walk(err, 0);
  return out;
}

/** The first Node/undici error code anywhere in the chain, or "". */
export function failureCode(err: unknown): string {
  for (const e of chainOf(err)) if (typeof e.code === "string" && e.code) return e.code;
  return "";
}

export function classifyFailure(err: unknown): { kind: FailureKind; code: string } {
  const chain = chainOf(err);
  const codes = chain.map((e) => (typeof e.code === "string" ? e.code : "")).filter(Boolean);
  const has = (set: Set<string>) => codes.find((c) => set.has(c));
  const pick = (kind: FailureKind, code: string | undefined) => (code ? { kind, code } : undefined);
  const urlBad =
    codes.includes("ERR_INVALID_URL") ||
    chain.some((e) => typeof e.message === "string" && /^Invalid URL\b/.test(e.message));
  return (
    pick("trust", has(TRUST_CODES)) ??
    pick("expiry", has(EXPIRY_CODES)) ??
    pick("name", has(NAME_CODES)) ??
    pick(
      "tls",
      codes.find((c) => c.startsWith("ERR_TLS_") || c.startsWith("ERR_SSL_") || c.startsWith("CERT_")),
    ) ??
    pick("dns", has(DNS_CODES)) ??
    pick("network", has(NETWORK_CODES)) ??
    (urlBad
      ? { kind: "url" as const, code: "ERR_INVALID_URL" }
      : { kind: "other" as const, code: codes[0] ?? "" })
  );
}

/** Remove every credential-shaped thing a message could carry. */
export function redact(text: string, secrets: readonly string[] = []): string {
  let out = text;
  for (const s of secrets) if (s && s.length >= 4) out = out.split(s).join("[redacted]");
  return out
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]")
    .replace(/(access_token|client_secret|client_id)=[^&\s"]+/gi, "$1=[redacted]")
    .replace(/(\/\/)[^/@\s]+@/g, "$1[redacted]@");
}

export interface FailureContext {
  /** The API host (and port when not 443), never a full URL. */
  host: string;
  /** "CrowdStrike NG-SIEM" — the sentence starts with it. */
  label: string;
  /** Who issued the certificate a separate check connection was shown (trust failures only). */
  issuer?: string;
}

/** One analyst sentence naming what to check. */
export function describeFetchFailure(err: unknown, ctx: FailureContext): string {
  const { kind, code } = classifyFailure(err);
  const { host, label } = ctx;
  switch (kind) {
    case "dns":
      return `${label}: could not resolve ${host} (${code}). Check the cloud / base URL setting and this server's DNS.`;
    case "network":
      return `${label}: the connection to ${host} failed (${code}). Check the network path, firewall or proxy between this server and CrowdStrike.`;
    case "trust": {
      const by = ctx.issuer
        ? `, and a check connection was shown a certificate issued by "${ctx.issuer}"`
        : "";
      return `${label}: the TLS certificate from ${host} was rejected (${code})${by}. This usually means the network inspects TLS. Add that proxy's root CA as a PEM bundle in DFIR_CROWDSTRIKE_SIEM_CA (verification stays on).`;
    }
    case "expiry":
      return `${label}: the TLS certificate from ${host} is outside its validity dates (${code}). Check this server's clock; if the clock is right, something on the network is presenting a stale certificate.`;
    case "name":
      return `${label}: the TLS certificate from ${host} is for a different host (${code}). Check the cloud / base URL setting; if it is right, something on the network is intercepting TLS.`;
    case "tls":
      return `${label}: the TLS connection to ${host} failed (${code}). Check for TLS inspection or a proxy on the network path.`;
    case "url":
      return `${label}: the API base URL is not a valid URL. Check DFIR_CROWDSTRIKE_SIEM_BASE_URL (https:// plus the API host) or leave it blank to use the cloud.`;
    default:
      return `${label}: could not reach ${host}${code ? ` (${code})` : ""}. The server log has the full error.`;
  }
}

/** The whole chain on one line for the server log: name, message and code of each error. */
export function fetchFailureLogLine(err: unknown, secrets: readonly string[] = []): string {
  const parts = chainOf(err).map((e) => {
    const name = typeof e.name === "string" ? e.name : "Error";
    const msg = typeof e.message === "string" ? e.message : "";
    const code = typeof e.code === "string" ? ` [${e.code}]` : "";
    return `${name}: ${msg}${code}`.replace(/\s+/g, " ").trim();
  });
  const line = parts.length ? parts.join(" <- ") : String(err);
  return redact(line, secrets).slice(0, LOG_MAX);
}
