// What one web-log line establishes — the fields the combined format carries and the fields it
// does not (#933 item 1, the prerequisite phase).
//
// `combinedLogImport.ts` reads the Apache/nginx/Squid "combined" shape and its regex is not
// end-anchored on purpose: everything a real deployment appends after the User-Agent — Squid's
// `%Ss:%Sh` result and hierarchy codes, a request time, a vhost, an `X-Forwarded-For` header — was
// parsed past and dropped. So a cache HIT (the proxy answered from its own copy; nothing came from
// upstream) read exactly like a MISS, a CONNECT tunnel read like a request for a URL, and a 302
// read like a 200 with a small body.
//
// THE FIELDS ARE READ AS LEGS, NOT AS A VERDICT. Squid's result code says what the PROXY did for
// its client; the hierarchy code says what the NEXT HOP was. "The origin" is said only when the
// hierarchy code names a direct fetch. A byte count is the size the server LOGGED, never proof of a
// body or of a completed transfer (Apache's `%b` excludes headers; Squid's `%<st` includes them;
// neither is network bytes, and a CONNECT 200 is a tunnel opening).
//
// A TRAILER TOKEN IS NEVER READ FROM ITS OWN SHAPE. The combined grammar does not describe the
// appended fields, so a token that looks like a Squid code could be an attacker-controlled header
// an Apache LogFormat appends. The Squid slot is a property of the FILE: either declared by the
// caller, or inferred only when the file is long enough and almost every line carries a
// literal result code in the same slot. Everything else stays unlabelled — kept for the analyst,
// never an indicator, never the client's identity.
//
// THE CHAIN IS NOT HERE. Which request led to which redirect, which response, which payload, and
// which endpoint file matches a transfer is a join across records (and formats) — it needs Zeek
// `http.log`/`files.log` rows as events, request/session ids and HTTP/2 stream ids. This module
// only stops the line from dropping what that join will need, and from misreading what it shows.

import { createHash } from "node:crypto";

const TRAILER_TOKEN_MAX = 40;
const DIGEST_HEX = 16;
const TRAILER_TOKENS_MAX = 6;
const TRAILER_WORDS_MAX = 80;
const HOST_MAX = 120;
/** Below this many parsed lines a file cannot establish a trailer profile by inference. */
export const MIN_PROFILE_LINES = 20;
const PROFILE_SHARE = 0.95;

export type TargetForm = "origin" | "absolute" | "authority" | "asterisk" | "invalid";

export interface TargetReading {
  form: TargetForm;
  /** The destination host an absolute or authority target names ("" otherwise). */
  host: string;
  port: string;
  /** "" for an ordinary origin-form path — today's rows say nothing extra. */
  words: string;
}

// RFC 9112 request-target forms. A form is a FACT about the line; it is not the deployment's role:
// an origin server must accept an absolute-form target, and a reverse or intercepting proxy logs
// origin-form. Only a declared/inferred Squid trailer evidences proxy handling.
export function readTarget(method: string, target: string): TargetReading {
  const t = target.trim();
  const verb = method.trim().toUpperCase();
  if (verb === "CONNECT") {
    const m = /^([^:/?#\s]+):(\d{1,5})$/.exec(t);
    if (m)
      return {
        form: "authority",
        host: m[1].toLowerCase().slice(0, HOST_MAX),
        port: m[2],
        words: `tunnel attempt to ${m[1].toLowerCase().slice(0, HOST_MAX)}:${m[2]} — the requests inside are not in this record`,
      };
    const bare = /^([^:/?#\s]+)$/.exec(t);
    if (bare)
      return {
        form: "authority",
        host: bare[1].toLowerCase().slice(0, HOST_MAX),
        port: "",
        words: `tunnel attempt to ${bare[1].toLowerCase().slice(0, HOST_MAX)} — no port in this record; the requests inside are not in this record`,
      };
    return { form: "invalid", host: "", port: "", words: "invalid tunnel target" };
  }
  if (t === "*")
    return { form: "asterisk", host: "", port: "", words: "asterisk-form request (server-wide)" };
  const abs = /^https?:\/\/([^/:?#\s]+)(?::(\d{1,5}))?/i.exec(t);
  if (abs)
    return {
      form: "absolute",
      host: abs[1].toLowerCase().slice(0, HOST_MAX),
      port: abs[2] ?? "",
      words: "absolute-form request target",
    };
  if (t.startsWith("/")) return { form: "origin", host: "", port: "", words: "" };
  return { form: "invalid", host: "", port: "", words: "invalid request target" };
}

export interface SquidReading {
  /** The result code as written, upper-cased ("" when the token is not a `RESULT:HIER` pair). */
  result: string;
  hierarchy: string;
  /** `proxy: …; upstream: …` — the two legs the codes establish. */
  words: string;
  /** True when the result code is in the literal table. */
  known: boolean;
}

// What the PROXY did for its client, per Squid's own documentation of `%Ss`. Each entry says only
// what the code establishes; whether a body reached the client is not one of these facts.
const SQUID_RESULT: Record<string, string> = {
  TCP_HIT: "served from its cache",
  TCP_MEM_HIT: "served from its in-memory cache",
  TCP_IMS_HIT: "answered the client's revalidation from its cache (304)",
  TCP_NEGATIVE_HIT: "served a cached error response",
  TCP_OFFLINE_HIT: "served from its cache (offline mode)",
  TCP_REFRESH_UNMODIFIED: "revalidated upstream and served its cached copy",
  TCP_REFRESH_MODIFIED: "revalidated upstream and served the new copy",
  TCP_REFRESH_FAIL_OLD: "revalidation failed; served the stale cached copy",
  TCP_REFRESH_FAIL_ERR: "revalidation failed; returned an error",
  TCP_CLIENT_REFRESH_MISS: "the client forced a refresh; fetched upstream",
  TCP_MISS: "cache miss; fetched upstream",
  TCP_SWAPFAIL_MISS: "cached object unreadable; fetched upstream",
  TCP_DENIED: "denied the request",
  TCP_DENIED_REPLY: "denied after an upstream reply",
  TCP_TUNNEL: "tunnelled the connection",
  TCP_REDIRECT: "redirected the client itself",
  NONE: "",
  NONE_ABORTED: "the client aborted",
  UDP_HIT: "served from its cache (UDP)",
  UDP_MISS: "cache miss (UDP)",
  UDP_DENIED: "denied the request (UDP)",
  UDP_INVALID: "the request was invalid (UDP)",
  UDP_MISS_NOFETCH: "cache miss, not fetched (UDP)",
};

// What the NEXT HOP was, per `%Sh`. "The origin" is said only where Squid says it went direct.
const SQUID_HIERARCHY: Record<string, string> = {
  HIER_NONE: "not contacted",
  NONE: "not contacted",
  HIER_DIRECT: "fetched from the origin (direct)",
  ORIGINAL_DST: "fetched from the intercepted destination",
  DIRECT: "fetched from the origin (direct)",
  FIRSTUP_PARENT: "fetched through a parent proxy",
  DEFAULT_PARENT: "fetched through a parent proxy",
  ROUNDROBIN_PARENT: "fetched through a parent proxy",
  SOURCE_HASH_PARENT: "fetched through a parent proxy",
  CARP: "fetched through a peer (CARP)",
  PARENT_HIT: "served by a parent proxy's cache",
  SIBLING_HIT: "served by a sibling proxy's cache",
  CLOSEST_PARENT: "fetched through a parent proxy",
  CLOSEST_PARENT_MISS: "fetched through a parent proxy",
  CLOSEST_DIRECT: "fetched from the origin (direct)",
  FIRST_PARENT_MISS: "fetched through a parent proxy",
  ANY_OLD_PARENT: "fetched through a parent proxy",
  NO_PARENT_DIRECT: "fetched from the origin (direct)",
  SINGLE_PARENT: "fetched through a parent proxy",
  PINNED: "fetched over a pinned connection",
  TIMEOUT_DIRECT: "fetched from the origin (direct, after a peer timeout)",
};

const SQUID_TOKEN = /^([A-Z][A-Z0-9_]*)(?::([A-Z][A-Z0-9_]*))?$/;

/** Is this token a Squid `%Ss` (optionally `:%Sh`) pair whose RESULT the table names? */
export function isKnownSquidToken(token: string): boolean {
  const m = SQUID_TOKEN.exec(token.trim().toUpperCase());
  return m !== null && m[1] in SQUID_RESULT;
}

/** Read a Squid `RESULT:HIERARCHY` token as its two legs. An unknown code is kept verbatim. */
export function readSquidTrailer(token: string): SquidReading {
  const raw = token.trim().toUpperCase();
  const m = SQUID_TOKEN.exec(raw);
  if (!m) return { result: "", hierarchy: "", words: "", known: false };
  const [, result, hierarchy = ""] = m;
  const known = result in SQUID_RESULT;
  const proxy = known ? SQUID_RESULT[result] : `result ${result.slice(0, TRAILER_TOKEN_MAX)}`;
  const upstream = hierarchy
    ? (SQUID_HIERARCHY[hierarchy] ?? `next hop ${hierarchy.slice(0, TRAILER_TOKEN_MAX)}`)
    : "";
  const parts = [proxy ? `proxy: ${proxy}` : "", upstream ? `upstream: ${upstream}` : ""].filter(Boolean);
  return { result, hierarchy, words: parts.join("; ").slice(0, TRAILER_WORDS_MAX), known };
}

export interface TrailerProfile {
  /** Index into the trailer tokens that holds the Squid `%Ss:%Sh` pair. */
  squidSlot: number;
  /** How the profile was established — said in the row's words. */
  source: "declared" | "inferred";
}

/** Split the text after the User-Agent into tokens: a quoted run is one token, bare runs split. */
export function trailerTokens(rest: string): string[] {
  const out: string[] = [];
  const re = /"((?:[^"\\]|\\.)*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rest)) !== null && out.length < TRAILER_TOKENS_MAX) {
    const token = (m[1] ?? m[2] ?? "").replace(/\\(["\\])/g, "$1").trim();
    if (token) out.push(token.slice(0, TRAILER_TOKEN_MAX * 4));
  }
  return out;
}

/**
 * The file's trailer profile, inferred from every line's trailer: a slot is the Squid slot only
 * when the file carries at least MIN_PROFILE_LINES trailers and at least PROFILE_SHARE of them
 * hold a KNOWN result code in that same slot. One line's shape can never establish it — an Apache
 * LogFormat that appends an attacker-controlled header would otherwise mint proxy semantics.
 */
export function inferTrailerProfile(trailers: readonly string[][]): TrailerProfile | null {
  const lines = trailers.length;
  if (lines < MIN_PROFILE_LINES) return null;
  const width = Math.min(TRAILER_TOKENS_MAX, Math.max(0, ...trailers.map((t) => t.length)));
  for (let slot = 0; slot < width; slot++) {
    const hits = trailers.filter((t) => t[slot] !== undefined && isKnownSquidToken(t[slot])).length;
    if (hits >= lines * PROFILE_SHARE) return { squidSlot: slot, source: "inferred" };
  }
  return null;
}

export interface TrailerReading {
  squid: SquidReading | null;
  /** Every token the profile does not name — kept verbatim, bounded, never an indicator. */
  unlabelled: string[];
  /** `[squid words (squid_combined, inferred from the file)]` and `[trailer: …]`, in order. */
  words: string[];
  /**
   * `|squid:<result>:<hierarchy>|trailer:<digest>` — the disposition verbatim (a hit and a miss of
   * one URL are two rows) and a DIGEST of the unlabelled tokens. The tokens themselves stay out of
   * the key (an attacker-writable header is a label, not an identity) but their digest must be in
   * it: aggregation keeps one row's description, so a trailer shown and not keyed would vanish.
   */
  keySegment: string;
}

/** Read one line's trailer under the file's profile. With no profile nothing is labelled. */
export function readTrailer(tokens: readonly string[], profile: TrailerProfile | null): TrailerReading {
  const squidToken = profile ? tokens[profile.squidSlot] : undefined;
  const squid = squidToken ? readSquidTrailer(squidToken) : null;
  const unlabelled = tokens
    .filter((_, i) => !(profile && i === profile.squidSlot))
    .map((t) => t.slice(0, TRAILER_TOKEN_MAX));
  const words: string[] = [];
  if (squid?.words)
    words.push(
      `${squid.words} (squid_combined, ${profile?.source === "declared" ? "declared" : "inferred from the file"})`,
    );
  if (unlabelled.length) words.push(`trailer: ${unlabelled.join(" ").slice(0, TRAILER_WORDS_MAX)}`);
  const digest = unlabelled.length
    ? createHash("sha256").update(unlabelled.join(" ")).digest("hex").slice(0, DIGEST_HEX)
    : "";
  return {
    squid,
    unlabelled,
    words,
    keySegment: `${squid ? `|squid:${squid.result.toLowerCase()}:${squid.hierarchy.toLowerCase()}` : ""}${digest ? `|trailer:${digest}` : ""}`,
  };
}

/**
 * What the logged byte count does NOT establish — "" when it needs no words. The row already shows
 * the count; these words are the facts the count alone would be read against. Apache's `%b`
 * excludes headers, Squid's `%<st` includes them, neither is network bytes, and no status proves
 * the client received them — so a count on a tunnel, a HEAD or a bodiless status is named as such
 * rather than left to read as a response body.
 */
export function readSize(method: string, status: number, bytes: string): string {
  const verb = method.trim().toUpperCase();
  const logged = /^\d{1,19}$/.test(bytes.trim());
  if (verb === "CONNECT") return logged ? "the logged size is the tunnel's, not a response body" : "";
  if (verb === "HEAD") return "no body by definition (HEAD)";
  if (status === 204 || (status >= 100 && status < 200)) return "no body for this status";
  return "";
}

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

/** What the status itself establishes about a body or a destination. "" when it adds nothing. */
export function statusWords(status: number): string {
  if (REDIRECT_STATUS.has(status)) return "redirect — the Location is not in this format";
  if (status === 304) return "not modified — no body";
  return "";
}
