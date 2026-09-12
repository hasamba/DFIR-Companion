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
import { isIP } from "node:net";

const TRAILER_TOKEN_MAX = 40;
const DIGEST_HEX = 16;
const TRAILER_TOKENS_MAX = 6;
/** The remainder past the token cap, kept as one token so it still reaches the row's identity. */
const TRAILER_REMAINDER_MAX = 400;
const TRAILER_WORDS_MAX = 80;
const HOST_MAX = 120;

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
// A host is a real host or nothing: a bracketed literal must be an ADDRESS node:net recognises as
// IPv6 (`[:::]` is not), and a registered name must be dot-separated labels of letters, digits and
// hyphens, with any percent escape well formed (`bad%ZZ.example` is not a host). Shape alone is not
// enough — a malformed authority that passes becomes a domain indicator and a key field.
const HOST_LABEL = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/;
const PERCENT_OK = /^(?:[^%]|%[0-9A-Fa-f]{2})*$/;
function isHost(h: string): boolean {
  if (!h || h.length > HOST_MAX) return false;
  if (h.startsWith("[")) return h.endsWith("]") && isIP(h.slice(1, -1)) === 6;
  if (!PERCENT_OK.test(h)) return false;
  const labels = h.replace(/\.$/, "").split(".");
  return labels.length > 0 && labels.every((l) => HOST_LABEL.test(decodeLabel(l)));
}
// A percent-escaped label is judged — and returned — as the characters it denotes: an encoded
// `%32%30%33.0.113.9` is the address `203.0.113.9`, and must be recorded as one.
function decodeLabel(l: string): string {
  try {
    return decodeURIComponent(l);
  } catch {
    return l;
  }
}
/** The host as the characters it denotes: percent escapes decoded, case folded. */
function canonicalHost(h: string): string {
  return h.startsWith("[") ? h.toLowerCase() : decodeLabel(h).toLowerCase();
}

export function readTarget(method: string, target: string): TargetReading {
  // A control character in a target is not something to clean away — deleting it would turn
  // `http://good.example\u007f.invalid/x` into a valid-looking host and mint a fabricated
  // indicator. The target is REJECTED instead. Brackets stay (a bracketed IPv6 literal is a valid
  // host); what keeps a forged tag out of the words is the strict host validation below.
  // Checked on the RAW value, before trimming: `trim()` removes edge controls, and a target that
  // carried one is malformed wherever it sat.
  if (/[\u0000-\u001f\u007f-\u009f]/.test(target))
    return { form: "invalid", host: "", port: "", words: "invalid request target" };
  const t = target.trim();
  const verb = method.trim().toUpperCase();
  const tunnel = (host: string, port: string): TargetReading => ({
    form: "authority",
    host: canonicalHost(host).slice(0, HOST_MAX),
    port,
    words: `tunnel attempt to ${canonicalHost(host).slice(0, HOST_MAX)}${port ? `:${port}` : ""}${
      port ? "" : " — no port in this record"
    } — the requests inside are not in this record`,
  });
  if (verb === "CONNECT") {
    // authority-form is `uri-host [":" port]` and NOTHING else: the whole target must be a valid
    // host (a name or a bracketed IP literal) and an optional port. A partial match would let
    // `evil][status=success:443` reach the row's words and forge a tag.
    const at = t.lastIndexOf(":");
    const host = at > 0 && !t.endsWith("]") ? t.slice(0, at) : t;
    const port = at > 0 && !t.endsWith("]") ? t.slice(at + 1) : "";
    if (isHost(host) && (port === "" || /^\d{1,5}$/.test(port))) return tunnel(host, port);
    return { form: "invalid", host: "", port: "", words: "invalid tunnel target" };
  }
  if (t === "*")
    return { form: "asterisk", host: "", port: "", words: "asterisk-form request (server-wide)" };
  // absolute-form: scheme, a valid authority, then a path/query or nothing. A prefix match would
  // call `http://example.com:abc/x` absolute-form and take `example.com` as its host.
  const abs = /^https?:\/\/([^/?#]*)(?:[/?#].*)?$/i.exec(t);
  if (abs) {
    const authority = abs[1];
    const at = authority.lastIndexOf(":");
    const hasPort = at > 0 && !authority.endsWith("]");
    const host = hasPort ? authority.slice(0, at) : authority;
    const port = hasPort ? authority.slice(at + 1) : "";
    if (isHost(host) && (port === "" || /^\d{1,5}$/.test(port)))
      return {
        form: "absolute",
        host: canonicalHost(host).slice(0, HOST_MAX),
        port,
        words: "absolute-form request target",
      };
    return { form: "invalid", host: "", port: "", words: "invalid request target" };
  }
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

// Trailer text is attacker-writable and is rendered INSIDE the row's `[tag]` brackets, so a token
// carrying `] [proxy: served from its cache` would forge a tag the reader trusts. Brackets become
// parentheses and every control character goes before the token is shown.
const showToken = (t: string): string =>
  t
    .replace(/\[/g, "(")
    .replace(/\]/g, ")")
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

/**
 * Is this token a Squid `%Ss:%Sh` pair the tables FULLY name? Both halves must be present and
 * recognised: a
 * known result with an unknown hierarchy (`TCP_MISS:NONCE_7`) is attacker-shaped text in the slot,
 * and treating it as a bounded disposition would put one unbounded value per row into the key.
 */
export function isKnownSquidToken(token: string): boolean {
  const m = SQUID_TOKEN.exec(token.trim().toUpperCase());
  if (!m || !(m[1] in SQUID_RESULT)) return false;
  // BOTH halves, both present: `squid_combined` always writes `%Ss:%Sh`, so a bare result is not
  // the field this reader claims to understand.
  return m[2] !== undefined && m[2] in SQUID_HIERARCHY;
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

/**
 * The file's trailer layout, DECLARED by whoever knows the deployment's LogFormat. It is never
 * inferred from the tokens themselves: a token's shape is the client's to choose wherever the
 * format appends a request header, so twenty Squid-shaped values from two egress addresses would
 * otherwise mint proxy semantics — and disposition keys — that no line establishes.
 */
export interface TrailerProfile {
  /** Index into the trailer tokens that holds the Squid `%Ss:%Sh` pair. */
  squidSlot: number;
}

/** Split the text after the User-Agent into tokens: a quoted run is one token, bare runs split. */
export function trailerTokens(rest: string): string[] {
  const out: string[] = [];
  const re = /"((?:[^"\\]|\\.)*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rest)) !== null) {
    const token = (m[1] ?? m[2] ?? "").replace(/\\(["\\])/g, "$1").trim();
    if (!token) continue;
    // Past the token cap the REMAINDER is folded into one last token rather than dropped: it must
    // still reach the row's identity, or two lines differing only in a late field would fold into
    // one and lose a row.
    if (out.length >= TRAILER_TOKENS_MAX - 1) {
      out.push(rest.slice(m.index).trim().slice(0, TRAILER_REMAINDER_MAX));
      break;
    }
    out.push(token.slice(0, TRAILER_TOKEN_MAX * 4));
  }
  return out;
}

/**
 * Pack whole tags into `room` characters, in evidence order, dropping any that does not fit — a
 * substring of a serialised `[a] [b]` sequence would leave a half-open tag and hide the fact it
 * names. Returns the rendered text (with its leading space) — "" when nothing fits.
 */
export function packTags(tags: readonly string[], room: number): string {
  const kept: string[] = [];
  let left = room;
  for (const tag of tags) {
    const cost = tag.length + 3;
    if (cost > left) continue;
    kept.push(tag);
    left -= cost;
  }
  return kept.length ? ` [${kept.join("] [")}]` : "";
}

export interface TrailerReading {
  squid: SquidReading | null;
  /** Every token the profile does not name — kept verbatim, bounded, never an indicator. */
  unlabelled: string[];
  /** The proxy's legs, with how the profile was established — "" when no Squid value was read. */
  squidWords: string;
  /** `trailer: <tokens>` — "" when every token was named. Shown LAST: it is uninterpreted text. */
  trailerWords: string;
  /**
   * `|squid:<result>:<hierarchy>` — the disposition, a bounded discriminator from a literal table:
   * a cache hit and a miss of one URL are two rows.
   */
  dispositionKey: string;
  /**
   * `|trailer:<digest>` of the unlabelled tokens ("" when there are none). A VARIANT, not part of
   * the row's base identity: the tokens are unbounded (a request time, a forwarded-for chain), so
   * the caller bounds how many variants one base keeps — but a trailer that is SHOWN must be in
   * the key, or aggregation's first-description-wins rule would hide it.
   */
  variantKey: string;
}

/** Read one line's trailer under the file's DECLARED profile. With no profile nothing is labelled. */
export function readTrailer(tokens: readonly string[], profile: TrailerProfile | null): TrailerReading {
  const slotToken = profile ? tokens[profile.squidSlot] : undefined;
  // The slot is the Squid slot for the FILE; this LINE's value still has to be one of the pairs the
  // tables name. A line whose slot holds anything else keeps that value as an unlabelled token —
  // bounded, neutralised, and a variant of the key — rather than being read as a disposition (or
  // dropped, which would hide the one line that differs from every other).
  const recognised = slotToken !== undefined && isKnownSquidToken(slotToken);
  const squid = recognised ? readSquidTrailer(slotToken) : null;
  // The tokens that carry no label: their IDENTITY is the bounded raw text (so two long vhosts or
  // forwarded-for chains that differ only past the display width stay two rows), and their DISPLAY
  // is that text neutralised and clipped.
  const raw = tokens.filter((_, i) => !(recognised && profile && i === profile.squidSlot));
  const unlabelled = raw.map((t) => showToken(t).slice(0, TRAILER_TOKEN_MAX)).filter(Boolean);
  const squidWords = squid?.words ? `${squid.words} (squid_combined, declared format)` : "";
  const trailerWords = unlabelled.length
    ? `trailer: ${unlabelled.join(" ").slice(0, TRAILER_WORDS_MAX)}`
    : "";
  const digest = raw.some((t) => t.trim())
    ? createHash("sha256").update(raw.join(" ")).digest("hex").slice(0, DIGEST_HEX)
    : "";
  return {
    squid,
    unlabelled,
    squidWords,
    trailerWords,
    dispositionKey: squid ? `|squid:${squid.result.toLowerCase()}:${squid.hierarchy.toLowerCase()}` : "",
    variantKey: digest ? `|trailer:${digest}` : "",
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
  // A CONNECT's size is the tunnel's only when the proxy ANSWERED 2xx: on a 407 or a 403 no tunnel
  // exists and the bytes are that error response's own.
  if (verb === "CONNECT")
    return logged
      ? status >= 200 && status < 300
        ? "the logged size is the tunnel's, not a response body"
        : "no tunnel was established; the logged size is the error response's"
      : "";
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
