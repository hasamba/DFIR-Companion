// Deterministic importer for the Apache/Nginx/Squid "combined" access-log format — the near-
// universal line shape used by web-server access logs AND Squid forward-proxy logs configured
// with the squid_combined logformat:
//
//   10.30.10.14 - arjun.mehta@corp.com [15/May/2024:06:50:28 +0000] "CONNECT vault.io:443 HTTP/1.1" 200 123 "-" "curl/7.88.1"
//   10.30.20.11 - - [14/May/2024:19:00:00 +0000] "GET /api/v4/projects HTTP/1.1" 200 3417 "-" "curl/7.81.0"
//
// Neither an Apache/nginx access log nor a Squid access log carries a maliciousness verdict — this
// is raw web/proxy telemetry, not a detection feed (same stance as kapeImport.ts/plasoImport.ts) —
// so severity stays Info by default, with a conservative bump only for a clear, generic signal: an
// access-denied response (401/403/407). The git smart-HTTP clone/push URL signature
// (…/repo.git/info/refs?service=git-upload-pack — the canonical way ANY git client clones from ANY
// self-hosted git server, regardless of the hosting product) is tagged T1213 (Data from Information
// Repositories) without escalating severity on its own, since browsing/cloning company repos is
// routine for many roles; a 403 on the SAME line still gets the Low bump (a denied clone attempt).
//
// Every distinct destination host (from an absolute-URL request or a CONNECT tunnel target) becomes
// a domain IOC, and the authenticated user (the Squid %u field, when present) is folded into the
// description so the asset-graph's UPN detection picks it up for free.
//
// The HTTP Referer is a first-class spillage surface: apps routinely leak secrets/tokens in the
// referring URL's query string (`?token=…`, `?jwt=…`). The request URI already survives in the
// description, but the referer was previously PARSED-then-DISCARDED — so a secret carried in the
// Referer header vanished. It's now captured: the referer's host becomes a domain IOC, a referer
// that carries a query string (the actual leak vector) is emitted as a `url` IOC — url IOCs aren't
// collapsed by aggregation, so a secret-bearing referer survives even when its request line
// aggregates into a busier sibling — and the referer is folded into the event description too.
//
// The HTTP User-Agent is the other attacker-controlled field this format carries, and was likewise
// PARSED-then-DISCARDED. It's a classic injection / scanner / C2 surface (a bot's UA, a prompt-
// injection payload smuggled into the UA, a hand-crafted exploit tool string). It's now folded into
// the description, and a UA that does NOT have the structural shape of a real User-Agent — i.e. does
// not open with a `Product/Version` token (Mozilla/5.0, curl/8.0, Prometheus/2.47.0, git/2.34.1) — is
// emitted as an `other` IOC. That's a low-false-positive STRUCTURAL anomaly test, not a maliciousness
// guess: ordinary product UAs stay quiet (no IOC, preserving "routine traffic → no IOC"), while prose/
// markup smuggled into the field survives even when its request line (often `GET / 200`) aggregates
// into a benign sibling and the representative description carries a different UA.
//
// This importer is deliberately NOT "smart" about deciding what's malicious per line — guessing from
// domain-name shape (TLD, DGA-ish labels) is unreliable and easy to game. The goal is that EVERY
// unique request pattern survives as its own (aggregated) event so downstream correlation/synthesis
// can judge it, instead of a per-line heuristic silently discarding the rare ones — the
// needle-in-haystack failure mode this importer replaces for these two formats (see
// logAggregate.ts's truncation fix for the analogous issue on formats WITHOUT a dedicated importer).
// Known limitation: aggregateEvents' shared maxEvents cap (default 2000) still sorts
// severest-then-noisiest before truncating, same as every other siemImport-based importer — a log
// with more than 2000 DISTINCT aggregated request patterns could still lose rare ones; out of scope
// here (that cap is shared code, not specific to this format).

import type { Severity } from "./stateTypes.js";
import {
  aggregateEvents,
  addIoc,
  mergeRowIocs,
  MONTHS,
  oneLine,
  worst,
  type MappedEvent,
  type SiemIoc,
  type SiemParseResult,
  maxEventsDefault,
} from "./siemImport.js";
import { secretSpillSignal } from "./secretSpillRules.js";
import { boundedAggKey } from "./aggKey.js";
import { identityMark, showToken } from "./recordIdentity.js";
import { inspectRequestFields, MAX_ATTACK_VARIANTS } from "./webRequestDecode.js";
import {
  packTags,
  readSize,
  readTarget,
  readTrailer,
  statusWords,
  trailerTokens,
  type TrailerProfile,
} from "./webRecordFields.js";
import { isIP } from "node:net";
import { createCanonicalEvent } from "./canonicalEvent.js";

export interface CombinedLogImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  /**
   * The file's trailer layout, declared by the caller. Without it every appended token stays
   * unlabelled: the layout is the deployment's, and a token's shape — the client's to choose
   * wherever an Apache format appends a request header — never establishes it.
   */
  trailerProfile?: TrailerProfile | null;
}

export type CombinedLogParseResult = SiemParseResult;

export const COMBINED_LOG_SOURCE = "Web Access Log";

// Filename hints: access.log, access_log, web_access.log, proxy_access.log, gitlab_access.log, …
const FILENAME_RE = /(?:^|[._-])access[_.-]?log(?:\.\w+)?$/i;

// "IP ident user [date] "METHOD URI[ PROTOCOL]" status bytes "referer" "user-agent"". The protocol
// token is optional/loose (`[^"]*`) so a bare "CONNECT host:port" with no trailing HTTP/x.x still
// matches, and bytes may be "-" (no body). The Referer and the User-Agent are ESCAPE-AWARE: Apache
// and nginx write a quote inside either field as `\"`, and a capture that stopped at the first
// quote silently dropped the tail — where a payload sits (#930 item 3). Not end-anchored on
// purpose: real formats append fields after the UA (request time, X-Forwarded-For, vhost).
const QUOTED = String.raw`"((?:[^"\\]|\\.)*)"`;
// The trailing group captures what a deployment appends after the User-Agent — Squid's %Ss:%Sh,
// a request time, a vhost, an X-Forwarded-For header (#933 item 1). It was parsed past and lost.
const LINE_RE = new RegExp(
  String.raw`^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(([A-Z]+)\s+(\S+)(?:\s+[^"]*)?)"\s+(\d{3})\s+(\S+)\s+${QUOTED}\s+${QUOTED}(.*)$`,
);
const unquote = (s: string | undefined): string => (s ?? "").replace(/\\(["\\])/g, "$1");
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/;

// Is this text an Apache/Nginx/Squid combined access log? True when a meaningful share of the
// first non-blank lines match the line shape, or the filename says so outright.
export function looksLikeCombinedLog(filename: string, text: string): boolean {
  if (FILENAME_RE.test((filename ?? "").trim())) return true;
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(0, 50);
  if (!lines.length) return false;
  const hits = lines.filter((l) => LINE_RE.test(l)).length;
  return hits >= 2 && hits >= lines.length * 0.5;
}

// "14/May/2024:19:00:00 +0000" → ISO. Returns "" when unparseable.
export function parseApacheDate(raw: string): string {
  const m = raw
    .trim()
    .match(/^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-]\d{4}))?$/);
  if (!m) return "";
  const [, dd, mon, yyyy, hh, mi, ss, tz] = m;
  const month = MONTHS[mon];
  if (!month) return "";
  const offset = tz ? `${tz.slice(0, 3)}:${tz.slice(3)}` : "Z";
  const t = Date.parse(`${yyyy}-${month}-${dd.padStart(2, "0")}T${hh}:${mi}:${ss}${offset}`);
  return Number.isNaN(t) ? "" : new Date(t).toISOString();
}

// git smart-HTTP clone/push signature — the canonical way any git client (CLI, GitLab, Gitea,
// Bitbucket…) fetches/pushes over HTTPS, regardless of the hosting product.
const GIT_SMART_HTTP =
  /\.git\/(?:info\/refs\?service=git-(?:upload|receive)-pack|git-(?:upload|receive)-pack)\b/i;

// A conventional User-Agent opens with a `Product/Version` token (Mozilla/5.0, curl/8.0,
// Prometheus/2.47.0, git/2.34.1, python-requests/2.31). A payload smuggled into the UA field — prose,
// markup, an injection directive — does not. This structural test flags the anomaly with a low
// false-positive rate WITHOUT guessing at maliciousness (a genuinely odd-but-benign UA getting a
// review flag is harmless; a browser/tool UA never trips it).
const UA_PRODUCT = /^[A-Za-z][\w.-]*\/[\w.]/;

function classify(uri: string, status: number): { severity: Severity; mitre: string[] } {
  const mitre = GIT_SMART_HTTP.test(uri) ? ["T1213"] : [];
  const severity: Severity = status === 401 || status === 403 || status === 407 ? "Low" : "Info";
  return { severity, mitre };
}

// The first field of a combined-log line is the client, but only as an ADDRESS when the server
// logs one — `HostnameLookups On` puts a resolved name there instead, and "-" means unavailable.
// `srcIp` must hold an address or nothing, so a name is dropped rather than stored as one.
function clientAddress(raw: string | undefined): string {
  const v = (raw ?? "").trim();
  if (!v || v === "-") return "";
  // A real parser, not a shape test: `999.999.999.999` is not an address, so it must not become a
  // `srcIp`, and it must not count as a second client when a trailer profile is inferred.
  return isIP(v) ? v : "";
}

// What the per-path attack-variant bound needs to know about a row (see parseCombinedLog).
export interface AttackMeta {
  /** The aggregation key with every variant segment removed — one per method|status|client|host|path. */
  base: string;
  /** …kept in its two halves, because the path is attacker-controlled and may contain a `|`. */
  prefix: string;
  path: string;
  families: string[];
  /** The row's variant identity: its attack payload digest and its unlabelled-trailer digest. */
  digest: string;
  /** True when an attack shape fired — an overflow row then names the families. */
  hasAttack: boolean;
  /** The description an overflow row takes, minus what it will be given. */
  overflowTail: string;
}

/** The overflow row's key segment and marker — family-independent, so the bound is one group per path. */
export const ATTACK_OVERFLOW = "attack:overflow";
/** …and the marker for rows whose only variant was an unlabelled trailer value. */
export const TRAILER_OVERFLOW = "trailer:overflow";

// A row with no attack signal keeps today's layout when it fits. When the attacker-controlled
// target would push the status and the record's own facts past the 600-character clip, the row
// takes a FIXED-SLOT layout instead — the status and the tags first, the bounded target after —
// so a 700-character URI can never hide the response code or the cache disposition (#933 item 1).
function plainDescription(
  method: string,
  uri: string,
  status: number,
  bytesTag: string,
  tags: readonly string[],
  userTag: string,
  refTag: string,
  uaTag: string,
  mark: string,
  lossy: boolean,
): string {
  const tagText = tags.length ? ` [${tags.join("] [")}]` : "";
  // Both layouts pack WHOLE tags (packTags): a substring of a serialised `[a] [b]` sequence would
  // leave a half-open tag and hide the fact it names.
  const whole = oneLine(`${method} ${uri} -> ${status}${bytesTag}${tagText}${userTag}${refTag}${uaTag}`);
  // Byte-for-byte when the whole record fits and nothing shown was clipped or neutralised; the
  // identity mark rides along whenever it was (identityMark).
  if (!lossy && whole.length <= 600) return whole;
  if (whole.length + mark.length <= 600) return `${whole}${mark}`;
  // Rebuilt from WHOLE tags in evidence order — never a substring of a serialised sequence, which
  // would leave a half-open `[redir` and drop the fact it names. A rebuilt line is never the whole
  // record, so it always carries the mark.
  const max = 600 - mark.length;
  const head = `[status: ${status}]`;
  // The tail is measured, not reserved: room the user, Referer and UA excerpts do not use goes to
  // the record's own tags.
  const tail = `${userTag.slice(0, 50)}${refTag.slice(0, 62)}${uaTag.slice(0, 62)}`;
  const room =
    max - head.length - 1 - method.length - 1 - Math.min(uri.length, 200) - bytesTag.length - tail.length;
  const keptText = packTags(tags, room);
  return `${oneLine(`${head}${keptText} ${method} ${uri.slice(0, 200)}${bytesTag}${tail}`).slice(0, max)}${mark}`;
}

// An attack row's slots are BOUNDED before composition, not sliced after it: the families and the
// matched excerpts are attacker-shaped and unbounded, so a four-family hit on all three fields
// would otherwise consume the whole 600 characters and leave the record's own facts — the status's
// tag, the proxy's legs — cut off mid-tag (#933 item 1). Each slot closes its own bracket, so the
// row's brackets always balance.
const ATTACK_LABELS_MAX = 120;
const ATTACK_MATCH_MAX = 160;
/** Reserved for the record's own facts — the status's tag, the proxy's legs — before the payload. */
const ATTACK_TAGS_RESERVE = 200;

function attackDescription(
  attack: { labels: string[]; slots: string[] },
  method: string,
  uri: string,
  status: number,
  bytesTag: string,
  tags: readonly string[],
  userTag: string,
  referer: string,
  ua: string,
  mark: string,
): string {
  // An attack row's excerpts are always clipped, so it always carries the identity mark.
  const max = 600 - mark.length;
  // The matched excerpts are DECODED attacker text rendered inside a `[tag]`, so a payload
  // carrying `] [status: success] [` would forge a tag beside the real one. Brackets become
  // parentheses first — the same rule the trailer tokens follow (#933 item 1).
  const clip = (text: string, max: number): string => {
    const safe = text.replace(/\[/g, "(").replace(/\]/g, ")");
    return safe.length <= max ? safe : `${safe.slice(0, max - 1)}…`;
  };
  const head = `[web-attack: ${clip(attack.labels.join(","), ATTACK_LABELS_MAX)}] [status: ${status}]`;
  // With record tags to place, the attacker-shaped slots give way: the request target and the
  // referer/UA excerpts shrink, and the matched text is clipped to what is left after the tags'
  // reserve. A four-family hit on all three fields then still shows the status's own tag and the
  // proxy's legs — the facts the payload would otherwise crowd out.
  const wanted = tags.reduce((n, t) => n + t.length + 3, 0);
  const reserve = Math.min(wanted, ATTACK_TAGS_RESERVE);
  const tail =
    ` ${method} ${uri.slice(0, reserve ? 120 : 200)}${bytesTag}${userTag.slice(0, 50)}` +
    `${referer ? ` (ref ${referer.slice(0, reserve ? 40 : 60)})` : ""}` +
    `${ua ? ` (ua ${ua.slice(0, reserve ? 40 : 60)})` : ""}`;
  const matchMax = Math.max(40, Math.min(ATTACK_MATCH_MAX, max - head.length - tail.length - reserve));
  const match = attack.slots.length ? ` [match: ${clip(attack.slots.join(" | "), matchMax)}]` : "";
  const room = max - head.length - match.length - tail.length;
  return `${oneLine(`${head}${match}${packTags(tags, room)}${tail}`).slice(0, max)}${mark}`;
}

// Map one combined-log line to a forensic event (collecting IOCs), or null if it doesn't match.
// `attackMeta`, when given, receives the row's attack identity so the caller can bound variants.
export function mapCombinedLogLine(
  line: string,
  sink: Map<string, SiemIoc>,
  attackMeta?: Map<MappedEvent, AttackMeta>,
  profile: TrailerProfile | null = null,
): MappedEvent | null {
  const m = LINE_RE.exec(line);
  if (!m) return null;
  const [
    ,
    clientRaw,
    ,
    userRaw,
    dateRaw,
    requestLine,
    method,
    uriRaw,
    statusRaw,
    bytesRaw,
    refererQuoted,
    uaQuoted,
    restRaw,
  ] = m;
  const status = Number(statusRaw);
  // The bound is applied ONCE, here, before host, IOC, description or key construction touches a
  // field: every later step runs on the CLIPPED text, so a 10 MB referer is neither a 10 MB url IOC
  // nor a 10 MB interpolation (#930 item 3). A clipped field fires `oversized@<field>` instead of
  // being scanned in part — a payload after a prefix window would otherwise be free.
  const {
    inspection: attack,
    fields,
    decodedTarget,
    decodedReferer,
  } = inspectRequestFields({
    target: uriRaw,
    referer: unquote(refererQuoted),
    ua: unquote(uaQuoted),
  });
  const uri = fields.target;
  const refererRaw = fields.referer;
  const uaRaw = fields.ua;
  const timestamp = parseApacheDate(dateRaw);
  const user = userRaw && userRaw !== "-" ? userRaw : "";
  // The client address is the FIRST field of a combined-log line, and it was the one field this
  // mapper threw away: the capture group existed, the destructuring skipped past it, and no
  // `srcIp` ever reached the event — while the sibling Zeek flow mapper has populated `srcIp` all
  // along. Every "which host attacked this server" question dead-ends without it (#930 item 3).
  // "-" is the placeholder when the address is unavailable.
  const client = clientAddress(clientRaw);
  // What this line establishes about its own fields (#933 item 1): the request target's RFC 9112
  // form (a fact about the line, never the deployment's role), the proxy's two legs when the FILE
  // declares or evidences a Squid trailer, whether the status or the method allows a body at all,
  // and every trailer token the profile does not name — kept verbatim, never an indicator.
  // A control character between the method, the target and the protocol is consumed by the line
  // grammar's `\s+` separators, so the target reaches the reader looking clean. The REQUEST LINE
  // the grammar itself captured is checked instead — not a span found by scanning for a quote,
  // which an escaped quote in an earlier field could move: a control anywhere in it makes the
  // target invalid, and no host of it becomes an indicator (#933 item 1).
  const target = CONTROL_CHARS.test(requestLine ?? "")
    ? ({ form: "invalid", host: "", port: "", words: "invalid request target" } as const)
    : readTarget(method, uri);
  // The destination host is the one the WHOLE-target parse validated: a malformed target
  // (`http://ev]il:abc/x`) is invalid, and nothing of it becomes an indicator or a key field.
  const host = target.host;
  // A host that is an ADDRESS is an ip indicator, not a domain: `[2001:db8::1]` as a domain value
  // breaks validation, enrichment and correlation downstream.
  const hostIp = host.startsWith("[") ? host.slice(1, -1) : isIP(host) ? host : "";
  if (hostIp) addIoc(sink, "ip", hostIp);
  else if (host) addIoc(sink, "domain", host);
  const trailer = readTrailer(trailerTokens(restRaw ?? ""), profile);
  const sizeWords = readSize(method, status, bytesRaw ?? "");
  const statusTail = statusWords(status);
  // Evidence order — what the row must keep first when a long target forces the fixed layout: the
  // proxy's legs, what the status itself establishes, what the size does not, the target's form,
  // and last the uninterpreted trailer text.
  const tags = [
    ...(trailer.squidWords ? [trailer.squidWords] : []),
    ...(statusTail ? [statusTail] : []),
    ...(sizeWords ? [sizeWords] : []),
    ...(target.words ? [target.words] : []),
    ...(trailer.trailerWords ? [trailer.trailerWords] : []),
  ];
  // Both layouts pack WHOLE tags (packTags): a substring of a serialised `[a] [b]` sequence would
  // leave a half-open tag and hide the fact it names.

  // Referer capture (see module comment): host → domain IOC; a referer with a query string is the
  // secret-leak vector, so emit it as an unaggregated url IOC that survives even if this request
  // line aggregates into a busier sibling. "-" is Apache/nginx's "no referer".
  const referer = refererRaw && refererRaw !== "-" ? refererRaw : "";
  // The Referer is attacker-controlled too, so its host goes through the SAME whole-authority
  // validation as the request target: `http://ev]il:abc/x` mints no domain indicator.
  const refHost = referer ? readTarget("GET", referer).host : "";
  // A Referer is a claim the client makes, not an observed connection: an ADDRESS found only there
  // is no ip indicator (ip indicators feed enrichment and export as "seen"), and a numeric host is
  // no domain either. A named host stays the domain indicator it has always been — a spillage
  // surface (module comment) — and a secret-bearing referer still becomes the url indicator below.
  const refIsAddress = refHost.startsWith("[") || isIP(refHost) !== 0;
  if (refHost && !refIsAddress) addIoc(sink, "domain", refHost);
  if (referer && /^https?:\/\//i.test(referer) && referer.includes("?")) addIoc(sink, "url", referer);

  // User-Agent capture (see module comment): a UA that doesn't open like a real `Product/Version`
  // string is anomalous (bot/scanner/injection payload) — emit it as an `other` IOC so it survives
  // even when its request line aggregates into a benign sibling. "-" is Apache/nginx's "no UA".
  const ua = uaRaw && uaRaw !== "-" ? uaRaw : "";
  if (ua && !UA_PRODUCT.test(ua)) addIoc(sink, "other", ua.slice(0, 400));

  const { severity, mitre } = classify(uri, status);
  // Every client-written field is neutralised before it is shown beside the row's tags (showToken):
  // a Referer of `http://x/) [proxy: served from its cache]` must read as text, never as the leg
  // words the trailer reader earned. The RAW values still feed the key, the indicators and the
  // spill check above and below.
  const shownUri = showToken(uri);
  const shownRef = showToken(referer);
  const shownUa = showToken(ua);
  const userTag = user ? ` [${showToken(user)}]` : "";
  const bytesTag = bytesRaw && bytesRaw !== "-" ? ` (${bytesRaw}b)` : "";
  const refTag = shownRef ? ` (ref ${shownRef})` : "";
  const uaTag = shownUa ? ` (ua ${shownUa})` : "";
  // A secret carried in the request URI or the Referer is a spill the moment this line is written.
  // Graded Medium (see secretSpillRules.ts) so it reaches the forensic timeline synthesis reads —
  // web logs are otherwise Info-by-default and land in the analyst-only super-timeline. The
  // DECODED forms are scanned too, so a `%5F`-encoded token no longer hides from the rules.
  const spill = secretSpillSignal(`${uri} ${referer} ${decodedTarget} ${decodedReferer}`);
  const graded: Severity = attack || spill ? worst(severity, "Medium") : severity;
  const techniques = [...new Set([...mitre, ...(spill?.mitre ?? []), ...(attack ? ["T1190"] : [])])];

  // The attack segment of the key: the families AND a digest of the matched evidence, so two
  // payloads of one family on one path are two rows while the same payload with different padding
  // is one. Placed with the bounded fields, BEFORE the path (see the field-order note below).
  const attackSegment = attack ? `|attack:${attack.families.join(",")}:${attack.digest}` : "";
  // The target's form and the proxy's disposition are bounded discriminators and belong with the
  // other bounded fields: a cache hit and a miss of one URL are two rows, and an unknown result
  // code keys verbatim rather than folding into a class. The trailer's unlabelled tokens are NOT
  // in the key — an attacker-writable header is a label, not an identity.
  // The target's form and the proxy's DISPOSITION are bounded discriminators (a literal table) and
  // belong with the other bounded fields. The unlabelled trailer's digest is NOT: a request time or
  // a forwarded-for chain is unbounded, so keying the base on it would be one group per request —
  // the aggregator's cap would then drop rare evidence and the attack-variant bound would be
  // handed back. It is a VARIANT of the base instead, bounded by the same pass (see
  // boundRecordVariants), so a shown trailer cannot fold away silently and cannot explode either.
  const recordKey = `|form:${target.form}${trailer.dispositionKey}`;
  // The logged size is part of the identity (#930 item 4): two requests for one path that the
  // server answered with different sizes are two facts, and a served-exposure reading must not
  // inherit one row's size for the group. Bounded by its own frame, like the path below.
  const sizeKey = /^\d{1,19}$/.test((bytesRaw ?? "").trim()) ? `|z${bytesRaw.trim()}` : "|z-";
  const baseKey = `weblog|${method}|${status}${sizeKey}|${client}|${host}${recordKey}${spill ? `|spill:${spill.families.join(",")}` : ""}`;
  // The path is the one attacker-controlled part of the key, so it is FRAMED with its own length:
  // `|p<len>:<path>`. Unframed, a path could spell out another segment — `squid:tcp_hit:none|
  // trailer:overflow|foo` — and collide with the overflow row's key, hiding it inside an ordinary
  // row's count. A framed segment cannot: the frame begins with `p` and a length the path cannot
  // choose (#933 item 1).
  const path = uri.split("?")[0];
  const pathKey = `|p${path.length}:${path}`;

  // A row with no attack signal keeps today's layout byte-for-byte. A row with one takes a
  // FIXED-SLOT layout: prefix, then the status in its own slot, then one match slot per firing
  // field, then the method and the BOUNDED original, then the tail tags each with its own cap — so
  // no attacker-controlled field can push the evidence or the status past the clip, and the
  // analyst always sees the text that fired and what the server answered. "web-attack", never
  // "compromise": a 200 does not prove execution and a 500 does not prove prevention.
  // One variant dimension per row. A row WITH an attack is identified by its payload: the
  // trailer digest stays out, or trailer churn on one payload would consume the 64-payload
  // budget and fold a genuinely different payload into an overflow row, losing its excerpt. The
  // trailer's words still show on the row that survives — the trade the UA and the Referer take.
  const fullKey = `${baseKey}${attackSegment}${attack ? "" : trailer.variantKey}${pathKey}`.toLowerCase();
  const mark = identityMark(fullKey);
  // Shown text that is not the record's own: a trailer (clipped per token and packed as a tag), a
  // neutralised bracket or control character in any client field.
  const lossy =
    Boolean(trailer.variantKey) ||
    `${shownUri}${shownRef}${shownUa}${showToken(user)}` !== `${uri}${referer}${ua}${user}`;
  const description = attack
    ? attackDescription(attack, method, shownUri, status, bytesTag, tags, userTag, shownRef, shownUa, mark)
    : plainDescription(method, shownUri, status, bytesTag, tags, userTag, refTag, uaTag, mark, lossy);

  const event: MappedEvent = {
    timestamp,
    description,
    severity: graded,
    mitre: techniques,
    // Aggregate by method+host+path (query string dropped) so pagination/param variants collapse
    // together while a genuinely different path/host stays distinct. A spill-bearing line gets its
    // OWN key: aggregation is first-description-wins, so without this a secret-carrying request
    // merges into a busier ref-less sibling on the same path and its secret vanishes from the
    // description — leaving a Medium with no visible reason. Measured on the spillage-full-matrix
    // benchmark: the JWT in a Referer on `GET /` produced no distinguishable event at all.
    // The client address is part of the key, not just the row. Aggregation keeps ONE row's
    // identity (the first, unless a later row is strictly more severe), so a `srcIp` that is not a
    // discriminator would pin one arbitrary client's address to a group of thousands — a WRONG
    // attribution, which is worse than the missing field it replaces. Keying on it costs one group
    // per client per path; these rows are Info and land in the analyst-only super-timeline, so the
    // extra groups do not reach the AI prompt.
    //
    // FIELD ORDER IS THE POINT, and the request path is the reason. It is unbounded and it is
    // ATTACKER-CONTROLLED, so any discriminator placed after it can be pushed past the key's length
    // bound by a long enough URI — and a truncated key does not merely miscount, it collapses two
    // rows and DELETES one row's identity. With the path in the middle, a 600-character request
    // would have folded two clients back into one attributed row, and taken the spill marker with
    // it. So: every bounded field first (method, status, client, host, spill), the path LAST, and
    // boundedAggKey rather than a raw slice — it keeps a digest of the FULL key in the tail, so two
    // long paths sharing a 400-character prefix stay two rows. This is the rule aggKey.ts states.
    aggKey: boundedAggKey(fullKey),
    sources: [COMBINED_LOG_SOURCE],
    ...(client ? { srcIp: client } : {}),
    // The line's own facts, typed (#930 item 4): what a join may read instead of the description.
    // The target is kept AS SENT (bounded), so a reader decodes it under its own policy.
    canonical: createCanonicalEvent({
      event: { category: "network", type: "web-request" },
      ...(client ? { network: { source: { address: client } } } : {}),
      web: {
        method,
        ...(host ? { host } : {}),
        target: uri.slice(0, 2048),
        targetForm: target.form,
        statusCode: status,
        responseState: "recorded",
        ...(/^\d{1,19}$/.test((bytesRaw ?? "").trim()) ? { responseBodyLen: Number(bytesRaw.trim()) } : {}),
        bodies: [],
        bodiesTotal: 0,
        records: 1,
      },
      time: { observed: dateRaw ?? "", normalized: timestamp },
      evidence: { rawRecords: [{ source: "combined-access-log", locator: `line:${identityMark(fullKey)}` }] },
      producer: { importer: "combined-log", parserVersion: "1", mappingVersion: "combined-log-v1" },
    }),
  };
  // Every row whose identity carries a variant — an attack payload, an unlabelled trailer, or
  // both — is bounded per base key, so neither can multiply groups without limit.
  if ((attack || trailer.variantKey) && attackMeta) {
    attackMeta.set(event, {
      base: `${baseKey}${pathKey}`.toLowerCase(),
      prefix: baseKey.toLowerCase(),
      path: pathKey.toLowerCase(),
      families: attack?.families ?? [],
      digest: attack ? attack.digest : trailer.variantKey,
      hasAttack: Boolean(attack),
      // Whole tags here too (packTags): the overflow row is the one the analyst reads when the
      // bound fires, so it must not end in a half-open `[redirect`.
      overflowTail: `${method} ${uri.split("?")[0].slice(0, 200)} -> ${status}${packTags(tags, 120)}`,
    });
  }
  return event;
}

// Bound the number of attack VARIANTS one path may keep as separate rows (#930 item 3). Each
// distinct payload is its own aggregation key, so a scanner run with thousands of payloads on one
// path would otherwise be thousands of groups in the aggregator's map and its pre-cap sort. The
// first MAX_ATTACK_VARIANTS distinct payloads per base key stay verbatim; every later distinct one
// is rewritten onto ONE family-independent overflow key per base key (a key that named the
// families would be one overflow group per family combination — the bound handed back), and a
// final pass gives every overflow row the same description carrying the finished family union,
// so the aggregator's first-description-wins rule cannot hide part of it. The bound is per path:
// different paths are different evidence. Returns old key → overflow key for every rewritten row,
// so IOC provenance recorded under the old key (mergeRowIocs ran before this) can follow the row.
function boundRecordVariants(mapped: MappedEvent[], meta: Map<MappedEvent, AttackMeta>): Map<string, string> {
  const seen = new Map<string, Set<string>>();
  const overflowFamilies = new Map<string, Set<string>>();
  const overflowCounts = new Map<string, number>();
  const overflowRows: Array<{ event: MappedEvent; base: string }> = [];
  for (const event of mapped) {
    const m = meta.get(event);
    if (!m) continue;
    // Attack-bearing and trailer-only rows are bounded SEPARATELY: sharing one budget let 65
    // benign trailer values consume it and fold the first real attack payload into a row the
    // family union then labelled a web-attack — one benign request claimed as an attack, one
    // attack's evidence lost.
    const budget = `${m.base}|${m.hasAttack ? "attack" : "trailer"}`;
    const digests = seen.get(budget) ?? new Set<string>();
    seen.set(budget, digests);
    if (digests.has(m.digest)) continue;
    if (digests.size < MAX_ATTACK_VARIANTS) {
      digests.add(m.digest);
      continue;
    }
    const fam = overflowFamilies.get(budget) ?? new Set<string>();
    for (const f of m.families) fam.add(f);
    overflowFamilies.set(budget, fam);
    overflowCounts.set(budget, (overflowCounts.get(budget) ?? 0) + 1);
    overflowRows.push({ event, base: budget });
  }
  const rewritten = new Map<string, string>();
  for (const { event, base } of overflowRows) {
    const m = meta.get(event)!;
    // The row's OWN kind decides its marker and words — never the base-wide family union.
    const families = m.hasAttack ? [...(overflowFamilies.get(base) ?? [])].sort().join(",") : "";
    // The prefix and the path come from the row, NOT from splitting `base` at its last `|`: the
    // path is attacker-controlled and a `|` in it would put the marker inside the path, colliding
    // with an ordinary row whose path merely contains the marker's text.
    const marker = m.hasAttack ? ATTACK_OVERFLOW : TRAILER_OVERFLOW;
    const overflowKey = boundedAggKey(`${m.prefix}|${marker}${m.path}`);
    rewritten.set(event.aggKey, overflowKey);
    event.aggKey = overflowKey;
    const what = m.hasAttack ? "distinct payloads" : "distinct appended trailer values";
    event.description =
      `${families ? `[web-attack: ${families}] ` : ""}` +
      `[overflow: ${what} beyond ${MAX_ATTACK_VARIANTS} on this path folded] ${m.overflowTail}`;
  }
  return rewritten;
}

// Parse a combined-format access/proxy log into the shared SIEM result shape (aggregated + capped).
// Pure, no AI.
export function parseCombinedLog(text: string, opts: CombinedLogImportOptions = {}): CombinedLogParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  const attackMeta = new Map<MappedEvent, AttackMeta>();
  let total = 0;

  const lines = text.split(/\r?\n/).map((l) => l.trim());
  // A LogFormat is a property of the deployment, so the trailer profile is DECLARED, never read off
  // the lines (#933 item 1): a Squid-shaped token is the client's to write wherever an Apache format
  // appends a request header, and no count of lines or of clients turns that into the server's
  // format. Without a declaration every appended token is shown unlabelled.
  const profile = opts.trailerProfile ?? null;

  for (const line of lines) {
    if (!line) continue;
    const rowSink = new Map<string, SiemIoc>();
    const m = mapCombinedLogLine(line, rowSink, attackMeta, profile);
    if (m) {
      total++;
      mergeRowIocs(sink, rowSink, m.aggKey);
      mapped.push(m);
    }
  }
  // With aggregation off nothing is folded, so nothing may be rewritten either: every row keeps its
  // own payload — the no-aggregation mode exists to preserve exactly that.
  const rewritten =
    opts.aggregate === false ? new Map<string, string>() : boundRecordVariants(mapped, attackMeta);
  if (rewritten.size) {
    // An IOC extracted from an overflow row was attributed to the row's ORIGINAL key; follow it to
    // the overflow key or resolveExtractedFrom drops the provenance silently.
    for (const [key, ioc] of sink) {
      if (!ioc.sourceAggKeys?.some((k) => rewritten.has(k))) continue;
      const keys = [...new Set(ioc.sourceAggKeys.map((k) => rewritten.get(k) ?? k))];
      sink.set(key, { ...ioc, sourceAggKeys: keys });
    }
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);

  return {
    events,
    iocs: [...sink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format: "combined-log",
    hostname: "",
  };
}
