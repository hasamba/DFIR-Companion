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
import { inspectRequestFields, MAX_ATTACK_VARIANTS } from "./webRequestDecode.js";

export interface CombinedLogImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
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
const LINE_RE = new RegExp(
  String.raw`^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)(?:\s+[^"]*)?"\s+(\d{3})\s+(\S+)\s+${QUOTED}\s+${QUOTED}`,
);
const unquote = (s: string | undefined): string => (s ?? "").replace(/\\(["\\])/g, "$1");

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

// The destination host from an absolute-URL request ("https://host/path") or a CONNECT tunnel
// target ("host:port"). "" for an ordinary relative-path request (the log's own server IS the
// destination — this importer doesn't know its own hostname, see module comment).
export function requestHost(uri: string): string {
  const abs = uri.match(/^https?:\/\/([^/:]+)/i);
  if (abs) return abs[1].toLowerCase();
  const connect = uri.match(/^([^:/]+):\d+$/);
  return connect ? connect[1].toLowerCase() : "";
}

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
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(v)) return v;
  if (/^[0-9a-f]*:[0-9a-f:]*$/i.test(v) && v.includes(":")) return v; // IPv6, incl. "::1"
  return "";
}

// What the per-path attack-variant bound needs to know about a row (see parseCombinedLog).
export interface AttackMeta {
  /** The aggregation key with the attack segment removed — one per method|status|client|host|path. */
  base: string;
  families: string[];
  digest: string;
  /** The description an overflow row takes, minus the families it will be given. */
  overflowTail: string;
}

/** The overflow row's key segment and marker — family-independent, so the bound is one group per path. */
export const ATTACK_OVERFLOW = "attack:overflow";

// Map one combined-log line to a forensic event (collecting IOCs), or null if it doesn't match.
// `attackMeta`, when given, receives the row's attack identity so the caller can bound variants.
export function mapCombinedLogLine(
  line: string,
  sink: Map<string, SiemIoc>,
  attackMeta?: Map<MappedEvent, AttackMeta>,
): MappedEvent | null {
  const m = LINE_RE.exec(line);
  if (!m) return null;
  const [, clientRaw, , userRaw, dateRaw, method, uriRaw, statusRaw, bytesRaw, refererQuoted, uaQuoted] = m;
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
  const host = requestHost(uri);
  if (host) addIoc(sink, "domain", host);

  // Referer capture (see module comment): host → domain IOC; a referer with a query string is the
  // secret-leak vector, so emit it as an unaggregated url IOC that survives even if this request
  // line aggregates into a busier sibling. "-" is Apache/nginx's "no referer".
  const referer = refererRaw && refererRaw !== "-" ? refererRaw : "";
  const refHost = referer ? requestHost(referer) : "";
  if (refHost) addIoc(sink, "domain", refHost);
  if (referer && /^https?:\/\//i.test(referer) && referer.includes("?")) addIoc(sink, "url", referer);

  // User-Agent capture (see module comment): a UA that doesn't open like a real `Product/Version`
  // string is anomalous (bot/scanner/injection payload) — emit it as an `other` IOC so it survives
  // even when its request line aggregates into a benign sibling. "-" is Apache/nginx's "no UA".
  const ua = uaRaw && uaRaw !== "-" ? uaRaw : "";
  if (ua && !UA_PRODUCT.test(ua)) addIoc(sink, "other", ua.slice(0, 400));

  const { severity, mitre } = classify(uri, status);
  const userTag = user ? ` [${user}]` : "";
  const bytesTag = bytesRaw && bytesRaw !== "-" ? ` (${bytesRaw}b)` : "";
  const refTag = referer ? ` (ref ${referer})` : "";
  const uaTag = ua ? ` (ua ${ua})` : "";
  // A row with no attack signal keeps today's layout byte-for-byte. A row with one takes a
  // FIXED-SLOT layout: prefix, then the status in its own slot, then one match slot per firing
  // field, then the method and the BOUNDED original, then the tail tags each with its own cap — so
  // no attacker-controlled field can push the evidence or the status past the clip, and the
  // analyst always sees the text that fired and what the server answered. "web-attack", never
  // "compromise": a 200 does not prove execution and a 500 does not prove prevention.
  const description = attack
    ? oneLine(
        `[web-attack: ${attack.labels.join(",")}] [status: ${status}]` +
          `${attack.slots.length ? ` [match: ${attack.slots.join(" | ")}]` : ""} ` +
          `${method} ${uri.slice(0, 200)}${bytesTag}${userTag.slice(0, 50)}` +
          `${referer ? ` (ref ${referer.slice(0, 60)})` : ""}${ua ? ` (ua ${ua.slice(0, 60)})` : ""}`,
      ).slice(0, 600)
    : oneLine(`${method} ${uri} -> ${status}${bytesTag}${userTag}${refTag}${uaTag}`).slice(0, 600);

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
  const baseKey = `weblog|${method}|${status}|${client}|${host}${spill ? `|spill:${spill.families.join(",")}` : ""}`;
  const pathKey = `|${uri.split("?")[0]}`;

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
    aggKey: boundedAggKey(`${baseKey}${attackSegment}${pathKey}`.toLowerCase()),
    sources: [COMBINED_LOG_SOURCE],
    ...(client ? { srcIp: client } : {}),
  };
  if (attack && attackMeta) {
    attackMeta.set(event, {
      base: `${baseKey}${pathKey}`.toLowerCase(),
      families: attack.families,
      digest: attack.digest,
      overflowTail: `${method} ${uri.split("?")[0].slice(0, 200)} -> ${status}`,
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
// different paths are different evidence.
function boundAttackVariants(mapped: MappedEvent[], meta: Map<MappedEvent, AttackMeta>): void {
  const seen = new Map<string, Set<string>>();
  const overflowFamilies = new Map<string, Set<string>>();
  const overflowRows: Array<{ event: MappedEvent; base: string }> = [];
  for (const event of mapped) {
    const m = meta.get(event);
    if (!m) continue;
    const digests = seen.get(m.base) ?? new Set<string>();
    seen.set(m.base, digests);
    if (digests.has(m.digest)) continue;
    if (digests.size < MAX_ATTACK_VARIANTS) {
      digests.add(m.digest);
      continue;
    }
    const fam = overflowFamilies.get(m.base) ?? new Set<string>();
    for (const f of m.families) fam.add(f);
    overflowFamilies.set(m.base, fam);
    overflowRows.push({ event, base: m.base });
  }
  for (const { event, base } of overflowRows) {
    const families = [...(overflowFamilies.get(base) ?? [])].sort().join(",");
    const m = meta.get(event)!;
    const [prefix, path] = [base.slice(0, base.lastIndexOf("|")), base.slice(base.lastIndexOf("|"))];
    event.aggKey = boundedAggKey(`${prefix}|${ATTACK_OVERFLOW}${path}`);
    event.description =
      `[web-attack: ${families}] [overflow: distinct payloads beyond ${MAX_ATTACK_VARIANTS} on this path folded] ` +
      m.overflowTail;
  }
}

// Parse a combined-format access/proxy log into the shared SIEM result shape (aggregated + capped).
// Pure, no AI.
export function parseCombinedLog(text: string, opts: CombinedLogImportOptions = {}): CombinedLogParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  const attackMeta = new Map<MappedEvent, AttackMeta>();
  let total = 0;

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const rowSink = new Map<string, SiemIoc>();
    const m = mapCombinedLogLine(line, rowSink, attackMeta);
    if (m) {
      total++;
      mergeRowIocs(sink, rowSink, m.aggKey);
      mapped.push(m);
    }
  }
  boundAttackVariants(mapped, attackMeta);

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
