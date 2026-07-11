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
import { aggregateEvents, addIoc, mergeRowIocs, oneLine, type MappedEvent, type SiemIoc, type SiemParseResult } from "./siemImport.js";

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
// matches, and bytes may be "-" (no body).
const LINE_RE = /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)(?:\s+[^"]*)?"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"/;

// Is this text an Apache/Nginx/Squid combined access log? True when a meaningful share of the
// first non-blank lines match the line shape, or the filename says so outright.
export function looksLikeCombinedLog(filename: string, text: string): boolean {
  if (FILENAME_RE.test((filename ?? "").trim())) return true;
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(0, 50);
  if (!lines.length) return false;
  const hits = lines.filter((l) => LINE_RE.test(l)).length;
  return hits >= 2 && hits >= lines.length * 0.5;
}

const MONTHS: Record<string, string> = {
  Jan: "01", Feb: "02", Mar: "03", Apr: "04", May: "05", Jun: "06",
  Jul: "07", Aug: "08", Sep: "09", Oct: "10", Nov: "11", Dec: "12",
};

// "14/May/2024:19:00:00 +0000" → ISO. Returns "" when unparseable.
export function parseApacheDate(raw: string): string {
  const m = raw.trim().match(/^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-]\d{4}))?$/);
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
const GIT_SMART_HTTP = /\.git\/(?:info\/refs\?service=git-(?:upload|receive)-pack|git-(?:upload|receive)-pack)\b/i;

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

// Map one combined-log line to a forensic event (collecting IOCs), or null if it doesn't match.
export function mapCombinedLogLine(line: string, sink: Map<string, SiemIoc>): MappedEvent | null {
  const m = LINE_RE.exec(line);
  if (!m) return null;
  const [, , , userRaw, dateRaw, method, uri, statusRaw, bytesRaw, refererRaw, uaRaw] = m;
  const status = Number(statusRaw);
  const timestamp = parseApacheDate(dateRaw);
  const user = userRaw && userRaw !== "-" ? userRaw : "";
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
  const description = oneLine(`${method} ${uri} -> ${status}${bytesTag}${userTag}${refTag}${uaTag}`).slice(0, 600);

  return {
    timestamp,
    description,
    severity,
    mitre,
    // Aggregate by method+host+path (query string dropped) so pagination/param variants collapse
    // together while a genuinely different path/host stays distinct.
    aggKey: `weblog|${method}|${host}|${uri.split("?")[0]}|${status}`.toLowerCase().slice(0, 400),
    sources: [COMBINED_LOG_SOURCE],
  };
}

// Parse a combined-format access/proxy log into the shared SIEM result shape (aggregated + capped).
// Pure, no AI.
export function parseCombinedLog(text: string, opts: CombinedLogImportOptions = {}): CombinedLogParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let total = 0;

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const rowSink = new Map<string, SiemIoc>();
    const m = mapCombinedLogLine(line, rowSink);
    if (m) { total++; mergeRowIocs(sink, rowSink, m.aggKey); mapped.push(m); }
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? (Number(process.env.DFIR_MAX_EVENTS) || 2000),
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
