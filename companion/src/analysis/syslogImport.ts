// Deterministic importer for plain Linux/Unix syslog — both the modern RFC 5424 framing rsyslog
// emits by default and the classic RFC 3164 BSD framing:
//
//   <30>1 2024-05-16T13:40:26.263976Z APP-MTX-01 app - - - alertbot: posting to slack with token xoxb-…
//   <86>1 2024-05-16T13:09:55.931460Z APP-MTX-01 sshd 161779 - - Accepted password for jordan.lee from 10.66.10.23
//   May 16 13:40:26 app01 sshd[1234]: Failed password for invalid user admin from 203.0.113.9 port 41022 ssh2
//
// A host's syslog is raw telemetry, not a detection feed (same stance as ciscoAsaImport.ts /
// combinedLogImport.ts / kapeImport.ts) — so severity is Info by default, with a conservative Low
// bump only for the two generic, unambiguous signals syslog itself grades as noteworthy: an
// authentication FAILURE (the classic brute-force / access-abuse signal in auth/PAM logs), and a
// message whose syslog PRI severity is crit/alert/emerg (0–2). Auth SUCCESS and everyday daemon
// chatter stay Info. Nothing is dropped: like the ASA/combined-log importers, EVERY distinct
// message survives as its own aggregated event so downstream correlation/synthesis can judge it —
// this is exactly why plain syslog needs a deterministic importer rather than the AI line-triage
// path, which silently drops the rare high-signal line on a large, mostly-benign real log (a secret
// spilled into a one-off `app: loaded shared secret …` line is precisely what gets outvoted).
//
// The RFC 5424 timestamp is a full RFC 3339 value (year + timezone) — no guessing. The RFC 3164
// timestamp carries NO YEAR (`MMM DD HH:MM:SS`); like ASA/Snort an assumed year is stamped and the
// `mergeDelta` year-clamp re-anchors it once dated evidence lands. The host in the syslog line is
// carried through as the event's `asset`. Public IPs and http(s) URLs in the message become IOCs
// (RFC1918/loopback/CGNAT skipped, like the ASA/Snort importers). Pure, no AI. Reuses siemImport's
// aggregation + IOC sink.
//
// Cisco ASA is ALSO RFC-3164-framed, but it's detected ahead of this importer by its `%ASA-#-######`
// tag (see importDetect.ts), so an ASA export never reaches here.

import type { Severity } from "./stateTypes.js";
import {
  createEventAggregator,
  addIoc,
  cleanIp,
  isInternalIpv4,
  oneLine,
  parseBsdTime,
  worst,
  type MappedEvent,
  type SiemIoc,
  type SiemParseResult,
  maxEventsDefault,
} from "./siemImport.js";
import { throwIfImportAborted } from "./siemBuildProgress.js";
import { parseSshAuth, markSshBruteForce, type SshAuthEvent } from "./sshBruteForce.js";
import { secretSpillSignal } from "./secretSpillRules.js";

export interface SyslogImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  assumeYear?: number; // year stamped onto RFC 3164 (year-less) timestamps; default: current UTC year
}

export type SyslogParseResult = SiemParseResult;

export const SYSLOG_SOURCE = "Syslog";

// RFC 5424: "<PRI>VER TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG". The timestamp
// is RFC 3339 (starts with a 4-digit year), which anchors the line unambiguously.
const RFC5424_RE = /^<(\d{1,3})>\d{1,2}\s+(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/;
// RFC 3164: "[<PRI>]MMM DD HH:MM:SS HOSTNAME TAG[pid]: MSG". The trailing colon after the tag is
// required so an arbitrary "Mmm dd hh:mm:ss …" prose line isn't misclaimed.
const RFC3164_RE =
  /^(?:<(\d{1,3})>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s*(.*)$/;

// Auth-failure signals worth a Low bump — the generic brute-force / access-abuse markers that
// appear across sshd/PAM/sudo/su, independent of distro. Auth SUCCESS is deliberately NOT matched.
const AUTH_FAIL =
  /\b(?:failed password|authentication failure|invalid user|failed publickey|possible break-in attempt|failed login|incorrect password|authentication failed)\b/i;

const IPV4_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const URL_RE = /\bhttps?:\/\/[^\s"'<>()]+/gi;

// Strip the RFC 5424 STRUCTURED-DATA field ("-" or one-or-more "[…]" elements) off the front of the
// message remainder, leaving the free-text MSG.
function stripStructuredData(rest: string): string {
  const s = rest.replace(/^\s+/, "");
  if (s === "-") return "";
  if (s.startsWith("- ")) return s.slice(2).replace(/^\s+/, "");
  if (s.startsWith("[")) {
    let i = 0;
    while (s[i] === "[") {
      const close = s.indexOf("]", i);
      if (close === -1) break;
      i = close + 1;
    }
    return s.slice(i).replace(/^\s+/, "");
  }
  return s;
}

// Parse the RFC 5424 RFC-3339 timestamp (year + tz present) to a normalized ISO string. "" if bad.
function parse5424Time(ts: string): string {
  const t = Date.parse(ts.trim());
  return Number.isNaN(t) ? "" : new Date(t).toISOString();
}

interface ParsedSyslog {
  pri: number | null;
  timestamp: string;
  host: string;
  app: string;
  message: string;
  // TRUE only for RFC 3164, whose timestamp is `May 14 12:00:48` — no year, so `assumeYear` supplied
  // one. RFC 5424 carries a full RFC 3339 stamp and is therefore RECORDED, and one export routinely
  // mixes both framings. Tracking this per line rather than per file is what stops the merge's
  // year-clamp rewriting a real RFC 5424 timestamp that happens to be a minority year (#739).
  yearInferred: boolean;
}

// Parse one syslog line (RFC 5424 first, then RFC 3164). Returns null if neither framing matches.
export function parseSyslogLine(line: string, year: number): ParsedSyslog | null {
  const s = line.trim();
  const m5 = RFC5424_RE.exec(s);
  if (m5) {
    const [, priRaw, tsRaw, host, app, , , rest] = m5;
    return {
      pri: Number(priRaw),
      timestamp: parse5424Time(tsRaw),
      host: host === "-" ? "" : host,
      app: app === "-" ? "" : app,
      message: stripStructuredData(rest),
      yearInferred: false, // RFC 5424 timestamps carry their own year
    };
  }
  const m3 = RFC3164_RE.exec(s);
  if (m3) {
    const [, priRaw, tsRaw, host, tag, , msg] = m3;
    return {
      pri: priRaw != null ? Number(priRaw) : null,
      timestamp: parseBsdTime(tsRaw, year),
      host: host === "-" ? "" : host,
      app: tag,
      message: msg ?? "",
      yearInferred: true, // RFC 3164 is year-less; `year` above is the caller's guess
    };
  }
  return null;
}

// Is this text a plain syslog export? True when a meaningful share of the first non-blank lines
// carry the RFC 5424 or RFC 3164 framing. Conservative (>=3 hits and >=50%) so an arbitrary log
// that isn't syslog is left to the generic (AI) line-triage path.
export function looksLikeSyslog(text: string): boolean {
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(0, 50);
  if (!lines.length) return false;
  const hits = lines.filter((l) => RFC5424_RE.test(l) || RFC3164_RE.test(l)).length;
  return hits >= 3 && hits >= lines.length * 0.5;
}

// Map one parsed syslog line to a forensic event (collecting IOCs).
export function mapSyslogLine(line: string, year: number, sink: Map<string, SiemIoc>): MappedEvent | null {
  const p = parseSyslogLine(line, year);
  if (!p) return null;
  return mapParsedSyslog(p, sink);
}

// Map an already-parsed syslog record to a forensic event (collecting IOCs). Split out so parseSyslog
// can parse each line once and reuse the ParsedSyslog for both event mapping and sshd auth correlation.
function mapParsedSyslog(p: ParsedSyslog, sink: Map<string, SiemIoc>): MappedEvent {
  // IOCs from the free-text message: public IPs + http(s) URLs (and each URL's host as a domain).
  for (const ip of p.message.match(IPV4_RE) ?? []) {
    const clean = cleanIp(ip);
    if (clean && !isInternalIpv4(clean)) addIoc(sink, "ip", clean);
  }
  for (const url of p.message.match(URL_RE) ?? []) {
    addIoc(sink, "url", url);
    const host = url.match(/^https?:\/\/([^/:]+)/i)?.[1];
    if (host) addIoc(sink, "domain", host.toLowerCase());
  }

  const sev = p.pri != null ? p.pri % 8 : null;
  const base: Severity = (sev != null && sev <= 2) || AUTH_FAIL.test(p.message) ? "Low" : "Info";
  // An application that logs a token / password / connection string in the clear has spilled it to
  // every downstream log consumer. Medium so it reaches the forensic timeline synthesis reads —
  // syslog is otherwise Info-by-default, which demotes it to the analyst-only super-timeline.
  const spill = secretSpillSignal(p.message);
  const severity: Severity = spill ? worst(base, "Medium") : base;

  const appTag = p.app ? `${p.app}: ` : "";
  const description = oneLine(`syslog ${appTag}${p.message}`).slice(0, 600);
  // Collapse repetitive templated lines (rotating pids/session ids/counters) while keeping a
  // genuinely distinct message its own event: mask digit and hex runs in the aggregation key only.
  const template = p.message
    .replace(/0x[0-9a-f]+/gi, "#")
    .replace(/\d+/g, "#")
    .slice(0, 300);

  return {
    timestamp: p.timestamp,
    description,
    severity,
    mitre: spill?.mitre ?? [],
    // A spill-bearing line gets its own key: the template masks digit runs, so two different
    // tokens from the same daemon would otherwise collapse into one first-description-wins row.
    aggKey: `syslog|${p.host}|${p.app}|${template}${spill ? `|spill:${spill.families.join(",")}` : ""}`
      .toLowerCase()
      .slice(0, 400),
    sources: [SYSLOG_SOURCE],
    ...(p.host ? { asset: p.host } : {}),
    ...(p.yearInferred ? { yearInferred: true } : {}),
  };
}

// Streaming accumulator behind parseSyslog / parseSyslogProgress: each line is parsed, mapped, and
// fed straight into the shared event aggregator, so memory is bounded by the distinct-key set — not
// the row count. The ONE exception is an sshd login SUCCESS, which must be buffered until the whole
// log has been seen: the brute-force-success correlation is a post-pass that rewrites specific
// mapped events — and ONLY accepted ones, so successes are the only events held back (bounded by
// real logins, which are rare). A login FAILURE streams into the aggregator like any other line and
// contributes just a compact {ms, ip} tuple to the correlation — an auth.log flood of failed
// passwords (exactly the input this correlation targets) must not re-materialize the mapped events
// the streaming rework exists to avoid. finish() runs the correlation, folds the success buffer
// into the aggregator, and assembles the result. finish() re-sorts by severity/count/timestamp, so
// relative to the pre-streaming line-order feed, ordering only shifts on exact three-way ties.
function createSyslogAccumulator(opts: SyslogImportOptions): {
  line(raw: string): void;
  finish(): SyslogParseResult;
} {
  const year = opts.assumeYear ?? new Date().getUTCFullYear();
  const maxIocs = opts.maxIocs ?? 5000;
  const sink = new Map<string, SiemIoc>();
  const agg = createEventAggregator({
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  const sshEvents: MappedEvent[] = []; // ONLY accepted sshd logins — everything else streams into agg
  const sshAuth: SshAuthEvent<number>[] = []; // accepted keyed by index in `sshEvents`; failed carry key -1
  let total = 0;

  return {
    line(raw: string): void {
      const line = raw.trim();
      if (!line) return;
      const p = parseSyslogLine(line, year);
      if (!p) return;
      const m = mapParsedSyslog(p, sink);
      total++;
      // Hold back sshd login SUCCESSES for the brute-force-success correlation in finish() — the
      // only events markSshBruteForce ever rewrites. A FAILURE contributes just its {ms, ip} to the
      // correlation (its key is never read; -1 marks "not buffered") and streams into the
      // aggregator like any other line, so a failed-password flood cannot re-materialize the log.
      if (/^sshd\b/i.test(p.app)) {
        const auth = parseSshAuth(p.message);
        if (auth?.result === "accepted") {
          sshAuth.push({
            key: sshEvents.push(m) - 1,
            ms: Date.parse(p.timestamp) || 0,
            ip: auth.ip,
            result: "accepted",
          });
          return;
        }
        if (auth) {
          sshAuth.push({ key: -1, ms: Date.parse(p.timestamp) || 0, ip: auth.ip, result: "failed" });
        }
      }
      agg.add(m);
    },
    finish(): SyslogParseResult {
      // A successful SSH login preceded by a burst of failures from the same IP = brute force that
      // landed (T1110.001). Escalate that accepted event to Medium and keep it a DISTINCT aggregation
      // group (its digit-masked key would otherwise fold it in with benign accepted logins).
      for (const hit of markSshBruteForce(sshAuth)) {
        const e = sshEvents[hit.key];
        e.severity = worst(e.severity, "Medium");
        if (!e.mitre.includes("T1110.001")) e.mitre.push("T1110.001");
        e.description =
          `${e.description} — SSH login succeeded after ${hit.failures} failed attempts from ${hit.ip} (possible brute-force success)`.slice(
            0,
            600,
          );
        e.aggKey = `${e.aggKey}|bruteforce|${hit.ip}`.slice(0, 400);
      }
      for (const m of sshEvents) agg.add(m);

      const { events, groups } = agg.finish();
      const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);

      return {
        events,
        iocs: [...sink.values()].slice(0, maxIocs),
        total,
        kept: events.length,
        dropped: Math.max(0, total - represented),
        groups,
        format: "syslog",
        hostname: "",
      };
    },
  };
}

// Parse a plain syslog export into the shared SIEM result shape (aggregated + capped). Pure, no AI.
// Lines are walked with an indexOf cursor — never split into an all-lines array — so peak retention
// beyond the input text is the aggregator's distinct-key set plus the accepted-sshd-login buffer.
export function parseSyslog(text: string, opts: SyslogImportOptions = {}): SyslogParseResult {
  const acc = createSyslogAccumulator(opts);
  let cursor = 0;
  while (cursor <= text.length) {
    const nl = text.indexOf("\n", cursor);
    const end = nl === -1 ? text.length : nl;
    acc.line(text.slice(cursor, end));
    cursor = end + 1;
  }
  return acc.finish();
}

const SYSLOG_CHUNK_LINES = 5000;
// Counting newlines is far cheaper per iteration than parsing, so it yields on a coarser budget —
// but it MUST yield, or a multi-million-line input would block the event loop (and any pending
// cancellation) for the whole count before the parse loop's first await.
const SYSLOG_COUNT_CHUNK = 1_000_000;

// parseSyslog for the import route: identical result, but yields to the event loop (reporting
// done/total lines) every SYSLOG_CHUNK_LINES and honors the job's AbortSignal — a multi-million-line
// export must not stall every other request for the whole parse. Mirrors parseWinEventXmlProgress.
// The sync parseSyslog stays for tests and non-route callers.
export async function parseSyslogProgress(
  text: string,
  opts: SyslogImportOptions = {},
  onProgress?: (done: number, total: number) => void | Promise<void>,
  signal?: AbortSignal,
): Promise<SyslogParseResult> {
  throwIfImportAborted(signal);
  // Count newline-separated segments in yieldable chunks (the trailing empty segment after the last
  // newline is included, matching the cursor loop below) so the count itself cannot stall the event
  // loop or a pending cancellation on a huge input.
  let total = 1;
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) {
    total++;
    if (total % SYSLOG_COUNT_CHUNK === 0) {
      await new Promise<void>((resolve) => setImmediate(resolve));
      throwIfImportAborted(signal);
    }
  }

  const acc = createSyslogAccumulator(opts);
  let scanned = 0;
  let cursor = 0;
  while (cursor <= text.length) {
    const nl = text.indexOf("\n", cursor);
    const end = nl === -1 ? text.length : nl;
    acc.line(text.slice(cursor, end));
    cursor = end + 1;
    scanned++;
    if (scanned % SYSLOG_CHUNK_LINES === 0) {
      await onProgress?.(scanned, total);
      await new Promise<void>((resolve) => setImmediate(resolve));
      throwIfImportAborted(signal);
    }
  }
  if (scanned % SYSLOG_CHUNK_LINES !== 0) await onProgress?.(scanned, total);
  throwIfImportAborted(signal);
  return acc.finish();
}
