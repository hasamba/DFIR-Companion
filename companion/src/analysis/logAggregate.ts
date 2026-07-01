// Deterministic log reduction: collapse many near-identical log lines into a small
// set of counted "templates" BEFORE the AI sees them. A firewall/VPN/syslog file is
// mostly repetition (rekeying, retransmissions, heartbeats) — emitting one forensic
// event per line floods the timeline and burns API quota. Instead we group lines by
// a normalized template (variable tokens masked), count occurrences, and record the
// first/last time each pattern was seen. The AI then decides which TEMPLATES are
// suspicious and writes one aggregated event per template ("20 failed logins …").
//
// This is intentionally simple and dependency-free (a poor-man's Drain/logreduce):
// mask volatile numeric tokens, keep words and IP addresses, group by the result.

export interface LogTemplate {
  template: string;        // normalized pattern (volatile tokens masked) — the group key
  count: number;           // how many raw lines collapsed into this template
  firstTimestamp: string;  // leading timestamp of the first occurrence (best effort, "" if none)
  lastTimestamp: string;   // leading timestamp of the last occurrence
  example: string;         // a representative raw line (the first occurrence)
}

// Leading-timestamp detectors, tried in order. Best-effort: used only to report a
// pattern's first/last time. If none match we leave it blank and let the AI read the
// time from the example line. Order matters (more specific first).
const TS_PATTERNS: RegExp[] = [
  /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/, // ISO-8601
  /^\[\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?\]/,          // Apache "[28/May/2026:09:00:01 +0000]"
  /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/,                              // RFC 3164 syslog "May 28 09:00:01"
  /^\d{10,13}\b/,                                                              // epoch seconds/millis
];

// Pull a leading timestamp off a line. Returns the matched timestamp (or "") and the
// remainder of the line with that timestamp removed (so it doesn't pollute the template).
export function splitLeadingTimestamp(line: string): { timestamp: string; rest: string } {
  for (const re of TS_PATTERNS) {
    const m = re.exec(line);
    if (m) return { timestamp: m[0].trim(), rest: line.slice(m[0].length).trim() };
  }
  return { timestamp: "", rest: line };
}

// A digit-free placeholder (private-use code point) that the `\d+ → N` mask can't
// touch, so protected IP addresses survive masking and can be restored afterwards.
const IP_SENTINEL = String.fromCharCode(0xe000);

// Normalize a (timestamp-stripped) line into a template by masking volatile tokens.
// IP addresses are PRESERVED — a source IP is forensically meaningful, so a brute
// force from ONE host groups together while distributed sources stay distinct.
// Everything else numeric (sequence numbers, counters, #ids, hex, ports, the trailing
// _N of identifiers) collapses to a placeholder so repetitions group.
export function templateizeLine(rest: string): string {
  // Swap each IP for the digit-free sentinel, mask the rest, then restore IPs in order.
  const ips: string[] = [];
  let s = rest.replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, (ip) => {
    ips.push(ip);
    return IP_SENTINEL;
  });
  s = s
    .replace(/\b0x[0-9a-fA-F]+\b/g, "HEX") // hex literals → digit-free token (survives the digit mask)
    .replace(/#\d+/g, "#N")                // #ids (e.g. "#871204")
    .replace(/\d+/g, "N")                  // any remaining digit run
    .replace(/\s+/g, " ")                  // collapse whitespace
    .trim();
  let k = 0;
  s = s.split(IP_SENTINEL).reduce((acc, part, i) => (i === 0 ? part : acc + (ips[k++] ?? "") + part), "");
  return s;
}

export interface AggregateOptions {
  // Cap on the number of templates returned. Protects the AI call from a pathological
  // log with thousands of distinct patterns.
  maxTemplates?: number;
}

// Group log lines into counted templates. Order within a count tie follows first
// appearance, so the output is stable/deterministic.
export function aggregateLogLines(lines: readonly string[], opts: AggregateOptions = {}): LogTemplate[] {
  const groups = new Map<string, LogTemplate>();
  const insertionOrder = new Map<string, number>();
  let order = 0;

  for (const line of lines) {
    const { timestamp, rest } = splitLeadingTimestamp(line);
    const template = templateizeLine(rest);
    const existing = groups.get(template);
    if (existing) {
      existing.count += 1;
      existing.lastTimestamp = timestamp || existing.lastTimestamp;
    } else {
      groups.set(template, { template, count: 1, firstTimestamp: timestamp, lastTimestamp: timestamp, example: line });
      insertionOrder.set(template, order++);
    }
  }

  const all = [...groups.values()];
  const byInsertion = (a: LogTemplate, b: LogTemplate): number =>
    insertionOrder.get(a.template)! - insertionOrder.get(b.template)!;
  const byCountDesc = (a: LogTemplate, b: LogTemplate): number => b.count - a.count || byInsertion(a, b);

  const max = opts.maxTemplates ?? 400;
  if (all.length <= max) return all.sort(byCountDesc);

  // Truncation needed. A naive "most frequent first" cap silently drops RARE templates once a log
  // has more than `max` distinct patterns — but a rare (often count=1) template is exactly where a
  // one-off attack line (a single unusual upload, a lone 403 on a sensitive path) lives; the
  // thousands of repetitive baseline lines it's competing with are the LEAST likely to be signal.
  // So truncate the FREQUENT end instead: sort rarest-first, keep up to `max`, then restore the
  // frequency-first presentation order the AI prompt expects.
  const kept = [...all].sort((a, b) => a.count - b.count || byInsertion(a, b)).slice(0, max);
  return kept.sort(byCountDesc);
}
