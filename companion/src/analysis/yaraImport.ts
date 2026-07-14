// Deterministic importer for YARA CLI scan output (`yara -s -m [-g] <rules> <target>`). YARA is a
// DETECTOR, so this consumes its verdict (which rule matched which file) rather than evaluating rules
// itself — the same "ingest the tool's output" stance as the Chainsaw/Hayabusa/Snort importers, and
// consistent with the product principle (CLAUDE.md). There is no pre-existing importer for raw YARA
// output, so this is the one genuinely-new importer in the external-tools feature (#211).
//
// YARA's default text output is one MATCH-HEADER line per (rule, file):
//
//   EvilRule [apt,trojan] [author="x",score=85,sha256="ab…"] C:\evidence\a.dll
//   0x1a2b:$s1: 4d 5a 90 00
//   0x3c4d:$s2: this program cannot be run
//
// The optional `[…]` blocks are tags (`-g`, comma list, no `=`) and/or metadata (`-m`, key=value).
// `-s` adds indented `0xOFFSET:$id:` string-match lines under the header. YARA output carries NO
// timestamp (it's a scan result), so events are undated and mergeDelta stamps them at import time.
// Severity defaults to Medium (a match is a real detection) and is bumped ONLY on an explicit rule-meta
// signal (score / threat_level / severity) — never inferred from the rule name. Matched file → file IOC;
// hash meta → hash IOC. Pure, no AI. Reuses siemImport's helpers.

import type { Severity } from "./stateTypes.js";
import { aggregateEvents, addIoc, oneLine, type MappedEvent, type SiemIoc, type SiemParseResult,
  maxEventsDefault,
} from "./siemImport.js";

export interface YaraImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export const YARA_SOURCE = "YARA";

const STRING_LINE = /^\s*0x[0-9a-fA-F]+:(\$[A-Za-z0-9_*]+):/;
const HEADER_LINE = /^[A-Za-z_]\w*\s+\S/;
const HEX_HASH = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const MITRE_RE = /\bT\d{4}(?:\.\d{3})?\b/g;
// A tail that looks like a scanned path/file (has a separator or a dotted extension) — used to gate
// DETECTION so an arbitrary "Word something" log line isn't mistaken for a YARA header.
const PATHISH = /[\\/]|\.[A-Za-z0-9]{1,8}(?:$|\s)/;

interface YaraMatch {
  rule: string;
  file: string;
  tags: string[];
  meta: Record<string, string>;
  strings: string[];
}

// Split a metadata block on commas, honoring double-quoted values (which may contain commas).
function splitMeta(block: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let inQ = false;
  for (const ch of block) {
    if (ch === '"') { inQ = !inQ; cur += ch; }
    else if (ch === "," && !inQ) { parts.push(cur); cur = ""; }
    else cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  return parts;
}

// Parse a YARA match-header line into rule + tags + meta + file. Returns null if it isn't a header.
function parseHeader(line: string): YaraMatch | null {
  const m = line.match(/^([A-Za-z_]\w*)\s+(.*)$/);
  if (!m) return null;
  const rule = m[1];
  let rest = m[2].trim();
  const tags: string[] = [];
  const meta: Record<string, string> = {};
  // Consume leading `[ … ]` blocks: a block containing `=` is metadata, otherwise a tag list.
  while (rest.startsWith("[")) {
    const end = rest.indexOf("]");
    if (end < 0) break;
    const block = rest.slice(1, end);
    rest = rest.slice(end + 1).trim();
    if (block.includes("=")) {
      for (const kv of splitMeta(block)) {
        const eq = kv.indexOf("=");
        if (eq <= 0) continue;
        const k = kv.slice(0, eq).trim().toLowerCase();
        let v = kv.slice(eq + 1).trim();
        if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
        if (k) meta[k] = v;
      }
    } else {
      for (const t of block.split(",")) { const tt = t.trim(); if (tt) tags.push(tt); }
    }
  }
  const file = rest.trim();
  if (!file) return null;
  return { rule, file, tags, meta, strings: [] };
}

// Is this text YARA CLI scan output? True when a meaningful share of the first lines are match-headers
// (with a path-ish target) or `-s` string lines. Pure. Conservative so a stray log line doesn't trip it.
export function looksLikeYara(text: string): boolean {
  const lines = text.split(/\r?\n/).map((l) => l.replace(/\s+$/, "")).filter((l) => l.trim()).slice(0, 100);
  if (!lines.length) return false;
  let headers = 0;
  let strings = 0;
  for (const l of lines) {
    if (STRING_LINE.test(l)) { strings++; continue; }
    if (HEADER_LINE.test(l)) {
      const h = parseHeader(l.trim());
      if (h && PATHISH.test(h.file)) headers++;
    }
  }
  return headers >= 1 && headers + strings >= lines.length * 0.5;
}

function severityFromMeta(meta: Record<string, string>): Severity {
  const score = Number(meta.score ?? meta.severity_score ?? "");
  const level = (meta.threat_level ?? meta.threatlevel ?? meta.severity ?? "").toLowerCase();
  if ((Number.isFinite(score) && score >= 90) || level === "critical") return "Critical";
  if ((Number.isFinite(score) && score >= 70) || level === "high") return "High";
  return "Medium";
}

function mitreFromYara(tags: string[], meta: Record<string, string>): string[] {
  const hay = [...tags, ...Object.values(meta)].join(" ");
  const out = new Set<string>();
  for (const m of hay.matchAll(MITRE_RE)) out.add(m[0].toUpperCase());
  return [...out];
}

// Parse YARA scan output into the shared SIEM result shape (aggregated + capped). Pure.
export function parseYaraOutput(text: string, opts: YaraImportOptions = {}): SiemParseResult {
  const matches: YaraMatch[] = [];
  let cur: YaraMatch | null = null;

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, "");
    if (!line.trim()) continue;
    const sm = line.match(STRING_LINE);
    if (sm) { if (cur && cur.strings.length < 20) cur.strings.push(sm[1]); continue; }
    const h = HEADER_LINE.test(line.trim()) ? parseHeader(line.trim()) : null;
    if (h) { cur = h; matches.push(h); continue; }
    cur = null;   // an unrecognized line ends the current match's string run
  }

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = matches.map((ev) => {
    if (ev.file && ev.file !== "-") addIoc(sink, "file", ev.file.slice(0, 300));
    for (const key of ["hash", "sha256", "md5", "sha1", "imphash"]) {
      const v = ev.meta[key]?.trim();
      if (v && HEX_HASH.test(v)) addIoc(sink, "hash", v.toLowerCase());
    }
    const sha = HEX_HASH.test((ev.meta.sha256 ?? "").trim()) ? ev.meta.sha256.trim().toLowerCase() : undefined;
    const md5 = HEX_HASH.test((ev.meta.md5 ?? "").trim()) ? ev.meta.md5.trim().toLowerCase() : undefined;
    const desc = `YARA: ${ev.rule} matched ${ev.file}` +
      (ev.tags.length ? ` [${ev.tags.join(", ")}]` : "") +
      (ev.strings.length ? ` (${ev.strings.slice(0, 8).join(", ")})` : "");
    return {
      timestamp: "",   // no event time in YARA output — mergeDelta stamps it at import time
      description: oneLine(desc).slice(0, 600),
      severity: severityFromMeta(ev.meta),
      mitre: mitreFromYara(ev.tags, ev.meta),
      aggKey: `yara|${ev.rule.toLowerCase()}|${ev.file.toLowerCase()}`.slice(0, 400),
      sources: [YARA_SOURCE],
      path: ev.file.slice(0, 300),
      ...(sha ? { sha256: sha } : {}),
      ...(md5 ? { md5 } : {}),
    };
  });

  const total = matches.length;
  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);

  return {
    events,
    iocs: [...sink.values()].slice(0, opts.maxIocs ?? 5000),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format: "yara",
    hostname: "",
  };
}
