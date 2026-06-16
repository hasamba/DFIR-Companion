// Interpreter that turns a validated ImporterSpec (pure data) into an ExternalImporter the
// detection seam + pipeline can run. Reuses the existing siemImport mapping helpers, so its output
// is the SAME SiemParseResult every built-in importer returns. NO code from the spec is executed —
// only declarative field bindings + length-bounded regex tests (ReDoS-guarded).
import type { Severity } from "./stateTypes.js";
import {
  extractRecords, aggregateEvents, addIoc, genericIocs, cleanIp, normalizeTime,
  getCI, getPath, str,
  type SiemIoc, type MappedEvent, type SiemParseResult,
} from "./siemImport.js";
import { parseCsv } from "./csvImport.js";
import type { ImporterSpec } from "./importerSpec.js";

type Row = Record<string, unknown>;

// Same shape as importDetect.ts's DetectContext (kept structurally compatible).
export interface EngineDetectContext {
  filename: string;
  text: string;
  root: unknown;
  sample: Row | null;
  csvHeaders: Set<string> | null;
}

export interface ExternalImporter {
  id: string;
  label: string;
  priority: number;
  detect(ctx: EngineDetectContext): boolean;
  parse(text: string, opts?: { minSeverity?: Severity }): SiemParseResult;
}

// Compile a user regex defensively: invalid → null (never throws); callers bound the tested input.
function safeRegex(src: string): RegExp | null {
  try { return new RegExp(src); } catch { return null; }
}
function getField(rec: Row, key: string): unknown {
  return key.includes(".") ? getPath(rec, key) : getCI(rec, key);
}

export function buildImporter(spec: ImporterSpec): ExternalImporter {
  const fnameRe = spec.match.filenamePattern ? safeRegex(spec.match.filenamePattern) : null;
  const keyEquals = Object.entries(spec.match.keyEquals ?? {}).map(([k, p]) => [k, safeRegex(p)] as const);

  const detect = (ctx: EngineDetectContext): boolean => {
    if (fnameRe && !fnameRe.test((ctx.filename ?? "").slice(0, 1024))) return false;

    const fmt = spec.match.format;
    const wantJson = fmt === "json" || fmt === "ndjson";
    const wantCsv = fmt === "csv";
    if (wantJson && !ctx.sample) return false;
    if (wantCsv && !ctx.csvHeaders) return false;

    if (spec.match.requireHeaders || spec.match.anyHeaders) {
      const h = ctx.csvHeaders;
      if (!h) return false;
      if (spec.match.requireHeaders && !spec.match.requireHeaders.every((x) => h.has(x.toLowerCase()))) return false;
      if (spec.match.anyHeaders && !spec.match.anyHeaders.some((x) => h.has(x.toLowerCase()))) return false;
    }

    if (spec.match.requireKeys || spec.match.anyKeys || keyEquals.length) {
      const s = ctx.sample;
      if (!s) return false;
      if (spec.match.requireKeys && !spec.match.requireKeys.every((k) => getField(s, k) != null)) return false;
      if (spec.match.anyKeys && !spec.match.anyKeys.some((k) => getField(s, k) != null)) return false;
      for (const [k, re] of keyEquals) {
        if (!re || !re.test(str(getField(s, k)).slice(0, 4096))) return false;
      }
    }
    return true;
  };

  return { id: spec.id, label: spec.label, priority: spec.match.priority, detect, parse: buildParse(spec) };
}

function applyTransform(v: string, t?: string): string {
  switch (t) {
    case "trim": return v.trim();
    case "lowercase": return v.toLowerCase();
    case "basename": return v.trim().split(/[\\/]/).pop() || v.trim();
    case "cleanIp": return cleanIp(v);
    case "defang": return v.replace(/:\/\//g, "[://]").replace(/\./g, "[.]");
    case "refang": return v.replace(/\[\.\]/g, ".").replace(/\[:\/\/\]/g, "://").replace(/hxxp/gi, "http");
    default: return v;
  }
}

function bindStr(rec: Row, b: { from: string[]; transform?: string; join?: string }): string {
  if (b.join) {
    const parts = b.from.map((k) => str(getField(rec, k)).trim()).filter(Boolean);
    return parts.length ? applyTransform(parts.join(b.join), b.transform) : "";
  }
  for (const k of b.from) {
    const raw = str(getField(rec, k)).trim();
    if (raw) return applyTransform(raw, b.transform);
  }
  return "";
}

// Column-aware {{name}} substitution — column names may contain spaces, so we cannot reuse the
// reportTemplate {{\w+}} engine. No helpers, no nested logic → no injection surface.
function renderDesc(template: string, rec: Row): string {
  return template
    .replace(/\{\{\s*([^}]+?)\s*\}\}/g, (_m, key: string) => str(getField(rec, key.trim())).trim())
    .replace(/\s+/g, " ")
    .trim();
}

const TID = /\bT\d{4}(?:\.\d{3})?\b/gi;
function resolveMitre(rec: Row, b: ImporterSpec["map"]["mitre"]): string[] {
  if (!b) return [];
  if ("fixed" in b) return [...new Set(b.fixed.map((t) => t.toUpperCase()))];
  const raw = bindStr(rec, b);
  return [...new Set((raw.match(TID) ?? []).map((t) => t.toUpperCase()))];
}

function resolveSeverity(rec: Row, b: ImporterSpec["map"]["severity"]): Severity {
  if (!b) return "Info";
  if (typeof b === "string") return b;
  const raw = bindStr(rec, b);
  if (raw && b.map) {
    const hit = b.map[raw] ?? Object.entries(b.map).find(([k]) => k.toLowerCase() === raw.toLowerCase())?.[1];
    if (hit) return hit;
  }
  return b.default ?? "Info";
}

function resolveTs(rec: Row, b: ImporterSpec["map"]["timestamp"]): string {
  const raw = bindStr(rec, b);
  if (!raw) return "";
  if (b.format === "epoch_s" || b.format === "epoch_ms") {
    const n = Number(raw);
    if (!Number.isFinite(n)) return "";
    return normalizeTime(new Date(b.format === "epoch_s" ? n * 1000 : n).toISOString());
  }
  return normalizeTime(raw);
}

function rowsOf(text: string, format: string): { rows: Row[]; format: string } {
  const t = text.trim();
  const json = format === "json" || format === "ndjson" || (format === "auto" && (t[0] === "{" || t[0] === "["));
  if (json) {
    const { records, format: f } = extractRecords(text);
    return { rows: records, format: f };
  }
  const { headers, rows } = parseCsv(text);
  const objs = rows.map((cells) => {
    const o: Row = {};
    headers.forEach((h, i) => { o[h] = cells[i] ?? ""; });
    return o;
  });
  return { rows: objs, format: "csv" };
}

function buildParse(spec: ImporterSpec): ExternalImporter["parse"] {
  const m = spec.map;
  return (text, opts) => {
    const { rows, format } = rowsOf(text, spec.match.format);
    const iocSink = new Map<string, SiemIoc>();
    const mapped: MappedEvent[] = [];
    let host = "";

    for (const rec of rows) {
      let description = renderDesc(m.description, rec);
      if (!description) continue;
      const userVal = m.user ? bindStr(rec, m.user) : "";
      if (userVal) description = `${description} (user ${userVal})`;
      const severity = resolveSeverity(rec, m.severity);
      const asset = m.asset ? bindStr(rec, m.asset) : "";
      if (asset && !host) host = asset;

      const opt = (key: keyof typeof m, name: string): Record<string, string> => {
        const b = m[key] as { from: string[]; transform?: string } | undefined;
        if (!b) return {};
        const v = bindStr(rec, b);
        return v ? { [name]: v } : {};
      };

      mapped.push({
        timestamp: resolveTs(rec, m.timestamp),
        description,
        severity,
        mitre: resolveMitre(rec, m.mitre),
        aggKey: `${severity}|${description}`,
        ...(asset ? { asset } : {}),
        ...opt("sha256", "sha256"),
        ...opt("md5", "md5"),
        ...opt("path", "path"),
        ...opt("processName", "processName"),
        ...opt("parentName", "parentName"),
        ...opt("srcIp", "srcIp"),
        ...opt("dstIp", "dstIp"),
        ...(m.port ? (() => { const v = bindStr(rec, m.port!); const n = Number(v); return Number.isFinite(n) && v ? { port: n } : {}; })() : {}),
      });

      for (const rule of m.iocs ?? []) {
        if ("autoExtract" in rule) {
          genericIocs(rule.autoExtract.map((k) => [k, str(getField(rec, k))] as [string, string]), iocSink);
        } else {
          for (const k of rule.from) {
            const v = applyTransform(str(getField(rec, k)).trim(), rule.transform);
            if (v) addIoc(iocSink, rule.type, v);
          }
        }
      }
    }

    const { events, groups } = aggregateEvents(mapped, {
      aggregate: spec.options.aggregate,
      minSeverity: opts?.minSeverity ?? spec.options.minSeverity,
      maxEvents: spec.options.maxEvents,
    });
    let iocs = [...iocSink.values()];
    if (spec.options.maxIocs && iocs.length > spec.options.maxIocs) iocs = iocs.slice(0, spec.options.maxIocs);
    return { events, iocs, total: rows.length, kept: events.length, dropped: rows.length - events.length, groups, format, hostname: host };
  };
}
