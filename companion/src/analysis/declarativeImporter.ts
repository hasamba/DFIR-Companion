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

// Implemented in Task 3 — temporary stub returning an empty result.
function buildParse(spec: ImporterSpec): ExternalImporter["parse"] {
  return () => ({ events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format: "empty", hostname: "" });
}
