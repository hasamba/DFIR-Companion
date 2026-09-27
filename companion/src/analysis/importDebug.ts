import { BUILTIN_KINDS } from "./importerSpec.js";
import { safeColumnName } from "./importShape.js";

/**
 * Per-import debug detail (#1736): what an importer DECIDED while it read a file — which source
 * column fed each event field, how many rows it skipped and why, which fallback it took, and where
 * a parse failed. It goes to the always-on debug log and, for a failed import, into the redacted
 * support bundle (#1735), which does NOT run this through its text redactor (a field path such as
 * `host.name` would read as a domain). So this module is the privacy boundary, and it is fail-closed:
 *
 * - Source column names pass only the support bundle's generic-column allowlist; anything else is
 *   `<unlisted>`. Never a value.
 * - Event-field targets are a closed list. Reasons, observations and fallbacks are code-authored
 *   slugs; anything else becomes `other`.
 * - A custom importer's id is analyst-authored and can carry a client or incident name, so the kind
 *   is recorded as `custom`. Only built-in kinds keep their name.
 * - Counts are non-negative safe integers and saturate. Every map is capped and says so.
 *
 * One recorder belongs to one import attempt. Whoever starts the attempt creates it, passes it in
 * the importer's options as `debug`, and hands it to the terminal seam (success line, failure ring).
 * Nothing looks a recorder up by name, so two attempts on the same file cannot swap details.
 */

export const DEBUG_TARGETS = [
  "timestamp",
  "host",
  "user",
  "message",
  "severity",
  "event_id",
  "source_ip",
  "dest_ip",
  "source_port",
  "dest_port",
  "process",
  "parent_process",
  "command_line",
  "path",
  "hash",
  "rule",
  "channel",
  "provider",
  "url",
  "domain",
  "action",
  "protocol",
  "category",
] as const;
export type DebugTarget = (typeof DEBUG_TARGETS)[number];
const TARGET_SET: ReadonlySet<string> = new Set(DEBUG_TARGETS);

/** Why a row, a key or a decision happened. Code-authored, never data-derived. */
const SLUG = /^[a-z][a-z0-9_]{0,48}$/;
const OTHER = "other";
const MAX_TARGETS = DEBUG_TARGETS.length;
const MAX_SOURCES_PER_TARGET = 16;
const MAX_CODES = 32;
const PHASES = new Set(["detect", "read", "parse", "map", "merge", "settle", "ai"]);

export type { ImportDebugSummary, ImportOutcome } from "./importDebugTypes.js";
import type { ImportDebugSummary, ImportOutcome } from "./importDebugTypes.js";

export interface ImportDebugRecorder {
  detected(kind: string, detection?: { confident: boolean; decision: string }): void;
  field(target: DebugTarget, source: string, n?: number): void;
  skipped(reason: string, n?: number): void;
  omitted(reason: string, n?: number): void;
  observed(code: string, n?: number): void;
  fallback(code: string, n?: number): void;
  counts(c: { total?: number; kept?: number; dropped?: number }): void;
  failedAt(phase: string, row?: number): void;
  finish(outcome: ImportOutcome): void;
  summary(): ImportDebugSummary;
}

function safeInt(n: unknown): number | undefined {
  if (typeof n !== "number" || !Number.isFinite(n) || n < 0) return undefined;
  return Math.min(Math.floor(n), Number.MAX_SAFE_INTEGER);
}

function slug(code: unknown): string {
  return typeof code === "string" && SLUG.test(code) ? code : OTHER;
}

export function safeKind(kind: unknown): string {
  if (typeof kind !== "string" || kind === "") return "unknown";
  return BUILTIN_KINDS.has(kind) ? kind : "custom";
}

type Counter = Map<string, number>;

function bump(map: Counter, key: string, n: number, cap: number, onCap: () => void): void {
  if (!map.has(key) && map.size >= cap) return onCap();
  map.set(key, Math.min((map.get(key) ?? 0) + n, Number.MAX_SAFE_INTEGER));
}

/** A null-prototype plain object from a Map, so a key such as `__proto__` stays data. */
function toRecord(map: Counter): Record<string, number> {
  const out = Object.create(null) as Record<string, number>;
  for (const [k, v] of map) out[k] = v;
  return out;
}

export function createImportDebugRecorder(): ImportDebugRecorder {
  let kind = "unknown";
  let detection: ImportDebugSummary["detection"];
  const counts: ImportDebugSummary["counts"] = {};
  const fields = new Map<string, Counter>();
  const skipped: Counter = new Map();
  const omitted: Counter = new Map();
  const observations: Counter = new Map();
  const fallbacks: Counter = new Map();
  let failure: ImportDebugSummary["failure"];
  let outcome: ImportOutcome | undefined;
  let truncated = false;
  const capped = (): void => {
    truncated = true;
  };
  const inc = (map: Counter, code: string, n?: number): void => {
    const by = n === undefined ? 1 : safeInt(n);
    if (by === undefined || by === 0) return;
    bump(map, slug(code), by, MAX_CODES, capped);
  };

  return {
    detected(k, d) {
      kind = safeKind(k);
      if (d) detection = { confident: d.confident === true, decision: slug(d.decision) };
    },
    field(target, source, n) {
      if (!TARGET_SET.has(target)) return;
      const by = n === undefined ? 1 : safeInt(n);
      if (!by) return;
      let bySource = fields.get(target);
      if (!bySource) {
        if (fields.size >= MAX_TARGETS) return capped();
        fields.set(target, (bySource = new Map()));
      }
      bump(bySource, safeColumnName(String(source ?? "")), by, MAX_SOURCES_PER_TARGET, capped);
    },
    skipped: (r, n) => inc(skipped, r, n),
    omitted: (r, n) => inc(omitted, r, n),
    observed: (c, n) => inc(observations, c, n),
    fallback: (c, n) => inc(fallbacks, c, n),
    counts(c) {
      for (const key of ["total", "kept", "dropped"] as const) {
        const v = safeInt(c[key]);
        if (v !== undefined) counts[key] = v;
      }
    },
    failedAt(phase, row) {
      const r = safeInt(row);
      failure = { phase: PHASES.has(phase) ? phase : OTHER, ...(r !== undefined ? { row: r } : {}) };
    },
    finish(o) {
      outcome = o;
    },
    summary() {
      const f = Object.create(null) as Record<string, Record<string, number>>;
      for (const [t, m] of fields) f[t] = toRecord(m);
      return Object.freeze({
        kind,
        ...(detection ? { detection: { ...detection } } : {}),
        counts: { ...counts },
        fields: f,
        skipped: toRecord(skipped),
        omitted: toRecord(omitted),
        observations: toRecord(observations),
        fallbacks: toRecord(fallbacks),
        ...(failure ? { failure: { ...failure } } : {}),
        ...(outcome ? { outcome } : {}),
        truncated,
      });
    },
  };
}

function cleanCounter(v: unknown, keyOk: (k: string) => boolean, cap: number): Record<string, number> {
  const out = Object.create(null) as Record<string, number>;
  if (!v || typeof v !== "object") return out;
  let n = 0;
  for (const [k, raw] of Object.entries(v)) {
    const c = safeInt(raw);
    if (!keyOk(k) || c === undefined || n >= cap) continue;
    out[k] = c;
    n++;
  }
  return out;
}

/**
 * Re-validate a summary at a trust boundary (the diagnostics ring, the support bundle). A summary
 * built by createImportDebugRecorder already passes; this stops anything else — a future caller that
 * hand-builds one — from carrying a value past the redactor that this data bypasses.
 */
export function sanitizeImportDebugSummary(input: unknown): ImportDebugSummary | undefined {
  if (!input || typeof input !== "object") return undefined;
  const s = input as Partial<ImportDebugSummary>;
  const slugOk = (k: string): boolean => SLUG.test(k);
  const fields = Object.create(null) as Record<string, Record<string, number>>;
  if (s.fields && typeof s.fields === "object") {
    for (const [t, m] of Object.entries(s.fields)) {
      if (!TARGET_SET.has(t)) continue;
      fields[t] = cleanCounter(m, (k) => safeColumnName(k) === k, MAX_SOURCES_PER_TARGET);
    }
  }
  const c = s.counts ?? {};
  const counts: ImportDebugSummary["counts"] = {};
  for (const key of ["total", "kept", "dropped"] as const) {
    const v = safeInt((c as Record<string, unknown>)[key]);
    if (v !== undefined) counts[key] = v;
  }
  const failurePhase = s.failure?.phase;
  const failureRow = safeInt(s.failure?.row);
  return {
    kind: safeKind(s.kind),
    ...(s.detection
      ? { detection: { confident: s.detection.confident === true, decision: slug(s.detection.decision) } }
      : {}),
    counts,
    fields,
    skipped: cleanCounter(s.skipped, slugOk, MAX_CODES),
    omitted: cleanCounter(s.omitted, slugOk, MAX_CODES),
    observations: cleanCounter(s.observations, slugOk, MAX_CODES),
    fallbacks: cleanCounter(s.fallbacks, slugOk, MAX_CODES),
    ...(s.failure
      ? {
          failure: {
            phase: typeof failurePhase === "string" && PHASES.has(failurePhase) ? failurePhase : OTHER,
            ...(failureRow !== undefined ? { row: failureRow } : {}),
          },
        }
      : {}),
    ...(s.outcome === "succeeded" || s.outcome === "failed" || s.outcome === "cancelled"
      ? { outcome: s.outcome }
      : {}),
    truncated: s.truncated === true,
  };
}

/**
 * The one debug-log line for an import's decisions. No file name: a label is chosen by the analyst
 * or an adversary, and an unstructured line is only safe in the support bundle when every
 * identifying part sits where the redactor looks for it. The caseId goes in the line's scope.
 */
export function formatImportDebugLine(summary: ImportDebugSummary): string {
  return `[import-debug] importer ${summary.kind}: ${JSON.stringify(summary)}`;
}
