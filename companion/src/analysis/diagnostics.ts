// Operator-facing Health / Diagnostics (#118). PURE logic only — no I/O, no network.
// The route in server.ts gathers the raw inputs (disk stats, case list, in-memory queue
// state, import audit timestamps) and feeds them to these functions, which aggregate,
// classify, and REDACT them into a shareable report. Keeping the transforms pure makes the
// whole surface unit-testable without spinning up a server or touching the filesystem.
import { isLocalAiProvider } from "./anonymize.js";
import { visionEnv } from "../config/aiEnv.js";
import type { DiskStats, DiskWarningLevel, DiskWarnThresholds } from "./diskWarn.js";
import type { ImporterLoadError } from "./importerStore.js";

/** Human-readable byte size (binary units, 1 decimal place under 100). */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

/** Compact age like "3m", "2h", "5d" from a millisecond duration (negative → "0s"). */
export function formatAge(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "0s";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

// ── AI config sanity (REDACTED — never carries an API key) ──────────────────────────────
// All fields here are non-secret config: provider names, model ids, base URLs, numeric
// bounds. API keys (DFIR_VISION_KEY etc.) are deliberately NOT read so they can never leak into
// the diagnostics payload or the copy-to-clipboard blob.
export interface AiDiagnostics {
  configured: boolean;
  provider: string | null;
  model: string | null;
  synthModel: string | null;
  secondOpinionModel: string | null;
  velociraptorModel: string | null;
  baseUrl: string | null;
  imageDetail: string;
  timeoutMs: number;
  maxTokens: number;
  contextTokens: number;
  anonymizeDefault: boolean;
  // True when the configured provider/base URL is local (Ollama or a localhost endpoint) —
  // i.e. screenshots/text never leave the machine. Surfaced so operators can confirm OPSEC.
  local: boolean;
}

/** A small subset of process.env — only the readable, NON-secret AI config keys. */
export type EnvLike = Record<string, string | undefined>;

function num(v: string | undefined, fallback: number): number {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function orNull(v: string | undefined): string | null {
  const t = (v ?? "").trim();
  return t ? t : null;
}

/**
 * Build the redacted AI-config view from the environment. NEVER includes secrets.
 * `configured` mirrors how startServer decides whether a provider exists: a provider name
 * AND a model are the minimum (a key may legitimately be absent for a local Ollama).
 */
export function buildAiDiagnostics(env: EnvLike): AiDiagnostics {
  // Vision/screenshot config: DFIR_VISION_* (legacy DFIR_AI_* honored as a fallback via visionEnv).
  const provider = orNull(visionEnv(env, "PROVIDER"));
  const model = orNull(visionEnv(env, "MODEL"));
  const baseUrl = orNull(visionEnv(env, "BASE_URL"));
  return {
    configured: Boolean(provider && model),
    provider,
    model,
    synthModel: orNull(env.DFIR_AI_SYNTH_MODEL) ?? model,
    secondOpinionModel: orNull(env.DFIR_AI_SECOND_OPINION_MODEL),
    velociraptorModel: orNull(env.DFIR_AI_VELO_MODEL),
    baseUrl,
    imageDetail: orNull(visionEnv(env, "IMAGE_DETAIL")) ?? "high",
    timeoutMs: num(env.DFIR_AI_TIMEOUT_MS, 180_000),
    maxTokens: num(env.DFIR_AI_MAX_TOKENS, 16_000),
    contextTokens: num(env.DFIR_AI_CONTEXT_TOKENS, 128_000),
    anonymizeDefault: (env.DFIR_ANONYMIZE ?? "on").toLowerCase() !== "off",
    local: isLocalAiProvider(provider ?? undefined, baseUrl ?? undefined),
  };
}

// ── Importer health ─────────────────────────────────────────────────────────────────────
export interface ImportAttemptStats {
  total: number;
  last24h: number;
  last7d: number;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** Bucket import-attempt timestamps (ms) into 24h / 7d / all-time counts. */
export function summarizeImportAttempts(importedAtMs: readonly number[], now: number): ImportAttemptStats {
  let last24h = 0;
  let last7d = 0;
  for (const t of importedAtMs) {
    if (!Number.isFinite(t)) continue;
    const age = now - t;
    if (age <= DAY_MS) last24h++;
    if (age <= 7 * DAY_MS) last7d++;
  }
  return { total: importedAtMs.length, last24h, last7d };
}

// A recorded importer failure (in-memory ring; resets on restart). `kind` is the detected
// import format ("siem", "csv", …); `error` is the failure message.
export interface ImporterFailure {
  at: string; // ISO-8601
  caseId: string;
  kind: string;
  filename: string;
  error: string;
}

// A recorded background AI failure (analysis/synthesis), classified by ProviderError kind
// when available ("auth" | "billing" | "rate_limit" | "timeout" | "transport" | "context" |
// "other"), else "other".
export interface AiError {
  at: string; // ISO-8601
  caseId: string;
  phase: string; // "extracting" | "synthesizing" | "import" | …
  kind: string;
  detail: string;
}

/** Count AI errors by their classified kind, most-frequent first. */
export function countByKind(errors: readonly AiError[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const e of errors) out[e.kind] = (out[e.kind] ?? 0) + 1;
  return out;
}

// ── Per-importer health (#84) ───────────────────────────────────────────────────────────
// A single per-importer breakdown consolidating the three places import health was previously
// split across: aggregate attempts (above), per-case import-meta, and registry load-errors
// (importerStore.ts). In-memory, per-importer-id; resets on restart like the rings above —
// updated by dispatchImport's custom-importer branch (server.ts) after every run.
export interface ImporterRunStat {
  lastRunAt: string; // ISO-8601
  lastStatus: "ok" | "error";
  total: number;   // records found in the container (last run)
  kept: number;     // events emitted (last run)
  dropped: number;  // records not represented (last run)
  lastError: string | null;
}

// One row of the diagnostics per-importer table: static registry meta + live run stats merged.
// An importer that loaded but never ran shows null stat fields rather than being omitted — the
// analyst should see it's registered but idle, not silently absent from the table.
export interface ImporterHealth {
  id: string;
  label: string;
  file: string;
  priority: number;
  lastRunAt: string | null;
  lastStatus: "ok" | "error" | null;
  total: number | null;
  kept: number | null;
  dropped: number | null;
  lastError: string | null;
}

/** Merge custom-importer registry meta with their live run stats into the per-importer table. */
export function summarizeImporterHealth(
  meta: readonly { id: string; label: string; file: string; priority: number }[],
  runStats: ReadonlyMap<string, ImporterRunStat>,
): ImporterHealth[] {
  return meta.map((m) => {
    const s = runStats.get(m.id);
    return {
      id: m.id, label: m.label, file: m.file, priority: m.priority,
      lastRunAt: s?.lastRunAt ?? null,
      lastStatus: s?.lastStatus ?? null,
      total: s?.total ?? null,
      kept: s?.kept ?? null,
      dropped: s?.dropped ?? null,
      lastError: s?.lastError ?? null,
    };
  });
}

// ── Cases overview & on-demand size scan ────────────────────────────────────────────────
export interface CaseSize {
  caseId: string;
  bytes: number;
}

export interface ScannedFile {
  caseId: string;
  path: string; // relative to the case dir
  bytes: number;
}

export interface SizeReport {
  totalBytes: number;
  cases: CaseSize[]; // largest first
  largestFiles: Array<{ caseId: string; path: string; bytes: number }>; // largest first
}

/**
 * Aggregate a flat list of scanned files into total bytes, per-case sizes (largest first),
 * and the top-N largest individual files. Pure — the recursive walk that produces the file
 * list lives in the route (compute-on-demand, so the default diagnostics load stays cheap).
 */
export function aggregateCaseSizes(files: readonly ScannedFile[], topN = 10): SizeReport {
  const byCase = new Map<string, number>();
  let totalBytes = 0;
  for (const f of files) {
    const b = Number.isFinite(f.bytes) && f.bytes > 0 ? f.bytes : 0;
    totalBytes += b;
    byCase.set(f.caseId, (byCase.get(f.caseId) ?? 0) + b);
  }
  const cases = [...byCase.entries()]
    .map(([caseId, bytes]) => ({ caseId, bytes }))
    .sort((a, b) => b.bytes - a.bytes);
  const largestFiles = [...files]
    .filter((f) => Number.isFinite(f.bytes) && f.bytes > 0)
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, Math.max(0, topN))
    .map((f) => ({ caseId: f.caseId, path: f.path, bytes: f.bytes }));
  return { totalBytes, cases, largestFiles };
}

// ── The full diagnostics report ─────────────────────────────────────────────────────────
export interface QueueDiagnostics {
  bufferedCaptures: number; // screenshots buffered, not yet analyzed
  casesBuffering: number;
  oldestBufferedAgeMs: number | null;
  synthInFlight: number; // synthesis runs currently executing
  pendingAnalysisCases: number; // cases with a pending_analysis.json failure marker
}

export interface DiskDiagnostics extends DiskStats {
  level: DiskWarningLevel;
  thresholds: DiskWarnThresholds;
}

export interface DiagnosticsReport {
  generatedAt: string; // ISO-8601
  uptimeMs: number;
  casesRoot: string;
  disk: DiskDiagnostics;
  cases: { count: number; open: number; closed: number; archived: number };
  queue: QueueDiagnostics;
  ai: AiDiagnostics & { recentErrors: AiError[]; errorCounts: Record<string, number> };
  importers: {
    attempts: ImportAttemptStats;
    recentFailures: ImporterFailure[];
    customImporters: number;
    perImporter: ImporterHealth[]; // per-custom-importer breakdown (#84)
    loadErrors: ImporterLoadError[]; // malformed *.json specs (importerStore.loadAll), shown alongside
  };
  backups: {
    enabled: boolean;
    totalCount: number;
    totalBytes: number;
    retain: number;
  };
}

/**
 * Render a redacted, shareable plain-text blob for the "Copy diagnostics to clipboard"
 * button. Inputs are already redacted (no keys / PII); this is purely a formatter, so the
 * copied text can never contain anything the JSON report didn't.
 */
export function buildDiagnosticsText(r: DiagnosticsReport): string {
  const lines: string[] = [];
  lines.push("=== DFIR Companion — Diagnostics ===");
  lines.push(`generated:   ${r.generatedAt}`);
  lines.push(`uptime:      ${formatAge(r.uptimeMs)}`);
  lines.push(`cases root:  ${r.casesRoot}`);
  lines.push("");
  lines.push("-- Disk --");
  lines.push(
    `  ${formatBytes(r.disk.freeBytes)} free of ${formatBytes(r.disk.totalBytes)} ` +
      `(${r.disk.usedPct.toFixed(1)}% used, level=${r.disk.level})`,
  );
  lines.push("");
  lines.push("-- Cases --");
  lines.push(`  ${r.cases.count} total (${r.cases.open} open, ${r.cases.closed} closed)`);
  lines.push("");
  lines.push("-- Queue / processing --");
  lines.push(`  buffered screenshots: ${r.queue.bufferedCaptures} across ${r.queue.casesBuffering} case(s)`);
  if (r.queue.oldestBufferedAgeMs != null) lines.push(`  oldest buffered:      ${formatAge(r.queue.oldestBufferedAgeMs)}`);
  lines.push(`  synthesis in flight:  ${r.queue.synthInFlight}`);
  lines.push(`  failed-analysis cases: ${r.queue.pendingAnalysisCases}`);
  lines.push("");
  lines.push("-- AI --");
  if (!r.ai.configured) {
    lines.push("  not configured");
  } else {
    lines.push(`  provider: ${r.ai.provider} (${r.ai.local ? "local" : "external"})`);
    lines.push(`  model:    ${r.ai.model}`);
    if (r.ai.synthModel && r.ai.synthModel !== r.ai.model) lines.push(`  synth:    ${r.ai.synthModel}`);
    if (r.ai.secondOpinionModel) lines.push(`  2nd-op:   ${r.ai.secondOpinionModel}`);
    if (r.ai.baseUrl) lines.push(`  base URL: ${r.ai.baseUrl}`);
    lines.push(`  timeout:  ${r.ai.timeoutMs}ms · max tokens: ${r.ai.maxTokens} · context: ${r.ai.contextTokens}`);
    lines.push(`  anonymize default: ${r.ai.anonymizeDefault ? "on" : "off"}`);
  }
  const counts = Object.entries(r.ai.errorCounts);
  if (counts.length) {
    lines.push(`  recent AI errors: ${counts.map(([k, n]) => `${k}=${n}`).join(", ")}`);
  }
  lines.push("");
  lines.push("-- Importers --");
  lines.push(
    `  attempts: ${r.importers.attempts.last24h} (24h) · ${r.importers.attempts.last7d} (7d) · ${r.importers.attempts.total} total`,
  );
  lines.push(`  custom importers loaded: ${r.importers.customImporters}`);
  if (r.importers.recentFailures.length) {
    lines.push(`  recent failures (${r.importers.recentFailures.length}):`);
    for (const f of r.importers.recentFailures.slice(0, 10)) {
      lines.push(`    [${f.at}] ${f.caseId} ${f.kind} ${f.filename}: ${f.error}`);
    }
  } else {
    lines.push("  recent failures: none");
  }
  if (r.importers.perImporter.length) {
    lines.push(`  per-importer health (${r.importers.perImporter.length}):`);
    for (const p of r.importers.perImporter) {
      const run = p.lastRunAt
        ? `${p.lastStatus} — ${p.kept ?? 0}/${p.total ?? 0} kept, ${p.dropped ?? 0} dropped, last run ${p.lastRunAt}`
        : "never run";
      lines.push(`    ${p.id} (${p.label}): ${run}`);
      if (p.lastError) lines.push(`      last error: ${p.lastError}`);
    }
  }
  if (r.importers.loadErrors.length) {
    lines.push(`  spec load errors (${r.importers.loadErrors.length}):`);
    for (const e of r.importers.loadErrors) {
      lines.push(`    ${e.file}: ${e.errors.map((x) => `${x.path}: ${x.message}`).join("; ")}`);
    }
  }
  return lines.join("\n");
}
