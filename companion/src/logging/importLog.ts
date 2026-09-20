/**
 * The import log lines (#1438). Pure formatters plus a per-case progress throttle; the seams that
 * emit them (dispatchImport, commitDedicatedImport, settleForensicImport, onAiStatus,
 * recordImportFailure) call these and write through the server logger with `{ caseId }`, so every
 * line lands in the session log AND the case's own log.
 *
 * Why lines at the seams and not in the importers: no importer logs today, and there are ~60 of
 * them across ~30 entry points. Every text import crosses dispatchImport or commitDedicatedImport
 * on the way in, settleForensicImport on the way out, onAiStatus for progress and
 * recordImportFailure on failure — five places, and the last line before a crash then always
 * names the file and how far it got.
 *
 * Format: `[import] <caseId> <label>: <what>` — the prefix the batched Velociraptor driver
 * (analysis/ingest/velociraptorBulk.ts) already uses, so one grep finds every import line.
 */

export const IMPORT_LOG_PREFIX = "[import]";

// Progress lines for one case are at most one per interval unless the import's label changes.
export const DEFAULT_PROGRESS_INTERVAL_MS = 10_000;

// A label comes from a filename the analyst (or an adversary's export) chose. Control characters
// would forge lines in the session log and in the case's audit-trail log; strip them, and cap it.
const MAX_LABEL = 200;
export function sanitizeLabel(label: string): string {
  const clean = label.replace(/[\x00-\x1f\x7f]+/g, " ").trim();
  return clean.length > MAX_LABEL ? `${clean.slice(0, MAX_LABEL)}…` : clean;
}

// The only place a progress detail is allowed onto the log from onAiStatus: the "<kind> import —
// done/total" shape every import path emits (createImportJobTracking, ingestStreamed, the dedicated
// routes' inline callbacks). Enrichment, screenshot and exposure-check statuses share the phase but
// not the shape, so they never print under the [import] prefix.
export const IMPORT_PROGRESS_DETAIL = /\bimport — (?:committed batch )?\d+\/\d+$/;

export function describeMb(bytes: number): string {
  const mb = bytes / (1024 * 1024);
  return mb < 10 ? `${mb.toFixed(1)} MB` : `${Math.round(mb)} MB`;
}

function seconds(ms: number): string {
  return ms < 10_000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms / 1000)} s`;
}

export interface ImportStartInfo {
  caseId: string;
  label: string;
  kind: string;
  bytes?: number;
  lines?: number;
  source?: string; // where the file came from: "drop folder", "push", "hunt H.1", …
}

export function formatImportStart(info: ImportStartInfo): string {
  const size =
    info.bytes !== undefined
      ? `, ${describeMb(info.bytes)}`
      : info.lines !== undefined
        ? `, ${info.lines} line(s)`
        : "";
  const via = info.source ? ` via ${info.source}` : "";
  return `${IMPORT_LOG_PREFIX} ${info.caseId} ${sanitizeLabel(info.label)}: start — ${info.kind}${size}${via}`;
}

export function formatImportMerged(caseId: string, label: string, elapsedMs: number): string {
  return `${IMPORT_LOG_PREFIX} ${caseId} ${sanitizeLabel(label)}: parsed and merged in ${seconds(elapsedMs)}`;
}

export interface ImportSettledInfo {
  caseId: string;
  label?: string;
  forensicAdded: number;
  forensicRemoved: number;
  superAdded: number;
  iocsAdded: number;
  iocsRemoved?: number;
  elapsedMs?: number;
}

// The outcome line: what the analyst will find in each timeline after the demote pass.
export function formatImportSettled(info: ImportSettledInfo): string {
  const who = info.label ? `${info.caseId} ${sanitizeLabel(info.label)}` : info.caseId;
  const forensic = `forensic +${info.forensicAdded}${info.forensicRemoved ? `/-${info.forensicRemoved}` : ""}`;
  const iocs = `IOCs +${info.iocsAdded}${info.iocsRemoved ? `/-${info.iocsRemoved}` : ""}`;
  const took = info.elapsedMs !== undefined ? ` (${seconds(info.elapsedMs)})` : "";
  return `${IMPORT_LOG_PREFIX} ${who}: done — ${forensic}, super +${info.superAdded}, ${iocs}${took}`;
}

export interface ImportFailedInfo {
  caseId: string;
  label: string;
  kind: string;
  message: string; // already redacted by the caller
  elapsedMs?: number;
}

export function formatImportCancelled(caseId: string, label: string, elapsedMs: number): string {
  return `${IMPORT_LOG_PREFIX} ${caseId} ${sanitizeLabel(label)}: cancelled after ${seconds(elapsedMs)} — stored evidence retained`;
}

export function formatImportFailed(info: ImportFailedInfo): string {
  const took = info.elapsedMs !== undefined ? ` after ${seconds(info.elapsedMs)}` : "";
  return `${IMPORT_LOG_PREFIX} ${info.caseId} ${sanitizeLabel(info.label)}: FAILED (${info.kind})${took} — ${sanitizeLabel(info.message)}`;
}

export interface ImportProgressThrottle {
  /** The line to log for this progress detail, or null when it is too soon to log again. */
  note(caseId: string, detail: string): string | null;
  /** Forget the case (its import ended) so the next one logs at once. */
  clear(caseId: string): void;
}

// The label is the text before the first " — " ("THOR import — 5000/12000" → "THOR import"); a new
// label means a new import for the case and always logs, whatever the clock says.
function labelOf(detail: string): string {
  const i = detail.indexOf(" — ");
  return i === -1 ? detail : detail.slice(0, i);
}

/**
 * At most one progress line per case per interval, plus one whenever the import changes. Bounded:
 * one entry per case that is mid-import, dropped on clear().
 */
export function createImportProgressThrottle(
  opts: { intervalMs?: number; now?: () => number } = {},
): ImportProgressThrottle {
  const interval = opts.intervalMs ?? DEFAULT_PROGRESS_INTERVAL_MS;
  const now = opts.now ?? (() => Date.now());
  const last = new Map<string, { at: number; label: string }>();
  return {
    note(caseId, detail) {
      const t = now();
      const label = labelOf(detail);
      const prev = last.get(caseId);
      if (prev && prev.label === label && t - prev.at < interval) return null;
      last.set(caseId, { at: t, label });
      return `${IMPORT_LOG_PREFIX} ${caseId}: ${sanitizeLabel(detail)}`;
    },
    clear(caseId) {
      last.delete(caseId);
    },
  };
}
