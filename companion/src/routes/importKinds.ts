import type { ImportDebugRecorder } from "../analysis/importDebug.js";
import { emitImportRefused } from "./importDebugEmit.js";
import type { Response } from "express";
import { getAiLimiter, sendRateLimited } from "../http/rateLimiter.js";

// The import kinds whose parsers STREAM: they report parse progress and honor the abort signal
// mid-parse, so their jobs are cancellable even without an AI dependency. One list shared by the
// twin /import + /import-file registrations (import.ts) and the resume handler's cancellable
// predicate (importRecovery.ts) — these must stay in lockstep, or a resumed job silently loses
// the cancel button its first run had. The next streaming importer is added HERE, nowhere else.
// (Named after the parse-progress capability, not "streaming" — import.ts already uses a
// `streaming` parameter for plaso file-streaming, which is a different thing.)
export const PARSE_PROGRESS_KINDS: ReadonlySet<string> = new Set(["evtxxml", "syslog"]);

// Accepts unknown so the resume handler can pass `job.parameters?.kind` unvalidated.
export function hasParseProgress(kind: unknown): boolean {
  return typeof kind === "string" && PARSE_PROGRESS_KINDS.has(kind);
}

// CSV/log imports are themselves an LLM call (free-form data the model must interpret), so they
// respect the per-case AI toggle exactly like screenshot analysis + synthesis: with AI OFF, the
// evidence is saved but NOT sent to the model. Deterministic imports have no LLM call, so they
// proceed and populate the timeline + IOCs regardless (synthesis still waits for AI — see
// resynthesizeInBackground). This keeps "AI off" meaning no LLM call / nothing leaves for the
// model, and stops the dashboard from claiming the AI is analyzing while off. Shared by the twin
// /import + /import-file registrations, which also OR it into their jobs' cancellable flag.
export function isAiDependent(kind: string): boolean {
  return kind === "csv" || kind === "log";
}

// A CSV/log import runs a direct LLM analysis, so it bears AI cost even though the /import and
// /import-file routes ride the generous DETERMINISTIC-import limiter (300/min) rather than the AI
// one. Meter that AI cost against the per-case AI budget — the same 20/min cap /synthesize uses — so
// these routes cannot be a back door around it. Returns true (and has written a 429) when the caller
// should stop; deterministic kinds and unmetered budgets return false. Called after the no-provider
// 501 check, so it only fires when an LLM call will actually be made.
export function rejectIfAiImportOverBudget(kind: string, caseId: string, res: Response): boolean {
  if (!isAiDependent(kind)) return false;
  const limiter = getAiLimiter();
  const now = Date.now();
  if (!limiter.tryAcquire(caseId, now)) {
    sendRateLimited(
      res,
      limiter.retryAfterMs(caseId, now),
      "AI-analysis import rate exceeded for this case, try again shortly",
    );
    return true;
  }
  return false;
}

/**
 * The refusals /import and /import-file make right after detection — an unknown format (400 with the
 * route's own hint), a CSV/log with no AI provider (501), a CSV/log over the per-case AI budget (429).
 * Each records its reason on the attempt's recorder (#1736). Returns true when it has answered.
 */
export function refuseDetectedImport(o: {
  kind: string;
  caseId: string;
  res: Response;
  hasSynthesisProvider: boolean;
  unknown: () => object;
  debug: ImportDebugRecorder;
}): boolean {
  if (o.kind === "unknown") {
    emitImportRefused(o.caseId, o.debug, "unknown_format");
    o.res.status(400).json(o.unknown());
    return true;
  }
  if (isAiDependent(o.kind) && !o.hasSynthesisProvider) {
    emitImportRefused(o.caseId, o.debug, "no_ai_provider");
    o.res.status(501).json({ error: "AI provider not configured for CSV/log analysis" });
    return true;
  }
  if (rejectIfAiImportOverBudget(o.kind, o.caseId, o.res)) {
    emitImportRefused(o.caseId, o.debug, "ai_budget_exceeded");
    return true;
  }
  return false;
}
