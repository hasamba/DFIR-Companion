/**
 * Rate limit on the AI-cost-bearing case routes. Lifted out of createApp by #416.
 *
 * THE THREAT is an attacker who knows a caseId burning the operator's AI budget: 20 requests per
 * minute per case is generous for one analyst and useless for a script. The limiter key is the
 * caseId, so rotating endpoints does not evade the cap (#25).
 *
 * MOUNTED PER-EXACT-PATH, not as a prefix. `app.use("/cases/:id/import", ...)` would also swallow
 * the non-AI undo / redo / undo-stack routes under /import, throttling a pure read and locking the
 * analyst out of their own import history (#23) — so the paths are matched explicitly instead.
 *
 * The set covers EVERY route that issues an LLM call. The deep-pass/preview GET and the read-only
 * GETs (synth-meta, ai-cost, hypotheses, ai-control, confidence-control, adversary-hints,
 * starred-report) are NOT limited: they cost zero AI tokens.
 *
 * That claim is now ASSERTED, not just written down. It had drifted: eight AI routes added after
 * this file was written were never added to the set, so the per-case cap could be walked around by
 * simply using a different AI feature. tests/architecture/aiRouteCoverage.test.ts scans the route
 * files for AI-gated POSTs and fails on any that is neither listed here nor explicitly excluded
 * below, so the next one cannot be forgotten silently.
 *
 * ONE DELIBERATE EXCLUSION: POST /cases/:id/push. It triggers an import and therefore synthesis, so
 * it does bear AI cost — but it is the external collector's ingest endpoint, authenticated by a
 * per-case push token rather than a session. The threat this gate answers is "an attacker who knows
 * a caseId", and knowing a caseId is not enough to reach /push. Capping it at 20/min would throttle
 * a legitimate bulk collector instead, so it keeps its own credential as its control.
 *
 * REGISTRATION ORDER IS PART OF THE CONTRACT. This gate must be mounted after the route families
 * that need no limit and before registerImportRoutes; tests/architecture/routeInventory.test.ts
 * records the whole interleaved layer list, and the middleware's NAME and arity are what it
 * records — hence the named `aiRateLimitGate` function expression below.
 */
import type { Express, Request, Response, NextFunction } from "express";
import { getAiLimiter, getDeterministicImportLimiter } from "../http/rateLimiter.js";

/** The DETERMINISTIC bulk-import routes. They parse and grade with no LLM call, so they are metered
 *  by their own generous per-case limiter (getDeterministicImportLimiter), NOT the 20/min AI cap —
 *  which used to reject most files of a normal multi-file Velociraptor collection. /import-csv and
 *  /import-log stay on the AI limiter: each is a single AI analysis call, not a bulk path. */
export const IMPORT_LIMIT_PATHS = new Set(["/import", "/import-file"]);

/** Static AI-cost POST routes, relative to /cases/:id. Exported for the coverage test. */
export const AI_LIMIT_PATHS = new Set([
  "/import-csv",
  "/import-log", // a single CSV/log AI analysis call
  "/synthesize",
  "/deep-pass", // explicit synthesis
  "/second-opinion",
  "/second-opinion/apply",
  "/second-opinion/apply-all", // 2nd LLM opinion
  "/ask", // Ask-the-case GraphRAG
  "/executive-summary",
  "/starred-report",
  "/view-summary",
  "/remediation-plan", // report AI
  "/hypothesis-review",
  "/narrative", // narrative + hypothesis AI
  "/memory/next-steps", // memory-forensics next-step AI
  "/timeline-gaps/hypothesize", // gap hypotheses
  "/translate-query", // natural-language → query translation
  "/false-positive/suggest", // FP suggestions
  "/playbook/suggest-hunts",
  "/tagger/suggest-rule",
  "/velociraptor/suggest-hunts",
  "/adversary-hints/hunt-technique", // per-technique hunt suggestions
  "/anon-control", // flipping the toggle forces a re-synthesis
]);

/** AI-cost POST routes carrying a dynamic segment, so the static set cannot express them. */
export const AI_LIMIT_PATTERNS = [/^\/events\/[^/]+\/explain$/, /^\/sessions\/[^/]+\/summary$/];

export function mountAiRateLimit(app: Express): void {
  const aiLimited = getAiLimiter().middleware((req) => req.params.id);
  const importLimited = getDeterministicImportLimiter().middleware((req) => req.params.id);
  app.use("/cases/:id", function aiRateLimitGate(req: Request, res: Response, next: NextFunction) {
    if (req.method !== "POST") return next();
    // Strip the /cases/:id/ prefix to compare against the static set, and FOLD CASE. Express routes
    // case-insensitively, so POST /cases/c1/SYNTHESIZE reaches the same handler as the lowercase
    // spelling; a case-sensitive Set lookup missed it, fell through to next(), and ran the AI call
    // with no cap at all. Only the route suffix is folded — the caseId is already stripped, so the
    // limiter key is untouched.
    // The optional trailing slash goes too. Express is not in "strict routing" mode, so
    // /cases/c1/synthesize/ reaches the same handler as /cases/c1/synthesize, while an exact Set lookup
    // does not — one keystroke past the gate.
    const rel =
      req.path
        .replace(/^\/cases\/[^/]+\//, "/")
        .replace(/\/+$/, "")
        .toLowerCase() || "/";
    if (IMPORT_LIMIT_PATHS.has(rel)) {
      return importLimited(req, res, next);
    }
    if (AI_LIMIT_PATHS.has(rel) || AI_LIMIT_PATTERNS.some((re) => re.test(rel))) {
      return aiLimited(req, res, next);
    }
    next();
  });
}
