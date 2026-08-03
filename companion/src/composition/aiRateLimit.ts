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
 * REGISTRATION ORDER IS PART OF THE CONTRACT. This gate must be mounted after the route families
 * that need no limit and before registerImportRoutes; tests/architecture/routeInventory.test.ts
 * records the whole interleaved layer list, and the middleware's NAME and arity are what it
 * records — hence the named `aiRateLimitGate` function expression below.
 */
import type { Express, Request, Response, NextFunction } from "express";
import { getAiLimiter } from "../http/rateLimiter.js";

/** Static AI-cost POST routes, relative to /cases/:id. */
const AI_LIMIT_PATHS = new Set([
  "/import",
  "/import-file",
  "/import-csv",
  "/import-log", // import triggers synthesis
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
]);

export function mountAiRateLimit(app: Express): void {
  const aiLimited = getAiLimiter().middleware((req) => req.params.id);
  app.use("/cases/:id", function aiRateLimitGate(req: Request, res: Response, next: NextFunction) {
    if (req.method !== "POST") return next();
    // Strip the /cases/:id/ prefix to compare against the static set.
    const rel = req.path.replace(/^\/cases\/[^/]+\//, "/");
    // /events/:eid/explain has a dynamic segment — match it explicitly.
    const isExplain = /^\/events\/[^/]+\/explain$/.test(rel);
    if (AI_LIMIT_PATHS.has(rel) || isExplain) {
      return aiLimited(req, res, next);
    }
    next();
  });
}
