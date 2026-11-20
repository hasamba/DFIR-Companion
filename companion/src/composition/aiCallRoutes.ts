/**
 * Which case routes the AI-off gate refuses (#2757). Read by composition/aiOffGate.ts.
 *
 * ONE SOURCE OF TRUTH, not a second list. Every POST that spends AI budget is already listed by the
 * AI rate limiter (composition/aiRateLimit.ts), and tests/architecture/aiRouteCoverage.test.ts fails
 * when a new AI route is missing there. The gate reuses that list, so a new AI button that is
 * metered is also switched off, without anyone remembering a second place. The only additions are
 * model-calling routes the limiter deliberately leaves out; the only removals are routes that
 * already give their own AI-off answer. tests/server/aiOffGate.test.ts checks every entry.
 */
import { AI_LIMIT_PATHS, AI_LIMIT_PATTERNS } from "./aiRateLimit.js";

/** Metered routes that answer AI-off themselves, so the gate leaves them alone. Each needs a reason. */
export const AI_OFF_OWN_ANSWER = new Map<string, string>([
  [
    "/import-csv",
    "with AI off the file is saved as evidence and answered 202 analyzed:false (refuseAiOffImport, " +
      "#1806); a 409 would lose the upload",
  ],
  ["/import-log", "same as /import-csv: saved as evidence, not analyzed (refuseAiOffImport, #1806)"],
  ["/watson/message", "Watson answers its own 409 'AI is off for this case' (watsonRunOrRefuse)"],
  ["/watson/paste", "Watson answers its own 409 'AI is off for this case' (watsonRunOrRefuse)"],
]);

/** Model-calling routes the rate limiter does not meter. Each needs a reason. */
export const AI_OFF_EXTRA_PATHS = new Map<string, string>([
  ["/mcp/agent", "runs the MCP investigation agent, a Claude Code model session, over case evidence"],
  ["/mcp/agent-upload", "same agent as /mcp/agent, over an uploaded sample"],
]);

/** Metered routes that call a model only for some request bodies. */
const AI_OFF_ONLY_WHEN = new Map<string, (body: unknown) => boolean>([
  // Without `ai` the route returns its deterministic candidates and calls no model (routes/findings.ts).
  ["/false-positive/suggest", (body) => Boolean((body as { ai?: unknown } | undefined)?.ai)],
]);

/**
 * Routes whose model call depends on what the handler loads, so they check the switch in the handler
 * with routes/aiOffRefusal.ts. Listed here so the drift test can tell them from a forgotten route.
 */
export const AI_OFF_IN_HANDLER = new Map<string, string>([
  [
    "/analysis-runs/:runId/replay",
    "only synthesis, deep-pass and AI-dependent import replays call a model; tagger, enrichment " +
      "and report replays do not, so the run is loaded before the switch is read",
  ],
]);

const isMetered = (rel: string): boolean =>
  AI_LIMIT_PATHS.has(rel) || AI_LIMIT_PATTERNS.some((re) => re.test(rel));

/** True when this request would call a model and must be refused while the case's AI is off. */
export function aiOffGateApplies(method: string, rel: string, body: unknown): boolean {
  if (method !== "POST") return false;
  if (AI_OFF_EXTRA_PATHS.has(rel)) return true;
  if (AI_OFF_OWN_ANSWER.has(rel) || !isMetered(rel)) return false;
  const when = AI_OFF_ONLY_WHEN.get(rel);
  return when ? when(body) : true;
}
