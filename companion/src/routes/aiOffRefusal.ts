/**
 * The one answer a case-AI route gives when the case's AI switch is off (#2757).
 *
 * The switch is the analyst's cost and privacy control, and it is OFF by default on every new case.
 * Before #2757 only Watson and the AI-dependent imports read it; every manual AI button (synthesize,
 * explain, executive summary, deep pass, second opinion, ...) checked only that a provider was
 * configured and sent case data to the model with the switch off.
 *
 * Most routes are refused by the central gate (composition/aiOffGate.ts) before their handler runs.
 * A route that calls a model only for some requests, decided after it has loaded something (the
 * analysis-run replay), refuses in its handler with the same helper, so the wording cannot drift.
 * Same wording family as Watson's own refusal (analysis/ai/watson/roundContext.ts WatsonAiOff).
 */
import type { Response } from "express";

export const AI_OFF_TEXT = "AI is off for this case — turn AI on to use this";

export function sendAiOff(res: Response): Response {
  return res.status(409).json({ error: AI_OFF_TEXT, aiOff: true });
}
