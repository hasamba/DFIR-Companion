import { WATSON_TURN_TEXT_MAX } from "../analysis/ai/watson/chatStore.js";
import type { RouteAiPreviewAction } from "./aiPreviewRouteAction.js";
import { watsonRoundDeps } from "./watsonDeps.js";

/**
 * "Preview what the AI will see" for a Watson message (#2491). `params.text` is the analyst's draft.
 *
 * Runs the round's own request building and its callAiJson call (analysis/ai/watson/preview.ts), so
 * the AI preview stops it at the gate with exactly the masked request a real round would send for the
 * same draft. Nothing is saved: no chat turn, no paste marked read, no standard questions seeded.
 * The same checks as the real message route: an empty or too-long draft, and a Watson with no model.
 */
export const watsonPreviewAction: RouteAiPreviewAction = {
  label: "Watson message",
  needs: "ai",
  prepare: async (ctx, caseId, params) => {
    const text = typeof params.text === "string" ? params.text.trim() : "";
    if (!text) return "text is required";
    if (text.length > WATSON_TURN_TEXT_MAX)
      return `message is longer than ${WATSON_TURN_TEXT_MAX} characters`;
    const deps = watsonRoundDeps(ctx);
    if (!deps) return "AI provider not configured for Watson";
    const pipeline = ctx.options.pipeline!;
    return () => pipeline.watsonPreview(caseId, text, deps);
  },
};
