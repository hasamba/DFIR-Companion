import type { AiCallContext } from "./aiContext.js";
import { converseRestored } from "./converseRestored.js";
import { analyzeRestored } from "./providerCall.js";
import type { ProviderCallContext } from "./providerCallContext.js";

/**
 * The pipeline's two AI-call gates, bound to its context (Codex P1-1). The binding sits inside the
 * object literal that assigns the context, so the context does not exist yet when this runs: each
 * function calls `getCtx()` when it is CALLED, never when it is built.
 */
export function gateBindings(
  getCtx: () => ProviderCallContext,
): Pick<AiCallContext, "analyzeRestored"> & Required<Pick<AiCallContext, "converseRestored">> {
  return {
    analyzeRestored: (caseId, state, provider, req, label, skipPresidioGate) =>
      analyzeRestored(getCtx(), caseId, state, provider, req, label, skipPresidioGate),
    converseRestored: (caseId, state, provider, req, session, label) =>
      converseRestored(getCtx(), caseId, state, provider, req, session, label),
  };
}
