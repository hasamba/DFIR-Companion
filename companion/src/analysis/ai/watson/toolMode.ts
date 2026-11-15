import type { AIProvider } from "../../../providers/provider.js";
import type { WatsonRoundContext } from "./roundContext.js";

// Which mode a Watson round runs in (phase 5): native tool calls, or the one-step hop. Tool mode needs
// a cap above 0, a provider that can make a tool-calling turn, the gate's converseRestored and a
// model the server has not seen refuse tools. A reaction round always runs the hop (U4).

/** The highest DFIR_AI_WATSON_MAX_TOOL_CALLS takes effect (D13). */
export const WATSON_MAX_TOOL_CALLS_CEILING = 10;
/** Super-timeline searches per question (D4b, R2). A constant, not a setting. */
export const WATSON_MAX_SUPER_SEARCHES = 2;
/** Characters of tool-result text the model gets per question before old results are stubbed (D4c). */
export const WATSON_TRANSCRIPT_BUDGET_CHARS = 80_000;

// Capability keys of models that refused tools (D12). The provider object is rebuilt for every round,
// so the key is name, model and base URL. It never holds a key or secret. A restart clears it.
const toolsRejected = new Set<string>();

/** The capability key of a provider: `${name}|${model}|${endpoint}`. */
export const toolsKey = (p: AIProvider): string => `${p.name}|${p.model}|${p.endpoint ?? ""}`;

/** Remember that this provider's model refused tools: its next rounds run the hop. */
export function markToolsRejected(p: AIProvider): void {
  toolsRejected.add(toolsKey(p));
}

/** Tool calls this round may make; 0 means the one-step hop. */
export function watsonToolCap(ctx: WatsonRoundContext, reaction: boolean): number {
  const max = Math.min(Math.floor(ctx.maxToolCalls ?? 0), WATSON_MAX_TOOL_CALLS_CEILING);
  if (reaction || !(max > 0)) return 0;
  const p = ctx.provider;
  if (!p.supportsTools || typeof p.converse !== "function" || !ctx.converseRestored) return 0;
  return toolsRejected.has(toolsKey(p)) ? 0 : max;
}
