import type { AIProvider } from "../providers/provider.js";
import { buildSynthesisProvider } from "./aiProviders.js";

/**
 * The model Watson talks to. `DFIR_AI_WATSON_MODEL` set: the synthesis provider's settings (provider,
 * key, base URL) with that model. Blank: the synthesis provider exactly as synthesis builds it, so
 * Watson follows `DFIR_AI_SYNTH_MODEL`. Undefined when no provider is configured at all.
 */
export function buildWatsonProvider(env: NodeJS.ProcessEnv): AIProvider | undefined {
  const model = env.DFIR_AI_WATSON_MODEL?.trim();
  return buildSynthesisProvider(env, model || undefined);
}
