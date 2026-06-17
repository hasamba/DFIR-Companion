// Resolve the extended-thinking / Chain-of-Thought budget for a SYNTHESIS run (issue #121, feature 1).
//
// Three inputs, in precedence order:
//   1. an explicit per-run token budget (`thinkingTokens`) — wins outright; 0 forces thinking OFF
//      for this one run regardless of the env default;
//   2. the per-run **deep-reasoning toggle** (`deepReasoning`) — the dashboard "🧠 deep reasoning"
//      checkbox on Synthesize / 2nd opinion; uses the env budget when set, else a sensible default,
//      so the analyst gets deep reasoning on demand with NO .env edit + restart;
//   3. otherwise the global env default (`DFIR_AI_SYNTH_THINKING_TOKENS`) that applies to every
//      synthesis call.
//
// Returns the budget in tokens, or 0 when thinking should be OFF. PURE — unit-tested, no I/O.

export const DEFAULT_SYNTH_THINKING_TOKENS = 8000;
// Anthropic requires a thinking budget of at least this; a smaller value is treated as "off".
export const MIN_SYNTH_THINKING_TOKENS = 1024;

export interface SynthThinkingInput {
  thinkingTokens?: number; // explicit per-run budget (0 = force off for this run)
  deepReasoning?: boolean; // per-run toggle (Synthesize button / 2nd opinion); off by default
}

// envBudget is the resolved DFIR_AI_SYNTH_THINKING_TOKENS value (any number; <min counts as 0).
export function resolveSynthThinkingBudget(opts: SynthThinkingInput, envBudget: number): number {
  const env = Number.isFinite(envBudget) && envBudget >= MIN_SYNTH_THINKING_TOKENS ? Math.floor(envBudget) : 0;
  if (opts.thinkingTokens !== undefined) {
    const n = Math.floor(opts.thinkingTokens);
    return n >= MIN_SYNTH_THINKING_TOKENS ? n : 0; // explicit per-run value (0/low = off)
  }
  if (opts.deepReasoning) return env || DEFAULT_SYNTH_THINKING_TOKENS; // toggle: env budget, else default
  return env; // global env default (every synthesis), 0 when unset/too-low
}
