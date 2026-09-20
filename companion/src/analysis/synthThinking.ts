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

// Where the budget came from (#1468). Recorded on every synthesis run so "did deep reasoning help
// this case?" can be answered from the run records afterwards:
//   - "toggle": a per-run choice — the 🧠 checkbox, or an explicit per-run budget;
//   - "env":    the global DFIR_AI_SYNTH_THINKING_TOKENS default, with no per-run input;
//   - "off":    thinking was off for this run, whatever asked for it.
export type SynthThinkingSource = "toggle" | "env" | "off";

export interface SynthThinking {
  tokens: number;
  source: SynthThinkingSource;
}

// envBudget is the resolved DFIR_AI_SYNTH_THINKING_TOKENS value (any number; <min counts as 0).
export function resolveSynthThinking(opts: SynthThinkingInput, envBudget: number): SynthThinking {
  const env =
    Number.isFinite(envBudget) && envBudget >= MIN_SYNTH_THINKING_TOKENS ? Math.floor(envBudget) : 0;
  if (opts.thinkingTokens !== undefined) {
    const n = Math.floor(opts.thinkingTokens);
    // explicit per-run value (0/low = off); a per-run value is a per-run choice, so "toggle"
    return n >= MIN_SYNTH_THINKING_TOKENS ? { tokens: n, source: "toggle" } : { tokens: 0, source: "off" };
  }
  // toggle: env budget, else default
  if (opts.deepReasoning) return { tokens: env || DEFAULT_SYNTH_THINKING_TOKENS, source: "toggle" };
  // global env default (every synthesis), off when unset/too-low
  return env > 0 ? { tokens: env, source: "env" } : { tokens: 0, source: "off" };
}

// Token count only — kept for callers that do not record the source.
export function resolveSynthThinkingBudget(opts: SynthThinkingInput, envBudget: number): number {
  return resolveSynthThinking(opts, envBudget).tokens;
}
