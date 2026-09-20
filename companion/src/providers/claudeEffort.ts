// Map a synthesis thinking budget (tokens) to the claude CLI's `--effort` tier (#1468).
//
// The dashboard's 🧠 deep-reasoning toggle puts `thinkingTokens` on the AnalyzeRequest. The API
// providers spend it as an exact budget (anthropic → `thinking.budget_tokens`, openrouter →
// `reasoning.max_tokens`). The claude-code provider has no such knob: the CLI takes a coarse
// `--effort <low|medium|high|xhigh|max>` tier, and because the provider runs with
// `--setting-sources ""` the user's own effort setting never loads — only an explicit flag counts.
// Without this mapping the toggle is a silent no-op on claude-code.
//
// Tiers, chosen so the toggle's DEFAULT budget lands on "high" and DFIR_AI_SYNTH_THINKING_TOKENS
// picks the tier:
//   < 1024          → undefined  (below the minimum every provider treats as "thinking off")
//   1024 – 7999     → "medium"   (a deliberately small env budget)
//   8000 – 31999    → "high"     (DEFAULT_SYNTH_THINKING_TOKENS is 8000 — the toggle with no env)
//   ≥ 32000         → "xhigh"    (a large env budget)
// "max" is never chosen: it is the CLI's unbounded tier, and a token budget is a ceiling, not a
// request to remove one. "low" is never chosen either: below the minimum the flag is simply
// omitted, which leaves the CLI at its own default rather than forcing it down.

// Mirrors MIN_SYNTH_THINKING_TOKENS in analysis/synthThinking.ts (and the MIN_THINKING_TOKENS in
// anthropic.ts / openrouter.ts). Kept local: providers/ is the platform layer and may not import
// from analysis/ (check:boundaries).
const MIN_THINKING_TOKENS = 1024;
const HIGH_FROM_TOKENS = 8000;
const XHIGH_FROM_TOKENS = 32000;

export type ClaudeEffort = "medium" | "high" | "xhigh";

export function effortForBudget(tokens: number | undefined): ClaudeEffort | undefined {
  if (tokens === undefined || Number.isNaN(tokens) || tokens < MIN_THINKING_TOKENS) return undefined;
  if (tokens >= XHIGH_FROM_TOKENS) return "xhigh";
  if (tokens >= HIGH_FROM_TOKENS) return "high";
  return "medium";
}
