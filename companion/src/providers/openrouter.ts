import { OpenAIProvider, type OpenAIOptions } from "./openai.js";
import type { AnalyzeRequest } from "./provider.js";

// OpenRouter requires a thinking budget of at least this many tokens to be worth enabling.
const MIN_THINKING_TOKENS = 1024;

export class OpenRouterProvider extends OpenAIProvider {
  override readonly name = "openrouter";
  constructor(opts: OpenAIOptions) {
    super({ ...opts, baseUrl: opts.baseUrl ?? "https://openrouter.ai/api/v1" });
  }

  // OpenRouter exposes a UNIFIED `reasoning` parameter across reasoning-capable models (Anthropic
  // extended thinking, OpenAI o-series, etc.), so Chain-of-Thought (#121) works whatever model the
  // synthesis call points at. `max_tokens` is the thinking budget. A model with no reasoning mode
  // ignores it server-side — graceful no-op. The final answer still arrives in message.content, so
  // response parsing is unchanged.
  protected override reasoningBody(req: AnalyzeRequest): Record<string, unknown> {
    const budget = req.thinkingTokens && req.thinkingTokens >= MIN_THINKING_TOKENS ? Math.floor(req.thinkingTokens) : 0;
    return budget > 0 ? { reasoning: { max_tokens: budget } } : {};
  }
}
