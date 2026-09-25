import { OpenAIProvider, type OpenAIOptions } from "./openai.js";
import type { AnalyzeRequest } from "./provider.js";

// The smallest thinking budget that means the 🧠 deep-reasoning toggle is on — the same threshold
// OpenRouter uses.
const MIN_THINKING_TOKENS = 1024;

export class OllamaCloudProvider extends OpenAIProvider {
  override readonly name = "ollama";
  // thinkingTokens → `reasoning_effort` in reasoningBody().
  readonly supportsThinking = true;
  constructor(opts: OpenAIOptions) {
    super({ ...opts, baseUrl: opts.baseUrl ?? "https://ollama.com/v1" });
  }

  // Ollama's OpenAI-compatible API takes `reasoning_effort`; a model with no thinking mode ignores
  // it. Deep reasoning on → "high". Off → "low", not omitted: a reasoning model (GLM) left at its
  // default can spend the whole output limit thinking and return no answer. Never "none": GLM then
  // writes its reasoning into `content` and the JSON answer breaks.
  protected override reasoningBody(req: AnalyzeRequest): Record<string, unknown> {
    const deep = (req.thinkingTokens ?? 0) >= MIN_THINKING_TOKENS;
    return { reasoning_effort: deep ? "high" : "low" };
  }
}
