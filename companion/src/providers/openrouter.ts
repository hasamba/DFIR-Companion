import { OpenAIProvider, type OpenAIOptions } from "./openai.js";

export class OpenRouterProvider extends OpenAIProvider {
  override readonly name = "openrouter";
  constructor(opts: OpenAIOptions) {
    super({ ...opts, baseUrl: opts.baseUrl ?? "https://openrouter.ai/api/v1" });
  }
}
