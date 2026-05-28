import { OpenAIProvider, type OpenAIOptions } from "./openai.js";

export class OllamaCloudProvider extends OpenAIProvider {
  override readonly name = "ollama";
  constructor(opts: OpenAIOptions) {
    super({ ...opts, baseUrl: opts.baseUrl ?? "https://ollama.com/v1" });
  }
}
