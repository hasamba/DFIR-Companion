import { OpenAIProvider, type OpenAIOptions } from "./openai.js";

// LiteLLM exposes an OpenAI-compatible /chat/completions endpoint (it proxies 100+
// model backends behind one OpenAI shape), so a local — or self-hosted — LiteLLM proxy
// is just the OpenAI provider pointed at the proxy's base URL. The default targets a
// `litellm` proxy on its standard local port; override the host/port with DFIR_AI_BASE_URL.
// The proxy may require a virtual/master key (set DFIR_AI_KEY) or none at all when run
// fully local with no auth — an empty key sends a harmless `Bearer` the proxy ignores.
export class LiteLlmProvider extends OpenAIProvider {
  override readonly name = "litellm";
  constructor(opts: OpenAIOptions) {
    super({ ...opts, baseUrl: opts.baseUrl ?? "http://localhost:4000/v1" });
  }
}
