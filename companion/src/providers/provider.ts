export interface AnalyzeImage {
  base64: string;
  mimeType: string; // e.g. "image/webp"
}

export interface AnalyzeRequest {
  systemPrompt: string;
  userPrompt: string;
  images: AnalyzeImage[];
}

export interface AnalyzeResult {
  rawText: string; // expected to be JSON matching deltaSchema
}

export type ProviderErrorKind = "auth" | "billing" | "rate_limit" | "timeout" | "transport" | "context" | "other";

export class ProviderError extends Error {
  constructor(message: string, readonly kind: ProviderErrorKind) {
    super(message);
    this.name = "ProviderError";
  }
}

// Map an HTTP status from a chat-completions call to an error kind.
export function httpErrorKind(status: number): ProviderErrorKind {
  if (status === 402) return "billing";
  if (status === 401 || status === 403) return "auth";
  if (status === 429) return "rate_limit";
  if (status === 408 || status >= 500) return "transport";
  return "other";
}

// A clear, actionable error message for a failed provider call. 402/401/429 are the
// common operator problems (no credits, bad key, rate limit) — say what to DO, and
// include a short snippet of the provider's own error body when present.
export function httpErrorMessage(provider: string, status: number, body?: string): string {
  const snippet = body ? ` — ${body.replace(/\s+/g, " ").trim().slice(0, 180)}` : "";
  // A 400 about context length is the model rejecting an oversized prompt — say what to DO.
  if (status === 400 && body && /context length|maximum context|too many tokens|reduce the length/i.test(body)) {
    return `${provider} HTTP 400 (context too large): the prompt exceeds the model's context window. ` +
      `Reduce the input (lower DFIR_AI_SYNTH_MAX_EVENTS, split the import into smaller files / fewer rows per batch) ` +
      `or set DFIR_AI_CONTEXT_TOKENS to your model's real window so the tool trims to fit.${snippet}`;
  }
  switch (status) {
    case 402:
      return `${provider} HTTP 402 (payment required): the ${provider} account is out of credits or has no active billing. ` +
        `Add credits/billing on the provider, or switch DFIR_AI_PROVIDER / DFIR_AI_MODEL (e.g. a cheaper model, OpenRouter, or local Ollama).${snippet}`;
    case 401:
    case 403:
      return `${provider} HTTP ${status} (auth): the API key is missing, invalid, or lacks access to the model. Check DFIR_AI_KEY and DFIR_AI_MODEL.${snippet}`;
    case 429:
      return `${provider} HTTP 429 (rate limit / quota): too many requests or quota exhausted. Wait and retry, slow imports, or switch model/provider.${snippet}`;
    default:
      return `${provider} HTTP ${status}${snippet}`;
  }
}

export interface AIProvider {
  readonly name: string;
  analyze(req: AnalyzeRequest): Promise<AnalyzeResult>;
}

export class ProviderRegistry {
  private providers = new Map<string, AIProvider>();
  register(p: AIProvider): void {
    this.providers.set(p.name, p);
  }
  get(name: string): AIProvider {
    const p = this.providers.get(name);
    if (!p) throw new ProviderError(`unknown provider: ${name}`, "other");
    return p;
  }
}

export class MockProvider implements AIProvider {
  constructor(readonly name: string, private readonly canned: string) {}
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    return { rawText: this.canned };
  }
}
