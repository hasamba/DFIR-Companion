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

export class ProviderError extends Error {
  constructor(message: string, readonly kind: "auth" | "rate_limit" | "timeout" | "transport" | "other") {
    super(message);
    this.name = "ProviderError";
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
