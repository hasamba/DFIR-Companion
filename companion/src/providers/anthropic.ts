import { type AIProvider, type AnalyzeRequest, type AnalyzeResult, ProviderError, httpErrorKind, httpErrorMessage } from "./provider.js";

type FetchFn = typeof fetch;

export interface AnthropicOptions {
  apiKey: string;
  model: string;       // e.g. "claude-haiku-4-5-20251001", "claude-sonnet-4-6"
  baseUrl?: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
  maxTokens?: number;
}

export class AnthropicProvider implements AIProvider {
  readonly name = "anthropic";
  private readonly fetchFn: FetchFn;
  private readonly baseUrl: string;

  constructor(private readonly opts: AnthropicOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.baseUrl = opts.baseUrl ?? "https://api.anthropic.com/v1";
  }

  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    const content: unknown[] = [{ type: "text", text: req.userPrompt }];
    for (const img of req.images) {
      content.push({
        type: "image",
        source: { type: "base64", media_type: img.mimeType, data: img.base64 },
      });
    }

    const maxTokens = this.opts.maxTokens ?? 16000;
    const timeoutMs = this.opts.timeoutMs ?? 60_000;
    let res: Response;
    try {
      res = await this.fetchFn(`${this.baseUrl}/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": this.opts.apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: this.opts.model,
          max_tokens: maxTokens,
          system: req.systemPrompt,
          messages: [{ role: "user", content }],
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      const msg = (err as Error).name === "TimeoutError"
        ? `Anthropic request timed out after ${timeoutMs}ms`
        : `Anthropic transport error: ${(err as Error).message}`;
      throw new ProviderError(msg, "transport");
    }
    if (!res.ok) {
      // 529 = Anthropic overloaded — treat as rate limit so the caller can retry/wait
      const kind = res.status === 529 ? "rate_limit" : httpErrorKind(res.status);
      const body = await res.text().catch(() => "");
      throw new ProviderError(httpErrorMessage("Anthropic", res.status, body), kind);
    }
    const json = (await res.json()) as { content?: { type: string; text?: string }[] };
    const text = json.content?.find(b => b.type === "text")?.text;
    if (!text) throw new ProviderError("Anthropic returned no content", "other");
    return { rawText: text };
  }
}
