import { type AIProvider, type AnalyzeRequest, type AnalyzeResult, ProviderError, httpErrorKind, httpErrorMessage, requestSignal } from "./provider.js";

type FetchFn = typeof fetch;

export interface GeminiOptions {
  apiKey: string;
  model: string;       // e.g. "gemini-1.5-pro"
  baseUrl?: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
  maxTokens?: number;  // cap on output tokens (maxOutputTokens)
}

export class GeminiProvider implements AIProvider {
  readonly name = "gemini";
  private readonly fetchFn: FetchFn;
  private readonly baseUrl: string;
  constructor(private readonly opts: GeminiOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.baseUrl = opts.baseUrl ?? "https://generativelanguage.googleapis.com/v1beta";
  }

  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    const parts: unknown[] = [{ text: `${req.systemPrompt}\n\n${req.userPrompt}` }];
    for (const img of req.images) {
      parts.push({ inline_data: { mime_type: img.mimeType, data: img.base64 } });
    }
    const url = `${this.baseUrl}/models/${this.opts.model}:generateContent?key=${this.opts.apiKey}`;
    const timeoutMs = this.opts.timeoutMs ?? 60_000;
    let res: Response;
    try {
      res = await this.fetchFn(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          contents: [{ role: "user", parts }],
          generationConfig: {
            responseMimeType: "application/json",
            ...(this.opts.maxTokens ? { maxOutputTokens: this.opts.maxTokens } : {}),
          },
        }),
        signal: requestSignal(timeoutMs, req.signal),
      });
    } catch (err) {
      const msg = (err as Error).name === "TimeoutError"
        ? `Gemini request timed out after ${timeoutMs}ms`
        : `Gemini transport error: ${(err as Error).message}`;
      throw new ProviderError(msg, "transport");
    }
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new ProviderError(httpErrorMessage("Gemini", res.status, body), httpErrorKind(res.status));
    }
    const json = (await res.json()) as { candidates?: { content?: { parts?: { text?: string }[] } }[] };
    const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) throw new ProviderError("Gemini returned no content", "other");
    return { rawText: text };
  }
}
