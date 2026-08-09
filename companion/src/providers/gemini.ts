import { type AIProvider, type AnalyzeRequest, type AnalyzeResult, ProviderError, httpErrorKind, httpErrorMessage, requestSignal } from "./provider.js";
import { validateBaseUrl } from "./urlValidation.js";

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
  readonly model: string;
  private readonly fetchFn: FetchFn;
  private readonly baseUrl: string;
  constructor(private readonly opts: GeminiOptions) {
    this.model = opts.model;
    this.fetchFn = opts.fetchFn ?? fetch;
    this.baseUrl = opts.baseUrl ?? "https://generativelanguage.googleapis.com/v1beta";
    const urlErr = validateBaseUrl(this.baseUrl);
    if (urlErr) throw new ProviderError(urlErr, "transport");
  }

  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    const parts: unknown[] = [{ text: `${req.systemPrompt}\n\n${req.userPrompt}` }];
    for (const img of req.images) {
      parts.push({ inline_data: { mime_type: img.mimeType, data: img.base64 } });
    }
    // The key goes in a header, never the query string: a URL is written into the request line, so
    // ?key=... lands in the access log of every proxy or gateway on the path — and baseUrl is
    // operator-configurable, so that path is not always one they control. Google supports both.
    const url = `${this.baseUrl}/models/${this.opts.model}:generateContent`;
    const timeoutMs = this.opts.timeoutMs ?? 60_000;
    let res: Response;
    try {
      res = await this.fetchFn(url, {
        method: "POST",
        headers: { "content-type": "application/json", "x-goog-api-key": this.opts.apiKey },
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
    const json = (await res.json()) as {
      candidates?: { content?: { parts?: { text?: string }[] } }[];
      usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number; cachedContentTokenCount?: number };
    };
    const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) throw new ProviderError("Gemini returned no content", "other");
    // Google's Generative Language response includes usageMetadata (promptTokenCount,
    // candidatesTokenCount, cachedContentTokenCount). Parse it so the Diagnostics "AI cost — this
    // case" card shows real token counts for Gemini instead of always 0/0 (bug #3). Google does
    // not report a dollar cost, so costUSD is omitted (matching the other providers).
    const u = json.usageMetadata;
    const usage = u && {
      ...(u.promptTokenCount !== undefined ? { inputTokens: u.promptTokenCount } : {}),
      ...(u.candidatesTokenCount !== undefined ? { outputTokens: u.candidatesTokenCount } : {}),
      ...(u.cachedContentTokenCount !== undefined ? { cacheReadTokens: u.cachedContentTokenCount } : {}),
    };
    return { rawText: text, ...(usage ? { usage } : {}) };
  }
}
