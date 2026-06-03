import { type AIProvider, type AnalyzeRequest, type AnalyzeResult, ProviderError, httpErrorKind, httpErrorMessage } from "./provider.js";

type FetchFn = typeof fetch;

export interface OpenAIOptions {
  apiKey: string;
  model: string;
  baseUrl?: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
  // Cap on completion tokens. Bounds cost AND keeps OpenRouter's per-request
  // affordability check (credits >= (input + max_output) * price) from reserving the
  // model's full max output — the usual cause of a 402 on a large (e.g. THOR) request.
  maxTokens?: number;
  // "high" tiles the image at full resolution (best for reading small text in
  // forensic screenshots); "low" downscales to one tile (cheaper, blurrier).
  imageDetail?: "high" | "low" | "auto";
}

export class OpenAIProvider implements AIProvider {
  readonly name: string = "openai";
  private readonly fetchFn: FetchFn;
  private readonly baseUrl: string;
  constructor(private readonly opts: OpenAIOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.baseUrl = opts.baseUrl ?? "https://api.openai.com/v1";
  }

  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    const detail = this.opts.imageDetail ?? "high";
    const content: unknown[] = [{ type: "text", text: req.userPrompt }];
    for (const img of req.images) {
      content.push({
        type: "image_url",
        image_url: { url: `data:${img.mimeType};base64,${img.base64}`, detail },
      });
    }
    const timeoutMs = this.opts.timeoutMs ?? 60_000;
    let res: Response;
    try {
      res = await this.fetchFn(`${this.baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${this.opts.apiKey}` },
        body: JSON.stringify({
          model: this.opts.model,
          response_format: { type: "json_object" },
          ...(this.opts.maxTokens ? { max_tokens: this.opts.maxTokens } : {}),
          messages: [
            { role: "system", content: req.systemPrompt },
            { role: "user", content },
          ],
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      const msg = (err as Error).name === "TimeoutError"
        ? `OpenAI request timed out after ${timeoutMs}ms`
        : `OpenAI transport error: ${(err as Error).message}`;
      throw new ProviderError(msg, "transport");
    }
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new ProviderError(httpErrorMessage(this.name === "openrouter" ? "OpenRouter" : "OpenAI", res.status, body), httpErrorKind(res.status));
    }
    const json = (await res.json()) as { choices?: { message?: { content?: string } }[] };
    const text = json.choices?.[0]?.message?.content;
    if (!text) throw new ProviderError("OpenAI returned no content", "other");
    return { rawText: text };
  }
}
