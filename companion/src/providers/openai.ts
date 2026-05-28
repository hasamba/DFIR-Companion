import { type AIProvider, type AnalyzeRequest, type AnalyzeResult, ProviderError } from "./provider.js";

type FetchFn = typeof fetch;

export interface OpenAIOptions {
  apiKey: string;
  model: string;
  baseUrl?: string;
  fetchFn?: FetchFn;
}

function mapStatus(status: number): ProviderError["kind"] {
  if (status === 401 || status === 403) return "auth";
  if (status === 429) return "rate_limit";
  if (status === 408 || status >= 500) return "transport";
  return "other";
}

export class OpenAIProvider implements AIProvider {
  readonly name = "openai";
  private readonly fetchFn: FetchFn;
  private readonly baseUrl: string;
  constructor(private readonly opts: OpenAIOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.baseUrl = opts.baseUrl ?? "https://api.openai.com/v1";
  }

  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    const content: unknown[] = [{ type: "text", text: req.userPrompt }];
    for (const img of req.images) {
      content.push({ type: "image_url", image_url: { url: `data:${img.mimeType};base64,${img.base64}` } });
    }
    const res = await this.fetchFn(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${this.opts.apiKey}` },
      body: JSON.stringify({
        model: this.opts.model,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: req.systemPrompt },
          { role: "user", content },
        ],
      }),
    });
    if (!res.ok) throw new ProviderError(`OpenAI HTTP ${res.status}`, mapStatus(res.status));
    const json = (await res.json()) as { choices?: { message?: { content?: string } }[] };
    const text = json.choices?.[0]?.message?.content;
    if (!text) throw new ProviderError("OpenAI returned no content", "other");
    return { rawText: text };
  }
}
