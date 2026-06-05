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
  // The model's context window, in tokens. When set (>0), a pre-flight guard estimates the
  // request and keeps it inside this window — reducing the sent max_tokens if the prompt is
  // large-but-fits, or failing fast with a clear "context" error if the prompt alone is too
  // big — instead of a cryptic upstream "maximum context length is N tokens" 400. 0/unset
  // disables the guard.
  contextTokens?: number;
  // "high" tiles the image at full resolution (best for reading small text in
  // forensic screenshots); "low" downscales to one tile (cheaper, blurrier).
  imageDetail?: "high" | "low" | "auto";
}

// Rough token estimate (~4 chars/token) — mirrors analysis/promptBudget without coupling the
// provider layer to it. Conservative enough with the 5% margin the guard applies.
function estTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

export class OpenAIProvider implements AIProvider {
  readonly name: string = "openai";
  private readonly fetchFn: FetchFn;
  private readonly baseUrl: string;
  constructor(private readonly opts: OpenAIOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.baseUrl = opts.baseUrl ?? "https://api.openai.com/v1";
  }

  // Human-friendly name for error messages — subclasses share this OpenAI-compatible
  // request path, so resolve the label from the (possibly overridden) provider name
  // rather than hardcoding "OpenAI".
  private get label(): string {
    switch (this.name) {
      case "openrouter": return "OpenRouter";
      case "ollama": return "Ollama";
      case "litellm": return "LiteLLM";
      default: return "OpenAI";
    }
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

    // Pre-flight context guard: keep the request inside the model's window so an oversized
    // prompt fails fast with an actionable message (or sends with reduced output room),
    // rather than a cryptic upstream "maximum context length" 400.
    let maxTokens = this.opts.maxTokens;
    const ctx = this.opts.contextTokens ?? 0;
    if (ctx > 0) {
      // ~1100 tokens per full-detail image tile (upper bound); "low" is roughly one tile.
      const imageTokens = req.images.length * (detail === "low" ? 400 : 1200);
      const promptTokens = estTokens(req.systemPrompt) + estTokens(req.userPrompt) + imageTokens;
      const margin = Math.max(1000, Math.ceil(ctx * 0.05));
      const MIN_OUTPUT = 1024;
      if (promptTokens + margin >= ctx - MIN_OUTPUT) {
        throw new ProviderError(
          `${this.label} prompt is ~${promptTokens.toLocaleString()} tokens, over the model's ${ctx.toLocaleString()}-token context. ` +
          `Reduce the input (lower DFIR_AI_SYNTH_MAX_EVENTS, split the import into smaller files / fewer rows per batch) ` +
          `or set DFIR_AI_CONTEXT_TOKENS to your model's real window.`,
          "context",
        );
      }
      const room = ctx - promptTokens - margin;   // shrink reserved output to fit if needed
      if (maxTokens === undefined || maxTokens > room) maxTokens = Math.max(MIN_OUTPUT, room);
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
          ...(maxTokens ? { max_tokens: maxTokens } : {}),
          messages: [
            { role: "system", content: req.systemPrompt },
            { role: "user", content },
          ],
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      const msg = (err as Error).name === "TimeoutError"
        ? `${this.label} request timed out after ${timeoutMs}ms`
        : `${this.label} transport error: ${(err as Error).message}`;
      throw new ProviderError(msg, "transport");
    }
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new ProviderError(httpErrorMessage(this.label, res.status, body), httpErrorKind(res.status));
    }
    const json = (await res.json()) as { choices?: { message?: { content?: string } }[] };
    const text = json.choices?.[0]?.message?.content;
    if (!text) throw new ProviderError(`${this.label} returned no content`, "other");
    return { rawText: text };
  }
}
