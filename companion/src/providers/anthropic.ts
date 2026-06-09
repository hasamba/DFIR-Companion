import { type AIProvider, type AnalyzeRequest, type AnalyzeResult, type ProviderUsage, ProviderError, httpErrorKind, httpErrorMessage } from "./provider.js";

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
          // Prompt caching (GA — no beta header). Mark ONLY the static system prompt as the
          // cacheable prefix: extraction reuses it across many screenshot batches, so the
          // prefix is billed once and read cheaply thereafter. The case content (user message
          // + screenshots) follows this breakpoint and is NEVER cached — OPSEC: only the
          // static instructions are retained provider-side for the (5-min) cache TTL, never
          // forensic evidence. A prefix under the model's minimum (1024 tokens; 2048 on Haiku)
          // silently no-ops — confirm via usage.cache_* below (DFIR_AI_DEBUG_USAGE), don't assume.
          system: [{ type: "text", text: req.systemPrompt, cache_control: { type: "ephemeral" } }],
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
    const json = (await res.json()) as {
      content?: { type: string; text?: string }[];
      usage?: {
        input_tokens?: number;
        output_tokens?: number;
        cache_creation_input_tokens?: number;
        cache_read_input_tokens?: number;
      };
    };
    const text = json.content?.find(b => b.type === "text")?.text;
    if (!text) throw new ProviderError("Anthropic returned no content", "other");
    const u = json.usage;
    const usage: ProviderUsage | undefined = u && {
      ...(u.input_tokens !== undefined ? { inputTokens: u.input_tokens } : {}),
      ...(u.output_tokens !== undefined ? { outputTokens: u.output_tokens } : {}),
      ...(u.cache_creation_input_tokens !== undefined ? { cacheCreationTokens: u.cache_creation_input_tokens } : {}),
      ...(u.cache_read_input_tokens !== undefined ? { cacheReadTokens: u.cache_read_input_tokens } : {}),
    };
    // Confirm prompt caching actually fired (default-quiet: extraction makes many calls).
    // Set DFIR_AI_DEBUG_USAGE to see per-call cache read/write so a sub-threshold no-op is
    // visible rather than silently assumed.
    if (process.env.DFIR_AI_DEBUG_USAGE && usage && ((usage.cacheReadTokens ?? 0) > 0 || (usage.cacheCreationTokens ?? 0) > 0)) {
      console.warn(`[DFIR] anthropic cache: read=${usage.cacheReadTokens ?? 0} write=${usage.cacheCreationTokens ?? 0} input=${usage.inputTokens ?? 0} tokens`);
    }
    return { rawText: text, ...(usage ? { usage } : {}) };
  }
}
