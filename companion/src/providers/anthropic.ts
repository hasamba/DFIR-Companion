import {
  type AIProvider,
  type AnalyzeRequest,
  type AnalyzeResult,
  type ProviderUsage,
  ProviderError,
  httpErrorKind,
  httpErrorMessage,
  requestSignal,
} from "./provider.js";
import { validateBaseUrl } from "./urlValidation.js";
import {
  readBoundedJson,
  readBoundedText,
  RESPONSE_SIZE_LIMITS,
  ResponseTooLargeError,
} from "./boundedResponse.js";
import { effortForBudget } from "./claudeEffort.js";

type FetchFn = typeof fetch;

// Anthropic requires the extended-thinking budget to be ≥1024 tokens; a smaller ask means "off".
const MIN_THINKING_TOKENS = 1024;
// Keep this much output room above the thinking budget (budget_tokens must be < max_tokens).
const THINKING_OUTPUT_HEADROOM = 4096;
// Only these models still take a fixed `thinking.budget_tokens`: Claude 3.x, the 4.0–4.5 Opus/Sonnet
// line, and Haiku 4.5. Opus 4.7+, Sonnet 5 and the Opus 5 / Fable lines reject budget_tokens with a
// 400; they take adaptive thinking plus an `output_config.effort` tier instead. Unknown ids (a proxy
// alias) are treated as current models.
const BUDGET_THINKING_MODEL = /^claude-(3|haiku-4|(opus|sonnet)-4(-[0-5])?(-\d{8})?$)/;
// Opus 4.6 / Sonnet 4.6 take adaptive thinking but have no `xhigh` tier.
const NO_XHIGH_MODEL = /^claude-(opus|sonnet)-4-6/;
// Current models can think on every call (Opus 5 does so by default), and thinking counts toward
// max_tokens. Reserve this much on top of the configured cap so the cap still means "answer room".
const THINKING_ROOM = 16_000;

export interface AnthropicOptions {
  apiKey: string;
  model: string; // e.g. "claude-haiku-4-5-20251001", "claude-sonnet-4-6"
  baseUrl?: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
  maxTokens?: number;
}

export class AnthropicProvider implements AIProvider {
  readonly name = "anthropic";
  readonly model: string;
  // thinkingTokens → `thinking.budget_tokens` on older models, an effort tier on current ones (#1468).
  readonly supportsThinking = true;
  private readonly fetchFn: FetchFn;
  private readonly baseUrl: string;

  constructor(private readonly opts: AnthropicOptions) {
    this.model = opts.model;
    this.fetchFn = opts.fetchFn ?? fetch;
    this.baseUrl = opts.baseUrl ?? "https://api.anthropic.com/v1";
    const urlErr = validateBaseUrl(this.baseUrl);
    if (urlErr) throw new ProviderError(urlErr, "transport");
  }

  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    const content: unknown[] = [{ type: "text", text: req.userPrompt }];
    for (const img of req.images) {
      content.push({
        type: "image",
        source: { type: "base64", media_type: img.mimeType, data: img.base64 },
      });
    }

    let maxTokens = this.opts.maxTokens ?? 16000;
    // Extended thinking / Chain-of-Thought (issue #121). When the caller asks for a thinking budget
    // (synthesis only), enable it: the model reasons in `thinking` blocks before the final answer.
    // Older models take the budget as-is; the Messages API requires budget_tokens ≥ 1024 AND
    // < max_tokens, so we bump max_tokens to keep output headroom above the budget. Current models
    // reject budget_tokens and get adaptive thinking at an effort tier instead. Thinking forces temperature=1 — we never
    // send a custom temperature, so the default is already compatible. Prompt caching is UNAFFECTED:
    // the cache breakpoint stays on the static system prompt (OPSEC) and thinking happens in the reply.
    const legacyThinking = BUDGET_THINKING_MODEL.test(this.opts.model);
    const thinkingBudget =
      legacyThinking && req.thinkingTokens && req.thinkingTokens >= MIN_THINKING_TOKENS
        ? Math.floor(req.thinkingTokens)
        : 0;
    if (thinkingBudget > 0) maxTokens = Math.max(maxTokens, thinkingBudget + THINKING_OUTPUT_HEADROOM);
    // Current models: the same budget picks an effort tier (the claude-code mapping, #1468).
    const tier = legacyThinking ? undefined : effortForBudget(req.thinkingTokens);
    const effort = tier === "xhigh" && NO_XHIGH_MODEL.test(this.opts.model) ? "high" : tier;
    if (!legacyThinking) maxTokens += THINKING_ROOM;
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
          ...(thinkingBudget > 0 ? { thinking: { type: "enabled", budget_tokens: thinkingBudget } } : {}),
          ...(effort ? { thinking: { type: "adaptive" }, output_config: { effort } } : {}),
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
        signal: requestSignal(timeoutMs, req.signal),
      });
    } catch (err) {
      const msg =
        (err as Error).name === "TimeoutError"
          ? `Anthropic request timed out after ${timeoutMs}ms`
          : `Anthropic transport error: ${(err as Error).message}`;
      throw new ProviderError(msg, "transport");
    }
    if (!res.ok) {
      // 529 = Anthropic overloaded — treat as rate limit so the caller can retry/wait
      const kind = res.status === 529 ? "rate_limit" : httpErrorKind(res.status);
      const body = await readBoundedText(res, {
        maxBytes: RESPONSE_SIZE_LIMITS.text,
        context: "Anthropic",
      }).catch(() => "");
      throw new ProviderError(httpErrorMessage("Anthropic", res.status, body), kind);
    }
    type AnthropicMessageResponse = {
      content?: { type: string; text?: string }[];
      stop_reason?: string;
      stop_details?: { category?: string | null } | null;
      usage?: {
        input_tokens?: number;
        output_tokens?: number;
        cache_creation_input_tokens?: number;
        cache_read_input_tokens?: number;
      };
    };
    let json: AnthropicMessageResponse;
    try {
      json = await readBoundedJson<AnthropicMessageResponse>(res, {
        maxBytes: RESPONSE_SIZE_LIMITS.json,
        context: "Anthropic",
      });
    } catch (err) {
      const kind = err instanceof ResponseTooLargeError ? "transport" : "other";
      throw new ProviderError(`Anthropic response error: ${(err as Error).message}`, kind);
    }
    // Check why the model stopped before reading content. A refusal is HTTP 200 with no usable
    // answer; a max_tokens stop is a cut-off JSON document that would fail to parse downstream.
    if (json.stop_reason === "refusal") {
      const category = json.stop_details?.category;
      throw new ProviderError(`Anthropic declined the request${category ? ` (${category})` : ""}`, "other");
    }
    if (json.stop_reason === "max_tokens") {
      throw new ProviderError(
        `Anthropic reply was cut off at max_tokens (${maxTokens}) — raise DFIR_AI_MAX_TOKENS`,
        "context",
      );
    }
    const text = json.content?.find((b) => b.type === "text")?.text;
    if (!text) throw new ProviderError("Anthropic returned no content", "other");
    const u = json.usage;
    const usage: ProviderUsage | undefined = u && {
      ...(u.input_tokens !== undefined ? { inputTokens: u.input_tokens } : {}),
      ...(u.output_tokens !== undefined ? { outputTokens: u.output_tokens } : {}),
      ...(u.cache_creation_input_tokens !== undefined
        ? { cacheCreationTokens: u.cache_creation_input_tokens }
        : {}),
      ...(u.cache_read_input_tokens !== undefined ? { cacheReadTokens: u.cache_read_input_tokens } : {}),
    };
    // Confirm prompt caching actually fired (default-quiet: extraction makes many calls).
    // Set DFIR_AI_DEBUG_USAGE to see per-call cache read/write so a sub-threshold no-op is
    // visible rather than silently assumed.
    if (
      process.env.DFIR_AI_DEBUG_USAGE &&
      usage &&
      ((usage.cacheReadTokens ?? 0) > 0 || (usage.cacheCreationTokens ?? 0) > 0)
    ) {
      console.warn(
        `[DFIR] anthropic cache: read=${usage.cacheReadTokens ?? 0} write=${usage.cacheCreationTokens ?? 0} input=${usage.inputTokens ?? 0} tokens`,
      );
    }
    return { rawText: text, ...(usage ? { usage } : {}) };
  }
}
