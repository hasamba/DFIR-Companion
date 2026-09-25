import {
  type AIProvider,
  type AnalyzeRequest,
  type AnalyzeResult,
  type ProviderUsage,
  ProviderError,
  httpErrorKind,
  httpErrorMessage,
  outputLimitError,
  requestSignal,
} from "./provider.js";
import { validateBaseUrl } from "./urlValidation.js";
import { readBoundedJson, readBoundedText, RESPONSE_SIZE_LIMITS } from "./boundedResponse.js";

type FetchFn = typeof fetch;

export interface GeminiOptions {
  apiKey: string;
  model: string; // e.g. "gemini-1.5-pro"
  baseUrl?: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
  maxTokens?: number; // cap on output tokens (maxOutputTokens)
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
      const msg =
        (err as Error).name === "TimeoutError"
          ? `Gemini request timed out after ${timeoutMs}ms`
          : `Gemini transport error: ${(err as Error).message}`;
      throw new ProviderError(msg, "transport");
    }
    if (!res.ok) {
      const body = await readBoundedText(res, {
        maxBytes: RESPONSE_SIZE_LIMITS.text,
        context: "Gemini",
      }).catch(() => "");
      throw new ProviderError(httpErrorMessage("Gemini", res.status, body), httpErrorKind(res.status));
    }
    const json = await readBoundedJson<GeminiResponse>(res, {
      maxBytes: RESPONSE_SIZE_LIMITS.json,
      context: "Gemini",
    });
    const text = replyText(json, req, this.opts.maxTokens);
    const usage = parseUsage(json.usageMetadata);
    return { rawText: text, ...(usage ? { usage } : {}) };
  }
}

type GeminiResponse = {
  candidates?: { content?: { parts?: { text?: string }[] }; finishReason?: string }[];
  usageMetadata?: {
    promptTokenCount?: number;
    candidatesTokenCount?: number;
    cachedContentTokenCount?: number;
    thoughtsTokenCount?: number;
  };
};

/**
 * The answer text, or a thrown error. finishReason MAX_TOKENS means the model hit maxOutputTokens —
 * on a thinking model the hidden thoughts count against it. A cut-off with no text, or any cut-off
 * when the caller rejects truncated output, is an output_limit error; otherwise the partial text is
 * returned for the caller to salvage.
 */
function replyText(json: GeminiResponse, req: AnalyzeRequest, maxTokens: number | undefined): string {
  const candidate = json.candidates?.[0];
  const text = candidate?.content?.parts?.[0]?.text;
  if (candidate?.finishReason === "MAX_TOKENS" && (!text || req.rejectTruncated)) {
    throw outputLimitError("Gemini", maxTokens, json.usageMetadata?.thoughtsTokenCount);
  }
  if (!text) throw new ProviderError("Gemini returned no content", "other");
  return text;
}

// Google's Generative Language response includes usageMetadata (promptTokenCount,
// candidatesTokenCount, cachedContentTokenCount). Parse it so the Diagnostics "AI cost — this
// case" card shows real token counts for Gemini instead of always 0/0 (bug #3). Google does
// not report a dollar cost, so costUSD is omitted (matching the other providers).
function parseUsage(u: GeminiResponse["usageMetadata"]): ProviderUsage | undefined {
  return (
    u && {
      ...(u.promptTokenCount !== undefined ? { inputTokens: u.promptTokenCount } : {}),
      ...(u.candidatesTokenCount !== undefined ? { outputTokens: u.candidatesTokenCount } : {}),
      ...(u.cachedContentTokenCount !== undefined ? { cacheReadTokens: u.cachedContentTokenCount } : {}),
    }
  );
}
