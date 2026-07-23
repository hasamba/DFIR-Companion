import {
  type AIProvider, type AnalyzeRequest, type AnalyzeResult, type ProviderUsage,
  type ProviderErrorKind, ProviderError,
} from "./provider.js";
import { type ClaudeRunner, defaultClaudeRunner } from "./claudeRunner.js";
import { extractJsonText } from "../analysis/extractJson.js";

export interface ClaudeCodeOptions {
  model: string;         // maps to --model (alias like "haiku" or a full id); "" → omit the flag
  bin?: string;          // DFIR_AI_CLAUDE_CODE_BIN, or "claude" on PATH
  timeoutMs?: number;
  runner?: ClaudeRunner; // injected in tests; defaults to the real spawn runner
}

// The claude CLI's terminal stream-json event (fields we consume).
interface ClaudeResultEvent {
  type: "result";
  subtype?: string;
  is_error?: boolean;
  api_error_status?: number | string | null;
  result?: string;
  total_cost_usd?: number;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
    cache_creation_input_tokens?: number;
    cache_read_input_tokens?: number;
  };
  // Keyed by the CONCRETE model id(s) actually invoked (e.g. "claude-sonnet-4-6") — present even
  // when --model was given as an alias ("sonnet"/"haiku"/"opus"), which the CLI resolves before
  // billing. Confirmed live: NOT always a single key — a call can also carry a small internal
  // Haiku sub-call (routing/classification, a handful of output tokens) alongside the primary
  // generation, so picking "the first key" is wrong; see pickResolvedModel() below.
  modelUsage?: Record<string, { outputTokens?: number }>;
}

// One `assistant` stream event (fields we consume). The CLI emits a separate event per assistant
// message — and keeps thinking blocks in their own event — so a CONTINUED answer arrives as
// several of these.
interface ClaudeAssistantEvent {
  type: "assistant";
  message?: { content?: { type?: string; text?: string }[] };
}

// Concatenated text of one assistant event ("" when it carried only thinking/tool blocks).
function eventText(e: ClaudeAssistantEvent): string {
  return (e.message?.content ?? []).filter((b) => b.type === "text" && typeof b.text === "string")
    .map((b) => b.text as string).join("");
}

// Reassemble an answer the CLI split across assistant messages. When a response hits the model's
// max output tokens, the CLI continues the turn in a NEW assistant message — and the continuation
// re-opens a markdown fence right where the previous message was cut, mid-value. Confirmed live
// (case meridian-espionage-gt, second-opinion synthesis): part 1 ended `..."a known CDN, cloud`
// and part 2 began "```\n provider, or hosting service...". Dropping that re-opened fence (and the
// newline the CLI puts after it, which would otherwise land as a raw newline inside a JSON string)
// splices the parts back into the single JSON document the model meant to write.
//
// A second message is NOT always a continuation, though. The model may instead abandon the
// truncated attempt and rewrite the whole answer from the top — captured live on case
// veridia-deep-pass (deep-pass final synthesis): part 1 was cut mid-string at `...the SSH pivot
// from AN`, and part 2 was a complete, fenced, 16-finding document. Splicing those glues a
// truncated document onto a whole one, and part 1's half-open string literal then swallows the
// next line, so JSON.parse dies with `Bad control character in string literal` — at ~9 minutes and
// ~50k output tokens per wasted attempt.
//
// The two cases are told apart by RESULT, not by a guess about the text: splice first, and keep
// that splice whenever it parses. Only when it does not, and the final part parses cleanly ON ITS
// OWN, is the earlier text an abandoned draft to be dropped. If neither parses, the splice is
// returned unchanged so the existing truncation repair still gets its chance at it.
function parsesCleanly(text: string): boolean {
  try {
    const value: unknown = JSON.parse(extractJsonText(text));
    return !!value && typeof value === "object";
  } catch {
    return false;
  }
}

function stitchContinuation(parts: readonly string[]): string {
  const spliced = parts
    .map((p, i) => (i === 0 ? p : p.replace(/^[ \t]*```(?:json)?[ \t]*\r?\n?/i, "")))
    .join("");
  if (parts.length < 2 || parsesCleanly(spliced)) return spliced;
  const last = parts[parts.length - 1];
  return parsesCleanly(last) ? last : spliced;
}

// modelUsage can hold more than one model per call (a cheap internal routing/classification
// sub-call plus the primary generation) — the entry with the most OUTPUT tokens is the one that
// actually produced the response text, so that's the "resolved model" worth surfacing/logging.
function pickResolvedModel(modelUsage: ClaudeResultEvent["modelUsage"]): string | undefined {
  const entries = Object.entries(modelUsage ?? {});
  if (entries.length === 0) return undefined;
  return entries.reduce((best, cur) => ((cur[1]?.outputTokens ?? 0) > (best[1]?.outputTokens ?? 0) ? cur : best))[0];
}

// Isolation flags: replace the default system prompt, load NO settings/hooks/CLAUDE.md, no MCP,
// and NO tools. The empty tool allowlist also strips tool schemas that otherwise cost ~15k input
// tokens per call, and guarantees a single-turn call can't hang on a tool-permission prompt.
const ISOLATION_ARGS = ["--strict-mcp-config", "--setting-sources", "", "--allowed-tools", ""];

export class ClaudeCodeProvider implements AIProvider {
  readonly name = "claude-code";
  readonly model: string;
  private readonly bin: string;
  private readonly timeoutMs: number;
  private readonly runner: ClaudeRunner;

  constructor(opts: ClaudeCodeOptions) {
    this.model = opts.model;
    this.bin = opts.bin?.trim() || "claude";
    this.timeoutMs = opts.timeoutMs ?? 180_000;
    this.runner = opts.runner ?? defaultClaudeRunner;
  }

  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    const content: unknown[] = [{ type: "text", text: req.userPrompt }];
    for (const img of req.images) {
      content.push({ type: "image", source: { type: "base64", media_type: img.mimeType, data: img.base64 } });
    }
    const stdin = JSON.stringify({ type: "user", message: { role: "user", content } }) + "\n";

    const args = [
      "-p",
      "--input-format", "stream-json",
      "--output-format", "stream-json",
      "--verbose",
      ...(this.model ? ["--model", this.model] : []),
      "--system-prompt", req.systemPrompt,
      ...ISOLATION_ARGS,
    ];

    const run = await this.runner({ bin: this.bin, args, stdin, timeoutMs: this.timeoutMs, signal: req.signal });

    if (run.spawnError) {
      if (run.spawnError.code === "ENOENT") {
        throw new ProviderError(
          `Claude Code CLI not found (tried "${this.bin}"). Install Claude Code and run \`claude auth login\`, ` +
          `or set DFIR_AI_CLAUDE_CODE_BIN to its path.`,
          "other",
        );
      }
      throw new ProviderError(`Claude Code failed to start: ${run.spawnError.message}`, "transport");
    }
    if (run.timedOut) {
      throw new ProviderError(`Claude Code timed out after ${this.timeoutMs}ms`, "timeout");
    }

    // Parse newline-delimited JSON events: keep the terminal `result`, every assistant text block
    // (for the continuation stitch below), and note any rejected rate limit.
    let resultEvent: ClaudeResultEvent | undefined;
    let rateLimited = false;
    const assistantTexts: string[] = [];
    for (const line of run.stdout.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      let evt: unknown;
      try { evt = JSON.parse(t); } catch { continue; }
      const e = evt as { type?: string; rate_limit_info?: { status?: string } };
      if (e.type === "result") resultEvent = evt as ClaudeResultEvent;
      else if (e.type === "assistant") {
        const text = eventText(evt as ClaudeAssistantEvent);
        if (text) assistantTexts.push(text);
      } else if (e.type === "rate_limit_event" && e.rate_limit_info?.status && e.rate_limit_info.status !== "allowed") {
        rateLimited = true;
      }
    }

    if (!resultEvent) {
      const snip = (run.stderr || run.stdout).replace(/\s+/g, " ").trim().slice(0, 200);
      const kind: ProviderErrorKind = rateLimited ? "rate_limit" : "transport";
      throw new ProviderError(`Claude Code produced no result (exit ${run.code ?? "null"})${snip ? ` — ${snip}` : ""}`, kind);
    }

    if (resultEvent.is_error || (resultEvent.subtype && resultEvent.subtype !== "success")) {
      const kind = classify(resultEvent, rateLimited);
      const msg = resultEvent.result?.trim() || `Claude Code error (${resultEvent.subtype ?? "unknown"})`;
      throw new ProviderError(`Claude Code: ${msg}`, kind);
    }

    // `result` holds ONLY the LAST assistant message, so a max_tokens continuation would hand the
    // caller the tail half of the JSON (which then fails to parse). Two or more assistant text
    // messages can only mean a continued turn here — tools are disabled — so stitch them instead.
    const text = assistantTexts.length > 1 ? stitchContinuation(assistantTexts) : resultEvent.result;
    if (!text) throw new ProviderError("Claude Code returned no content", "other");

    const u = resultEvent.usage;
    const resolvedModel = pickResolvedModel(resultEvent.modelUsage);
    const hasUsage = !!u || resultEvent.total_cost_usd !== undefined || !!resolvedModel;
    const usage: ProviderUsage | undefined = hasUsage ? {
      ...(u?.input_tokens !== undefined ? { inputTokens: u.input_tokens } : {}),
      ...(u?.output_tokens !== undefined ? { outputTokens: u.output_tokens } : {}),
      ...(u?.cache_creation_input_tokens !== undefined ? { cacheCreationTokens: u.cache_creation_input_tokens } : {}),
      ...(u?.cache_read_input_tokens !== undefined ? { cacheReadTokens: u.cache_read_input_tokens } : {}),
      ...(resultEvent.total_cost_usd !== undefined ? { costUSD: resultEvent.total_cost_usd } : {}),
      ...(resolvedModel ? { resolvedModel } : {}),
    } : undefined;

    return { rawText: text, ...(usage ? { usage } : {}) };
  }
}

function classify(e: ClaudeResultEvent, rateLimited: boolean): ProviderErrorKind {
  if (rateLimited) return "rate_limit";
  const status = typeof e.api_error_status === "number" ? e.api_error_status : undefined;
  if (status === 401 || status === 403) return "auth";
  if (status === 429) return "rate_limit";
  if (status !== undefined && status >= 500) return "transport";
  const msg = (e.result ?? "").toLowerCase();
  if (/log ?in|unauthor|not signed in|authenticate|auth/.test(msg)) return "auth";
  if (/rate limit|quota|usage limit/.test(msg)) return "rate_limit";
  return "other";
}
