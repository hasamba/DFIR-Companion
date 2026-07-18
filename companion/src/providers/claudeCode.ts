import {
  type AIProvider, type AnalyzeRequest, type AnalyzeResult, type ProviderUsage,
  type ProviderErrorKind, ProviderError,
} from "./provider.js";
import { type ClaudeRunner, defaultClaudeRunner } from "./claudeRunner.js";

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

    // Parse newline-delimited JSON events: keep the terminal `result`, and note any rejected rate limit.
    let resultEvent: ClaudeResultEvent | undefined;
    let rateLimited = false;
    for (const line of run.stdout.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      let evt: unknown;
      try { evt = JSON.parse(t); } catch { continue; }
      const e = evt as { type?: string; rate_limit_info?: { status?: string } };
      if (e.type === "result") resultEvent = evt as ClaudeResultEvent;
      else if (e.type === "rate_limit_event" && e.rate_limit_info?.status && e.rate_limit_info.status !== "allowed") {
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

    const text = resultEvent.result;
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
