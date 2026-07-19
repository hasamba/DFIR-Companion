import { tmpdir } from "node:os";
import {
  type AIProvider, type AnalyzeRequest, type AnalyzeResult, type ProviderUsage,
  type ProviderErrorKind, ProviderError,
} from "./provider.js";
import { type CodexRunner, defaultCodexRunner } from "./codexRunner.js";

export interface CodexOptions {
  model: string;         // maps to `codex -m <model>`; "" → omit (codex default)
  bin?: string;          // DFIR_AI_CODEX_BIN, or "codex" on PATH
  timeoutMs?: number;
  runner?: CodexRunner;  // injected in tests; defaults to the real spawn runner
}

// Text-only provider that drives `codex exec`. Codex is a coding agent, not a vision model, so
// screenshot extraction is rejected up front; codex is meant for the text/synthesis role.
export class CodexProvider implements AIProvider {
  readonly name = "codex";
  readonly model: string;
  private readonly bin: string;
  private readonly timeoutMs: number;
  private readonly runner: CodexRunner;

  constructor(opts: CodexOptions) {
    this.model = opts.model;
    this.bin = opts.bin?.trim() || "codex";
    this.timeoutMs = opts.timeoutMs ?? 180_000;
    this.runner = opts.runner ?? defaultCodexRunner;
  }

  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    if (req.images.length > 0) {
      throw new ProviderError(
        "Codex is text-only and can't read screenshots. Use a vision provider for extraction " +
        "and set codex as the text/synthesis model (DFIR_AI_SYNTH_PROVIDER=codex).",
        "other",
      );
    }

    const prompt = `${req.systemPrompt}\n\n${req.userPrompt}`;
    const cwd = tmpdir(); // a neutral dir: codex exec runs read-only, outside any git repo
    // No PROMPT argument — codex reads it from stdin instead (see codexRunner.ts for why: a
    // `.cmd`-shimmed CLI on Windows runs through cmd.exe's ~8KB command-line limit, well below a
    // typical synthesis prompt).
    const args = [
      "exec",
      "--json",
      "--skip-git-repo-check",
      "--sandbox", "read-only",
      "-C", cwd,
      ...(this.model ? ["-m", this.model] : []),
    ];

    const run = await this.runner({ bin: this.bin, args, stdin: prompt, timeoutMs: this.timeoutMs, signal: req.signal, cwd });

    if (run.spawnError) {
      if (run.spawnError.code === "ENOENT") {
        throw new ProviderError(
          `Codex CLI not found (tried "${this.bin}"). Install it (\`npm i -g @openai/codex\`) and run ` +
          `\`codex login\` (or set OPENAI_API_KEY), or set DFIR_AI_CODEX_BIN to its path.`,
          "other",
        );
      }
      throw new ProviderError(`Codex failed to start: ${run.spawnError.message}`, "transport");
    }
    if (run.timedOut) throw new ProviderError(`Codex timed out after ${this.timeoutMs}ms`, "timeout");

    const parsed = parseCodexOutput(run.stdout);
    if (!parsed.text) {
      // Codex's own `error` events are far more useful than stderr, which carries routine noise
      // ("Reading prompt from stdin...", MCP-client startup warnings) even on a fully successful
      // run — so stderr being non-empty is NOT by itself a failure signal.
      if (parsed.errors.length) {
        // MCP-client startup failures are unrelated to the request (they come from the user's own
        // ~/.codex/config.toml) and codex emits them on runs that otherwise succeed. Lead with the
        // real cause so it isn't pushed past the truncation by that noise.
        const mcpNoise = (m: string) => /^MCP client\b/i.test(m);
        const real = parsed.errors.filter((m) => !mcpNoise(m));
        const chosen = real.length ? real : parsed.errors;
        const snip = chosen.join("; ").replace(/\s+/g, " ").trim().slice(0, 300);
        throw new ProviderError(`Codex: ${snip}`, classifyKind(run.code, snip));
      }
      if ((run.code ?? 0) !== 0) {
        const snip = (run.stderr || "no output").replace(/\s+/g, " ").trim().slice(0, 300);
        throw new ProviderError(`Codex: ${snip}`, classifyKind(run.code, run.stderr));
      }
      throw new ProviderError("Codex returned no content", "other");
    }
    return { rawText: parsed.text, ...(parsed.usage ? { usage: parsed.usage } : {}) };
  }
}

// ── output parsing ────────────────────────────────────────────────────────────────────────────
// `codex exec --json` emits newline-delimited JSON events. The schema is NOT a stable contract —
// two materially different shapes are already confirmed in the wild, so both are handled:
//
//   codex-cli 0.39.x   {"id":"0","msg":{"type":"agent_message","message":"PONG"}}
//                      usage at msg.info.total_token_usage
//   codex-cli 0.144.x  {"type":"item.completed","item":{"type":"agent_message","text":"PONG"}}
//                      usage at turn.completed.usage
//
// Hence the layered unwrap (`msg`, then `item`, each falling back to the event itself) and the
// several accepted field spellings. Anything unrecognised degrades to the raw-stdout fallback
// rather than silently yielding an empty synthesis.
interface ParsedCodex { text?: string; usage?: ProviderUsage; errors: string[]; }

function parseCodexOutput(stdout: string): ParsedCodex {
  let agentText: string | undefined;  // from an explicit agent_message — the actual answer
  let anyText: string | undefined;    // fallback: any other message-like event
  let usage: ProviderUsage | undefined;
  const errors: string[] = [];
  for (const line of stdout.split("\n")) {
    const t = line.trim();
    if (!t || t[0] !== "{") continue;
    let evt: unknown;
    try { evt = JSON.parse(t); } catch { continue; }
    const e = asRecord(evt);
    if (!e) continue;
    const body = asRecord(e.msg) ?? e;          // 0.39.x envelope
    const payload = asRecord(body.item) ?? body; // 0.144.x item wrapper
    const outerType = typeof body.type === "string" ? body.type : "";
    const innerType = typeof payload.type === "string" ? payload.type : "";
    // Match ANY error-ish type at either level — 0.39.x emits `error` (MCP startup failures) and
    // `stream_error` (e.g. "model not found"), each with a human-readable `message` that is
    // shape-identical to an answer. A substring match is used deliberately rather than equality
    // against a fixed list, because returning one of these as the synthesis result would report a
    // hard failure as a confident finding.
    if (/error/i.test(outerType) || /error/i.test(innerType)) {
      const m = firstString(payload.message, payload.text, body.message, body.text);
      if (m) errors.push(m);
      continue;
    }
    const msg = extractText(payload);
    if (msg) {
      // Prefer a real agent_message: a turn also emits reasoning / command / tool items that carry
      // their own text, and those must never stand in for the model's answer.
      if (innerType === "agent_message" || outerType === "agent_message") agentText = msg;
      else anyText = msg;
    }
    const u = extractUsage(body) ?? extractUsage(payload);
    if (u) usage = u;
  }
  let text = agentText ?? anyText;
  if (!text) {
    const raw = stdout.split("\n").filter((l) => { const t = l.trim(); return t && t[0] !== "{"; }).join("\n").trim();
    if (raw) text = raw;
  }
  return { ...(text ? { text } : {}), ...(usage ? { usage } : {}), errors };
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : undefined;
}
function numOr(v: unknown): number | undefined {
  return typeof v === "number" ? v : undefined;
}
function firstString(...vs: unknown[]): string | undefined {
  for (const v of vs) if (typeof v === "string" && v.trim()) return v;
  return undefined;
}

function extractText(evt: unknown): string | undefined {
  const e = asRecord(evt);
  if (!e) return undefined;
  const direct = firstString(e.text, e.message, e.content, e.output_text, e.delta);
  if (direct) return direct;
  // content as an array of blocks: [{ type: "text", text: "..." }]
  const arr = Array.isArray(e.content) ? e.content : Array.isArray(e.output) ? e.output : undefined;
  if (arr) {
    const parts = arr.map((b) => { const r = asRecord(b); return r && typeof r.text === "string" ? r.text : ""; }).filter(Boolean);
    if (parts.length) return parts.join("");
  }
  // nested { message: { content|text: ... } }
  const nested = asRecord(e.message);
  if (nested) return extractText(nested);
  return undefined;
}

function extractUsage(evt: unknown): ProviderUsage | undefined {
  const e = asRecord(evt);
  if (!e) return undefined;
  // codex-cli 0.39.0: { type: "token_count", info: { total_token_usage: { input_tokens, output_tokens, … } } }
  const info = asRecord(e.info);
  const total = info ? (asRecord(info.total_token_usage) ?? asRecord(info.last_token_usage)) : undefined;
  const u = total ?? asRecord(e.usage) ?? asRecord(e.token_usage)
    ?? (typeof e.input_tokens === "number" || typeof e.output_tokens === "number" ? e : undefined);
  if (!u) return undefined;
  const inp = numOr(u.input_tokens) ?? numOr(u.prompt_tokens) ?? numOr(u.inputTokens);
  const out = numOr(u.output_tokens) ?? numOr(u.completion_tokens) ?? numOr(u.outputTokens);
  const cost = numOr(u.cost_usd) ?? numOr(u.costUSD) ?? numOr(u.total_cost_usd);
  if (inp === undefined && out === undefined && cost === undefined) return undefined;
  return {
    ...(inp !== undefined ? { inputTokens: inp } : {}),
    ...(out !== undefined ? { outputTokens: out } : {}),
    ...(cost !== undefined ? { costUSD: cost } : {}),
  };
}

function classifyKind(code: number | null, stderr: string): ProviderErrorKind {
  const s = (stderr || "").toLowerCase();
  if (/unauthor|not (logged|signed) in|auth|login|api key|401|403/.test(s)) return "auth";
  if (/rate limit|quota|429|too many requests/.test(s)) return "rate_limit";
  if (/5\d\d|network|econn|socket|timed out/.test(s)) return "transport";
  return code === null ? "transport" : "other";
}
