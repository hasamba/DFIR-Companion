// Token budgeting for AI prompts, so a big case / wide-row import never exceeds the
// model's context window (the field failure was OpenRouter HTTP 400: "maximum context
// length is 128000 tokens. However, you requested about 251167 tokens"). We deliberately
// do NOT pull in a real tokenizer — that's a heavy dependency for a localhost tool, and
// ~4 chars/token is the standard rough rule for English + JSON. The 5% safety margin below
// absorbs the heuristic's drift and per-message role overhead.

// Conservative token estimate for a string (round up; ~4 chars/token).
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

// The model's usable context window, in tokens. Default 128000 — the common OpenRouter
// ceiling and exactly the limit that 400'd in the field. Raise via DFIR_AI_CONTEXT_TOKENS
// for a bigger-context model (Claude 200k, Gemini 1M). The default is safe: it only ever
// trims genuinely huge prompts — normal cases (capped at 300 events) sit far under it.
export const DEFAULT_CONTEXT_TOKENS = 128_000;
export function contextTokens(): number {
  const v = Number(process.env.DFIR_AI_CONTEXT_TOKENS);
  return Number.isFinite(v) && v > 0 ? v : DEFAULT_CONTEXT_TOKENS;
}

// The reserved completion-token budget (must match what the provider sends as max_tokens).
export const DEFAULT_MAX_OUTPUT_TOKENS = 16_000;
export function maxOutputTokens(): number {
  const v = Number(process.env.DFIR_AI_MAX_TOKENS);
  return Number.isFinite(v) && v > 0 ? v : DEFAULT_MAX_OUTPUT_TOKENS;
}

// Tokens available for INPUT once the reserved output and a safety margin are removed.
// margin = 5% of the context (min 1000) for tokenizer drift + system/role overhead.
export function inputTokenBudget(ctx = contextTokens(), maxOut = maxOutputTokens()): number {
  const margin = Math.max(1000, Math.ceil(ctx * 0.05));
  return Math.max(0, ctx - maxOut - margin);
}

// How many items from the FRONT of an already-prioritized list fit within a token budget.
// Always returns ≥1 (a single oversized item is still sent — the provider guard then trims
// the output room or raises a clear error). budgetTokens ≤ 0 disables trimming (keep all).
export function fitItemsToBudget<T>(items: readonly T[], render: (t: T) => string, budgetTokens: number): number {
  if (budgetTokens <= 0 || items.length === 0) return items.length;
  let used = 0;
  let n = 0;
  for (const it of items) {
    used += estimateTokens(render(it)) + 1; // +1 for the joining newline
    if (used > budgetTokens && n > 0) break;
    n++;
  }
  return n;
}

// Split items into batches that respect BOTH a max count and a per-batch token budget, so
// a few very wide rows (e.g. a SIEM/EDR CSV with long command-lines) don't form one batch
// that overflows the model context. A single item larger than the budget becomes its own
// batch (the provider guard handles it from there). budgetTokens ≤ 0 → count-only batching.
export function batchByBudget<T>(
  items: readonly T[],
  maxCount: number,
  render: (t: T) => string,
  budgetTokens: number,
): T[][] {
  const cap = Math.max(1, maxCount);
  const out: T[][] = [];
  let cur: T[] = [];
  let used = 0;
  for (const it of items) {
    const t = estimateTokens(render(it));
    const overCount = cur.length >= cap;
    const overBudget = budgetTokens > 0 && cur.length > 0 && used + t > budgetTokens;
    if (cur.length > 0 && (overCount || overBudget)) {
      out.push(cur);
      cur = [];
      used = 0;
    }
    cur.push(it);
    used += t;
  }
  if (cur.length > 0) out.push(cur);
  return out;
}
