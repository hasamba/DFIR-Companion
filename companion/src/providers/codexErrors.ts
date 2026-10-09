import type { ProviderErrorKind } from "./provider.js";

/**
 * Turn the `error` events of a failed `codex exec --json` run into one message an analyst can act
 * on (#2042).
 *
 * Codex prints warning-only `error` events on runs that may still succeed: MCP clients from the
 * user's own ~/.codex/config.toml that failed to start, a configured service tier the model does not
 * support, missing model metadata. The API's real refusal comes LAST, as a JSON string
 * (`{"type":"error","status":400,"error":{"type":"invalid_request_error","message":"…"}}`). Joining
 * everything in order and cutting at 300 characters therefore always cut the one sentence that
 * says what to fix. Here the warnings go, the envelope is unwrapped, and a model the account
 * cannot use becomes a "model" error that names the setting and is not retried. That kind needs
 * an API 4xx refusal (not 429) as well as the wording, so a transient error that merely mentions a
 * model stays retryable (#2051).
 */

const MAX_MESSAGE_CHARS = 300;

const WARNING_ONLY = [
  /^MCP client\b/i,
  /^Configured service tier\b.*\bwill be omitted\b/i,
  /^Model metadata for\b.*\bnot found\b/i,
];

const UNSUPPORTED_MODEL =
  /\bmodel\b.*\b(is not supported|not supported when|does not exist|is not available|not found|unsupported)\b/i;

// The text match alone is too broad (#2051): a reworded warning, a stream error or a 500 that says
// "model … not found" would become kind "model", which is never retried. So the error must also be
// the API's own client refusal — a described envelope that starts with a 4xx status other than 429.
// A plain-text refusal with no envelope falls back to the caller's classification and is retried.
const API_CLIENT_REFUSAL = /^(?!429\b)4\d\d\b/;

const MODEL_SETTING_HINT =
  'Change "Model (synthesis and imports)" in Settings, or leave it empty to use the Codex default.';

export interface CodexFailure {
  message: string;
  kind: ProviderErrorKind | undefined; // undefined → let the caller classify from the exit code
}

/** One message per error event: a JSON API envelope is reduced to "<status> <type> — <message>". */
export function describeCodexError(raw: string): string {
  const text = raw.trim();
  if (!text.startsWith("{")) return text;
  try {
    const env = JSON.parse(text) as { status?: unknown; error?: { type?: unknown; message?: unknown } };
    const inner = env.error;
    if (!inner || typeof inner.message !== "string" || !inner.message.trim()) return text;
    const status = typeof env.status === "number" ? String(env.status) : "";
    const type = typeof inner.type === "string" ? inner.type : "";
    const head = [status, type].filter(Boolean).join(" ");
    return head ? `${head} — ${inner.message.trim()}` : inner.message.trim();
  } catch {
    return text;
  }
}

const isWarningOnly = (m: string): boolean => WARNING_ONLY.some((rx) => rx.test(m));

/** A described API refusal (4xx, not 429) whose text says the model itself is the problem (#2051). */
const isModelRefusal = (m: string): boolean => API_CLIENT_REFUSAL.test(m) && UNSUPPORTED_MODEL.test(m);

/** Choose, rewrite and classify the errors of a run that produced no answer. */
export function codexFailure(errors: readonly string[]): CodexFailure {
  const described = errors.map(describeCodexError);
  const real = described.filter((m) => !isWarningOnly(m));
  const chosen = [...new Set(real.length ? real : described)];
  const joined = chosen.join("; ").replace(/\s+/g, " ").trim().slice(0, MAX_MESSAGE_CHARS);
  const unsupportedModel = real.some(isModelRefusal);
  return unsupportedModel
    ? { message: `${joined} ${MODEL_SETTING_HINT}`, kind: "model" }
    : { message: joined, kind: undefined };
}
