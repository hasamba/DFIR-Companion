// The provider-neutral contract for one native tool-calling turn (Watson phase 5).
//
// A caller keeps the transcript; a provider's `converse()` sends it once and returns either tool
// calls or final text. Nothing here loops, runs a tool or masks a value: those live with the caller.
// `opaque` is provider-private (signed reasoning, block order) and only the adapter that produced it
// reads it back. `opaqueText` is the readable part of it, exposed so the caller can scan it.
import { ProviderError, type ProviderUsage } from "./provider.js";

/** One tool the model may call. `parameters` is a JSON Schema object. */
export interface ToolSpec {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

export interface ToolCall {
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export interface ToolResult {
  id: string;
  name: string;
  content: string;
  isError?: boolean;
}

export type ToolTurn =
  | { role: "assistant"; text: string; calls: ToolCall[]; opaque?: unknown; opaqueText?: string[] }
  | { role: "tool"; results: ToolResult[] };

export interface ConverseRequest {
  systemPrompt: string;
  userPrompt: string;
  transcript: ToolTurn[];
  tools: ToolSpec[];
  toolChoice: "auto" | "none";
  /**
   * Unique per send of one conversation (Watson passes "t<n>"). A call the provider sent without an id
   * gets a synthetic one built from it, so ids never repeat across turns and are never renamed later.
   */
  idSalt?: string;
  signal?: AbortSignal;
  /**
   * The leading part of userPrompt a provider may cache (#2658). On a request a PROVIDER receives it is
   * always MASKED text and userPrompt starts with it; the masking gate sets it only when anonymization is
   * on (the analyst's rule: case data is cached at the provider only when masked). Providers that cannot
   * mark a cache boundary ignore it — userPrompt is always the whole prompt.
   */
  cachePrefix?: string;

  /**
   * Readable signed reasoning the caller will not send (it holds a value the masking now hides).
   * The adapter drops such a block exactly as it drops a block whose prefix changed.
   */
  withhold?: (readableText: string) => boolean;
}

export interface ConverseResult {
  text: string;
  calls: ToolCall[];
  opaque?: unknown;
  opaqueText?: string[];
  usage?: ProviderUsage;
}

/**
 * The provider or model refused the request because it cannot call tools. Kind "other" so no
 * existing kind-based handling changes; the generic retry checks for this class and never retries
 * it, because the same model refuses the same request every time.
 */
export class ToolsUnsupportedError extends ProviderError {
  constructor(message: string) {
    super(message, "other");
    this.name = "ToolsUnsupportedError";
  }
}

// Only these statuses carry a "this model has no tool support" refusal. Auth, rate limit and
// server errors keep their own kinds.
const TOOL_REJECTION_STATUSES = new Set([400, 404, 422]);
// The refusal strings providers send for a model without tool support. Context-length, auth and
// schema errors never match.
const TOOL_REJECTION_TEXT =
  /no endpoints found that support tool use|does not support tools|tool use is not supported|tools are not supported/i;

/** A synthetic call id: wire-safe ([A-Za-z0-9_-]), unique per send when `salt` is given. */
export function syntheticId(prefix: string, i: number, salt?: string): string {
  const safe = salt?.replace(/[^A-Za-z0-9_-]/g, "");
  return safe ? `${prefix.replace(/_?$/, "_")}${safe}_${i}` : `${prefix}${i}`;
}

export function isToolsRejection(status: number, body: string): boolean {
  return TOOL_REJECTION_STATUSES.has(status) && TOOL_REJECTION_TEXT.test(body);
}

/**
 * The provider refused the transcript because of a thinking block in it (a block bound to other
 * content, a changed block, or a final assistant turn that must start with one). The same body
 * fails the same way every time, so it is never retried; the tool loop can fall back to the
 * one-step hop instead.
 */
export class ThinkingBindingError extends ProviderError {
  constructor(message: string) {
    super(message, "other");
    this.name = "ThinkingBindingError";
  }
}

// Recorded Anthropic 400 messages about thinking blocks in the transcript.
const THINKING_REJECTION_TEXT =
  /must start with a thinking block|bound to a different conversation|invalid `?signature`? in `?thinking`? block|thinking`? (or `?redacted_thinking`? )?blocks? .*cannot be modified/i;

export function isThinkingRejection(status: number, body: string): boolean {
  return status === 400 && THINKING_REJECTION_TEXT.test(body);
}

/**
 * The provider refused the transcript's shape: a thought signature or the order of call and result
 * turns (Gemini). The same body fails the same way every time, so it is never retried. Unlike
 * ToolsUnsupportedError the model can call tools, so the tool loop falls back to the one-step hop
 * for this question only and never marks the model tool-less.
 */
export class TurnBindingError extends ProviderError {
  constructor(message: string) {
    super(message, "other");
    this.name = "TurnBindingError";
  }
}
