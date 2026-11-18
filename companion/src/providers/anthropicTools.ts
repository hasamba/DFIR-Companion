// Anthropic Messages API mapping for one tool-calling turn: the request body built from a
// ConverseRequest, and the reply parsed into a ConverseResult. The echo rules for earlier assistant
// turns (block order, dropped thinking after a masked change) live in anthropicEcho.ts.
import { API_CACHE, cachedUserContent } from "./cachedUserContent.js";
import type { ProviderUsage } from "./provider.js";
import type { ConverseRequest, ConverseResult, ToolCall, ToolTurn } from "./toolCalling.js";
import { syntheticId } from "./toolCalling.js";
import {
  type AnthropicBlock,
  type AnthropicOpaque,
  echoAssistantTurn,
  isThinkingBlock,
  prefixFingerprint,
  TEXT_JOIN,
} from "./anthropicEcho.js";

export interface AnthropicUsageWire {
  input_tokens?: number;
  output_tokens?: number;
  cache_creation_input_tokens?: number;
  cache_read_input_tokens?: number;
}

export interface AnthropicMessageResponse {
  content?: AnthropicBlock[];
  stop_reason?: string;
  stop_details?: { category?: string | null } | null;
  usage?: AnthropicUsageWire;
}

/** model, max_tokens and the thinking fields, chosen by the provider exactly as for analyze. */
export type AnthropicBaseParams = Record<string, unknown>;

function toolResultMessage(turn: Extract<ToolTurn, { role: "tool" }>) {
  return {
    role: "user",
    content: turn.results.map((r) => ({
      type: "tool_result",
      tool_use_id: r.id,
      content: r.content,
      ...(r.isError ? { is_error: true } : {}),
    })),
  };
}

/**
 * The request body, plus the fingerprint of everything in it. The reply's thinking blocks are bound
 * to exactly that, so the fingerprint goes into the reply's opaque value.
 */
export function anthropicToolBody(
  req: ConverseRequest,
  base: AnthropicBaseParams,
): { body: Record<string, unknown>; prefixHash: string } {
  // Built the same way on every send of a loop: the tools and system never change mid-loop.
  const tools = req.tools.map((t) => ({
    name: t.name,
    description: t.description,
    input_schema: t.parameters,
  }));
  // Prompt caching: the static system prompt, plus the cache prefix when the gate set one (#2658, #2675).
  const system = [{ type: "text", text: req.systemPrompt, cache_control: { type: "ephemeral" } }];
  const messages: unknown[] = [
    { role: "user", content: cachedUserContent(req.userPrompt, req.cachePrefix, API_CACHE) },
  ];
  const binding = { model: base.model, thinking: base.thinking, output_config: base.output_config };
  const fingerprint = () => prefixFingerprint(binding, system, tools, messages);
  for (const turn of req.transcript) {
    if (turn.role === "tool") messages.push(toolResultMessage(turn));
    else messages.push({ role: "assistant", content: echoAssistantTurn(turn, fingerprint(), req.withhold) });
  }
  const body = { ...base, tools, tool_choice: { type: req.toolChoice }, system, messages };
  return { body, prefixHash: fingerprint() };
}

function plainInput(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

// Every tool_use gets a present, unique id: tool results are matched back by it. A repaired id or a
// dropped malformed block means the stored turn differs from what the model sent, so every thinking
// block after that point would be bound to content that never existed: it is not stored (`kept`).
function repairBlocks(raw: unknown[], salt?: string): { blocks: AnthropicBlock[]; kept: AnthropicBlock[] } {
  const seen = new Set<string>();
  const blocks: AnthropicBlock[] = [];
  const kept: AnthropicBlock[] = [];
  let altered = false;
  raw.forEach((item, i) => {
    const b = item as AnthropicBlock | null;
    if (!b || typeof b !== "object" || typeof b.type !== "string") {
      altered = true;
      return;
    }
    let out = b;
    if (b.type === "tool_use") {
      let id =
        typeof b.id === "string" && b.id && !seen.has(b.id) ? b.id : syntheticId("toolu_dfir_", i, salt);
      while (seen.has(id)) id = `${id}_`;
      seen.add(id);
      if (id !== b.id) {
        out = { ...b, id };
        altered = true;
      }
    }
    blocks.push(out);
    if (!(altered && isThinkingBlock(out))) kept.push(out);
  });
  return { blocks, kept };
}

export function anthropicUsage(u: AnthropicUsageWire | undefined): ProviderUsage | undefined {
  return (
    u && {
      ...(u.input_tokens !== undefined ? { inputTokens: u.input_tokens } : {}),
      ...(u.output_tokens !== undefined ? { outputTokens: u.output_tokens } : {}),
      ...(u.cache_creation_input_tokens !== undefined
        ? { cacheCreationTokens: u.cache_creation_input_tokens }
        : {}),
      ...(u.cache_read_input_tokens !== undefined ? { cacheReadTokens: u.cache_read_input_tokens } : {}),
    }
  );
}

/** The readable thinking a built body echoes: what converse() would send, after every drop. */
export function anthropicEchoedText(body: Record<string, unknown>): string[] {
  const messages = (body.messages ?? []) as Array<{ role: string; content: unknown }>;
  return messages
    .filter((m) => m.role === "assistant" && Array.isArray(m.content))
    .flatMap((m) => m.content as AnthropicBlock[])
    .filter((b) => b.type === "thinking" && typeof b.thinking === "string" && b.thinking !== "")
    .map((b) => b.thinking as string);
}

/** A reply as tool calls or final text. Refusal and max_tokens are already handled by the send. */
export function parseAnthropicTurn(
  json: AnthropicMessageResponse,
  prefixHash: string,
  salt?: string,
): ConverseResult {
  const { blocks, kept } = repairBlocks(json.content ?? [], salt);
  const text = blocks
    .filter((b) => b.type === "text")
    .map((b) => String(b.text ?? ""))
    .join(TEXT_JOIN);
  const calls: ToolCall[] = blocks
    .filter((b) => b.type === "tool_use")
    .map((b) => ({ id: String(b.id), name: String(b.name ?? ""), input: plainInput(b.input) }));
  const opaqueText = kept
    .filter((b) => b.type === "thinking" && typeof b.thinking === "string" && b.thinking !== "")
    .map((b) => b.thinking as string);
  const opaque: AnthropicOpaque | undefined = kept.some(isThinkingBlock)
    ? { p: "anthropic", v: 1, prefixHash, blocks: kept }
    : undefined;
  const usage = anthropicUsage(json.usage);
  return {
    text,
    calls,
    ...(opaque ? { opaque } : {}),
    ...(opaqueText.length ? { opaqueText } : {}),
    ...(usage ? { usage } : {}),
  };
}
