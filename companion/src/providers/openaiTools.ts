// OpenAI chat-completions mapping for one tool-calling turn (OpenAI, OpenRouter, Ollama /v1): the
// request body built from a ConverseRequest, and the reply parsed into a ConverseResult.
//
// Vendor rules (Chat Completions reference; OpenRouter "Reasoning Tokens" guide):
//   - tools are `{type:"function", function:{name, description, parameters}}`; tool_choice is
//     "auto" | "none"; a call comes back as `tool_calls[{id, type, function:{name, arguments}}]`
//     with `arguments` a JSON string, and its result goes back as `{role:"tool", tool_call_id}`.
//   - OpenRouter returns `reasoning_details` on the assistant message. It must go back on that
//     message exactly as received, in order, and only next to the content it was produced with.
// So `opaque` keeps the reply's reasoning_details with the original content and tool calls. On the
// next send they go back only when the caller's (masked) turn still matches, on the same provider
// and model; otherwise they are dropped and the masked turn goes as given. An unmasked value is never
// sent to keep reasoning valid.
import type { ConverseRequest, ConverseResult, ToolCall, ToolTurn } from "./toolCalling.js";
import { syntheticId } from "./toolCalling.js";
import { canonical } from "./anthropicEcho.js";

export interface WireToolCall {
  id?: string;
  type?: string;
  function?: { name?: string; arguments?: string };
}

export interface ChatMessageWire {
  content?: string | null;
  reasoning?: unknown;
  refusal?: string | null;
  tool_calls?: WireToolCall[];
  reasoning_details?: unknown[];
}

interface OpenAiOpaque {
  p: "openai-compat"; // only this adapter echoes it; another provider's opaque value is ignored
  v: 1;
  provider: string;
  model: string;
  content: string;
  toolCalls: Required<WireToolCall>[];
  reasoningDetails: unknown[];
}

/** model, max_tokens and the provider's own extras (reasoning, usage), as for analyze. */
export type OpenAiBaseParams = Record<string, unknown>;
type AssistantTurn = Extract<ToolTurn, { role: "assistant" }>;

function wireCall(c: ToolCall): Required<WireToolCall> {
  return { id: c.id, type: "function", function: { name: c.name, arguments: JSON.stringify(c.input) } };
}

function readOpaque(value: unknown, provider: string, model: string): OpenAiOpaque | undefined {
  if (!value || typeof value !== "object") return undefined;
  const o = value as Partial<OpenAiOpaque>;
  const ok =
    o.p === "openai-compat" &&
    o.v === 1 &&
    o.provider === provider &&
    o.model === model &&
    typeof o.content === "string" &&
    Array.isArray(o.toolCalls) &&
    Array.isArray(o.reasoningDetails);
  return ok ? (o as OpenAiOpaque) : undefined;
}

function sameCalls(orig: Required<WireToolCall>[], calls: ToolCall[]): boolean {
  return (
    orig.length === calls.length &&
    orig.every((w, i) => {
      const c = calls[i];
      return (
        w.id === c.id &&
        w.function.name === c.name &&
        canonical(parseArgs(w.function.arguments)) === canonical(c.input)
      );
    })
  );
}

function assistantMessage(
  turn: AssistantTurn,
  provider: string,
  model: string,
  withhold?: (text: string) => boolean,
): Record<string, unknown> {
  const op = readOpaque(turn.opaque, provider, model);
  // Withheld readable reasoning drops the whole reasoning_details, as a changed turn does.
  const held = !!op && !!withhold && readableDetails(op.reasoningDetails).some(withhold);
  if (op && !held && op.content === turn.text && sameCalls(op.toolCalls, turn.calls)) {
    return {
      role: "assistant",
      content: op.content || null,
      ...(op.toolCalls.length ? { tool_calls: op.toolCalls } : {}),
      reasoning_details: op.reasoningDetails,
    };
  }
  return {
    role: "assistant",
    content: turn.text || null,
    ...(turn.calls.length ? { tool_calls: turn.calls.map(wireCall) } : {}),
  };
}

/** Every message of the request, from the system prompt to the last tool results. */
export function openAiMessages(req: ConverseRequest, provider: string, model: string): unknown[] {
  const messages: unknown[] = [
    { role: "system", content: req.systemPrompt },
    { role: "user", content: req.userPrompt },
  ];
  for (const turn of req.transcript) {
    if (turn.role === "assistant") messages.push(assistantMessage(turn, provider, model, req.withhold));
    else
      for (const r of turn.results) messages.push({ role: "tool", tool_call_id: r.id, content: r.content });
  }
  return messages;
}

export function openAiTools(req: ConverseRequest): unknown[] {
  return req.tools.map((t) => ({
    type: "function",
    function: { name: t.name, description: t.description, parameters: t.parameters },
  }));
}

/** The request body. response_format json_object stays on: the final answer is still JSON. */
export function openAiToolBody(
  req: ConverseRequest,
  base: OpenAiBaseParams,
  provider: string,
): Record<string, unknown> {
  return {
    ...base,
    response_format: { type: "json_object" },
    tools: openAiTools(req),
    tool_choice: req.toolChoice,
    messages: openAiMessages(req, provider, String(base.model)),
  };
}

function parseArgs(raw: unknown): Record<string, unknown> {
  if (typeof raw !== "string") return {};
  try {
    const v: unknown = JSON.parse(raw);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    return {}; // the dispatcher reports the missing arguments to the model
  }
}

// True when the model's argument string is a JSON object. Anything else is replaced by {}.
function argsParse(raw: unknown): boolean {
  try {
    const v: unknown = typeof raw === "string" ? JSON.parse(raw) : undefined;
    return !!v && typeof v === "object" && !Array.isArray(v);
  } catch {
    return false;
  }
}

/** Present, unique call ids: a missing or repeated one gets a wire-safe synthetic id (review M2). */
export function uniqueIds(
  raw: (string | undefined)[],
  prefix: string,
  salt?: string,
): { ids: string[]; repaired: boolean } {
  const seen = new Set<string>();
  let repaired = false;
  const ids = raw.map((r, i) => {
    const base = typeof r === "string" && r ? r : syntheticId(prefix, i, salt);
    let id = seen.has(base) ? syntheticId(prefix, i, salt) : base;
    while (seen.has(id)) id = `${id}_`;
    seen.add(id);
    // A synthetic id for a call sent without one is not a repair: it is stored and echoed unchanged.
    if (typeof r === "string" && r && id !== r) repaired = true;
    return id;
  });
  return { ids, repaired };
}

// The readable reasoning, so the caller can scan it: OpenRouter's text and summary entries (never
// the encrypted ones), else the plain `reasoning` string hosted Ollama returns.
function readableReasoning(m: ChatMessageWire): string[] {
  if (Array.isArray(m.reasoning_details) && m.reasoning_details.length)
    return readableDetails(m.reasoning_details);
  return typeof m.reasoning === "string" && m.reasoning ? [m.reasoning] : [];
}

function readableDetails(details: readonly unknown[]): string[] {
  return details.flatMap((d) => {
    const e = d as { type?: string; text?: unknown; summary?: unknown };
    const value =
      e.type === "reasoning.text" ? e.text : e.type === "reasoning.summary" ? e.summary : undefined;
    return typeof value === "string" && value ? [value] : [];
  });
}

/** The readable reasoning a built body echoes: what converse() would send, after every drop. */
export function openAiEchoedText(body: Record<string, unknown>): string[] {
  const messages = (body.messages ?? []) as Array<{ reasoning_details?: unknown }>;
  return messages.flatMap((m) =>
    Array.isArray(m.reasoning_details) ? readableDetails(m.reasoning_details) : [],
  );
}

/** A reply message as tool calls or final text. Stop reasons are already checked by the send. */
export function parseOpenAiTurn(
  m: ChatMessageWire,
  provider: string,
  model: string,
  salt?: string,
): Omit<ConverseResult, "usage"> {
  const wire = (m.tool_calls ?? []).filter((w) => w && typeof w === "object");
  const { ids, repaired } = uniqueIds(
    wire.map((w) => w.id),
    "call_dfir_",
    salt,
  );
  const toolCalls = wire.map((w, i) => ({
    id: ids[i],
    type: "function",
    function: { name: String(w.function?.name ?? ""), arguments: String(w.function?.arguments ?? "") },
  }));
  const calls = toolCalls.map((w) => ({
    id: w.id,
    name: w.function.name,
    input: parseArgs(w.function.arguments),
  }));
  const text = typeof m.content === "string" ? m.content : "";
  const details =
    Array.isArray(m.reasoning_details) && m.reasoning_details.length ? m.reasoning_details : undefined;
  // A renamed duplicate id or unreadable arguments mean the stored turn differs from what the model sent: its
  // reasoning is not kept.
  const altered = repaired || toolCalls.some((w) => !argsParse(w.function.arguments));
  const opaque: OpenAiOpaque | undefined =
    details && !altered
      ? { p: "openai-compat", v: 1, provider, model, content: text, toolCalls, reasoningDetails: details }
      : undefined;
  const opaqueText = readableReasoning(m);
  return { text, calls, ...(opaque ? { opaque } : {}), ...(opaqueText.length ? { opaqueText } : {}) };
}
