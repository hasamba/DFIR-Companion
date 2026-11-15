// Shared fixtures for the Anthropic tool-calling tests: a provider on a fake fetch that records each
// request body, canned Messages API responses, and ConverseRequest builders. No network.
import { fetchMock, jsonResponse } from "../helpers/fetchMock.js";
import { AnthropicProvider } from "../../src/providers/anthropic.js";
import type { ConverseRequest, ConverseResult, ToolTurn } from "../../src/providers/toolCalling.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Body = any;

export const TOOL = {
  name: "forensic_lookup",
  description: "Search the forensic timeline.",
  parameters: { type: "object", properties: { text: { type: "string" } }, required: ["text"] },
};

export function anthropicWith(responses: unknown[], model = "claude-opus-5-5") {
  const bodies: Body[] = [];
  let i = 0;
  const fetchFn = fetchMock(async (_url, init) => {
    bodies.push(JSON.parse(init?.body as string));
    const r = responses[Math.min(i++, responses.length - 1)];
    return r instanceof Response ? r : jsonResponse(r);
  });
  return { provider: new AnthropicProvider({ apiKey: "k", model, fetchFn }), bodies, fetchFn };
}

export function req(over: Partial<ConverseRequest> = {}): ConverseRequest {
  return {
    systemPrompt: "You are Watson.",
    userPrompt: "What ran on ANON_HOST_1?",
    transcript: [],
    tools: [TOOL],
    toolChoice: "auto",
    ...over,
  };
}

export const thinking = (sig: string, text = "") => ({ type: "thinking", thinking: text, signature: sig });
export const redacted = (data: string) => ({ type: "redacted_thinking", data });
export const text = (t: string) => ({ type: "text", text: t });
export const toolUse = (id: string, input: Record<string, unknown>, name = "forensic_lookup") => ({
  type: "tool_use",
  id,
  name,
  input,
});

export function response(content: unknown[], stop_reason = "tool_use") {
  return {
    content,
    stop_reason,
    usage: { input_tokens: 10, output_tokens: 5, cache_read_input_tokens: 3 },
  };
}

export function toolUseResponse(id: string, name: string, input: Record<string, unknown>) {
  return response([toolUse(id, input, name)]);
}

export const assistantTurn: Extract<ToolTurn, { role: "assistant" }> = {
  role: "assistant",
  text: "Looking.",
  calls: [{ id: "tu0", name: "forensic_lookup", input: { text: "a" } }],
};

export function toolTurn(...ids: string[]): ToolTurn {
  return {
    role: "tool",
    results: ids.map((id) => ({ id, name: "forensic_lookup", content: `rows for ${id}` })),
  };
}

/** The assistant turn a caller appends after a reply (clear-text fields as given, opaque kept). */
export function turnOf(r: ConverseResult): ToolTurn {
  return {
    role: "assistant",
    text: r.text,
    calls: r.calls,
    ...(r.opaque !== undefined ? { opaque: r.opaque } : {}),
  };
}
