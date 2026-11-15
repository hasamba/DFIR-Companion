// Shared fixtures for the OpenAI-compatible and Gemini tool-calling tests: providers on a fake fetch
// that records each request body, canned vendor replies in their recorded shapes, and transcript
// builders. No network, no secrets.
import { fetchMock, jsonResponse } from "../helpers/fetchMock.js";
import { OpenAIProvider, type OpenAIOptions } from "../../src/providers/openai.js";
import { OpenRouterProvider } from "../../src/providers/openrouter.js";
import { OllamaCloudProvider } from "../../src/providers/ollama.js";
import { GeminiProvider } from "../../src/providers/gemini.js";
import type { ConverseResult, ToolCall, ToolTurn } from "../../src/providers/toolCalling.js";

export { req, TOOL } from "./anthropicToolsHelpers.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Body = any;

function recorder(responses: unknown[]) {
  const bodies: Body[] = [];
  const urls: string[] = [];
  let i = 0;
  const fetchFn = fetchMock(async (url, init) => {
    urls.push(url);
    bodies.push(JSON.parse(init?.body as string));
    const r = responses[Math.min(i++, responses.length - 1)];
    return r instanceof Response ? r : jsonResponse(r);
  });
  return { bodies, urls, fetchFn };
}

type OpenAiFamily = "openai" | "openrouter" | "ollama";
const CTOR = { openai: OpenAIProvider, openrouter: OpenRouterProvider, ollama: OllamaCloudProvider };

export function openAiWith(kind: OpenAiFamily, responses: unknown[], over: Partial<OpenAIOptions> = {}) {
  const r = recorder(responses);
  const provider = new CTOR[kind]({ apiKey: "k", model: "m-1", fetchFn: r.fetchFn, ...over });
  return { provider, ...r };
}

export function geminiWith(responses: unknown[], model = "gemini-3-pro") {
  const r = recorder(responses);
  return { provider: new GeminiProvider({ apiKey: "k", model, fetchFn: r.fetchFn }), ...r };
}

/** A recorded-shape chat-completions reply. */
export function chat(message: Record<string, unknown>, finish_reason = "tool_calls") {
  return {
    choices: [{ message: { role: "assistant", content: null, ...message }, finish_reason }],
    usage: { prompt_tokens: 10, completion_tokens: 5 },
  };
}

export const wireCall = (id: string | undefined, args: string, name = "forensic_lookup") => ({
  ...(id !== undefined ? { id } : {}),
  type: "function",
  function: { name, arguments: args },
});

/** A recorded-shape generateContent reply. */
export function gem(parts: unknown[], finishReason = "STOP") {
  return {
    candidates: [{ content: { role: "model", parts }, finishReason }],
    usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5 },
  };
}

export const fc = (id: string | undefined, args: Record<string, unknown>, sig?: string) => ({
  functionCall: { ...(id !== undefined ? { id } : {}), name: "forensic_lookup", args },
  ...(sig ? { thoughtSignature: sig } : {}),
});

export function assistantTurn(id: string, input: Record<string, unknown> = { text: "x" }): ToolTurn {
  return { role: "assistant", text: "", calls: [{ id, name: "forensic_lookup", input }] };
}

export function toolTurn(...ids: string[]): ToolTurn {
  return {
    role: "tool",
    results: ids.map((id) => ({ id, name: "forensic_lookup", content: `rows for ${id}` })),
  };
}

/** The assistant turn a caller appends after a reply, optionally with masked edits. */
export function turnOf(r: ConverseResult, edit: { text?: string; calls?: ToolCall[] } = {}): ToolTurn {
  return {
    role: "assistant",
    text: edit.text ?? r.text,
    calls: edit.calls ?? r.calls,
    ...(r.opaque !== undefined ? { opaque: r.opaque } : {}),
  };
}

export const errorResponse = (status: number, body: unknown) => jsonResponse(body, status);
