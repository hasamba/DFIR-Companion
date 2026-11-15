import { describe, expect, it } from "vitest";
import type { ConverseRequest, ToolTurn } from "../../src/providers/toolCalling.js";
import {
  anthropicEchoedText,
  anthropicToolBody,
  parseAnthropicTurn,
} from "../../src/providers/anthropicTools.js";
import { openAiEchoedText, openAiToolBody, parseOpenAiTurn } from "../../src/providers/openaiTools.js";
import { geminiEchoedText, geminiToolBody, parseGeminiTurn } from "../../src/providers/geminiTools.js";
import { AnthropicProvider } from "../../src/providers/anthropic.js";
import { OpenAIProvider } from "../../src/providers/openai.js";
import { GeminiProvider } from "../../src/providers/gemini.js";

// Controller ruling on Task 4 concern 1: an adapter reports the readable reasoning it will actually
// send (the same drop logic as the body), and drops a block whose readable text the caller withholds.

const base = (transcript: ToolTurn[], withhold?: (t: string) => boolean): ConverseRequest => ({
  systemPrompt: "sys",
  userPrompt: "u",
  transcript,
  tools: [{ name: "lookup", description: "d", parameters: { type: "object" } }],
  toolChoice: "auto",
  ...(withhold ? { withhold } : {}),
});
const call = { id: "c1", name: "lookup", input: { q: "x" } };
const results: ToolTurn = { role: "tool", results: [{ id: "c1", name: "lookup", content: "r" }] };
const withholdIp = (t: string) => t.includes("8.8.8.8");

describe("Anthropic: echoed readable thinking", () => {
  const params = { model: "m", max_tokens: 100 };
  const turn = (thinking: string): ToolTurn => {
    const prefix = anthropicToolBody(base([]), params).prefixHash;
    const r = parseAnthropicTurn(
      {
        content: [
          { type: "thinking", thinking, signature: "SIG" },
          { type: "tool_use", id: "c1", name: "lookup", input: { q: "x" } },
        ],
      },
      prefix,
    );
    return { role: "assistant", ...r };
  };
  it("an unchanged block is kept and reported", () => {
    const req = base([turn("plain thought"), results]);
    expect(anthropicEchoedText(anthropicToolBody(req, params).body)).toEqual(["plain thought"]);
  });
  it("a withheld block is dropped from the body and not reported; the call still goes", () => {
    const req = base([turn("beacon to 8.8.8.8"), results], withholdIp);
    const { body } = anthropicToolBody(req, params);
    expect(anthropicEchoedText(body)).toEqual([]);
    expect(JSON.stringify(body)).not.toContain("8.8.8.8");
    expect(JSON.stringify(body)).toContain('"tool_use"');
  });
  it("a block the adapter drops anyway (changed prefix) is not reported", () => {
    const req = { ...base([turn("plain thought"), results]), userPrompt: "changed" };
    expect(anthropicEchoedText(anthropicToolBody(req, params).body)).toEqual([]);
  });
  it("the provider exposes the same answer", () => {
    const p = new AnthropicProvider({ apiKey: "k", model: "m" });
    expect(p.echoedReadableText(base([turn("beacon to 8.8.8.8"), results], withholdIp))).toEqual([]);
  });
});

describe("OpenAI-compatible: echoed readable reasoning_details", () => {
  const turn = (text: string): ToolTurn => {
    const r = parseOpenAiTurn(
      {
        content: "",
        tool_calls: [{ id: "c1", type: "function", function: { name: "lookup", arguments: '{"q":"x"}' } }],
        reasoning_details: [
          { type: "reasoning.text", text },
          { type: "reasoning.encrypted", data: "ENC" },
        ],
      },
      "openrouter",
      "m",
    );
    return { role: "assistant", ...r };
  };
  it("kept reasoning is reported; encrypted entries are not", () => {
    const body = openAiToolBody(base([turn("plain"), results]), { model: "m" }, "openrouter");
    expect(openAiEchoedText(body)).toEqual(["plain"]);
  });
  it("withheld reasoning drops the whole reasoning_details; the call still goes", () => {
    const body = openAiToolBody(
      base([turn("to 8.8.8.8"), results], withholdIp),
      { model: "m" },
      "openrouter",
    );
    expect(openAiEchoedText(body)).toEqual([]);
    expect(JSON.stringify(body)).not.toContain("8.8.8.8");
    expect(JSON.stringify(body)).not.toContain("ENC");
    expect(JSON.stringify(body)).toContain("tool_calls");
  });
  it("the provider exposes the same answer", () => {
    const p = new OpenAIProvider({ apiKey: "k", model: "m" });
    expect(p.echoedReadableText(base([turn("to 8.8.8.8"), results], withholdIp))).toEqual([]);
  });
});

describe("Gemini: echoed readable thought parts", () => {
  const turn = (thought: string): ToolTurn => {
    const r = parseGeminiTurn(
      [
        { text: thought, thought: true, thoughtSignature: "TS" },
        { functionCall: { id: "c1", name: "lookup", args: { q: "x" } }, thoughtSignature: "CS" },
      ],
      "gemini-x",
    );
    return { role: "assistant", ...r, calls: [{ ...call, id: r.calls[0].id }] };
  };
  it("a kept thought part is reported", () => {
    const body = geminiToolBody(base([turn("plain"), results]), "gemini-x");
    expect(geminiEchoedText(body)).toEqual(["plain"]);
  });
  it("a withheld thought part is dropped; the call keeps its own signature", () => {
    const body = geminiToolBody(base([turn("to 8.8.8.8"), results], withholdIp), "gemini-x");
    expect(geminiEchoedText(body)).toEqual([]);
    expect(JSON.stringify(body)).not.toContain("8.8.8.8");
    expect(JSON.stringify(body)).toContain('"thoughtSignature":"CS"');
  });
  it("the provider exposes the same answer", () => {
    const p = new GeminiProvider({ apiKey: "k", model: "gemini-x" });
    expect(p.echoedReadableText(base([turn("to 8.8.8.8"), results], withholdIp))).toEqual([]);
  });
});
