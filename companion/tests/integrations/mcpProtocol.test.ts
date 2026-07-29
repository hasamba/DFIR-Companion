import { describe, it, expect } from "vitest";
import {
  parseSseData, parseJsonRpcMessages, resultFor, toolsFrom, toolResultFrom,
} from "../../src/integrations/mcp/mcpProtocol.js";

const JSON_CT = "application/json";
const SSE_CT = "text/event-stream";

describe("parseSseData", () => {
  it("reads the data payload of each event", () => {
    expect(parseSseData("data: one\n\ndata: two\n\n")).toEqual(["one", "two"]);
  });

  it("strips exactly one leading space after the colon", () => {
    // "data:  x" is a payload of " x" — the second space is content, not framing.
    expect(parseSseData("data:  x\n\n")).toEqual([" x"]);
  });

  it("rejoins a multi-line data field with newlines", () => {
    expect(parseSseData("data: {\ndata: \"a\": 1\ndata: }\n\n")).toEqual(['{\n"a": 1\n}']);
  });

  it("ignores comments, keep-alives and fields that are not data", () => {
    expect(parseSseData(": keep-alive\nevent: message\nid: 7\nretry: 100\ndata: payload\n\n")).toEqual(["payload"]);
  });

  it("handles CRLF and bare CR line endings", () => {
    expect(parseSseData("data: one\r\n\r\ndata: two\r\r")).toEqual(["one", "two"]);
  });

  // A single-response call is the common case and servers routinely close without the final blank
  // line; dropping that event would lose the only message.
  it("delivers a final event that has no trailing blank line", () => {
    expect(parseSseData("data: last")).toEqual(["last"]);
  });

  it("returns nothing for a body with no data fields", () => {
    expect(parseSseData(": just a comment\n\n")).toEqual([]);
  });
});

describe("parseJsonRpcMessages", () => {
  it("reads a plain JSON response", () => {
    expect(parseJsonRpcMessages('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}', JSON_CT))
      .toEqual([{ jsonrpc: "2.0", id: 1, result: { ok: true } }]);
  });

  it("unwraps a batched JSON array into separate messages", () => {
    const body = '[{"jsonrpc":"2.0","id":1,"result":1},{"jsonrpc":"2.0","id":2,"result":2}]';
    expect(parseJsonRpcMessages(body, JSON_CT)).toHaveLength(2);
  });

  it("reads messages out of an SSE stream", () => {
    const body = 'data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n';
    expect(parseJsonRpcMessages(body, SSE_CT)).toEqual([{ jsonrpc: "2.0", id: 1, result: { ok: true } }]);
  });

  it("matches the content type even when it carries a charset", () => {
    const body = 'data: {"id":1}\n\n';
    expect(parseJsonRpcMessages(body, "text/event-stream; charset=utf-8")).toEqual([{ id: 1 }]);
  });

  // Progress noise and keep-alives share the stream with the response being waited on.
  it("skips a non-JSON frame inside a stream rather than failing the whole read", () => {
    const body = 'data: not json\n\ndata: {"jsonrpc":"2.0","id":1,"result":"ok"}\n\n';
    expect(parseJsonRpcMessages(body, SSE_CT)).toEqual([{ jsonrpc: "2.0", id: 1, result: "ok" }]);
  });

  // A whole body that is not JSON is a different situation: it WAS the answer.
  it("throws when a non-stream body is not JSON", () => {
    expect(() => parseJsonRpcMessages("<html>502 Bad Gateway</html>", JSON_CT))
      .toThrow(/not JSON/);
  });

  it("returns nothing for an empty body", () => {
    expect(parseJsonRpcMessages("", JSON_CT)).toEqual([]);
  });
});

describe("resultFor", () => {
  it("returns the result of the matching id", () => {
    const messages = [{ id: 1, result: "first" }, { id: 2, result: "second" }];
    expect(resultFor(messages, 2)).toBe("second");
  });

  // A stream legitimately carries server-initiated messages beside the response.
  it("ignores notifications and other ids in the stream", () => {
    const messages = [
      { method: "notifications/progress", params: { pct: 50 } },
      { id: 9, result: "other" },
      { id: 3, result: "mine" },
    ];
    expect(resultFor(messages, 3)).toBe("mine");
  });

  it("throws with the server's message and code on a JSON-RPC error", () => {
    const messages = [{ id: 1, error: { code: -32601, message: "Method not found" } }];
    expect(() => resultFor(messages, 1)).toThrow(/code -32601.*Method not found/);
  });

  it("throws when nothing answered the request", () => {
    expect(() => resultFor([{ method: "notifications/progress" }], 1)).toThrow(/no response/);
  });
});

describe("toolsFrom", () => {
  it("reads name, description and schema", () => {
    const result = { tools: [{ name: "pslist", description: "list processes", inputSchema: { type: "object" } }] };
    expect(toolsFrom(result)).toEqual([
      { name: "pslist", description: "list processes", inputSchema: { type: "object" } },
    ]);
  });

  it("drops entries with no usable name", () => {
    expect(toolsFrom({ tools: [{ description: "nameless" }, { name: "ok" }] }))
      .toEqual([{ name: "ok", description: undefined, inputSchema: undefined }]);
  });

  it("returns nothing when the result carries no tools array", () => {
    expect(toolsFrom({})).toEqual([]);
    expect(toolsFrom(null)).toEqual([]);
  });
});

describe("toolResultFrom", () => {
  it("joins the text blocks and ignores the rest", () => {
    const result = {
      content: [
        { type: "text", text: "line one" },
        { type: "image", data: "…", mimeType: "image/png" },
        { type: "text", text: "line two" },
      ],
    };
    expect(toolResultFrom(result).text).toBe("line one\nline two");
  });

  it("carries structured output through when the tool emits it", () => {
    const result = { content: [], structuredContent: { processes: [{ pid: 4 }] } };
    expect(toolResultFrom(result).structured).toEqual({ processes: [{ pid: 4 }] });
  });

  // The tool ran and reported its own failure — the text beside it is the diagnostic, so the caller
  // decides what to do rather than losing it to a throw.
  it("reports a tool-level failure without discarding its output", () => {
    const result = { content: [{ type: "text", text: "no such profile" }], isError: true };
    const parsed = toolResultFrom(result);
    expect(parsed.isError).toBe(true);
    expect(parsed.text).toBe("no such profile");
  });

  it("survives a result with no content at all", () => {
    expect(toolResultFrom({})).toEqual({ text: "", structured: undefined, isError: false });
  });
});
