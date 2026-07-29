import { describe, it, expect, beforeEach } from "vitest";
import { McpClient, type McpHttpRequest, type McpHttpResponse, type McpHttpTransport } from "../../src/integrations/mcp/mcpClient.js";

// A transport that records what was sent and replays canned responses — the seam that keeps every
// test in this file off the network.
class FakeTransport implements McpHttpTransport {
  readonly sent: McpHttpRequest[] = [];
  private readonly queue: (McpHttpResponse | Error)[] = [];

  queueJson(body: unknown, extra: { status?: number; sessionId?: string } = {}): this {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (extra.sessionId) headers["mcp-session-id"] = extra.sessionId;
    this.queue.push({ status: extra.status ?? 200, headers, body: JSON.stringify(body) });
    return this;
  }

  queueSse(body: string, extra: { status?: number } = {}): this {
    this.queue.push({ status: extra.status ?? 200, headers: { "content-type": "text/event-stream" }, body });
    return this;
  }

  queueRaw(res: McpHttpResponse): this {
    this.queue.push(res);
    return this;
  }

  queueError(err: Error): this {
    this.queue.push(err);
    return this;
  }

  /**
   * The handshake pair every non-initialize test needs in front of its own responses.
   *
   * `id` is explicit because request ids keep ascending across a failed attempt — a retried
   * handshake is id 2, not id 1, and a real server echoes back whatever it was sent.
   */
  queueHandshake(sessionId = "sess-1", protocolVersion = "2025-06-18", id = 1): this {
    this.queueJson(
      { jsonrpc: "2.0", id, result: { protocolVersion, capabilities: {}, serverInfo: { name: "sift-mcp", version: "1.2.3" } } },
      { sessionId },
    );
    return this.queueRaw({ status: 202, headers: {}, body: "" });   // notifications/initialized
  }

  async send(req: McpHttpRequest): Promise<McpHttpResponse> {
    this.sent.push(req);
    const next = this.queue.shift();
    if (!next) throw new Error(`FakeTransport: no queued response for ${req.method} #${this.sent.length}`);
    if (next instanceof Error) throw next;
    return next;
  }

  bodyOf(index: number): Record<string, unknown> {
    return JSON.parse(this.sent[index].body ?? "{}") as Record<string, unknown>;
  }
}

let transport: FakeTransport;
const clientFor = (extra: { token?: string } = {}) =>
  new McpClient({ url: "http://192.168.1.50:8080/mcp", transport, timeoutMs: 1000, ...extra });

beforeEach(() => {
  transport = new FakeTransport();
});

describe("McpClient handshake", () => {
  it("sends initialize then the initialized notification", async () => {
    transport.queueHandshake();

    const info = await clientFor().initialize();

    expect(transport.bodyOf(0)).toMatchObject({ jsonrpc: "2.0", id: 1, method: "initialize" });
    expect(transport.bodyOf(1)).toEqual({ jsonrpc: "2.0", method: "notifications/initialized" });
    expect(info).toMatchObject({ serverName: "sift-mcp", serverVersion: "1.2.3", protocolVersion: "2025-06-18" });
  });

  it("offers both response shapes, since the server picks per request", async () => {
    transport.queueHandshake();
    await clientFor().initialize();
    expect(transport.sent[0].headers["accept"]).toBe("application/json, text/event-stream");
  });

  it("echoes the session id the server assigned on every later request", async () => {
    transport.queueHandshake("sess-abc").queueJson({ jsonrpc: "2.0", id: 2, result: { tools: [] } });

    await clientFor().listTools();

    expect(transport.sent[0].headers["mcp-session-id"]).toBeUndefined();   // none to send yet
    expect(transport.sent[1].headers["mcp-session-id"]).toBe("sess-abc");
    expect(transport.sent[2].headers["mcp-session-id"]).toBe("sess-abc");
  });

  // Negotiation is the point: a server a revision behind still works, and later requests must echo
  // what it chose rather than what we asked for.
  it("adopts the server's protocol version and echoes it back", async () => {
    transport.queueHandshake("sess-1", "2025-03-26").queueJson({ jsonrpc: "2.0", id: 2, result: { tools: [] } });

    await clientFor().listTools();

    expect(transport.bodyOf(0)).toMatchObject({ params: { protocolVersion: "2025-06-18" } });
    expect(transport.sent[2].headers["mcp-protocol-version"]).toBe("2025-03-26");
  });

  it("sends a bearer token when configured, and no auth header when not", async () => {
    transport.queueHandshake();
    await clientFor({ token: "secret-value" }).initialize();
    expect(transport.sent[0].headers["authorization"]).toBe("Bearer secret-value");

    transport = new FakeTransport();
    transport.queueHandshake();
    await clientFor().initialize();
    expect(transport.sent[0].headers["authorization"]).toBeUndefined();
  });

  it("handshakes once however many calls follow", async () => {
    transport.queueHandshake()
      .queueJson({ jsonrpc: "2.0", id: 2, result: { tools: [] } })
      .queueJson({ jsonrpc: "2.0", id: 3, result: { tools: [] } });

    const client = clientFor();
    await client.listTools();
    await client.listTools();

    expect(transport.sent.filter((r) => (r.body ?? "").includes('"initialize"'))).toHaveLength(1);
  });

  // A cached rejected promise would make every retry replay the original failure.
  it("retries the handshake after one fails", async () => {
    // The retry is request id 2 — ids stay unique across the failed attempt.
    transport.queueError(new Error("connection refused")).queueHandshake("sess-1", "2025-06-18", 2);

    const client = clientFor();
    await expect(client.initialize()).rejects.toThrow(/connection refused/);
    await expect(client.initialize()).resolves.toMatchObject({ serverName: "sift-mcp" });
  });
});

describe("McpClient.listTools", () => {
  it("returns the server's tools", async () => {
    transport.queueHandshake().queueJson({
      jsonrpc: "2.0", id: 2,
      result: { tools: [{ name: "pslist", description: "processes" }, { name: "malfind" }] },
    });

    expect((await clientFor().listTools()).map((t) => t.name)).toEqual(["pslist", "malfind"]);
  });

  it("reads a response the server chose to stream instead", async () => {
    transport.queueHandshake()
      .queueSse('data: {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"pslist"}]}}\n\n');

    expect((await clientFor().listTools()).map((t) => t.name)).toEqual(["pslist"]);
  });
});

describe("McpClient.callTool", () => {
  it("sends the tool name and arguments, and returns the joined text", async () => {
    transport.queueHandshake().queueJson({
      jsonrpc: "2.0", id: 2,
      result: { content: [{ type: "text", text: "pid 4 System" }] },
    });

    const result = await clientFor().callTool("pslist", { image_path: "/evidence/mem.raw" });

    expect(transport.bodyOf(2)).toMatchObject({
      method: "tools/call",
      params: { name: "pslist", arguments: { image_path: "/evidence/mem.raw" } },
    });
    expect(result.text).toBe("pid 4 System");
    expect(result.isError).toBe(false);
  });

  it("returns a tool-reported failure rather than throwing it away", async () => {
    transport.queueHandshake().queueJson({
      jsonrpc: "2.0", id: 2,
      result: { content: [{ type: "text", text: "unsupported profile" }], isError: true },
    });

    const result = await clientFor().callTool("pslist", {});
    expect(result).toMatchObject({ isError: true, text: "unsupported profile" });
  });

  it("throws when the server answers with a JSON-RPC error", async () => {
    transport.queueHandshake().queueJson({
      jsonrpc: "2.0", id: 2, error: { code: -32602, message: "image_path is required" },
    });

    await expect(clientFor().callTool("pslist", {})).rejects.toThrow(/image_path is required/);
  });

  it("throws on a non-2xx response, quoting what the server said", async () => {
    transport.queueHandshake()
      .queueRaw({ status: 401, headers: { "content-type": "application/json" }, body: '{"error":"bad token"}' });

    await expect(clientFor().callTool("pslist", {})).rejects.toThrow(/HTTP 401.*bad token/);
  });

  it("passes the caller's abort signal down to the transport", async () => {
    transport.queueHandshake().queueJson({ jsonrpc: "2.0", id: 2, result: { content: [] } });
    const controller = new AbortController();

    await clientFor().callTool("pslist", {}, controller.signal);

    expect(transport.sent.every((r) => r.signal === controller.signal)).toBe(true);
  });
});

describe("McpClient.close", () => {
  it("releases the session with a DELETE", async () => {
    transport.queueHandshake("sess-xyz")
      .queueJson({ jsonrpc: "2.0", id: 2, result: { tools: [] } })
      .queueRaw({ status: 204, headers: {}, body: "" });

    const client = clientFor();
    await client.listTools();
    await client.close();

    const last = transport.sent[transport.sent.length - 1];
    expect(last.method).toBe("DELETE");
    expect(last.headers["mcp-session-id"]).toBe("sess-xyz");
  });

  it("does nothing when no session was ever established", async () => {
    await clientFor().close();
    expect(transport.sent).toHaveLength(0);
  });

  // Teardown is the server's session to expire; a failure here must not fail the analysis.
  it("swallows a failed teardown", async () => {
    transport.queueHandshake("sess-1").queueError(new Error("gone"));
    const client = clientFor();
    await client.initialize();

    await expect(client.close()).resolves.toBeUndefined();
  });
});
