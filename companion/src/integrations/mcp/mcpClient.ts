import {
  MCP_PROTOCOL_VERSION, parseJsonRpcMessages, resultFor, toolsFrom, toolResultFrom,
  type McpServerInfo, type McpToolInfo, type McpToolResult,
} from "./mcpProtocol.js";

// MCP client over streamable HTTP (#296). Speaks exactly the three methods this feature needs —
// initialize, tools/list, tools/call — against an analyst's own SIFT/REMnux/windows-triage server.
//
// The transport is INJECTED rather than constructed inline, the same discipline ToolRunner already
// uses, so every test in this module runs without opening a socket. mcpHttpTransport.ts holds the
// only code that touches the network.
//
// Connections are per-call rather than pooled: an MCP run is minutes-scale and infrequent, so there
// is nothing worth amortising, and a fresh session per operation means a wedged one cannot poison
// the next run.
//
// This class is protocol only. The per-server tool allowlist (§10) is deliberately NOT enforced
// here — the allowlist lives on the registry entry, and the caller that holds it is the one that can
// enforce it without this class having to know about storage.

export interface McpHttpResponse {
  status: number;
  /** Header names lowercased, single-valued — the transport normalizes before returning. */
  headers: Record<string, string>;
  body: string;
}

export interface McpHttpRequest {
  url: string;
  method: "POST" | "DELETE";
  headers: Record<string, string>;
  body?: string;
  timeoutMs: number;
  /** Hard ceiling on the response body; the transport aborts past it. See DEFAULT_MAX_BYTES. */
  maxBytes: number;
  signal?: AbortSignal;
}

export interface McpHttpTransport {
  send(req: McpHttpRequest): Promise<McpHttpResponse>;
}

/**
 * Result-size ceiling, mirroring the `maxOutputBytes` a spawned tool gets (§10) — a compromised or
 * merely broken server must not be able to exhaust memory.
 *
 * Lower than the 100 MB a custom tool is allowed because the two are not comparable: a tool with
 * outputMode "file" streams to disk and is never held whole, whereas an MCP body has to be buffered
 * and JSON-parsed in one piece before any of it can be read.
 */
export const DEFAULT_MAX_BYTES = 32 * 1024 * 1024;

export interface McpClientOptions {
  url: string;
  transport: McpHttpTransport;
  token?: string;
  timeoutMs?: number;
  maxBytes?: number;
  clientName?: string;
  clientVersion?: string;
}

export class McpClient {
  private nextId = 1;
  private sessionId: string | null = null;
  private negotiatedVersion: string | null = null;
  private ready: Promise<McpServerInfo> | null = null;

  constructor(private readonly opts: McpClientOptions) {}

  /**
   * The handshake, at most once per client. A failed attempt clears the cached promise so a retry
   * is a real retry rather than a replay of the same rejection.
   */
  async initialize(signal?: AbortSignal): Promise<McpServerInfo> {
    if (!this.ready) {
      this.ready = this.handshake(signal).catch((err: unknown) => {
        this.ready = null;
        throw err;
      });
    }
    return this.ready;
  }

  async listTools(signal?: AbortSignal): Promise<McpToolInfo[]> {
    await this.initialize(signal);
    return toolsFrom(await this.rpc("tools/list", {}, signal));
  }

  async callTool(name: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<McpToolResult> {
    await this.initialize(signal);
    return toolResultFrom(await this.rpc("tools/call", { name, arguments: args }, signal));
  }

  /**
   * Release the server-side session. Best-effort by design: the session is the server's to expire,
   * and a failed teardown must never turn a successful analysis into a failed one.
   */
  async close(signal?: AbortSignal): Promise<void> {
    if (!this.sessionId) return;
    try {
      await this.send("DELETE", undefined, signal);
    } catch {
      // nothing to do — the server times its own sessions out
    }
    this.sessionId = null;
    this.ready = null;
  }

  private async handshake(signal?: AbortSignal): Promise<McpServerInfo> {
    const result = await this.rpc("initialize", {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: {
        name: this.opts.clientName ?? "dfir-companion",
        version: this.opts.clientVersion ?? "0",
      },
    }, signal) as {
      protocolVersion?: unknown;
      capabilities?: unknown;
      serverInfo?: { name?: unknown; version?: unknown };
    };

    // Take the server's revision rather than insisting on ours: the point of negotiation is that a
    // server one revision behind still works. Every later request echoes it back in a header.
    this.negotiatedVersion = typeof result?.protocolVersion === "string" ? result.protocolVersion : MCP_PROTOCOL_VERSION;

    // The spec has the client confirm before issuing any other request. Sent after the version and
    // session id are recorded, so it already carries both headers.
    await this.notify("notifications/initialized", signal);

    return {
      protocolVersion: this.negotiatedVersion,
      serverName: typeof result?.serverInfo?.name === "string" ? result.serverInfo.name : "unknown",
      serverVersion: typeof result?.serverInfo?.version === "string" ? result.serverInfo.version : "unknown",
      capabilities: (result?.capabilities ?? {}) as Record<string, unknown>,
    };
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      "content-type": "application/json",
      // The server chooses per request whether to answer with one JSON object or an SSE stream, so
      // a client that does not accept both leaves a spec-compliant server nothing to reply with.
      "accept": "application/json, text/event-stream",
    };
    if (this.opts.token) h["authorization"] = `Bearer ${this.opts.token}`;
    if (this.sessionId) h["mcp-session-id"] = this.sessionId;
    if (this.negotiatedVersion) h["mcp-protocol-version"] = this.negotiatedVersion;
    return h;
  }

  private async send(method: "POST" | "DELETE", body?: string, signal?: AbortSignal): Promise<McpHttpResponse> {
    const res = await this.opts.transport.send({
      url: this.opts.url,
      method,
      headers: this.headers(),
      body,
      timeoutMs: this.opts.timeoutMs ?? 300_000,
      maxBytes: this.opts.maxBytes ?? DEFAULT_MAX_BYTES,
      signal,
    });
    // The session id arrives on the initialize response and is echoed on everything after it. Read
    // it before the status check: a server that assigns a session and THEN reports an error still
    // wants that session torn down.
    const assigned = res.headers["mcp-session-id"];
    if (assigned) this.sessionId = assigned;

    if (res.status < 200 || res.status >= 300) {
      throw new Error(`MCP server returned HTTP ${res.status}${res.body ? `: ${res.body.slice(0, 200)}` : ""}`);
    }
    return res;
  }

  private async rpc(method: string, params: unknown, signal?: AbortSignal): Promise<unknown> {
    const id = this.nextId++;
    const res = await this.send("POST", JSON.stringify({ jsonrpc: "2.0", id, method, params }), signal);
    return resultFor(parseJsonRpcMessages(res.body, res.headers["content-type"] ?? ""), id);
  }

  /** A notification carries no id and expects no result — the server answers 202 with an empty body. */
  private async notify(method: string, signal?: AbortSignal): Promise<void> {
    await this.send("POST", JSON.stringify({ jsonrpc: "2.0", method }), signal);
  }
}
