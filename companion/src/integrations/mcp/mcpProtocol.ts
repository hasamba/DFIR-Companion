// MCP wire format (#296) — JSON-RPC 2.0 over streamable HTTP, the transport a self-hosted
// SIFT/REMnux/windows-triage server exposes.
//
// PURE and I/O-free on purpose. The fiddly parts of this protocol are the SSE framing and the
// "did the server answer me or hand me an error" bookkeeping, and both are ordinary string/object
// work — keeping them here means they unit-test without a socket, and the transport underneath
// (mcpHttpTransport.ts) stays a dumb POST that has nothing interesting to get wrong.
//
// Hand-rolled rather than taking @modelcontextprotocol/sdk: the SDK installs 91 packages (24 MB)
// including a second Express, hono, cors and an OAuth stack, all of it server-side machinery, to
// give a client that makes three calls. See issue #296 §5 — the SDK was the design's first choice
// until the dependency footprint was actually measured.

/** The spec revision this client speaks. Sent on initialize; the server may answer with another. */
export const MCP_PROTOCOL_VERSION = "2025-06-18";

export interface JsonRpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code?: number; message?: string; data?: unknown };
}

export interface McpToolInfo {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface McpServerInfo {
  protocolVersion: string;
  serverName: string;
  serverVersion: string;
  capabilities: Record<string, unknown>;
}

export interface McpToolResult {
  /** Every text block the tool returned, joined — what the ingest chain consumes. */
  text: string;
  /** A tool that emits structured output; preferred over `text` when present (§8). */
  structured: unknown;
  /** The tool ran and reported failure. NOT the same as a transport or JSON-RPC error. */
  isError: boolean;
}

/**
 * The `data:` payloads of an SSE body, one string per event.
 *
 * Written out rather than pulled from a library because the subset that matters here is small: the
 * server pushes JSON-RPC messages as events, and everything else in the grammar (`event:`, `id:`,
 * `retry:`, `:` keep-alive comments) is noise to a client that only reads responses. Multi-line
 * `data:` fields rejoin with newlines, per the EventSource spec.
 */
export function parseSseData(body: string): string[] {
  const payloads: string[] = [];
  // The grammar allows \r\n, \n or a bare \r to end a line; normalize before splitting.
  const lines = body.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  let data: string[] = [];

  const flush = (): void => {
    if (data.length > 0) { payloads.push(data.join("\n")); data = []; }
  };

  for (const line of lines) {
    if (line === "") { flush(); continue; }   // blank line dispatches the event
    if (line.startsWith(":")) continue;       // comment / keep-alive
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);   // one optional leading space is stripped
    if (field === "data") data.push(value);
  }
  // A body that ends without its final blank line still delivered that event — flush rather than
  // dropping the last (and for a single-response call, only) message.
  flush();
  return payloads;
}

function asMessages(parsed: unknown): JsonRpcMessage[] {
  // A server may batch several responses into one JSON array.
  return Array.isArray(parsed) ? (parsed as JsonRpcMessage[]) : [parsed as JsonRpcMessage];
}

/**
 * JSON-RPC messages out of a response body. Streamable HTTP lets the server answer the SAME request
 * either as one JSON object or as an SSE stream, at its discretion, so both shapes land here.
 *
 * A non-JSON frame inside a stream is skipped (keep-alives and progress noise are not errors), but a
 * non-JSON *body* throws — there the whole response was supposed to be the answer, and silently
 * returning nothing would surface later as a baffling "no response for id 1".
 */
export function parseJsonRpcMessages(body: string, contentType: string): JsonRpcMessage[] {
  if (contentType.toLowerCase().includes("text/event-stream")) {
    return parseSseData(body).flatMap((payload) => {
      try {
        return asMessages(JSON.parse(payload));
      } catch {
        return [];
      }
    });
  }
  if (!body.trim()) return [];
  try {
    return asMessages(JSON.parse(body));
  } catch {
    throw new Error(`MCP server returned a body that is not JSON: ${body.slice(0, 200)}`);
  }
}

/**
 * The result for `id`, or a thrown error carrying whatever the server said went wrong.
 *
 * Matching on id rather than taking the first message matters: a stream legitimately carries
 * server-initiated requests and progress notifications alongside the response being waited on.
 */
export function resultFor(messages: JsonRpcMessage[], id: number): unknown {
  const reply = messages.find((m) => m.id === id);
  if (!reply) {
    throw new Error("MCP server sent no response to the request");
  }
  if (reply.error) {
    const code = typeof reply.error.code === "number" ? ` (code ${reply.error.code})` : "";
    throw new Error(`MCP server returned an error${code}: ${reply.error.message ?? "no message"}`);
  }
  return reply.result;
}

/** The tools out of a tools/list result, keeping only entries that at least have a name. */
export function toolsFrom(result: unknown): McpToolInfo[] {
  const raw = (result as { tools?: unknown })?.tools;
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((t): t is { name: string } => !!t && typeof (t as { name?: unknown }).name === "string")
    .map((t) => ({
      name: t.name,
      description: typeof (t as McpToolInfo).description === "string" ? (t as McpToolInfo).description : undefined,
      inputSchema: (t as McpToolInfo).inputSchema,
    }));
}

/**
 * A tools/call result flattened to what the ingest chain needs.
 *
 * `isError: true` is the tool saying its own run failed, which is NOT a protocol error — the text
 * alongside it is the diagnostic, so it is returned rather than thrown and the caller decides.
 */
export function toolResultFrom(result: unknown): McpToolResult {
  const r = (result ?? {}) as { content?: unknown; structuredContent?: unknown; isError?: unknown };
  const blocks = Array.isArray(r.content) ? r.content : [];
  const text = blocks
    .filter((b): b is { type: string; text: string } =>
      !!b && (b as { type?: unknown }).type === "text" && typeof (b as { text?: unknown }).text === "string")
    .map((b) => b.text)
    .join("\n");
  return { text, structured: r.structuredContent, isError: r.isError === true };
}
