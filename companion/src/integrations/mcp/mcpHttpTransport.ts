import { request } from "undici";
import type { McpHttpRequest, McpHttpResponse, McpHttpTransport } from "./mcpClient.js";

// The only code in the MCP integration that touches the network (#296). Deliberately dumb: one
// request, a byte ceiling, a deadline. Everything with protocol semantics lives in mcpProtocol.ts
// where it can be tested without a socket.
//
// Built on the undici already in package.json rather than @modelcontextprotocol/sdk — see the note
// at the top of mcpProtocol.ts for the dependency measurement behind that call.

function lowercaseHeaders(raw: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (value === undefined) continue;
    // A repeated header collapses to its first value; none of the headers this client reads
    // (mcp-session-id, content-type) is legally repeated.
    out[key.toLowerCase()] = Array.isArray(value) ? value[0] : value;
  }
  return out;
}

export function createMcpHttpTransport(): McpHttpTransport {
  return {
    async send(req: McpHttpRequest): Promise<McpHttpResponse> {
      // One controller for both deadlines — the caller's cancel (a JobManager AbortSignal) and this
      // request's own timeout — so the read loop below has a single thing to watch.
      const controller = new AbortController();
      const abort = (): void => controller.abort();
      req.signal?.addEventListener("abort", abort, { once: true });
      const timer = setTimeout(abort, req.timeoutMs);

      try {
        const res = await request(req.url, {
          method: req.method,
          headers: req.headers,
          body: req.body,
          signal: controller.signal,
        });

        const chunks: Buffer[] = [];
        let size = 0;
        for await (const chunk of res.body) {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as ArrayBufferLike);
          size += buf.length;
          if (size > req.maxBytes) {
            // Stop pulling rather than reading a runaway body to the end just to reject it.
            controller.abort();
            throw new Error(
              `MCP response exceeded ${req.maxBytes} bytes — narrow the run, or have the tool write to a file the delivery layer can fetch`,
            );
          }
          chunks.push(buf);
        }

        return {
          status: res.statusCode,
          headers: lowercaseHeaders(res.headers),
          body: Buffer.concat(chunks).toString("utf8"),
        };
      } finally {
        clearTimeout(timer);
        req.signal?.removeEventListener("abort", abort);
      }
    },
  };
}
