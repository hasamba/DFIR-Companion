import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export interface AiStub {
  /** Origin with no trailing slash, e.g. http://127.0.0.1:53421 */
  url: string;
  close(): Promise<void>;
}

/**
 * A minimal OpenAI-compatible endpoint for the browser suite.
 *
 * The synthesis and CSV-import routes refuse to run without a provider (import-csv answers 501),
 * so the workflows that matter most cannot be tested without one. Pointing DFIR_AI_PROVIDER at
 * this stub exercises the real provider code path with no network and a fixed reply, which keeps
 * the assertions deterministic — a live model would make every synthesis assertion a coin flip.
 *
 * Deliberately NOT a full mock: it answers the two routes the OpenAI provider actually calls, and
 * 404s everything else so an unhandled route fails loudly instead of hanging the caller.
 */
export async function startAiStub(): Promise<AiStub> {
  const server: Server = createServer((req, res) => {
    const send = (code: number, body: unknown): void => {
      res.writeHead(code, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };

    if (req.method === "GET" && req.url?.startsWith("/v1/models")) {
      send(200, { object: "list", data: [{ id: "stub-model", object: "model" }] });
      return;
    }

    if (req.method === "POST" && req.url?.startsWith("/v1/chat/completions")) {
      // The body is drained but not inspected: the reply is fixed so assertions stay deterministic.
      req.resume();
      req.on("end", () => {
        send(200, {
          id: "chatcmpl-stub",
          object: "chat.completion",
          created: 0,
          model: "stub-model",
          choices: [
            {
              index: 0,
              message: { role: "assistant", content: STUB_REPLY },
              finish_reason: "stop",
            },
          ],
          usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
        });
      });
      return;
    }

    req.resume();
    send(404, { error: `stub has no route for ${req.method} ${req.url}` });
  });

  // Loopback only. A test run must never accept connections from the network.
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

/** Fixed assistant reply. Plain prose, so it is a valid answer to any prompt the app sends. */
const STUB_REPLY = "Stubbed analysis response for the E2E suite. No findings were inferred.";
