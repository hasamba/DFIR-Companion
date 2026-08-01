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
 *
 * WHAT THIS CANNOT TEST. The reply is fixed prose, so any endpoint that requires the model to
 * return STRUCTURED JSON cannot be exercised through it — /cases/:id/view-summary is the clearest
 * example: it retries four times against the schema and then answers 500. Making the stub
 * prompt-aware would fix that by teaching it each caller's expected schema, which is mocking the
 * product rather than standing in for a provider, so those endpoints are left uncovered and said
 * to be uncovered. See tests/e2e/workflows/analysis.spec.ts.
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

/**
 * Fixed assistant reply — a JSON DOCUMENT, not prose.
 *
 * pipeline.ts runs every completion through parseJsonLoose(), so a plain-prose reply makes
 * /cases/:id/synthesize answer 500 with "Unexpected token 'S' ... is not valid JSON". Prose was
 * enough for import-csv and silently wrong for synthesis, which is exactly the sort of gap a stub
 * hides until something exercises the other path.
 *
 * Semantically it says "nothing new was inferred": empty collections, so the seeded case is not
 * mutated and assertions elsewhere stay deterministic.
 */
// Every non-optional field of the synthesis schema in src/analysis/responseSchema.ts. Zod rejects
// the whole response if one is missing, and the route then answers 500 — so this list is the
// contract, not a convenience. If responseSchema gains a required field, this is where it shows up.
const STUB_REPLY = JSON.stringify({
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "Stubbed synthesis for the E2E suite.",
  summary: "Stubbed synthesis for the E2E suite. No findings were inferred.",
  forensicEvents: [],
  keyQuestions: [],
  nextSteps: [],
  hypotheses: [],
  uncertainties: [],
  evidenceRequests: [],
});
