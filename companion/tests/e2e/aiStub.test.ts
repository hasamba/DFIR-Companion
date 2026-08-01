import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startAiStub, type AiStub } from "./aiStub.js";

let stub: AiStub;

beforeAll(async () => {
  stub = await startAiStub();
});

afterAll(async () => {
  await stub.close();
});

describe("startAiStub", () => {
  it("answers chat completions in OpenAI shape", async () => {
    const res = await fetch(`${stub.url}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "stub", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { choices: { message: { content: string } }[] };
    expect(body.choices[0].message.content).toBeTypeOf("string");
    expect(body.choices[0].message.content.length).toBeGreaterThan(0);
  });

  it("replies with parseable JSON, because the pipeline parses every completion", async () => {
    const res = await fetch(`${stub.url}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "stub", messages: [{ role: "user", content: "synthesize" }] }),
    });
    const body = (await res.json()) as { choices: { message: { content: string } }[] };
    // pipeline.ts runs the reply through parseJsonLoose(); prose makes /synthesize answer 500.
    expect(() => JSON.parse(body.choices[0].message.content)).not.toThrow();
  });

  it("lists at least one model", async () => {
    const res = await fetch(`${stub.url}/v1/models`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { id: string }[] };
    expect(body.data.length).toBeGreaterThan(0);
  });

  it("returns the same content for the same prompt", async () => {
    const ask = async (): Promise<string> => {
      const r = await fetch(`${stub.url}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "stub", messages: [{ role: "user", content: "same" }] }),
      });
      const b = (await r.json()) as { choices: { message: { content: string } }[] };
      return b.choices[0].message.content;
    };
    expect(await ask()).toBe(await ask());
  });

  it("404s an unknown route rather than hanging the caller", async () => {
    const res = await fetch(`${stub.url}/v1/embeddings`, { method: "POST", body: "{}" });
    expect(res.status).toBe(404);
  });

  it("binds loopback only, so a test run never listens on the network", async () => {
    expect(stub.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });
});
