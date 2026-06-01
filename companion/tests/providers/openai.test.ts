import { describe, it, expect, vi } from "vitest";
import { OpenAIProvider } from "../../src/providers/openai.js";
import { ProviderError } from "../../src/providers/provider.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("OpenAIProvider", () => {
  it("sends images and returns assistant content", async () => {
    const fetchFn = vi.fn(async () =>
      jsonResponse({ choices: [{ message: { content: '{"summary":"done"}' } }] }),
    );
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    const result = await p.analyze({
      systemPrompt: "s", userPrompt: "u",
      images: [{ base64: "AAAA", mimeType: "image/webp" }],
    });
    expect(result.rawText).toBe('{"summary":"done"}');
    expect(fetchFn).toHaveBeenCalledOnce();
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body.model).toBe("gpt-4o");
    expect(JSON.stringify(body)).toContain("data:image/webp;base64,AAAA");
    // small forensic text needs full-resolution tiling, not a downscaled image
    expect(body.messages[1].content[1].image_url.detail).toBe("high");
  });

  it("honours an explicit imageDetail override", async () => {
    const fetchFn = vi.fn(async () =>
      jsonResponse({ choices: [{ message: { content: "{}" } }] }),
    );
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn, imageDetail: "low" });
    await p.analyze({ systemPrompt: "s", userPrompt: "u", images: [{ base64: "AAAA", mimeType: "image/png" }] });
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body.messages[1].content[1].image_url.detail).toBe("low");
  });

  it("maps 429 to a rate_limit ProviderError", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ error: "slow down" }, 429));
    const p = new OpenAIProvider({ apiKey: "k", model: "gpt-4o", fetchFn });
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }))
      .rejects.toMatchObject({ kind: "rate_limit" } as Partial<ProviderError>);
  });
});
