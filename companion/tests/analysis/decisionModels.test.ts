import { describe, it, expect, vi } from "vitest";
import { createDecisionModelCatalog } from "../../src/analysis/ai/jev/decisionModels.js";

// #2224: the Settings model picker lists only OpenRouter's decision models. The browser cannot reach
// openrouter.ai (CSP connect-src 'self'), so the server fetches the public catalog and caches it.

function entry(id: string, over: Record<string, unknown> = {}) {
  return {
    id,
    name: `Name of ${id}`,
    pricing: { prompt: "0.00000002", completion: "0" },
    architecture: { output_modalities: ["decisions"] },
    ...over,
  };
}

function ok(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}

const CATALOG = {
  data: [
    entry("typesafe/jev-1.14"),
    entry("baseten/mammoth-1:free", { pricing: { prompt: "0", completion: "0" } }),
    entry("openai/gpt-chat", { architecture: { output_modalities: ["text"] } }),
    { id: 42, name: "malformed" },
  ],
};

describe("the decision model catalog", () => {
  it("keeps only decision models, with a readable price or free", async () => {
    const fetchImpl = vi.fn(async () => ok(CATALOG));
    const list = await createDecisionModelCatalog(fetchImpl as unknown as typeof fetch).list();
    expect(list.stale).toBe(false);
    expect(list.models).toEqual([
      {
        id: "baseten/mammoth-1:free",
        name: "Name of baseten/mammoth-1:free",
        free: true,
        inputPerMillionUSD: 0,
      },
      { id: "typesafe/jev-1.14", name: "Name of typesafe/jev-1.14", free: false, inputPerMillionUSD: 0.02 },
    ]);
  });

  it("asks for decision models only and never sends a credential", async () => {
    const fetchImpl = vi.fn(async (_url: string, _init?: RequestInit) => ok(CATALOG));
    await createDecisionModelCatalog(fetchImpl as unknown as typeof fetch).list();
    const [url, init] = fetchImpl.mock.calls[0];
    expect(String(url)).toContain("output_modalities=decisions");
    expect(JSON.stringify(init?.headers ?? {})).not.toMatch(/authorization/i);
  });

  it("serves a cached list without refetching, and coalesces concurrent first loads", async () => {
    const fetchImpl = vi.fn(async () => ok(CATALOG));
    const catalog = createDecisionModelCatalog(fetchImpl as unknown as typeof fetch);
    await Promise.all([catalog.list(), catalog.list()]);
    await catalog.list();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("fails when the first load fails and nothing is cached", async () => {
    const fetchImpl = vi.fn(async () => new Response("down", { status: 503 }));
    await expect(createDecisionModelCatalog(fetchImpl as unknown as typeof fetch).list()).rejects.toThrow(
      /503/,
    );
  });

  it("serves the expired list marked stale when a refresh fails, and backs off before retrying", async () => {
    let now = 0;
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(ok(CATALOG))
      .mockResolvedValue(new Response("down", { status: 503 }));
    const catalog = createDecisionModelCatalog(fetchImpl as unknown as typeof fetch, () => now);
    await catalog.list();

    now = 2 * 60 * 60 * 1000; // past the one-hour cache
    const stale = await catalog.list();
    expect(stale.stale).toBe(true);
    expect(stale.models).toHaveLength(2);
    expect(fetchImpl).toHaveBeenCalledTimes(2);

    now += 10_000; // inside the back-off: no new request
    expect((await catalog.list()).stale).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(2);

    now += 120_000; // back-off over: it tries again
    await catalog.list();
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it("refuses a body that is not a catalog", async () => {
    const fetchImpl = vi.fn(async () => ok({ nope: true }));
    await expect(createDecisionModelCatalog(fetchImpl as unknown as typeof fetch).list()).rejects.toThrow();
  });

  it("hides a decision model known to refuse the questions the app sends (#2224 live probe)", async () => {
    const fetchImpl = vi.fn(async () =>
      ok({
        data: [entry("scaledown/classify-1"), entry("scaledown/classify-1:free"), entry("typesafe/jev-1.14")],
      }),
    );
    const list = await createDecisionModelCatalog(fetchImpl as unknown as typeof fetch).list();
    expect(list.models.map((m) => m.id)).toEqual(["typesafe/jev-1.14"]);
  });
});
