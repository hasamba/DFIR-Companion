import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../../src/analysis/anonDiscovered.js";
import { AnonMapStore } from "../../src/analysis/anonMap.js";
import { analyzeRestored, type ProviderCallContext } from "../../src/analysis/ai/providerCall.js";
import { runAiPreview } from "../../src/analysis/ai/aiPreviewScope.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// #2657: every AI call on a case gives a masked value the same token, through the case's saved map.

class Echo implements AIProvider {
  readonly name = "stub";
  readonly model = "stub-model";
  readonly sent: string[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req.userPrompt);
    return { rawText: JSON.stringify({ echo: req.userPrompt }) };
  }
}

async function setup() {
  const root = await mkdtemp(join(tmpdir(), "dfir-anonmap-send-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stores = {
    anonStore: new AnonControlStore(cases),
    customEntitiesStore: new CustomEntitiesStore(cases),
    discoveredStore: new DiscoveredEntitiesStore(cases),
    anonMapStore: new AnonMapStore(cases),
  };
  await stores.customEntitiesStore.save("c1", [
    { value: "Jane Doe", category: "PERSON" },
    { value: "John Roe", category: "PERSON" },
  ]);
  const ctx: ProviderCallContext = { log: createConsoleLogger("error"), opts: stores };
  return { ctx, stores };
}
const ask = (ctx: ProviderCallContext, p: AIProvider, userPrompt: string) =>
  analyzeRestored(ctx, "c1", emptyState("c1"), p, { systemPrompt: "s", userPrompt, images: [] });

describe("the case's masking map across AI calls (#2657)", () => {
  it("a value keeps its token in a later, separate call, even when it appears second", async () => {
    const { ctx } = await setup();
    const p = new Echo();
    await ask(ctx, p, "Jane Doe logged on.");
    await ask(ctx, p, "John Roe met Jane Doe.");
    const jane = /ANON_PERSON_\d+/.exec(p.sent[0])![0];
    expect(p.sent[1]).toContain(`met ${jane}.`);
    expect(p.sent[1]).not.toMatch(new RegExp(`^${jane} met`));
  });

  it("a different value in a later call never reuses an earlier value's number", async () => {
    const { ctx } = await setup();
    const p = new Echo();
    await ask(ctx, p, "Jane Doe logged on.");
    await ask(ctx, p, "John Roe logged on.");
    expect(p.sent[0]).not.toBe(p.sent[1]);
  });

  it("without the map, the same check fails (control)", async () => {
    const { ctx } = await setup();
    const { anonMapStore: _m, ...rest } = ctx.opts;
    const bare: ProviderCallContext = { ...ctx, opts: rest };
    const p = new Echo();
    await ask(bare, p, "Jane Doe logged on.");
    await ask(bare, p, "John Roe logged on.");
    expect(p.sent[0]).toBe(p.sent[1]); // both ANON_PERSON_1: the bug this issue fixes
  });

  it("a real send saves its tokens; the answer is restored", async () => {
    const { ctx, stores } = await setup();
    const out = (await ask(ctx, new Echo(), "Jane Doe logged on.")) as { echo: string };
    expect(out.echo).toBe("Jane Doe logged on.");
    expect((await stores.anonMapStore.load("c1")).pairs.map((x) => x.value)).toEqual(["Jane Doe"]);
  });

  it("the preview reuses saved tokens and saves nothing", async () => {
    const { ctx, stores } = await setup();
    const p = new Echo();
    await ask(ctx, p, "Jane Doe logged on.");
    const before = (await stores.anonMapStore.load("c1")).pairs;
    await runAiPreview(() => ask(ctx, p, "John Roe logged on."));
    expect((await stores.anonMapStore.load("c1")).pairs).toEqual(before);
  });

  // #3001: a literal equal to a saved token goes out escaped and comes back as itself. analyzeRestored
  // restores once; a second restore would turn the planted literal into "Jane Doe".
  it("a planted literal of a saved token is restored once, as itself", async () => {
    const { ctx } = await setup();
    const p = new Echo();
    await ask(ctx, p, "Jane Doe logged on.");
    const jane = /ANON_PERSON_\d+/.exec(p.sent[0])![0];
    const prompt = `planted ${jane} and Jane Doe.`;
    const out = (await ask(ctx, p, prompt)) as { echo: string };
    expect(p.sent[1]).toBe(`planted ANON-LITERAL_${jane.slice(5)} and ${jane}.`);
    expect(out.echo).toBe(prompt);
  });

  it("an unparseable answer is restored once too (parse-error path)", async () => {
    const { ctx } = await setup();
    await ask(ctx, new Echo(), "Jane Doe logged on.");
    const raw: AIProvider = {
      name: "stub",
      model: "stub-model",
      analyze: async (req) => ({ rawText: `not json: ${req.userPrompt}` }),
    };
    const err = await ask(ctx, raw, "planted ANON_PERSON_1 and Jane Doe.").catch((e: unknown) => e);
    expect((err as { rawText?: string }).rawText).toBe("not json: planted ANON_PERSON_1 and Jane Doe.");
  });

  it("concurrent calls agree: one value, one token; two values, two tokens", async () => {
    const { ctx, stores } = await setup();
    const p = new Echo();
    await Promise.all([ask(ctx, p, "Jane Doe"), ask(ctx, p, "John Roe"), ask(ctx, p, "Jane Doe")]);
    const saved = (await stores.anonMapStore.load("c1")).pairs;
    expect(saved).toHaveLength(2);
    const tokenOf = new Map(saved.map((x) => [x.value, x.token]));
    for (const sent of p.sent) {
      if (sent.includes("ANON_PERSON")) expect([...tokenOf.values()]).toContain(sent.trim());
    }
    expect(new Set(p.sent).size).toBe(2);
  });
});
