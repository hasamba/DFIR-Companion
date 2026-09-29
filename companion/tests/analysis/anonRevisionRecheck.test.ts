import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../../src/analysis/anonDiscovered.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { analyzeRestored, type ProviderCallContext } from "../../src/analysis/ai/providerCall.js";
import {
  AnonymizationChangedError,
  anonRevision,
  assertAnonRevision,
  bumpAnonRevision,
} from "../../src/analysis/anonRevision.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import type { PresidioClient } from "../../src/analysis/presidio.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// #1840: an AI call snapshots the anonymization lists, masks, runs the Presidio scan, and only then
// sends. A "Hide from AI" that lands inside that window used to be ignored — the call sent the value
// in clear after Hide had returned. The Hide here is injected by the TEST's Presidio stub (the scan
// sits exactly between masking and sending), never by a hook in production code.

const NAME = "Jane Doe";
const PROMPT = `The user ${NAME} ran the tool.`;

class CapturingProvider implements AIProvider {
  readonly name = "stub";
  readonly model = "stub-model";
  readonly sent: string[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req.userPrompt);
    // Echo the masked prompt back, so the test can see the answer is restored to real values.
    return { rawText: JSON.stringify({ echo: req.userPrompt }) };
  }
}

async function setup(caseId: string) {
  const root = await mkdtemp(join(tmpdir(), "dfir-anonrev-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  const stores = {
    anonStore: new AnonControlStore(cases),
    customEntitiesStore: new CustomEntitiesStore(cases),
    discoveredStore: new DiscoveredEntitiesStore(cases),
    presidioPendingStore: new PresidioPendingStore(cases),
  };
  return { cases, stores };
}

function ctxWith(opts: ProviderCallContext["opts"]): ProviderCallContext {
  return { log: createConsoleLogger("error"), opts };
}

/** A Presidio stub that reports nothing, and runs `during` on its Nth call (the hide under test). */
function presidio(during: (call: number) => Promise<void>, calls: { n: number }) {
  const client: PresidioClient = {
    analyze: async () => {
      calls.n++;
      await during(calls.n);
      return [];
    },
  };
  return { client, url: "http://localhost:5002", minScore: 0.6 };
}

describe("an AI call re-checks the anonymization right before it sends (#1840)", () => {
  it("masks again when a Hide lands between masking and sending", async () => {
    const { stores } = await setup("h1");
    const calls = { n: 0 };
    const hide = async (n: number) => {
      if (n === 1) await stores.customEntitiesStore.save("h1", [{ value: NAME, category: "PERSON" }]);
    };
    const provider = new CapturingProvider();
    const ctx = ctxWith({ ...stores, presidio: presidio(hide, calls) });
    const out = (await analyzeRestored(ctx, "h1", emptyState("h1"), provider, {
      systemPrompt: "s",
      userPrompt: PROMPT,
      images: [],
    })) as { echo: string };
    expect(provider.sent).toHaveLength(1);
    expect(provider.sent[0]).not.toContain(NAME);
    expect(provider.sent[0]).toMatch(/ANON_PERSON_\d+/);
    expect(calls.n).toBe(2); // the re-masked prompt was scanned again
    expect(out.echo).toContain(NAME); // the answer is restored with the anonymizer that masked it
  });

  it("masks when anonymization is turned on while an anonymization-off call is being prepared", async () => {
    const { stores } = await setup("h2");
    await stores.customEntitiesStore.save("h2", [{ value: NAME, category: "PERSON" }]);
    await stores.anonStore.save("h2", { ...(await stores.anonStore.load("h2")), enabled: false });
    let first = true;
    const anonStore = {
      load: async (caseId: string) => {
        const c = await stores.anonStore.load(caseId);
        if (first) {
          first = false;
          // The analyst turns masking on after this call read "off".
          await stores.anonStore.save(caseId, { ...c, enabled: true });
        }
        return c;
      },
    } as unknown as AnonControlStore;
    const provider = new CapturingProvider();
    await analyzeRestored(ctxWith({ ...stores, anonStore }), "h2", emptyState("h2"), provider, {
      systemPrompt: "s",
      userPrompt: PROMPT,
      images: [],
    });
    expect(provider.sent).toHaveLength(1);
    expect(provider.sent[0]).not.toContain(NAME);
  });

  it("holds and sends nothing when the anonymization changes on every attempt", async () => {
    const { stores } = await setup("h3");
    const calls = { n: 0 };
    const provider = new CapturingProvider();
    const ctx = ctxWith({ ...stores, presidio: presidio(async () => bumpAnonRevision("h3"), calls) });
    await expect(
      analyzeRestored(ctx, "h3", emptyState("h3"), provider, {
        systemPrompt: "s",
        userPrompt: PROMPT,
        images: [],
      }),
    ).rejects.toBeInstanceOf(AnonymizationChangedError);
    expect(provider.sent).toHaveLength(0);
  });

  it("does no extra work when nothing changes", async () => {
    const { stores } = await setup("h4");
    const calls = { n: 0 };
    const provider = new CapturingProvider();
    const ctx = ctxWith({ ...stores, presidio: presidio(async () => {}, calls) });
    await analyzeRestored(ctx, "h4", emptyState("h4"), provider, {
      systemPrompt: "s",
      userPrompt: PROMPT,
      images: [],
    });
    expect(provider.sent).toHaveLength(1);
    expect(calls.n).toBe(1);
  });

  it("an import chunk skips the gate only while its pre-scan revision is still current", async () => {
    const { stores } = await setup("h5");
    const calls = { n: 0 };
    const provider = new CapturingProvider();
    const ctx = ctxWith({ ...stores, presidio: presidio(async () => {}, calls) });
    const req = { systemPrompt: "s", userPrompt: PROMPT, images: [] };
    const scannedAt = anonRevision("h5");
    await analyzeRestored(ctx, "h5", emptyState("h5"), provider, req, "csv", scannedAt);
    expect(calls.n).toBe(0); // covered by the pre-scan
    // The analyst removes a hidden value after the pre-scan: the next chunk is gated itself.
    await stores.discoveredStore.suppress("h5", "something");
    await analyzeRestored(ctx, "h5", emptyState("h5"), provider, req, "csv", scannedAt);
    expect(calls.n).toBe(1);
  });
});

describe("what bumps the revision", () => {
  it("every analyst-side write bumps it; the OCR pass's own discoveries do not", async () => {
    const { stores } = await setup("r1");
    const moved = async (write: () => Promise<unknown>) => {
      const before = anonRevision("r1");
      await write();
      return anonRevision("r1") !== before;
    };
    expect(
      await moved(() => stores.customEntitiesStore.save("r1", [{ value: NAME, category: "PERSON" }])),
    ).toBe(true);
    expect(await moved(() => stores.discoveredStore.suppress("r1", "x"))).toBe(true);
    expect(await moved(() => stores.discoveredStore.unsuppress("r1", "x"))).toBe(true);
    expect(await moved(async () => stores.anonStore.save("r1", await stores.anonStore.load("r1")))).toBe(
      true,
    );
    expect(
      await moved(() => stores.discoveredStore.addDiscovered("r1", [{ value: "HOSTX", category: "HOST" }])),
    ).toBe(false);
  });

  it("assertAnonRevision holds a send once the revision moved", () => {
    const at = anonRevision("r2");
    expect(() => assertAnonRevision("r2", at, "x")).not.toThrow();
    bumpAnonRevision("r2");
    expect(() => assertAnonRevision("r2", at, "x")).toThrow(AnonymizationChangedError);
  });
});
