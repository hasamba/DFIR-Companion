import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import { CustomEntitiesStore } from "../../../src/analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../../../src/analysis/anonDiscovered.js";
import { AnonMapStore } from "../../../src/analysis/anonMap.js";
import { analyzeRestored, type ProviderCallContext } from "../../../src/analysis/ai/providerCall.js";
import { emptyState } from "../../../src/analysis/stateTypes.js";
import { createConsoleLogger } from "../../../src/logging/logger.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";

// #2658: the cacheable prefix reaches a provider only MASKED, only with anonymization on, and only when
// the masked prompt starts with it. The clear prefix never leaves the gate.

class Capture implements AIProvider {
  readonly name = "stub";
  readonly model = "stub-model";
  readonly sent: AnalyzeRequest[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    return { rawText: "{}" };
  }
}

const PREFIX = "<<<TIMELINE>>>\nJane Doe ran rclone\n<<<END TIMELINE>>>\n\n";
const PROMPT = `${PREFIX}CASE CONTEXT\nwhat did Jane Doe do?`;

async function setup(anonymize: boolean) {
  const root = await mkdtemp(join(tmpdir(), "dfir-cacheprefix-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const anonStore = new AnonControlStore(cases);
  await anonStore.save("c1", { ...(await anonStore.load("c1")), enabled: anonymize });
  const customEntitiesStore = new CustomEntitiesStore(cases);
  await customEntitiesStore.save("c1", [{ value: "Jane Doe", category: "PERSON" }]);
  const ctx: ProviderCallContext = {
    log: createConsoleLogger("error"),
    opts: {
      anonStore,
      customEntitiesStore,
      discoveredStore: new DiscoveredEntitiesStore(cases),
      anonMapStore: new AnonMapStore(cases),
    },
  };
  const p = new Capture();
  await analyzeRestored(ctx, "c1", emptyState("c1"), p, {
    systemPrompt: "s",
    userPrompt: PROMPT,
    cachePrefix: PREFIX,
    images: [],
  });
  return p.sent[0];
}

describe("the cache prefix through the masking gate (#2658)", () => {
  it("anonymization on: a masked prefix the masked prompt starts with", async () => {
    const sent = await setup(true);
    expect(sent.cachePrefix).toBeDefined();
    expect(sent.cachePrefix).not.toContain("Jane Doe");
    expect(sent.cachePrefix).toMatch(/ANON_PERSON_\d+ ran rclone/);
    expect(sent.userPrompt.startsWith(sent.cachePrefix!)).toBe(true);
    expect(sent.userPrompt).not.toContain("Jane Doe");
  });

  it("anonymization off: no prefix at all, the whole prompt in one piece", async () => {
    const sent = await setup(false);
    expect(sent.cachePrefix).toBeUndefined();
    expect(sent.userPrompt).toBe(PROMPT);
  });
});
