import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { caseMasker } from "../../src/analysis/ai/maskRequest.js";
import { AnonMapStore } from "../../src/analysis/anonMap.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { mirrorMaskText } from "../../src/composition/watsonMirrorWiring.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import type { RouteContext } from "../../src/routes/context.js";
import { jevAnonStores } from "../../src/routes/jevMasking.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #2708: the Telegram mirror masks under the case's masking-map lock, so a token it mints for a value
// new to the case is saved, and AI prompts and reports give that value the very same token.

const HOST = "ws-01.corp.local";

function state(caseId: string): InvestigationState {
  return {
    ...emptyState(caseId),
    forensicTimeline: [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00Z",
        description: `logon on ${HOST}`,
        severity: "High",
        sources: ["x"],
        asset: HOST,
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
      },
    ],
  };
}

async function setup() {
  const caseId = "c1";
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-mirror-mask-")));
  await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  const st = state(caseId);
  const ctx = { store: cases, options: { stateStore: { load: async () => st } } } as unknown as RouteContext;
  return { caseId, cases, st, ctx };
}

describe("the mirror's masking and the case's masking map (#2708)", () => {
  it("saves the token it mints, and a later AI send gives the value the same token", async () => {
    const { caseId, cases, st, ctx } = await setup();
    const out = await mirrorMaskText(ctx, caseId, `seen on ${HOST}`);
    if (!out.ok) throw new Error(`mirror masking failed: ${out.reason}`);
    expect(out.text).not.toContain(HOST);
    const token = /ANON_HOST_\d+/.exec(out.text)?.[0];
    expect(token).toBeDefined();
    const map = new AnonMapStore(cases);
    expect((await map.load(caseId)).pairs).toContainEqual(expect.objectContaining({ token, value: HOST }));

    // A real send (the AI path) masks under the same lock from the saved map.
    const sent = await map.withAnonMap(caseId, async (identity) => {
      const m = await caseMasker(
        { log: createConsoleLogger("error"), opts: jevAnonStores(cases) },
        caseId,
        st,
        undefined,
        undefined,
        identity,
      );
      return { anon: m.anon, result: m.mask(`host ${HOST}`) };
    });
    expect(sent).toBe(`host ${token}`);
  });

  it("still holds while names await approval, and saves nothing", async () => {
    const { caseId, cases, ctx } = await setup();
    await new PresidioPendingStore(cases).save(caseId, [{ value: "Jane Roe", category: "PERSON" }]);
    const out = await mirrorMaskText(ctx, caseId, `seen on ${HOST}`);
    expect(out).toEqual({ ok: false, reason: "names await approval in the Anonymization panel" });
    expect((await new AnonMapStore(cases).load(caseId)).pairs).toEqual([]);
  });
});
