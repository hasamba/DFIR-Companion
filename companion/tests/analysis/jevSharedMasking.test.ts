import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../../src/analysis/anonDiscovered.js";
import { createAnonymizer, deriveKnownEntities } from "../../src/analysis/anonymize.js";
import { toAnonPolicy } from "../../src/analysis/anonControl.js";
import { caseMasker } from "../../src/analysis/ai/maskRequest.js";
import { gradeEvents, type JevGraderDeps } from "../../src/analysis/ai/jev/jevGrader.js";
import { buildContainmentState } from "../../src/analysis/ai/jev/containmentState.js";
import { buildAnalystContext } from "../../src/analysis/ai/jev/jevDecomposed.js";
import type { JevAnswer } from "../../src/analysis/ai/jev/jevClient.js";
import type { ProviderCallContext } from "../../src/analysis/ai/providerCallContext.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #2515 — the Jev review and the containment check moved onto the shared masking step (caseMasker in
// ai/maskRequest.ts). Before that they built their own (known entities, anonymizer) pair through
// `buildImportAnonContext`. This test pins that the move changed NOTHING on the wire: the same input
// masked the old way and the new way gives byte-identical Jev states.
//
// It ran green against the real `buildImportAnonContext` before that function was deleted. The
// reference below is a frozen copy of its steps (control → policy → derived + custom + discovered
// entities, suppressed ones excluded → anonymizer → apply), so the proof outlives the deletion.

const HOST = "FIN-SRV-07";
const NAME = "Jane Doe";
const OCR_NAME = "Rex Halvorsen";
const SUPPRESSED = "PUBLIC-PRINTER";

const ev = (id: string, description: string, over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: `2026-01-01T00:0${id.length % 10}:00Z`,
  description,
  severity: "High",
  mitreTechniques: ["T1059.001"],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: HOST,
  ...over,
});

const timeline = [
  ev("e1", `logon by ${NAME} on ${HOST} from 10.20.30.40`),
  ev("e2", `powershell -enc AAA by ${OCR_NAME} printing to ${SUPPRESSED}`, {
    path: `C:\\Users\\jdoe\\a.ps1`,
  }),
  ev("e3", `net use \\\\${HOST}\\c$ as CORP\\svc-backup`),
];

async function seeded(maskingOff: boolean) {
  const root = await mkdtemp(join(tmpdir(), "dfir-jev-shared-mask-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await new CustomEntitiesStore(cases).save("c1", [{ value: NAME, category: "PERSON" }]);
  const discovered = new DiscoveredEntitiesStore(cases);
  await discovered.addDiscovered("c1", [
    { value: OCR_NAME, category: "PERSON" },
    { value: SUPPRESSED, category: "HOST" },
  ]);
  await discovered.suppress("c1", SUPPRESSED);
  const anonStore = new AnonControlStore(cases);
  if (maskingOff) await anonStore.save("c1", { ...(await anonStore.load("c1")), enabled: false });
  const ctx: ProviderCallContext = {
    log: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} } as never,
    opts: { anonStore, customEntitiesStore: new CustomEntitiesStore(cases), discoveredStore: discovered },
  };
  const state: InvestigationState = {
    ...emptyState("c1"),
    forensicTimeline: timeline,
    findings: [
      {
        id: "f1",
        title: `Encoded PowerShell on ${HOST}`,
        description: `run by ${NAME}`,
        severity: "High",
        relatedEventIds: ["e1", "e2", "e3"],
        mitreTechniques: ["T1059.001"],
        relatedIocs: [],
        sourceScreenshots: [],
        firstSeen: "2026-01-01T00:00:00Z",
        lastUpdated: "2026-01-01T00:00:00Z",
        status: "open",
      },
    ],
  };
  return { ctx, state };
}

/** The pre-#2515 Jev masking, frozen: what `buildImportAnonContext` + `anon.apply` did. */
async function oldMask(ctx: ProviderCallContext, state: InvestigationState): Promise<(t: string) => string> {
  const control = ctx.opts.anonStore ? await ctx.opts.anonStore.load("c1") : null;
  const policy = toAnonPolicy(control);
  if (!policy.enabled) return (t) => t;
  const known = deriveKnownEntities(state);
  const custom = ctx.opts.customEntitiesStore ? await ctx.opts.customEntitiesStore.load("c1") : [];
  const disc = ctx.opts.discoveredStore
    ? await ctx.opts.discoveredStore.load("c1")
    : { discovered: [], suppressed: [] };
  known.custom = [...custom, ...disc.discovered];
  known.suppressed = disc.suppressed;
  const anon = createAnonymizer(policy, known);
  return (t) => anon.apply(t);
}

/** Every Jev state one review would send, in order, with the given mask. */
async function reviewStates(mask: (t: string) => string, shape: "single" | "decomposed"): Promise<string[]> {
  const states: string[] = [];
  const deps: JevGraderDeps = {
    mask,
    ask: async (jevState, questions) => {
      states.push(JSON.stringify(jevState));
      const answers: Record<string, JevAnswer> = {};
      for (const [id, q] of Object.entries(questions))
        answers[id] =
          q.type === "noul"
            ? { type: "noul", noul: 0 }
            : q.type === "choice"
              ? { type: "choice", choice: Object.keys(q.criteria)[0], probabilities: {}, confidence: 1 }
              : { type: "score", score: 1, legend: {}, probabilities: {}, confidence: 1 };
      return { model: "m", answers, usage: { inputTokens: 0, outputTokens: 0 } };
    },
  };
  const caseContext = buildAnalystContext(
    [{ kind: "finding", ref: "f1", reason: "authorized", note: `admin ${NAME} on ${HOST}` } as never],
    mask,
  );
  await gradeEvents(deps, timeline, { batchSize: 2, shape, caseContext });
  return states;
}

describe("the Jev routes' masking is unchanged by the move to the shared step (#2515)", () => {
  for (const maskingOff of [false, true]) {
    const label = maskingOff ? "masking off" : "masking on";
    it(`review batches are byte-identical — ${label}`, async () => {
      const { ctx, state } = await seeded(maskingOff);
      const before = await oldMask(ctx, state);
      const after = (await caseMasker(ctx, "c1", state)).mask;
      for (const shape of ["single", "decomposed"] as const)
        expect(await reviewStates(after, shape)).toEqual(await reviewStates(before, shape));
      const wire = (await reviewStates(after, "single")).join("\n");
      if (maskingOff) expect(wire).toContain(NAME);
      else {
        expect(wire).not.toContain(NAME);
        expect(wire).not.toContain(OCR_NAME);
        expect(wire).not.toContain(HOST);
        expect(wire).toContain(SUPPRESSED); // a suppressed discovery is never tokenized
      }
    });

    it(`the containment state is byte-identical — ${label}`, async () => {
      const { ctx, state } = await seeded(maskingOff);
      const before = await oldMask(ctx, state);
      const after = (await caseMasker(ctx, "c1", state)).mask;
      const finding = state.findings[0];
      expect(JSON.stringify(buildContainmentState(finding, state, after))).toBe(
        JSON.stringify(buildContainmentState(finding, state, before)),
      );
    });
  }

  it("masking off reads no entity list (Presidio then has nothing to run on)", async () => {
    const { ctx, state } = await seeded(true);
    const m = await caseMasker(ctx, "c1", state);
    expect(m.known).toBeNull();
    expect(m.anon).toBeNull();
    expect(m.mask(`x ${HOST}`)).toBe(`x ${HOST}`);
  });
});
