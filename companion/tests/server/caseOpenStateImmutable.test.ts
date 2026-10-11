// #2126: every case-open panel GET that reads the full case now shares ONE state object, kept for
// five idle minutes. That is safe only while no handler, and nothing it calls, writes into it. Under
// the test runner the shared state is deep-frozen (routes/caseOpenState.ts), so an in-place sort,
// push or field assignment anywhere below these routes throws instead of leaking into another panel.
// This sweep runs every switched route over the seeded demo case and checks that a whole case open
// costs one full load.
import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Express } from "express";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { seedDemoCase } from "../../src/analysis/seedDemoCase.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { HostScopeStore } from "../../src/analysis/hostScopeStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { ServedLocationStore } from "../../src/analysis/servedLocation.js";
import { SensitiveLocationStore } from "../../src/analysis/sensitiveLocation.js";
import { HypothesisStore } from "../../src/analysis/hypothesisStore.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";

const CASE = "demo";

/** Every case-open panel GET switched to the shared full-state read. */
const CASE_OPEN_FULL_STATE_ROUTES = [
  "/ioc-risk",
  "/customer-exposure",
  "/cockpit",
  "/sessions",
  "/campaign-scope",
  "/served-exposure",
  "/kerberoast-chain",
  "/tls-graph",
  "/sensitive-access",
  "/playbook-match",
  "/hypotheses",
  "/host-scope",
  "/host-duplicates",
  "/second-look/preview",
  "/known-unknowns",
] as const;

let app: Express;
let stateStore: StateStore;

beforeAll(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-2126-frozen-"));
  await seedDemoCase(root, { caseId: CASE });
  const store = new CaseStore(root);
  stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  app = createApp(store, {
    stateStore,
    pipeline,
    aiConfigured: false,
    superTimelineStore,
    hostScopeStore: new HostScopeStore(store),
    assetOverridesStore: new AssetOverridesStore(store),
    hostDuplicateDismissalStore: new HostDuplicateDismissalStore(store),
    servedLocationStore: new ServedLocationStore(store),
    sensitiveLocationStore: new SensitiveLocationStore(store),
    hypothesisStore: new HypothesisStore(store),
  });
}, 60_000);

afterAll(() => vi.restoreAllMocks());

function spyLoads() {
  const loaded: InvestigationState[] = [];
  const real = stateStore.load.bind(stateStore);
  const load = vi.spyOn(stateStore, "load").mockImplementation(async (...args) => {
    const state = await real(...args);
    loaded.push(state);
    return state;
  });
  return { load, loaded };
}

const open = (paths: readonly string[]) =>
  Promise.all(paths.map((p) => request(app).get(`/cases/${CASE}${p}`)));

describe("case-open panels never write into the shared full state (#2126)", () => {
  it("every switched panel answers over a deep-frozen shared state, with fewer loads than panels", async () => {
    const { load, loaded } = spyLoads();
    const replies = await open(CASE_OPEN_FULL_STATE_ROUTES);
    replies.forEach((res, i) =>
      expect(res.status, `${CASE_OPEN_FULL_STATE_ROUTES[i]}: ${res.text}`).toBe(200),
    );
    expect(load.mock.calls.length).toBeLessThan(CASE_OPEN_FULL_STATE_ROUTES.length);
    // The seeded demo case must actually reach the panels, or the sweep proves nothing.
    expect(loaded[0].forensicTimeline.length).toBeGreaterThan(10);
    for (const state of loaded) expect(Object.isFrozen(state.forensicTimeline[0])).toBe(true);
    load.mockRestore();
  }, 60_000);

  // #2129: the super-timeline readers (cockpit, tls-graph, host-scope, host-duplicates, second-look)
  // used to post a no-op migrateSuper on every read, which moved the revision; they now share too.
  it("on a settled case every panel shares one load, then hits", async () => {
    const panels = CASE_OPEN_FULL_STATE_ROUTES;
    await open(panels); // the case settles: migrations done
    const { load } = spyLoads();
    await stateStore.save({ ...(await stateStore.load(CASE)), caseId: CASE }); // an edit: a fresh revision
    load.mockClear();
    const replies = await open(panels);
    replies.forEach((res, i) => expect(res.status, panels[i]).toBe(200));
    expect(load).toHaveBeenCalledTimes(1);
    for (const path of panels)
      expect((await request(app).get(`/cases/${CASE}${path}`)).status, path).toBe(200);
    expect(load).toHaveBeenCalledTimes(1);
    load.mockRestore();
  }, 60_000);
});
