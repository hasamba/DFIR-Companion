import { describe, expect, it } from "vitest";
import { watsonRawSearchDeps, watsonRoundDeps } from "../../src/routes/watsonDeps.js";
import type { RouteContext } from "../../src/routes/context.js";

// D12: the route builds Watson's one door to the raw record, or nothing when a piece is missing.

const superTimelineStore = { query: async () => ({ events: [], total: 0 }), meta: async () => ({}) };

function ctxOf(o: { status?: string; enabled?: boolean; withStore?: boolean; withWriter?: boolean } = {}) {
  const options = {
    watsonChatStore: {},
    watsonProvider: () => ({ name: "fake" }),
    ...(o.withWriter === false ? {} : { stateStore: {}, stateLock: {}, activityLogStore: {} }),
    ...(o.withStore === false ? {} : { superTimelineStore }),
  };
  return {
    options,
    store: { getCaseMeta: async () => ({ status: o.status ?? "open" }) },
    getControl: async () => ({ enabled: o.enabled ?? true }),
    markConclusionsOutOfDate: async () => undefined,
  } as unknown as RouteContext;
}

describe("watsonRawSearchDeps (D12)", () => {
  it("wires the super-timeline store as the reader, and the round deps carry it", () => {
    const deps = watsonRawSearchDeps(ctxOf());
    expect(deps?.reader).toBe(superTimelineStore);
    expect(deps?.writer).toBeDefined();
    expect(watsonRoundDeps(ctxOf())?.rawSearch?.reader).toBe(superTimelineStore);
  });

  it("is absent without a super-timeline store or a proposal writer", () => {
    expect(watsonRawSearchDeps(ctxOf({ withStore: false }))).toBeUndefined();
    expect(watsonRawSearchDeps(ctxOf({ withWriter: false }))).toBeUndefined();
    expect(watsonRoundDeps(ctxOf({ withStore: false }))).not.toHaveProperty("rawSearch");
  });

  it("is writable only with AI on and the case neither closed nor archived (D6c)", async () => {
    expect(await watsonRawSearchDeps(ctxOf())?.writable("c1")).toBe(true);
    expect(await watsonRawSearchDeps(ctxOf({ enabled: false }))?.writable("c1")).toBe(false);
    expect(await watsonRawSearchDeps(ctxOf({ status: "closed" }))?.writable("c1")).toBe(false);
    expect(await watsonRawSearchDeps(ctxOf({ status: "archived" }))?.writable("c1")).toBe(false);
  });
});
