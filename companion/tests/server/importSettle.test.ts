import { describe, it, expect, vi } from "vitest";
import { settleForensicImport } from "../../src/routes/importSettle.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// The one seam every import crosses: dual-write the ADDED rows → tag them → demote → diff against
// the post-demote state. Pinned here so a route can neither skip a step nor run them out of order.

function ev(id: string, severity: ForensicEvent["severity"], description = id): ForensicEvent {
  return {
    id,
    timestamp: "2026-05-02T10:00:00Z",
    description,
    severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

function state(events: ForensicEvent[], iocs: InvestigationState["iocs"] = []): InvestigationState {
  return { forensicTimeline: events, iocs } as unknown as InvestigationState;
}

describe("settleForensicImport", () => {
  it("dual-writes only the rows the import added, tags them, demotes, and diffs post-demote", async () => {
    const calls: string[] = [];
    const before = state([ev("old", "High")]);
    const merged = state([ev("old", "High"), ev("info", "Info"), ev("high", "High")]);
    const afterDemote = state([ev("old", "High"), ev("high", "High")]);
    const deps = {
      stateStore: { load: vi.fn(async () => merged), save: vi.fn(async () => {}) },
      superTimelineStore: {
        append: vi.fn(async (_c: string, events: ForensicEvent[]) => {
          calls.push(`append:${events.map((e) => e.id).join(",")}`);
          return events.length;
        }),
      },
      onSuperTimeline: vi.fn(() => calls.push("notify")),
      autoTagImported: vi.fn(async (_c: string, events: ForensicEvent[]) => {
        calls.push(`tag:${events.map((e) => e.id).join(",")}`);
      }),
      demoteForensicForCase: vi.fn(async () => {
        calls.push("demote");
        return afterDemote;
      }),
    };
    const r = await settleForensicImport(deps, "c1", before);
    expect(calls).toEqual(["append:info,high", "notify", "tag:info,high", "demote"]);
    expect(r.superTimelineAddedCount).toBe(2);
    // The diff is against the POST-demote state: the Info row is not "+1 event".
    expect(r.timelineDiff.added.map((e) => e.description)).toEqual(["high"]);
    expect(r.state).toBe(afterDemote);
  });

  it("returns the retained count the store reports, not the number handed to it", async () => {
    const before = state([]);
    const merged = state([ev("a", "Info"), ev("b", "Info")]);
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      superTimelineStore: { append: async () => 1 }, // the cap kept one
      autoTagImported: async () => {},
      demoteForensicForCase: async () => state([]),
    };
    expect((await settleForensicImport(deps, "c1", before)).superTimelineAddedCount).toBe(1);
  });

  it("still tags and demotes when the super-timeline append fails", async () => {
    const before = state([]);
    const merged = state([ev("a", "Info")]);
    const tagged: string[] = [];
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      superTimelineStore: {
        append: async () => {
          throw new Error("disk");
        },
      },
      autoTagImported: async (_c: string, events: ForensicEvent[]) => {
        tagged.push(...events.map((e) => e.id));
      },
      demoteForensicForCase: async () => state([]),
    };
    const r = await settleForensicImport(deps, "c1", before);
    expect(tagged).toEqual(["a"]);
    expect(r.superTimelineAddedCount).toBe(0);
    expect(r.state.forensicTimeline).toEqual([]);
  });

  it("skips the dual-write when no store is wired, and demotes anyway", async () => {
    const demote = vi.fn(async () => state([]));
    const r = await settleForensicImport(
      {
        stateStore: { load: async () => state([ev("a", "Info")]), save: async () => {} },
        autoTagImported: async () => {},
        demoteForensicForCase: demote,
      },
      "c1",
      state([]),
    );
    expect(demote).toHaveBeenCalledOnce();
    expect(r.superTimelineAddedCount).toBe(0);
  });
});

// ── #1157: per-event importedAt / importBatchId ─────────────────────────────────────────────────
describe("settleForensicImport — importedAt / importBatchId (#1157)", () => {
  it("stamps importedAt and importBatchId on rows genuinely new to this case, and saves them", async () => {
    const before = state([ev("old", "High")]);
    const merged = state([ev("old", "High"), ev("new1", "High"), ev("new2", "High")]);
    let saved: InvestigationState | undefined;
    const deps = {
      stateStore: {
        load: async () => merged,
        save: vi.fn(async (s: InvestigationState) => {
          saved = s;
        }),
      },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => saved ?? merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(deps.stateStore.save).toHaveBeenCalledOnce();
    const byId = new Map(saved!.forensicTimeline.map((e) => [e.id, e]));
    expect(byId.get("old")!.importedAt).toBeUndefined();
    expect(byId.get("old")!.importBatchId).toBeUndefined();
    expect(byId.get("new1")!.importedAt).toEqual(expect.any(String));
    expect(byId.get("new2")!.importedAt).toBe(byId.get("new1")!.importedAt);
    expect(byId.get("new1")!.importBatchId).toEqual(expect.any(String));
    expect(byId.get("new2")!.importBatchId).toBe(byId.get("new1")!.importBatchId);
  });

  // #1174: dashboard/WS subscribers were not notified at the instant the importedAt/importBatchId
  // stamps were saved — only whenever a LATER broadcast happened to fire.
  it("notifies onState with the stamped state right after the save, not just on a later broadcast", async () => {
    const before = state([ev("old", "High")]);
    const merged = state([ev("old", "High"), ev("new1", "High")]);
    let saved: InvestigationState | undefined;
    const onState = vi.fn();
    const deps = {
      stateStore: {
        load: async () => merged,
        save: async (s: InvestigationState) => {
          saved = s;
        },
      },
      onState,
      autoTagImported: async () => {},
      demoteForensicForCase: async () => saved ?? merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(onState).toHaveBeenCalledOnce();
    expect(onState).toHaveBeenCalledWith(saved);
  });

  it("does not fire onState when nothing new was imported (save never ran)", async () => {
    const before = state([ev("old", "High")]);
    const merged = state([ev("old", "High")]);
    const onState = vi.fn();
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      onState,
      autoTagImported: async () => {},
      demoteForensicForCase: async () => merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(onState).not.toHaveBeenCalled();
  });

  it("does not re-stamp a row that already existed before this import", async () => {
    const before = state([ev("old", "High")]);
    const merged = state([ev("old", "High")]); // nothing new — a no-op import
    const save = vi.fn(async () => {});
    const deps = {
      stateStore: { load: async () => merged, save },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(save).not.toHaveBeenCalled();
  });

  it("stamps new rows even when no super-timeline store is configured", async () => {
    const before = state([]);
    const merged = state([ev("new1", "Info")]);
    let saved: InvestigationState | undefined;
    const deps = {
      stateStore: {
        load: async () => merged,
        save: async (s: InvestigationState) => {
          saved = s;
        },
      },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => saved ?? merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(saved!.forensicTimeline[0].importedAt).toEqual(expect.any(String));
  });

  it("persists the stamp through demoteForensicForCase's own independent reload", async () => {
    // demoteForensicForCase in production reloads from the store itself — this fixture models
    // that by returning exactly what was saved, proving the stamp survived a save/reload round
    // trip rather than only existing on an in-memory object this function happens to return.
    const before = state([]);
    const merged = state([ev("new1", "High")]);
    let saved: InvestigationState = merged;
    const deps = {
      stateStore: {
        load: async () => merged,
        save: async (s: InvestigationState) => {
          saved = s;
        },
      },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => saved,
    };
    const r = await settleForensicImport(deps, "c1", before);
    expect(r.state.forensicTimeline[0].importedAt).toEqual(expect.any(String));
  });

  it("gives two separate imports different importedAt and importBatchId values", async () => {
    const before = state([]);
    let saved: InvestigationState | undefined;
    const deps = (mergedState: InvestigationState) => ({
      stateStore: {
        load: async () => mergedState,
        save: async (s: InvestigationState) => {
          saved = s;
        },
      },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => saved ?? mergedState,
    });
    await settleForensicImport(deps(state([ev("a", "High")])), "c1", before);
    const first = saved!.forensicTimeline[0];
    saved = undefined;
    await new Promise((r) => setTimeout(r, 2));
    await settleForensicImport(deps(state([ev("b", "High")])), "c1", before);
    const second = saved!.forensicTimeline[0];
    expect(second.importBatchId).not.toBe(first.importBatchId);
    expect(second.importedAt).not.toBe(first.importedAt);
  });

  it("stamps the rows dual-written to the super-timeline and offered to the tagger too", async () => {
    const before = state([]);
    const merged = state([ev("new1", "Info")]);
    let taggedEvents: ForensicEvent[] = [];
    let appendedEvents: ForensicEvent[] = [];
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      superTimelineStore: {
        append: async (_c: string, events: ForensicEvent[]) => {
          appendedEvents = events;
          return events.length;
        },
      },
      autoTagImported: async (_c: string, events: ForensicEvent[]) => {
        taggedEvents = events;
      },
      demoteForensicForCase: async () => state([]),
    };
    await settleForensicImport(deps, "c1", before);
    expect(appendedEvents[0].importedAt).toEqual(expect.any(String));
    expect(taggedEvents[0].importedAt).toEqual(expect.any(String));
  });
});
