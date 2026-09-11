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
      stateStore: { load: vi.fn(async () => merged) },
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
      stateStore: { load: async () => merged },
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
      stateStore: { load: async () => merged },
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
        stateStore: { load: async () => state([ev("a", "Info")]) },
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
