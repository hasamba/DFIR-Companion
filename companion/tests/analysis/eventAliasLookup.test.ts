// #2059: the stored-case resolver used to read the WHOLE overview (every finding and IOC) to get the
// lineage, and sent every tagged id to the liveness check. Only an id that is a KEY of the lineage can
// resolve to anything but itself, so only those ids (and their chains) need a liveness answer, and the
// lineage is read on its own.
import { describe, it, expect } from "vitest";
import {
  eventTargetIds,
  resolveStoredTargets,
  storedEventResolver,
  type EventAliasSource,
} from "../../src/analysis/eventAliasLookup.js";

function fakeSource(aliases: Record<string, string> | undefined, liveIds: string[]) {
  const asked: string[][] = [];
  const live = new Set(liveIds);
  const source: EventAliasSource & { loadOverview: () => never } = {
    loadOverview: () => {
      throw new Error("the resolver must not read the whole overview");
    },
    loadEventAliases: async () => aliases,
    hasForensicEventIds: async (_caseId, ids) => {
      asked.push([...ids]);
      return new Set(ids.filter((id) => live.has(id)));
    },
  };
  return { source, asked };
}

describe("storedEventResolver (#2059)", () => {
  it("never asks for liveness when no id is a lineage key", async () => {
    const { source, asked } = fakeSource({ a: "b" }, ["x", "b"]);
    const resolve = await storedEventResolver(source, "c1", ["x", "y", "b"]);
    expect(asked).toEqual([]);
    expect(["x", "y", "b"].map(resolve)).toEqual(["x", "y", "b"]);
  });

  it("asks only about lineage keys and their chains", async () => {
    const { source, asked } = fakeSource({ a: "b", c: "d" }, ["b"]);
    const resolve = await storedEventResolver(source, "c1", ["x", "a", "y"]);
    expect(asked).toHaveLength(1);
    expect([...asked[0]].sort()).toEqual(["a", "b"]);
    expect(resolve("a")).toBe("b");
    expect(resolve("x")).toBe("x");
  });

  it("answers as before for live, folded, chained and dangling ids", async () => {
    // a -> c (collapsed chain), d -> gone (dangling), e is live again despite its lineage.
    const { source } = fakeSource({ a: "c", b: "c", d: "gone", e: "c" }, ["c", "e", "plain"]);
    const resolve = await storedEventResolver(source, "c1", ["a", "b", "d", "e", "plain", "unknown"]);
    expect(["a", "b", "d", "e", "plain", "unknown"].map(resolve)).toEqual([
      "c",
      "c",
      "d",
      "e",
      "plain",
      "unknown",
    ]);
  });

  it("is the identity when the case has no lineage", async () => {
    const { source, asked } = fakeSource(undefined, []);
    const resolve = await storedEventResolver(source, "c1", ["a"]);
    expect(resolve("a")).toBe("a");
    expect(asked).toEqual([]);
  });
});

describe("resolveStoredTargets (#2059)", () => {
  it("adds resolvedTargetId only to a folded event target, without a liveness check for the rest", async () => {
    const { source, asked } = fakeSource({ m1e1: "t2e5" }, ["t2e5"]);
    const records = [
      { targetType: "event", targetId: "m1e1" },
      { targetType: "event", targetId: "other" },
      { targetType: "ioc", targetId: "m1e1" },
    ];
    const out = await resolveStoredTargets(source, "c1", records);
    expect(out).toEqual([
      { targetType: "event", targetId: "m1e1", resolvedTargetId: "t2e5" },
      { targetType: "event", targetId: "other" },
      { targetType: "ioc", targetId: "m1e1" },
    ]);
    expect(asked.flat().sort()).toEqual(["m1e1", "t2e5"]);
    expect(eventTargetIds(records)).toEqual(["m1e1", "other"]);
  });
});
