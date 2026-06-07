import { describe, it, expect } from "vitest";
import { diffIocs, isEmptyIocsDiff } from "../../src/analysis/iocsDiff.js";
import type { IOC } from "../../src/analysis/stateTypes.js";

function ioc(value: string, type: IOC["type"] = "hash", id = value): IOC {
  return { id, type, value, firstSeen: "2026-01-01T00:00:00Z" };
}

describe("diffIocs", () => {
  it("detects IOCs added by an import (by value, ignoring fresh ids)", () => {
    const before = [ioc("1.2.3.4", "ip", "i001")];
    const after = [ioc("1.2.3.4", "ip", "i001"), ioc("evil.com", "domain", "i002")];
    const d = diffIocs(before, after);
    expect(d.added).toEqual([{ value: "evil.com", type: "domain" }]);
    expect(d.removed).toEqual([]);
  });

  it("treats a re-import of the same IOCs as no change", () => {
    const set = [ioc("abc123", "hash"), ioc("9.9.9.9", "ip")];
    const reimport = [ioc("abc123", "hash", "x1"), ioc("9.9.9.9", "ip", "x2")];
    expect(isEmptyIocsDiff(diffIocs(set, reimport))).toBe(true);
  });

  it("treats the first import on an empty case as all-added", () => {
    const after = [ioc("a", "domain"), ioc("b", "ip")];
    const d = diffIocs([], after);
    expect(d.added).toHaveLength(2);
    expect(d.removed).toHaveLength(0);
  });

  it("matches by exact value (case-sensitive, like mergeDelta dedup)", () => {
    const before = [ioc("Evil.com", "domain")];
    const after = [ioc("Evil.com", "domain"), ioc("evil.com", "domain")];
    // mergeDelta keeps both distinct values, so the lowercase one is genuinely new
    expect(diffIocs(before, after).added).toEqual([{ value: "evil.com", type: "domain" }]);
  });

  it("returns an empty diff for identical IOC sets", () => {
    const set = [ioc("h1"), ioc("h2")];
    expect(isEmptyIocsDiff(diffIocs(set, set))).toBe(true);
  });
});
