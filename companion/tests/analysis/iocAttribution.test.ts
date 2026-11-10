// #2543 part 1b: the analyst IOC label — vocabulary, lookup by value (and merged aliases), the
// report projection, and the per-case side store.
import { describe, expect, it } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  attributionFor,
  cleanAttributionValue,
  isIocAttributionLabel,
  sanitizeAttributionMap,
  withIocAttribution,
} from "../../src/analysis/iocAttribution.js";
import { IOC_ATTRIBUTION_FILE, IocAttributionStore } from "../../src/analysis/iocAttributionStore.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import type { IOC } from "../../src/analysis/stateTypes.js";

const ioc = (value: string, extra: Partial<IOC> = {}): IOC => ({
  id: "i001",
  type: "ip",
  value,
  firstSeen: "2026-11-10T00:00:00Z",
  ...extra,
});
const entry = (value: string, label: string) => ({ value, label, setAt: "t", setBy: "a" });

describe("iocAttribution (#2543)", () => {
  it("accepts exactly attacker / ours / responder / unknown", () => {
    for (const l of ["attacker", "ours", "responder", "unknown"]) expect(isIocAttributionLabel(l)).toBe(true);
    for (const l of ["victim", "role", "", null, 1]) expect(isIocAttributionLabel(l)).toBe(false);
  });

  it("rejects a blank, multi-line or oversized value", () => {
    expect(cleanAttributionValue("  203.0.113.10 ")).toBe("203.0.113.10");
    expect(cleanAttributionValue("")).toBeNull();
    expect(cleanAttributionValue("a\nb")).toBeNull();
    expect(cleanAttributionValue("x".repeat(2049))).toBeNull();
    expect(cleanAttributionValue(42)).toBeNull();
  });

  it("looks a label up by value case-insensitively, then by a merged alias", () => {
    const map = sanitizeAttributionMap({ "evil.example": entry("EVIL.example", "attacker") });
    expect(attributionFor(ioc("evil.EXAMPLE"), map)).toBe("attacker");
    expect(attributionFor(ioc("www.evil.example", { aliasValues: ["evil.example"] }), map)).toBe("attacker");
    expect(attributionFor(ioc("other.example"), map)).toBeUndefined();
  });

  it("drops malformed entries from a loaded file", () => {
    const map = sanitizeAttributionMap({
      a: entry("a", "bogus"),
      b: { label: "ours" },
      c: entry("c", "ours"),
    });
    expect(Object.keys(map)).toEqual(["c"]);
  });

  it("the report projection stamps new objects and leaves the input untouched", () => {
    const input = [ioc("203.0.113.10")];
    const out = withIocAttribution(input, sanitizeAttributionMap({ x: entry("203.0.113.10", "ours") }));
    expect(out[0].attribution).toBe("ours");
    expect(input[0].attribution).toBeUndefined();
  });
});

describe("IocAttributionStore (#2543)", () => {
  it("sets, changes and clears a label in state/ioc-attribution.json, reporting old → new", async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-iocattr-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const store = new IocAttributionStore(cases);
    expect(await store.load("c1")).toEqual({});
    const a = await store.set("c1", "203.0.113.10", "ours", "alice");
    expect(a.change).toEqual({ value: "203.0.113.10", after: "ours" });
    const b = await store.set("c1", "203.0.113.10", "responder", "bob");
    expect(b.change).toEqual({ value: "203.0.113.10", before: "ours", after: "responder" });
    expect((await store.load("c1"))["203.0.113.10"]).toMatchObject({ label: "responder", setBy: "bob" });
    const raw = JSON.parse(await readFile(join(cases.stateDir("c1"), IOC_ATTRIBUTION_FILE), "utf8"));
    expect(Object.keys(raw)).toEqual(["203.0.113.10"]);
    const c = await store.set("c1", "203.0.113.10", null, "bob");
    expect(c.change).toEqual({ value: "203.0.113.10", before: "responder" });
    expect(await store.load("c1")).toEqual({});
  });

  it("two concurrent sets on different values both persist", async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-iocattr-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const store = new IocAttributionStore(cases);
    await Promise.all([store.set("c1", "a", "ours", "x"), store.set("c1", "b", "attacker", "y")]);
    expect(Object.keys(await store.load("c1")).sort()).toEqual(["a", "b"]);
  });
});
