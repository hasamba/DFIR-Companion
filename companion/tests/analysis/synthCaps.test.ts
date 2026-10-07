import { describe, it, expect } from "vitest";
import {
  capDisclosure,
  newestHypothesesFirst,
  rankCompromisedAssets,
  rankVerdictLines,
  tieBreakByValue,
} from "../../src/analysis/synthCaps.js";

describe("capDisclosure", () => {
  it("is empty when nothing was cut", () => {
    expect(capDisclosure(5, 5, "things")).toBe("");
    expect(capDisclosure(3, 2, "things")).toBe("");
  });
  it("names shown and total when rows were cut", () => {
    expect(capDisclosure(15, 20, "open analyst hypotheses")).toBe(
      "(showing 15 of 20 open analyst hypotheses)",
    );
  });
});

describe("newestHypothesesFirst", () => {
  const h = (id: string, createdAt: string, updatedAt = "") => ({ id, createdAt, updatedAt });
  it("orders by updatedAt desc, falls back to createdAt, without mutating", () => {
    const input = [
      h("a", "2026-01-01T00:00:00Z"),
      h("b", "2026-01-02T00:00:00Z", "2026-03-01T00:00:00Z"),
      h("c", "2026-02-01T00:00:00Z"),
    ];
    const copy = [...input];
    expect(newestHypothesesFirst(input).map((x) => x.id)).toEqual(["b", "c", "a"]);
    expect(input).toEqual(copy);
  });
  it("breaks equal timestamps by id", () => {
    const t = "2026-01-01T00:00:00Z";
    expect(newestHypothesesFirst([h("z", t, t), h("m", t, t)]).map((x) => x.id)).toEqual(["m", "z"]);
  });
});

describe("rankCompromisedAssets", () => {
  it("orders by ioc count desc then name", () => {
    const a = (name: string, n: number) => ({ name, iocIds: Array.from({ length: n }, (_, i) => `i${i}`) });
    const out = rankCompromisedAssets([a("B", 1), a("C", 3), a("A", 1)]);
    expect(out.map((x) => x.name)).toEqual(["C", "A", "B"]);
  });
});

describe("rankVerdictLines", () => {
  it("ranks malicious before suspicious, corroborated before lone, then value", () => {
    const rows = [
      { value: "z", verdict: "suspicious", corroborated: true, line: "z" },
      { value: "b", verdict: "malicious", corroborated: false, line: "b" },
      { value: "a", verdict: "malicious", corroborated: true, line: "a" },
      { value: "c", verdict: "malicious", corroborated: false, line: "c" },
    ];
    expect(rankVerdictLines(rows).map((r) => r.value)).toEqual(["a", "b", "c", "z"]);
  });
});

describe("tieBreakByValue", () => {
  it("compares by value", () => {
    expect(tieBreakByValue({ value: "a" }, { value: "b" })).toBeLessThan(0);
  });
});
