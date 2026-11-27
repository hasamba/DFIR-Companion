import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2946: the custom-entity editor reads a typed `*` (any category) or an IP/EXTIP `/` as a pattern,
// refuses an obviously bad one with the reason before Save, and shows each saved pattern's matches.

type Entry = { value: string; category: string; match?: string };
interface Api {
  anonCustomEntry(value: string, category: string): Entry | string;
  setAnonPatternReports(list: unknown): void;
  anonPatternTag(e: Entry): string;
}
const api = () => loadDashboardModule<Api>("dashboard-anon-patterns.js", ["dashboard-escape.js"]);

describe("anonCustomEntry", () => {
  const { anonCustomEntry } = api();

  it("keeps an ordinary value exact", () => {
    expect(anonCustomEntry("dc01", "HOST")).toEqual({ value: "dc01", category: "HOST" });
    expect(anonCustomEntry("C:/data/x", "PATH")).toEqual({ value: "C:/data/x", category: "PATH" });
  });

  it("flags a wildcard or a range as a pattern", () => {
    expect(anonCustomEntry("prod-*", "HOST")).toEqual({
      value: "prod-*",
      category: "HOST",
      match: "pattern",
    });
    expect(anonCustomEntry("10.20.0.0/16", "IP")).toEqual({
      value: "10.20.0.0/16",
      category: "IP",
      match: "pattern",
    });
  });

  it.each([
    ["*", "HOST"],
    ["a*", "HOST"],
    ["pr*od*web", "HOST"],
    ["10.20.*", "IP"],
    ["10.0.0.0/7", "IP"],
    ["10.20.0.0/40", "IP"],
    ["abcdefghij".repeat(110) + "*", "HOST"], // over the 1024-character cap (#3009)
  ])("refuses %s (%s) with a reason", (value, category) => {
    expect(typeof anonCustomEntry(value, category)).toBe("string");
  });
});

describe("anonPatternTag", () => {
  it("is empty for an exact value", () => {
    expect(api().anonPatternTag({ value: "dc01", category: "HOST" })).toBe("");
  });

  it("shows the known-match count and the values, escaped", () => {
    const m = api();
    m.setAnonPatternReports([
      { value: "prod-*", category: "HOST", count: 2, sample: ["prod-web01", "prod-<b>"] },
    ]);
    const html = m.anonPatternTag({ value: "prod-*", category: "HOST", match: "pattern" });
    expect(html).toContain(">pattern<");
    expect(html).toContain("matches 2 known values");
    expect(html).toContain("prod-web01");
    expect(html).toContain("prod-&lt;b&gt;");
    expect(html).not.toContain("<b>");
  });

  it("calls a range a range, and warns about a stored pattern that is not applied", () => {
    const m = api();
    m.setAnonPatternReports([
      { value: "10.0.0.0/7", category: "IP", count: 0, sample: [], invalid: "too wide." },
    ]);
    const html = m.anonPatternTag({ value: "10.0.0.0/7", category: "IP", match: "pattern" });
    expect(html).toContain("range not applied: too wide.");
    expect(html).toContain("only this exact text is hidden");
  });

  it("says counts come after Save for a pattern not saved yet", () => {
    expect(api().anonPatternTag({ value: "*-dev", category: "HOST", match: "pattern" })).toContain(
      "after Save",
    );
  });
});
