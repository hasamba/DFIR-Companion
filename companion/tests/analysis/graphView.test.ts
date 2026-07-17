import { describe, it, expect } from "vitest";
// The shared browser module lives outside companion/. It guards its window assignment,
// so importing its pure named exports in node works.
import { layoutOptions, dimOpacity, filterMatch } from "../../../public/js/graph-view.js";

describe("layoutOptions", () => {
  it("maps 'spread' to the cose layout", () => {
    expect(layoutOptions({ layout: "spread" }).name).toBe("cose");
  });
  it("passes other layout names through unchanged", () => {
    expect(layoutOptions({ layout: "dagre" }).name).toBe("dagre");
    expect(layoutOptions({ layout: "circle" }).name).toBe("circle");
  });
  it("always disables animation and fits with padding 30", () => {
    const o = layoutOptions({ layout: "circle" });
    expect(o.animate).toBe(false);
    expect(o.fit).toBe(true);
    expect(o.padding).toBe(30);
  });
  it("adds concentric + levelWidth callbacks for the concentric layout", () => {
    const o = layoutOptions({ layout: "concentric" });
    expect(typeof o.concentric).toBe("function");
    expect(typeof o.levelWidth).toBe("function");
    expect(o.levelWidth()).toBe(1);
  });
  it("marks breadthfirst as directed", () => {
    expect(layoutOptions({ layout: "breadthfirst" }).directed).toBe(true);
  });
});

describe("dimOpacity", () => {
  it("returns full opacity at 0", () => { expect(dimOpacity(0)).toBe(1); });
  it("returns ~0.1 at 90", () => { expect(dimOpacity(90)).toBeCloseTo(0.1, 5); });
  it("clamps to a 0.05 floor at 100", () => { expect(dimOpacity(100)).toBe(0.05); });
});

describe("filterMatch", () => {
  it("matches node name case-insensitively (query already lowercased)", () => {
    expect(filterMatch("WIN-DC01", undefined, "dc01")).toBe(true);
  });
  it("falls back to the edge label when there is no name", () => {
    expect(filterMatch(undefined, "RemoteInteractive (12)", "remote")).toBe(true);
  });
  it("returns false when neither field matches", () => {
    expect(filterMatch("host-a", "type 3", "zzz")).toBe(false);
  });
  it("treats missing name and label as an empty string (no throw)", () => {
    expect(filterMatch(undefined, undefined, "x")).toBe(false);
  });
});
