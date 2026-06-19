import { describe, it, expect } from "vitest";
import { clampButtonPosition, isDrag, parseButtonPos } from "../src/buttonPosition.js";

const size = { width: 200, height: 40 };
const vp = { width: 1000, height: 800 };

describe("clampButtonPosition", () => {
  it("leaves an in-bounds position unchanged", () => {
    expect(clampButtonPosition({ left: 300, top: 400 }, size, vp)).toEqual({ left: 300, top: 400 });
  });

  it("pulls a position past the right/bottom edge back inside (minus margin)", () => {
    // maxLeft = 1000 - 200 - 8 = 792 ; maxTop = 800 - 40 - 8 = 752
    expect(clampButtonPosition({ left: 5000, top: 5000 }, size, vp)).toEqual({ left: 792, top: 752 });
  });

  it("clamps negative coordinates to the margin", () => {
    expect(clampButtonPosition({ left: -50, top: -10 }, size, vp)).toEqual({ left: 8, top: 8 });
  });

  it("pins to the top-left margin when the button is larger than the viewport", () => {
    expect(clampButtonPosition({ left: 10, top: 10 }, { width: 1200, height: 900 }, vp)).toEqual({ left: 8, top: 8 });
  });

  it("honors a custom margin", () => {
    expect(clampButtonPosition({ left: 5000, top: 0 }, size, vp, 16)).toEqual({ left: 1000 - 200 - 16, top: 16 });
  });
});

describe("isDrag", () => {
  it("is false below the threshold and true at/above it", () => {
    expect(isDrag(1, 1)).toBe(false);          // hypot ≈ 1.41 < 4
    expect(isDrag(3, 0)).toBe(false);
    expect(isDrag(4, 0)).toBe(true);
    expect(isDrag(3, 3)).toBe(true);           // hypot ≈ 4.24 ≥ 4
  });
  it("honors a custom threshold", () => {
    expect(isDrag(5, 0, 10)).toBe(false);
    expect(isDrag(10, 0, 10)).toBe(true);
  });
});

describe("parseButtonPos", () => {
  it("accepts a valid {left, top} of finite numbers", () => {
    expect(parseButtonPos({ left: 10, top: 20 })).toEqual({ left: 10, top: 20 });
  });
  it("rejects malformed / non-finite / missing values", () => {
    expect(parseButtonPos(null)).toBeNull();
    expect(parseButtonPos("nope")).toBeNull();
    expect(parseButtonPos({ left: 10 })).toBeNull();
    expect(parseButtonPos({ left: "x", top: 1 })).toBeNull();
    expect(parseButtonPos({ left: NaN, top: 1 })).toBeNull();
    expect(parseButtonPos({ left: Infinity, top: 1 })).toBeNull();
  });
});
