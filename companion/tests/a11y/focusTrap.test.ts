import { describe, expect, it } from "vitest";
import { nextFocusIndex } from "../../../public/js/a11y/focus-trap.js";

describe("nextFocusIndex", () => {
  it("advances forward", () => {
    expect(nextFocusIndex(3, 0, false)).toBe(1);
    expect(nextFocusIndex(3, 1, false)).toBe(2);
  });

  it("wraps forward past the last element", () => {
    expect(nextFocusIndex(3, 2, false)).toBe(0);
  });

  it("wraps backward past the first element", () => {
    expect(nextFocusIndex(3, 0, true)).toBe(2);
  });

  it("treats an unknown current index as before the start", () => {
    expect(nextFocusIndex(3, -1, false)).toBe(0);
    expect(nextFocusIndex(3, -1, true)).toBe(2);
  });

  it("returns -1 when there is nothing focusable", () => {
    expect(nextFocusIndex(0, -1, false)).toBe(-1);
    expect(nextFocusIndex(0, 0, true)).toBe(-1);
  });

  it("stays put in a single-element ring", () => {
    // The only focusable control in a dialog must not lose focus to the page behind it.
    expect(nextFocusIndex(1, 0, false)).toBe(0);
    expect(nextFocusIndex(1, 0, true)).toBe(0);
  });
});
