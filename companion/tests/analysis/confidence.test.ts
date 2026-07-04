import { describe, it, expect } from "vitest";
import { confidenceLabel } from "../../src/analysis/confidence.js";

describe("confidenceLabel", () => {
  it("returns undefined for an unset confidence", () => {
    expect(confidenceLabel(undefined)).toBeUndefined();
  });

  it("buckets >=80 as high", () => {
    expect(confidenceLabel(80)).toBe("high");
    expect(confidenceLabel(100)).toBe("high");
  });

  it("buckets >=50 and <80 as medium", () => {
    expect(confidenceLabel(50)).toBe("medium");
    expect(confidenceLabel(79)).toBe("medium");
  });

  it("buckets <50 as low", () => {
    expect(confidenceLabel(0)).toBe("low");
    expect(confidenceLabel(49)).toBe("low");
  });
});
