import { describe, it, expect, beforeEach } from "vitest";
import { countryCentroid, _resetCentroidCache } from "../../src/analysis/countryCentroids.js";

// The data file companion/data/country-centroids.json is committed so these tests run offline.

beforeEach(() => {
  // Ensure each test gets a fresh load (avoids cross-test cache contamination).
  _resetCentroidCache();
});

describe("countryCentroid (#133)", () => {
  it('returns Germany centroid for uppercase alpha-2 "DE"', () => {
    const c = countryCentroid("DE");
    expect(c).toBeDefined();
    expect(c!.name).toBe("Germany");
    expect(c!.lat).toBeCloseTo(51.165691, 2);
    expect(c!.lon).toBeCloseTo(10.451526, 2);
  });

  it('returns Germany centroid for lowercase alpha-2 "de"', () => {
    const c = countryCentroid("de");
    expect(c).toBeDefined();
    expect(c!.name).toBe("Germany");
    expect(c!.lat).toBeCloseTo(51.17, 1);
    expect(c!.lon).toBeCloseTo(10.45, 1);
  });

  it('returns Germany centroid for full name "Germany"', () => {
    const c = countryCentroid("Germany");
    expect(c).toBeDefined();
    expect(c!.name).toBe("Germany");
    expect(c!.lat).toBeCloseTo(51.165691, 3);
    expect(c!.lon).toBeCloseTo(10.451526, 3);
  });

  it('returns Israel centroid for "IL"', () => {
    const c = countryCentroid("IL");
    expect(c).toBeDefined();
    expect(c!.name).toBe("Israel");
    expect(c!.lat).toBeCloseTo(31.046051, 2);
    expect(c!.lon).toBeCloseTo(34.851612, 2);
  });

  it('returns Israel centroid for full name "Israel"', () => {
    const c = countryCentroid("Israel");
    expect(c).toBeDefined();
    expect(c!.name).toBe("Israel");
  });

  it('returns Israel centroid for lowercase "israel"', () => {
    const c = countryCentroid("israel");
    expect(c).toBeDefined();
    expect(c!.name).toBe("Israel");
  });

  it('returns United States centroid for "US"', () => {
    const c = countryCentroid("US");
    expect(c).toBeDefined();
    expect(c!.name).toBe("United States");
    expect(c!.lat).toBeCloseTo(37.09024, 2);
    expect(c!.lon).toBeCloseTo(-95.712891, 2);
  });

  it('returns undefined for unknown code "ZZ"', () => {
    expect(countryCentroid("ZZ")).toBeUndefined();
  });

  it('returns undefined for empty string ""', () => {
    expect(countryCentroid("")).toBeUndefined();
  });

  it("returns undefined for whitespace-only input", () => {
    expect(countryCentroid("   ")).toBeUndefined();
  });

  it("is case-insensitive for full names", () => {
    const upper = countryCentroid("GERMANY");
    const lower = countryCentroid("germany");
    const mixed = countryCentroid("Germany");
    expect(upper).toBeDefined();
    expect(lower).toBeDefined();
    expect(mixed).toBeDefined();
    expect(upper!.lat).toBeCloseTo(mixed!.lat, 5);
    expect(lower!.lat).toBeCloseTo(mixed!.lat, 5);
  });
});
