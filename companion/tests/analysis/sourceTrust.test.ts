import { describe, it, expect } from "vitest";
import {
  trustForSource,
  trustForSources,
  effectiveTrustMap,
  sanitizeTrustValue,
  sanitizeTrustOverrides,
  DEFAULT_SOURCE_TRUST,
  SOURCE_TRUST_UNKNOWN,
} from "../../src/analysis/sourceTrust.js";

describe("trustForSource (#66)", () => {
  it("resolves exact and messy source strings via substring match", () => {
    expect(trustForSource("Velociraptor")).toBe(0.85);
    expect(trustForSource("velociraptor_processes.csv")).toBe(0.85);           // substring, not the csv=0.6 generic
    expect(trustForSource("corroborated by Velociraptor, THOR")).toBe(0.95);   // THOR is longer-key? both present → longest match
    expect(trustForSource("CrowdStrike Falcon")).toBe(1.0);
  });

  it("prefers the more specific tier (longest key wins)", () => {
    expect(trustForSource("SentinelOne")).toBe(0.95);          // not the sentinel=0.8 SIEM
    expect(trustForSource("Microsoft Sentinel")).toBe(0.8);    // the SIEM
  });

  it("falls back to UNKNOWN for unrecognized / empty / placeholder", () => {
    expect(trustForSource("SomeRandomTool")).toBe(SOURCE_TRUST_UNKNOWN);
    expect(trustForSource("")).toBe(SOURCE_TRUST_UNKNOWN);
    expect(trustForSource("unknown source")).toBe(SOURCE_TRUST_UNKNOWN);
  });

  it("honors an override map", () => {
    const map = effectiveTrustMap({ velociraptor: 0.4 });
    expect(trustForSource("Velociraptor", map)).toBe(0.4);
    expect(trustForSource("CrowdStrike", map)).toBe(1.0);      // untouched default
  });
});

describe("trustForSources (#66 — max across an event's sources)", () => {
  it("returns the highest-trust contributing tool", () => {
    expect(trustForSources(["generic log", "CrowdStrike"])).toBe(1.0);
    expect(trustForSources(["Velociraptor", "THOR"])).toBe(0.95);
  });
  it("falls back to UNKNOWN for a source-less event", () => {
    expect(trustForSources([])).toBe(SOURCE_TRUST_UNKNOWN);
    expect(trustForSources(undefined)).toBe(SOURCE_TRUST_UNKNOWN);
    expect(trustForSources(["unknown source"])).toBe(SOURCE_TRUST_UNKNOWN);
  });
});

describe("override sanitization (#66)", () => {
  it("clamps/validates a single value into [0,1]", () => {
    expect(sanitizeTrustValue(0.5)).toBe(0.5);
    expect(sanitizeTrustValue(1)).toBe(1);
    expect(sanitizeTrustValue(1.5)).toBeNull();
    expect(sanitizeTrustValue(-0.1)).toBeNull();
    expect(sanitizeTrustValue("nope")).toBeNull();
  });
  it("keeps only real keys with in-range values, lowercased", () => {
    expect(sanitizeTrustOverrides({ Velociraptor: 0.4, BadTool: 5, "": 0.3, ok: 0.9 }))
      .toEqual({ velociraptor: 0.4, ok: 0.9 });
  });
  it("returns {} for non-objects", () => {
    expect(sanitizeTrustOverrides(null)).toEqual({});
    expect(sanitizeTrustOverrides("x")).toEqual({});
  });
});

describe("DEFAULT_SOURCE_TRUST sanity", () => {
  it("all default weights are in [0,1]", () => {
    for (const v of Object.values(DEFAULT_SOURCE_TRUST)) {
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
    }
  });
});
