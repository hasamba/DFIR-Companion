import { describe, expect, it } from "vitest";
import { describeLookup, parseLookup } from "../../../src/analysis/ai/watson/lookupSchema.js";

describe("lookupSchema super-timeline search", () => {
  it("accepts a super-timeline search by text, hash, host or window", () => {
    expect(parseLookup({ source: "supertimeline", text: "mimikatz" })).toEqual({
      ok: true,
      query: { source: "supertimeline", text: "mimikatz" },
    });
    expect(parseLookup({ source: "supertimeline", hash: "A".repeat(64) })?.ok).toBe(true);
    expect(parseLookup({ source: "supertimeline", host: "ws-01" })?.ok).toBe(true);
    expect(
      parseLookup({ source: "supertimeline", from: "2026-01-01T00:00:00Z", to: "2026-01-02T00:00:00Z" })?.ok,
    ).toBe(true);
  });
  it("refuses a super-timeline search with nothing to narrow it", () => {
    expect(parseLookup({ source: "supertimeline" })).toEqual({
      ok: false,
      why: expect.stringMatching(/needs text, a hash, a host or a time window/),
    });
  });
  it("refuses ids, short text, a bad hash and a window over 7 days for the super-timeline", () => {
    expect(parseLookup({ source: "supertimeline", eventIds: ["e1"] })?.ok).toBe(false);
    expect(parseLookup({ source: "supertimeline", text: "ab" })?.ok).toBe(false);
    expect(parseLookup({ source: "supertimeline", hash: "xyz" })?.ok).toBe(false);
    expect(
      parseLookup({ source: "supertimeline", from: "2026-01-01T00:00:00Z", to: "2026-01-09T00:00:00Z" })?.ok,
    ).toBe(false);
  });
  it("refuses a hash on a forensic lookup, and keeps forensic lookups unchanged", () => {
    expect(parseLookup({ hash: "a".repeat(32) })?.ok).toBe(false);
    expect(parseLookup({ eventIds: ["e1"] })).toEqual({ ok: true, query: { eventIds: ["e1"] } });
    expect(parseLookup({ source: "forensic", eventIds: ["e1"] })).toEqual({
      ok: true,
      query: { eventIds: ["e1"] },
    });
    expect(parseLookup({ source: "forensic" })).toEqual({
      ok: false,
      why: expect.stringMatching(/named no/),
    });
  });
  it("describes a super-timeline search in plain words", () => {
    expect(describeLookup({ source: "supertimeline", text: "rclone", host: "ws-01" })).toBe(
      'super-timeline rows on host ws-01; containing "rclone"',
    );
    expect(describeLookup({ source: "supertimeline", hash: "a".repeat(32) })).toBe(
      `super-timeline rows with hash ${"a".repeat(32)}`,
    );
  });
});
