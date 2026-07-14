import { describe, it, expect, afterEach } from "vitest";
import {
  detectTimestomp,
  timestompThresholdMs,
  DEFAULT_TIMESTOMP_THRESHOLD_MS,
} from "../../src/analysis/timestompDetect.js";

describe("detectTimestomp — backdating ($SI earlier than $FN)", () => {
  it("flags a file whose $SI creation predates $FN creation beyond the threshold", () => {
    // Classic drop: malware backdated to look like an old system file; $FN keeps the real time.
    const v = detectTimestomp("2009-07-14T01:14:24.1234567Z", "2026-06-02T09:15:23.4821330Z");
    expect(v).not.toBeNull();
    expect(v?.mitre).toEqual(["T1070.006"]);
    expect(v?.severity).toBe("Medium");
    expect(v?.signals).toContain("backdated");
    expect(v?.deltaMs).toBeGreaterThan(0);
    expect(v?.note).toMatch(/timestomping/i);
  });

  it("does NOT flag when $SI and $FN creation are within the threshold", () => {
    // Normal file: $SI ≈ $FN (both set at creation), a few seconds apart.
    expect(detectTimestomp("2026-06-02T09:15:20.100Z", "2026-06-02T09:15:23.400Z")).toBeNull();
  });

  it("does NOT flag the reverse direction ($SI LATER than $FN) — only backdating counts", () => {
    // $SI later than $FN is normal (e.g. a file modified long after creation had its $SI touched).
    expect(detectTimestomp("2026-06-02T10:00:00.500Z", "2020-01-01T00:00:00.700Z")).toBeNull();
  });
});

describe("detectTimestomp — sub-second truncation fingerprint", () => {
  it("flags a whole-second $SI against a sub-second $FN even within the time threshold", () => {
    // Tool wrote a rounded $SI (zeroed sub-second) close in time; $FN retains 100ns precision.
    const v = detectTimestomp("2026-06-02T09:15:23.0000000Z", "2026-06-02T09:15:23.4821330Z");
    expect(v).not.toBeNull();
    expect(v?.signals).toContain("subsecond-zeroed");
  });

  it("flags $SI with no fractional field at all against a sub-second $FN", () => {
    const v = detectTimestomp("2026-06-02T09:15:23Z", "2026-06-02T09:15:23.4821330Z");
    expect(v?.signals).toContain("subsecond-zeroed");
  });

  it("does NOT fire the sub-second signal when a COPIED file preserves full-precision $SI", () => {
    // Copy from older source: $SI old but full precision → no truncation signal (still may backdate).
    const v = detectTimestomp("2019-03-01T12:00:00.9876543Z", "2026-06-02T09:15:23.4821330Z");
    expect(v?.signals).not.toContain("subsecond-zeroed");
    expect(v?.signals).toContain("backdated"); // the delta still trips backdating
  });

  it("does NOT fire when both $SI and $FN are whole seconds (source truncated precision)", () => {
    // Neither carries sub-seconds → can't distinguish, and small delta → no verdict at all.
    expect(detectTimestomp("2026-06-02T09:15:23Z", "2026-06-02T09:15:25Z")).toBeNull();
  });
});

describe("detectTimestomp — input tolerance & guards", () => {
  it("parses EZ-tools naive 'yyyy-MM-dd HH:mm:ss.fffffff' (space, no zone)", () => {
    const v = detectTimestomp("2010-01-01 00:00:00.0000000", "2026-06-02 09:15:23.4821330");
    expect(v).not.toBeNull();
    expect(v?.signals).toEqual(expect.arrayContaining(["backdated", "subsecond-zeroed"]));
  });

  it("returns null when either timestamp is missing", () => {
    expect(detectTimestomp("", "2026-06-02T09:15:23.4Z")).toBeNull();
    expect(detectTimestomp("2026-06-02T09:15:23.4Z", null)).toBeNull();
    expect(detectTimestomp(undefined, undefined)).toBeNull();
  });

  it("ignores FILETIME-0 / .NET min-date sentinels", () => {
    expect(detectTimestomp("0001-01-01T00:00:00.0000000", "2026-06-02T09:15:23.4Z")).toBeNull();
    expect(detectTimestomp("1601-01-01T00:00:00Z", "2026-06-02T09:15:23.4Z")).toBeNull();
  });

  it("returns null for unparseable input", () => {
    expect(detectTimestomp("not-a-date", "also-bad")).toBeNull();
  });
});

describe("timestompThresholdMs — env override", () => {
  afterEach(() => {
    delete process.env.DFIR_TIMESTOMP_THRESHOLD_MINUTES;
  });

  it("defaults to 10 minutes", () => {
    expect(timestompThresholdMs()).toBe(DEFAULT_TIMESTOMP_THRESHOLD_MS);
    expect(DEFAULT_TIMESTOMP_THRESHOLD_MS).toBe(10 * 60 * 1000);
  });

  it("honours a positive DFIR_TIMESTOMP_THRESHOLD_MINUTES override", () => {
    process.env.DFIR_TIMESTOMP_THRESHOLD_MINUTES = "1";
    expect(timestompThresholdMs()).toBe(60 * 1000);
    // A 5-minute delta now trips backdating (default 10 min would not).
    const v = detectTimestomp("2026-06-02T09:10:00.100Z", "2026-06-02T09:15:23.400Z", timestompThresholdMs());
    expect(v?.signals).toContain("backdated");
  });

  it("ignores a non-positive / invalid override", () => {
    process.env.DFIR_TIMESTOMP_THRESHOLD_MINUTES = "-3";
    expect(timestompThresholdMs()).toBe(DEFAULT_TIMESTOMP_THRESHOLD_MS);
    process.env.DFIR_TIMESTOMP_THRESHOLD_MINUTES = "abc";
    expect(timestompThresholdMs()).toBe(DEFAULT_TIMESTOMP_THRESHOLD_MS);
  });
});
