import { describe, it, expect, afterEach } from "vitest";
import {
  mapFindings,
  PresidioApprovalRequired,
  HttpPresidioClient,
  resolvePresidioMinScore,
  DEFAULT_PRESIDIO_MIN_SCORE,
  type PresidioFinding,
} from "../../src/analysis/presidio.js";

function f(entityType: string, value: string, score = 0.9): PresidioFinding {
  return { entityType, value, score };
}

describe("mapFindings", () => {
  it("maps allow-listed entity types to anonymizer categories", () => {
    const out = mapFindings(
      [
        f("PERSON", "Jane Doe"),
        f("CREDIT_CARD", "4111111111111111"),
        f("PHONE_NUMBER", "+972501234567"),
        f("US_SSN", "078-05-1120"),
        f("EMAIL_ADDRESS", "jane@example.com"),
      ],
      0.6,
    );
    expect(out).toEqual([
      { value: "Jane Doe", category: "PERSON" },
      { value: "4111111111111111", category: "CARD" },
      { value: "+972501234567", category: "PHONE" },
      { value: "078-05-1120", category: "NATID" },
      { value: "jane@example.com", category: "EMAIL" },
    ]);
  });

  it("DROPS DATE_TIME — a DFIR timeline is almost entirely timestamps", () => {
    expect(mapFindings([f("DATE_TIME", "2026-07-26 12:00:00")], 0.6)).toEqual([]);
  });

  it("drops other unlisted types rather than falling back to OTHER", () => {
    const out = mapFindings(
      [f("LOCATION", "Tel Aviv"), f("URL", "http://evil.test"), f("NRP", "Israeli")],
      0.6,
    );
    expect(out).toEqual([]);
  });

  it("drops findings below the score threshold", () => {
    expect(mapFindings([f("PERSON", "Jane Doe", 0.4)], 0.6)).toEqual([]);
  });

  it("drops findings that fired on an anonymization token", () => {
    expect(mapFindings([f("PERSON", "ANON_USER_3"), f("PERSON", "ANON_EXTIP_1")], 0.6)).toEqual([]);
  });

  it("dedupes by value and category, case-insensitively", () => {
    const out = mapFindings([f("PERSON", "Jane Doe"), f("PERSON", "jane doe")], 0.6);
    expect(out).toHaveLength(1);
  });

  it("drops blank values", () => {
    expect(mapFindings([f("PERSON", "   ")], 0.6)).toEqual([]);
  });
});

describe("resolvePresidioMinScore", () => {
  it("defaults to 0.6 when unset", () => {
    expect(resolvePresidioMinScore(undefined)).toBe(DEFAULT_PRESIDIO_MIN_SCORE);
  });

  // The regression this guards: process.env.X ?? "0.6" only defaults on `undefined`. A compose
  // file interpolating an unset variable (DFIR_PRESIDIO_MIN_SCORE=${UNSET}) hands the process an
  // EMPTY string, and Number("") is 0 — finite, so a naive `Number.isFinite` guard alone lets it
  // through as "gate on every finding of any score."
  it("defaults to 0.6 on an empty string, not 0", () => {
    expect(resolvePresidioMinScore("")).toBe(DEFAULT_PRESIDIO_MIN_SCORE);
  });

  it("defaults to 0.6 on a whitespace-only string", () => {
    expect(resolvePresidioMinScore("   ")).toBe(DEFAULT_PRESIDIO_MIN_SCORE);
  });

  it("parses a valid override", () => {
    expect(resolvePresidioMinScore("0.85")).toBe(0.85);
  });

  it("defaults to 0.6 on a non-numeric value", () => {
    expect(resolvePresidioMinScore("not-a-number")).toBe(DEFAULT_PRESIDIO_MIN_SCORE);
  });

  it("clamps a value above 1 down to 1", () => {
    expect(resolvePresidioMinScore("1.5")).toBe(1);
  });

  it("clamps a negative value up to 0", () => {
    expect(resolvePresidioMinScore("-0.2")).toBe(0);
  });
});

describe("PresidioApprovalRequired", () => {
  it("carries the findings and names itself", () => {
    const err = new PresidioApprovalRequired([{ value: "Jane Doe", category: "PERSON" }]);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("PresidioApprovalRequired");
    expect(err.findings).toHaveLength(1);
  });
});

// HttpPresidioClient never opens a real socket in tests — global fetch is stubbed per test and
// restored immediately after, so no test here ever leaves the network touched.
describe("HttpPresidioClient", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function stubFetch(body: unknown, ok = true, status = 200) {
    globalThis.fetch = (async () => ({
      ok,
      status,
      json: async () => body,
    })) as unknown as typeof fetch;
  }

  it("slices the exact substring named by start/end offsets, not an off-by-one neighbor", async () => {
    // "Jane Doe" sits at [0, 8) in this text. Off-by-one on either end would silently truncate
    // the name, and a truncated name would later mask only PART of it — leaving the rest exposed.
    const text = "Jane Doe met Bob.";
    stubFetch([{ entity_type: "PERSON", start: 0, end: 8, score: 0.95 }]);
    const client = new HttpPresidioClient("http://presidio.local");
    const findings = await client.analyze(text);
    expect(findings).toEqual([{ entityType: "PERSON", value: "Jane Doe", score: 0.95 }]);
  });

  it("slices a second, non-zero-offset span correctly", async () => {
    const text = "Jane Doe met Bob Smith.";
    // "Bob Smith" sits at [13, 22).
    stubFetch([{ entity_type: "PERSON", start: 13, end: 22, score: 0.8 }]);
    const client = new HttpPresidioClient("http://presidio.local");
    const findings = await client.analyze(text);
    expect(findings).toEqual([{ entityType: "PERSON", value: "Bob Smith", score: 0.8 }]);
  });

  it("drops entries missing required fields instead of throwing", async () => {
    stubFetch([
      { entity_type: "PERSON", start: 0, end: 4, score: 0.9 }, // valid, text below is "Jane"
      { entity_type: "PERSON", score: 0.9 }, // missing start/end
      { start: 0, end: 4, score: 0.9 }, // missing entity_type
      { entity_type: "PERSON", start: "0", end: 4, score: 0.9 }, // start is a string, not a number
    ]);
    const client = new HttpPresidioClient("http://presidio.local");
    const findings = await client.analyze("Jane Doe");
    expect(findings).toEqual([{ entityType: "PERSON", value: "Jane", score: 0.9 }]);
  });

  it("defaults a non-numeric score to 0 rather than throwing", async () => {
    stubFetch([{ entity_type: "PERSON", start: 0, end: 4, score: "high" }]);
    const client = new HttpPresidioClient("http://presidio.local");
    const findings = await client.analyze("Jane Doe");
    expect(findings).toEqual([{ entityType: "PERSON", value: "Jane", score: 0 }]);
  });

  it("rejects (does not throw synchronously) when the response body is not an array", async () => {
    stubFetch({ error: "not an array" });
    const client = new HttpPresidioClient("http://presidio.local");
    await expect(client.analyze("Jane Doe")).rejects.toThrow(/non-array/);
  });

  it("rejects when the HTTP status is not ok", async () => {
    stubFetch([], false, 500);
    const client = new HttpPresidioClient("http://presidio.local");
    await expect(client.analyze("Jane Doe")).rejects.toThrow(/500/);
  });
});
