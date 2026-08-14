import { describe, it, expect, afterEach } from "vitest";
import {
  mapFindings,
  PresidioApprovalRequired,
  HttpPresidioClient,
  PresidioTimeoutError,
  resolvePresidioMinScore,
  resolvePresidioTimeoutMs,
  DEFAULT_PRESIDIO_MIN_SCORE,
  DEFAULT_PRESIDIO_TIMEOUT_MS,
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

describe("resolvePresidioTimeoutMs", () => {
  it("defaults when unset", () => {
    expect(resolvePresidioTimeoutMs(undefined)).toBe(DEFAULT_PRESIDIO_TIMEOUT_MS);
  });

  // Same empty-string trap as the min-score resolver, but the failure here is total rather than
  // merely strict: Number("") is 0, and a 0ms budget aborts every request before it can start,
  // which in a fail-closed layer means no AI call in the product ever succeeds again.
  it("defaults on an empty string, not 0", () => {
    expect(resolvePresidioTimeoutMs("")).toBe(DEFAULT_PRESIDIO_TIMEOUT_MS);
  });

  it("defaults on a whitespace-only string", () => {
    expect(resolvePresidioTimeoutMs("   ")).toBe(DEFAULT_PRESIDIO_TIMEOUT_MS);
  });

  it("defaults on zero and on a negative value", () => {
    expect(resolvePresidioTimeoutMs("0")).toBe(DEFAULT_PRESIDIO_TIMEOUT_MS);
    expect(resolvePresidioTimeoutMs("-5000")).toBe(DEFAULT_PRESIDIO_TIMEOUT_MS);
  });

  it("defaults on a non-numeric value", () => {
    expect(resolvePresidioTimeoutMs("soon")).toBe(DEFAULT_PRESIDIO_TIMEOUT_MS);
  });

  it("parses a valid override", () => {
    expect(resolvePresidioTimeoutMs("90000")).toBe(90_000);
    expect(resolvePresidioTimeoutMs("600000")).toBe(600_000);
  });

  // setTimeout stores its delay in a 32-bit signed int. Past that ceiling Node does not wait
  // longer — it warns and uses 1ms — so an unclamped huge value makes every scan fail instantly,
  // the exact opposite of what someone raising the budget is asking for.
  it("clamps above Node's timer ceiling instead of silently becoming 1ms", () => {
    const MAX = 2_147_483_647;
    expect(resolvePresidioTimeoutMs(String(MAX))).toBe(MAX);
    expect(resolvePresidioTimeoutMs(String(MAX + 1))).toBe(MAX);
    expect(resolvePresidioTimeoutMs("999999999999")).toBe(MAX);
    expect(resolvePresidioTimeoutMs("1e30")).toBe(MAX);
  });

  // The measured floor this default has to clear is a CONTENDED chunk, not an idle one: on the
  // reference single-worker container a 50k chunk took ~1.7s alone and ~9.6s with five scans in
  // flight. The old 10s sat right on that edge, which is the bug this whole change fixes.
  it("defaults well clear of a contended chunk, not merely an idle one", () => {
    expect(DEFAULT_PRESIDIO_TIMEOUT_MS).toBeGreaterThanOrEqual(30_000);
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

  // What made the original outage expensive to diagnose: the client aborted with a bare
  // abort(), so a request that merely ran out of budget surfaced as DOMException "This operation
  // was aborted", which the pipeline then wrapped in "not reachable". The analyst was told to
  // start a container that had been up and healthy for an hour. A timeout must say so, name the
  // budget it blew, and name the setting that widens it.
  it("reports a timeout AS a timeout, naming the budget and the knob", async () => {
    // Never resolves on its own — only the client's own timer can end this call.
    // Rejects with signal.reason exactly as undici does, which is what carries the client's own
    // message out; `as Error` because AbortSignal.reason is typed `any`.
    globalThis.fetch = ((_url: string, init: { signal: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason as Error));
      })) as unknown as typeof fetch;
    const client = new HttpPresidioClient("http://presidio.local", 20);
    await expect(client.analyze("Jane Doe")).rejects.toBeInstanceOf(PresidioTimeoutError);
    await expect(client.analyze("Jane Doe")).rejects.toThrow(/no response within 20ms/);
    // Naming the size is what tells the analyst whether to raise the budget or shrink the input.
    await expect(client.analyze("Jane Doe")).rejects.toThrow(/8 characters/);
  });

  // The same timer fires whether the analyzer is busy or the connection is hanging — a dropped SYN,
  // a black-holing firewall, a wrong port. Claiming the host is up on that evidence would rebuild
  // the misdirection this error exists to prevent, just pointing the other way.
  it("does not assert the analyzer is reachable, having received no response", async () => {
    globalThis.fetch = ((_url: string, init: { signal: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason as Error));
      })) as unknown as typeof fetch;
    const err = await new HttpPresidioClient("http://presidio.local", 10)
      .analyze("Jane Doe")
      .then(() => null)
      .catch((e: Error) => e);
    expect(err, "the client must reject, not resolve, when nothing answers").toBeInstanceOf(Error);
    expect(err?.message).not.toMatch(/is running/);
    expect(err?.message).not.toMatch(/reachable/);
  });

  it("clears its timer on success, so a slow later call is not aborted by an earlier one", async () => {
    // A leaked timer from call 1 would fire mid-call 2 and abort a request that was fine.
    stubFetch([{ entity_type: "PERSON", start: 0, end: 4, score: 0.9 }]);
    const client = new HttpPresidioClient("http://presidio.local", 30);
    await client.analyze("Jane Doe");
    await new Promise((r) => setTimeout(r, 60));
    await expect(client.analyze("Jane Doe")).resolves.toHaveLength(1);
  });

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
