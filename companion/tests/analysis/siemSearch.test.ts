import { describe, expect, it } from "vitest";
import {
  checkSearchWindow,
  defaultSearchRange,
  inferredEventName,
  readSiemLimits,
  siemConfigured,
  siemQueryFingerprint,
  siemSearchText,
  SIEM_DEFAULTS,
} from "../../src/analysis/siemSearch.js";

// #2666: the pure half of running a CrowdStrike Next-Gen SIEM search — limits, the time window, the
// default range, the outcome sentence and the event-name inference for table() output.

const NOW = Date.parse("2026-11-17T12:00:00.000Z");
const DAY = 86_400_000;

describe("readSiemLimits / siemConfigured", () => {
  it("defaults to 7 days, 10,000 rows, 5 minutes and search-all", () => {
    expect(readSiemLimits({})).toEqual(SIEM_DEFAULTS);
    expect(SIEM_DEFAULTS).toEqual({
      maxWindowDays: 7,
      maxRows: 10_000,
      timeoutMs: 300_000,
      repository: "search-all",
    });
  });

  it("reads valid values and ignores junk", () => {
    const env = {
      DFIR_CROWDSTRIKE_SIEM_MAX_WINDOW_DAYS: "14",
      DFIR_CROWDSTRIKE_SIEM_MAX_ROWS: "abc",
      DFIR_CROWDSTRIKE_SIEM_TIMEOUT_MS: "-5",
      DFIR_CROWDSTRIKE_SIEM_REPOSITORY: " investigate_view ",
    };
    expect(readSiemLimits(env)).toEqual({
      maxWindowDays: 14,
      maxRows: 10_000,
      timeoutMs: 300_000,
      repository: "investigate_view",
    });
  });

  it("is configured only with both the client id and the secret", () => {
    expect(siemConfigured({})).toBe(false);
    expect(siemConfigured({ DFIR_CROWDSTRIKE_SIEM_CLIENT_ID: "a" })).toBe(false);
    expect(
      siemConfigured({ DFIR_CROWDSTRIKE_SIEM_CLIENT_ID: "a", DFIR_CROWDSTRIKE_SIEM_CLIENT_SECRET: " " }),
    ).toBe(false);
    expect(
      siemConfigured({ DFIR_CROWDSTRIKE_SIEM_CLIENT_ID: "a", DFIR_CROWDSTRIKE_SIEM_CLIENT_SECRET: "b" }),
    ).toBe(true);
    // The threat-intel client never switches the search on.
    expect(siemConfigured({ DFIR_CROWDSTRIKE_CLIENT_ID: "a", DFIR_CROWDSTRIKE_CLIENT_SECRET: "b" })).toBe(
      false,
    );
  });
});

describe("checkSearchWindow", () => {
  const iso = (ms: number) => new Date(ms).toISOString();

  it("accepts a window inside the limit", () => {
    const r = checkSearchWindow(iso(NOW - 3 * DAY), iso(NOW), 7, NOW);
    expect(r).toEqual({ ok: true, startMs: NOW - 3 * DAY, endMs: NOW });
  });

  it("refuses a wider window and names the limit and the setting — never clips", () => {
    const r = checkSearchWindow(iso(NOW - 12 * DAY), iso(NOW), 7, NOW);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error).toContain("12 days");
      expect(r.error).toContain("7 days");
      expect(r.error).toContain("DFIR_CROWDSTRIKE_SIEM_MAX_WINDOW_DAYS");
    }
  });

  it("refuses unreadable, reversed and future windows", () => {
    expect(checkSearchWindow("nope", iso(NOW), 7, NOW).ok).toBe(false);
    expect(checkSearchWindow(iso(NOW), iso(NOW - DAY), 7, NOW).ok).toBe(false);
    expect(checkSearchWindow(iso(NOW), iso(NOW + DAY), 7, NOW).ok).toBe(false);
  });
});

describe("defaultSearchRange", () => {
  const none = { start: null, end: null };

  it("uses the case scope window when it fits", () => {
    const scope = { start: "2026-11-01T00:00:00.000Z", end: "2026-11-03T00:00:00.000Z" };
    expect(defaultSearchRange(scope, undefined, 7, NOW)).toEqual(scope);
  });

  it("keeps the END of a window wider than the limit and moves the start forward", () => {
    const scope = { start: "2026-10-01T00:00:00.000Z", end: "2026-11-03T00:00:00.000Z" };
    expect(defaultSearchRange(scope, undefined, 7, NOW)).toEqual({
      start: "2026-10-27T00:00:00.000Z",
      end: "2026-11-03T00:00:00.000Z",
    });
  });

  it("falls back to the High/Critical span padded by a day, then to the last N days", () => {
    const span = { start: "2026-11-05T10:00:00.000Z", end: "2026-11-06T10:00:00.000Z" };
    expect(defaultSearchRange(none, span, 7, NOW)).toEqual({
      start: "2026-11-04T10:00:00.000Z",
      end: "2026-11-07T10:00:00.000Z",
    });
    expect(defaultSearchRange(none, undefined, 7, NOW)).toEqual({
      start: new Date(NOW - 7 * DAY).toISOString(),
      end: new Date(NOW).toISOString(),
    });
  });

  it("never ends in the future", () => {
    const span = { start: "2026-11-16T10:00:00.000Z", end: "2026-11-17T11:00:00.000Z" };
    expect(defaultSearchRange(none, span, 7, NOW).end).toBe(new Date(NOW).toISOString());
  });
});

describe("siemSearchText", () => {
  const base = {
    title: "Encoded PowerShell",
    rows: 0,
    events: 0,
    added: 0,
    truncated: false,
    timedOut: false,
  };

  it("found nothing", () => {
    expect(siemSearchText(base)).toBe("CrowdStrike NG-SIEM search Encoded PowerShell found nothing");
  });

  it("found N rows and added M new events", () => {
    expect(siemSearchText({ ...base, rows: 12, events: 12, added: 3 })).toBe(
      "CrowdStrike NG-SIEM search Encoded PowerShell finished. It found 12 rows and added 3 new events",
    );
  });

  it("first N of M when a real total is known, else the row cap cut the rest", () => {
    expect(
      siemSearchText({ ...base, rows: 100, events: 100, added: 1, truncated: true, total: 400 }),
    ).toContain("imported the first 100 of 400 rows");
    expect(siemSearchText({ ...base, rows: 100, events: 100, added: 1, truncated: true })).toContain(
      "imported the first 100 rows (the row cap cut the rest)",
    );
  });

  it("timed out keeps the rows already read", () => {
    expect(
      siemSearchText({
        ...base,
        rows: 40,
        events: 40,
        added: 2,
        truncated: true,
        timedOut: true,
        timeoutMs: 300_000,
      }),
    ).toBe(
      "CrowdStrike NG-SIEM search Encoded PowerShell timed out after 5 minutes. It imported the 40 rows already read and added 2 new events",
    );
  });

  it("names rows that were not Falcon events and a stopped search", () => {
    const t = siemSearchText({
      ...base,
      rows: 10,
      events: 4,
      added: 1,
      error: "CrowdStrike rate-limited the search.",
      truncated: true,
    });
    expect(t).toContain("6 rows were not Falcon events");
    expect(t).toContain("stopped early: CrowdStrike rate-limited the search.");
  });

  it("did not complete", () => {
    expect(siemSearchText({ ...base, failed: "Falcon refused the query" })).toBe(
      "CrowdStrike NG-SIEM search Encoded PowerShell did not complete: Falcon refused the query",
    );
  });
});

describe("inferredEventName (table() output carries no event name)", () => {
  it("infers the one event type of a filter + table query", () => {
    const q = `#event_simpleName=ProcessRollup2\n| ImageFileName=/\\\\powershell\\.exe$/i\n| table([@timestamp, ComputerName, CommandLine])`;
    expect(inferredEventName(q)).toBe("ProcessRollup2");
    expect(inferredEventName(`#event_simpleName="DnsRequest" | DomainName="x" | tail(100)`)).toBe(
      "DnsRequest",
    );
  });

  it("refuses aggregates, several types and comment-only mentions", () => {
    expect(inferredEventName(`#event_simpleName=ProcessRollup2 | groupBy([ComputerName, CommandLine])`)).toBe(
      "",
    );
    expect(inferredEventName(`#event_simpleName=ProcessRollup2 | count()`)).toBe("");
    expect(
      inferredEventName(`#event_simpleName=ProcessRollup2 OR #event_simpleName=DnsRequest | table([a])`),
    ).toBe("");
    expect(inferredEventName(`// #event_simpleName=ProcessRollup2\nComputerName=x | table([a])`)).toBe("");
    expect(inferredEventName(`in(field="#event_simpleName", values=["A"]) | table([a])`)).toBe("");
    expect(inferredEventName(`#event_simpleName=/Process.*/ | table([a])`)).toBe("");
  });
});

describe("siemQueryFingerprint", () => {
  it("ignores whitespace but not the repository or the range", () => {
    const a = siemQueryFingerprint(
      "x  |  y",
      "search-all",
      "2026-11-01T00:00:00.000Z",
      "2026-11-02T00:00:00.000Z",
    );
    const b = siemQueryFingerprint(
      "x | y",
      "search-all",
      "2026-11-01T00:00:00.000Z",
      "2026-11-02T00:00:00.000Z",
    );
    const c = siemQueryFingerprint("x | y", "other", "2026-11-01T00:00:00.000Z", "2026-11-02T00:00:00.000Z");
    const d = siemQueryFingerprint(
      "x | y",
      "search-all",
      "2026-11-02T00:00:00.000Z",
      "2026-11-03T00:00:00.000Z",
    );
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).not.toBe(d);
  });
});
