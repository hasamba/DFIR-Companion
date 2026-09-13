// A threat-intel assertion says WHEN it applies: the provider's own dated facts, each of its kind,
// against the case time — never "was malicious then" (#933 item 19).
import { describe, it, expect } from "vitest";
import { caseTime, intelTemporal, intelTimeTag } from "../../src/analysis/intelTemporal.js";
import type { IocEnrichment, IOC } from "../../src/analysis/stateTypes.js";
import type { IocProvenanceChain } from "../../src/analysis/iocProvenanceChain.js";

const NOW = "2026-05-01T12:00:00.000Z";
const hit = (over: Partial<IocEnrichment> = {}): IocEnrichment => ({
  source: "VirusTotal",
  verdict: "malicious",
  score: "52/73 detections",
  fetchedAt: NOW,
  ...over,
});
const chain = (over: Partial<IocProvenanceChain> = {}): IocProvenanceChain => ({
  iocId: "i1",
  value: "203.0.113.50",
  type: "ip",
  extraction: [],
  extractionTruncated: 0,
  extractionAuthoritative: true,
  enrichment: [],
  findings: [],
  ...over,
});
const ev = (timestamp: string, endTimestamp?: string) => ({
  eventId: "e1",
  timestamp,
  description: "x",
  severity: "Low" as const,
  ...(endTimestamp ? { count: 2, endTimestamp } : {}),
});
const ioc = (over: Partial<IOC> = {}): IOC => ({
  id: "i1",
  type: "ip",
  value: "203.0.113.50",
  firstSeen: "2026-04-01T00:00:00.000Z",
  ...over,
});

describe("the case time comes from dated extraction events, with its basis", () => {
  it("earliest event; an aggregated record is an interval; the basis is the chain's", () => {
    const c = caseTime(
      ioc(),
      chain({
        extraction: [
          ev("2021-04-29T21:41:00.000Z"),
          ev("2021-04-30T00:00:00.000Z", "2021-05-02T00:00:00.000Z"),
        ],
      }),
    );
    expect(c).toEqual({
      basis: "authoritative",
      from: "2021-04-29T21:41:00.000Z",
      to: "2021-05-02T00:00:00.000Z",
    });
    const approx = caseTime(
      ioc(),
      chain({ extractionAuthoritative: false, extraction: [ev("2021-04-29T21:41:00.000Z")] }),
    );
    expect(approx.basis).toBe("approximate");
  });
  it("no dated event → none; firstSeen is the import time, never the sighting", () => {
    const c = caseTime(ioc(), chain({ extraction: [ev("not a date")] }));
    expect(c).toEqual({ basis: "none", importedAt: "2026-04-01T00:00:00.000Z" });
  });
});

describe("VirusTotal facts, each of its own kind", () => {
  const S = { basis: "authoritative" as const, from: "2021-04-29T21:41:00.000Z" };
  it("the verdict was measured by a scan — after, before, same day, less than a day", () => {
    expect(
      intelTemporal(hit({ temporal: { verdictMeasuredAt: "2026-04-30T10:00:00.000Z" } }), S, NOW).words,
    ).toBe("verdict measured by the latest scan on 2026-04-30 — 1,827 days after the case time (2021-04-29)");
    expect(
      intelTemporal(hit({ temporal: { verdictMeasuredAt: "2020-01-01T00:00:00.000Z" } }), S, NOW).words,
    ).toBe("verdict measured by the latest scan on 2020-01-01 — 484 days before the case time (2021-04-29)");
    expect(
      intelTemporal(hit({ temporal: { verdictMeasuredAt: "2021-04-30T02:00:00.000Z" } }), S, NOW).words,
    ).toBe(
      "verdict measured by the latest scan on 2021-04-30 — less than one day from the case time (2021-04-29)",
    );
    expect(intelTemporal(hit({ temporal: { verdictMeasuredAt: "2021-04-29" } }), S, NOW).words).toBe(
      "verdict measured by the latest scan on 2021-04-29 — on the same day as the case time (2021-04-29)",
    );
  });
  it("a submission date is a submission date; a record update is not an observation", () => {
    const w = intelTemporal(
      hit({
        temporal: {
          firstSubmittedAt: "2019-03-01T00:00:00.000Z",
          verdictMeasuredAt: "2026-04-30T10:00:00.000Z",
        },
      }),
      S,
      NOW,
    ).words;
    expect(w).toContain(
      "first submitted to VirusTotal on 2019-03-01 — 790 days before the case time (2021-04-29) (a submission date, not when the file or URL came to exist)",
    );
    const r = intelTemporal(hit({ temporal: { recordUpdatedAt: "2026-04-30T10:00:00.000Z" } }), S, NOW).words;
    expect(r).toBe("VirusTotal record last updated 2026-04-30 (not an observation)");
    expect(r).not.toMatch(/after|before/);
  });
  it("never says was-malicious-then, still, covers or spans", () => {
    const w = intelTemporal(
      hit({ temporal: { firstSubmittedAt: "2019-03-01", verdictMeasuredAt: "2026-04-30" } }),
      S,
      NOW,
    ).words;
    expect(w).not.toMatch(/was malicious|still|covers|spans/i);
  });
});

describe("AbuseIPDB: a window, a point, a count", () => {
  const S = { basis: "authoritative" as const, from: "2021-04-29T21:41:00.000Z" };
  const abuse = (over: Partial<IocEnrichment> = {}) =>
    hit({
      source: "AbuseIPDB",
      verdict: "malicious",
      temporal: {
        queryWindow: { from: "2026-01-31T12:00:00.000Z", to: "2026-05-01T12:00:00.000Z" },
        lastReportAt: "2026-04-20T00:00:00.000Z",
        reportCount: 12,
      },
      ...over,
    });
  it("the case time is before the window; the latest report is a point; the count is the window's", () => {
    expect(intelTemporal(abuse(), S, NOW).words).toBe(
      "12 reports counted over the window 2026-01-31 → 2026-05-01; the case time (2021-04-29) is before that window; latest report 2026-04-20 — 1,817 days after the case time (2021-04-29)",
    );
  });
  it("inside the window; a harmless verdict says what no reports means", () => {
    const inside = { basis: "authoritative" as const, from: "2026-03-01T00:00:00.000Z" };
    expect(intelTemporal(abuse(), inside, NOW).words).toContain(
      "the case time (2026-03-01) is inside that window",
    );
    const clean = intelTemporal(
      abuse({
        verdict: "harmless",
        temporal: {
          queryWindow: { from: "2026-01-31T12:00:00.000Z", to: "2026-05-01T12:00:00.000Z" },
          reportCount: 0,
        },
      }),
      S,
      NOW,
    ).words;
    expect(clean).toBe(
      "0 reports counted over the window 2026-01-31 → 2026-05-01; the case time (2021-04-29) is before that window; no reports in that window says nothing about earlier dates",
    );
  });
});

describe("no facts, no case time, approximate basis", () => {
  const S = { basis: "authoritative" as const, from: "2021-04-29T21:41:00.000Z" };
  it("a hit without temporal facts is undated", () => {
    expect(intelTemporal(hit(), S, NOW).words).toBe(
      "the provider reports no dates; the lookup ran on 2026-05-01 — 1,828 days after the case time (2021-04-29)",
    );
  });
  it("no case time: the facts stand alone", () => {
    const none = { basis: "none" as const, importedAt: "2026-04-01T00:00:00.000Z" };
    expect(
      intelTemporal(hit({ temporal: { verdictMeasuredAt: "2026-04-30T10:00:00.000Z" } }), none, NOW).words,
    ).toBe(
      "verdict measured by the latest scan on 2026-04-30; no dated case time to compare (the indicator was imported on 2026-04-01)",
    );
  });
  it("an approximate basis names the approximately matching event", () => {
    const approx = { basis: "approximate" as const, from: "2021-04-29T21:41:00.000Z" };
    expect(
      intelTemporal(hit({ temporal: { verdictMeasuredAt: "2026-04-30T10:00:00.000Z" } }), approx, NOW).words,
    ).toContain("after the approximately matching event at 2021-04-29");
  });
  it("an interval case time is named as one", () => {
    const iv = {
      basis: "authoritative" as const,
      from: "2021-04-29T21:41:00.000Z",
      to: "2021-05-02T00:00:00.000Z",
    };
    expect(
      intelTemporal(hit({ temporal: { verdictMeasuredAt: "2026-04-30T10:00:00.000Z" } }), iv, NOW).words,
    ).toContain("after the case time (2021-04-29 → 2021-05-02)");
  });
});

describe("the synthesis tag covers every bad-verdict provider and is bounded", () => {
  const S = { basis: "authoritative" as const, from: "2021-04-29T21:41:00.000Z" };
  it("one clause per provider; harmless hits are not listed; long tags are cut with a count", () => {
    const tag = intelTimeTag(
      [
        hit({ temporal: { verdictMeasuredAt: "2026-04-30T10:00:00.000Z" } }),
        hit({
          source: "AbuseIPDB",
          verdict: "suspicious",
          temporal: {
            queryWindow: { from: "2026-01-31T12:00:00.000Z", to: "2026-05-01T12:00:00.000Z" },
            reportCount: 2,
          },
        }),
        hit({ source: "GeoIP", verdict: "unknown" }),
        hit({ source: "Hashlookup", verdict: "harmless" }),
      ],
      S,
      NOW,
    );
    expect(tag).toMatch(/^\[intel time: VirusTotal — verdict measured .*; AbuseIPDB — 2 reports .*\]$/);
    expect(tag).not.toMatch(/GeoIP|Hashlookup/);
    const many = intelTimeTag(
      Array.from({ length: 8 }, (_, i) =>
        hit({ source: `P${i}] [x`, temporal: { verdictMeasuredAt: "2026-04-30T10:00:00.000Z" } }),
      ),
      S,
      NOW,
    );
    expect(many.length).toBeLessThanOrEqual(400);
    expect(many).toMatch(/\(\+\d+ more\)\]$/);
    expect(many).not.toContain("] [x");
  });
});

describe("Codex round 1 pins", () => {
  const NOW2 = "2026-05-01T12:00:00.000Z";
  it("an absent AbuseIPDB count is not zero", () => {
    const S = { basis: "authoritative" as const, from: "2021-04-29T21:41:00.000Z" };
    const w = intelTemporal(
      hit({
        source: "AbuseIPDB",
        temporal: { queryWindow: { from: "2026-01-31T12:00:00.000Z", to: "2026-05-01T12:00:00.000Z" } },
      }),
      S,
      NOW2,
    ).words;
    expect(w).toContain("reports not counted by the provider over the window");
    expect(w).not.toContain("0 reports");
    expect(w).not.toContain("says nothing about earlier dates");
  });
  it("an interval case time: a fact within it, a gap from the nearest bound, an overlapping window", () => {
    const iv = {
      basis: "authoritative" as const,
      from: "2021-01-01T00:00:00.000Z",
      to: "2021-01-10T00:00:00.000Z",
    };
    expect(
      intelTemporal(hit({ temporal: { verdictMeasuredAt: "2021-01-05T00:00:00.000Z" } }), iv, NOW2).words,
    ).toContain("within the case time (2021-01-01 → 2021-01-10)");
    expect(
      intelTemporal(hit({ temporal: { verdictMeasuredAt: "2021-01-12T00:00:00.000Z" } }), iv, NOW2).words,
    ).toContain("2 days after the case time (2021-01-01 → 2021-01-10)");
    const w = intelTemporal(
      hit({
        source: "AbuseIPDB",
        temporal: {
          queryWindow: { from: "2021-01-05T00:00:00.000Z", to: "2021-04-05T00:00:00.000Z" },
          reportCount: 1,
        },
      }),
      iv,
      NOW2,
    ).words;
    expect(w).toContain("is overlapping that window");
  });
  it("a date-only fact on the adjacent day, under a day apart, is not comparable; two days apart is counted", () => {
    const S = { basis: "authoritative" as const, from: "2021-04-29T21:41:00.000Z" };
    expect(intelTemporal(hit({ temporal: { verdictMeasuredAt: "2021-04-30" } }), S, NOW2).words).toContain(
      "not comparable with the case time (2021-04-29) (a date without a time, less than a day apart)",
    );
    expect(intelTemporal(hit({ temporal: { verdictMeasuredAt: "2021-05-02" } }), S, NOW2).words).toContain(
      "3 days after",
    );
  });
  it("the case time's latest bound survives the chain's display cap", () => {
    const c = caseTime(
      ioc(),
      chain({
        extraction: [ev("2021-04-29T21:41:00.000Z")],
        extractionEarliest: "2021-04-29T21:41:00.000Z",
        extractionLatest: "2021-09-01T00:00:00.000Z",
      }),
    );
    expect(c).toEqual({
      basis: "authoritative",
      from: "2021-04-29T21:41:00.000Z",
      to: "2021-09-01T00:00:00.000Z",
    });
  });
});
