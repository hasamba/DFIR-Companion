import { describe, it, expect } from "vitest";
import { findingsCsv, iocsCsv, timelineCsv, forensicTimelineCsv, geoMapCsv } from "../../src/reports/csv.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { GeoMapData } from "../../src/analysis/geoMap.js";

describe("CSV renderers", () => {
  it("findingsCsv has a header and one row per finding, escaping commas/quotes", () => {
    const state = emptyState("c1");
    state.findings.push({
      id: "f1",
      severity: "High",
      title: 'PS, "encoded"',
      description: "d",
      relatedIocs: ["i1"],
      mitreTechniques: ["T1059"],
      sourceScreenshots: ["a.webp"],
      firstSeen: "t0",
      lastUpdated: "t1",
      status: "open",
    });
    const csv = findingsCsv(state);
    const rows = csv.trim().split("\n");
    expect(rows[0]).toContain("id,severity,effectiveSeverity,confidence,title");
    expect(rows[1]).toContain('"PS, ""encoded"""'); // escaped
  });

  it("findingsCsv's effectiveSeverity column downgrades a dismissed finding, leaving severity untouched", () => {
    // Regression for INC-2026-018 f8: a dismissed Critical false positive must not sort/filter
    // ahead of genuine open findings in a spreadsheet, but the original assessed severity is kept
    // as an audit trail in the `severity` column.
    const state = emptyState("c1");
    state.findings.push({
      id: "f8",
      severity: "Critical",
      title: "Velociraptor.exe flagged as malicious (false positive)",
      description: "d",
      relatedIocs: [],
      mitreTechniques: [],
      sourceScreenshots: [],
      firstSeen: "t0",
      lastUpdated: "t1",
      status: "dismissed",
    });
    const rows = findingsCsv(state).trim().split("\n");
    const cols = rows[1].split(",").map((c) => c.replace(/^"|"$/g, ""));
    expect(cols[1]).toBe("Critical"); // severity: unchanged
    expect(cols[2]).toBe("Info"); // effectiveSeverity: downgraded
  });

  it("iocsCsv guards formula-injection values with a leading single quote", () => {
    const state = emptyState("c1");
    state.iocs.push({ id: "i1", type: "url", value: "=cmd|'/C calc'!A0", firstSeen: "t0" });
    const csv = iocsCsv(state);
    expect(csv).toContain(`"'=cmd|'/C calc'!A0"`);
  });

  it("iocsCsv and timelineCsv produce headers even when empty", () => {
    const state = emptyState("c1");
    expect(iocsCsv(state).trim()).toBe(
      "id,type,value,firstSeen,sources,sourceCount,enrichment,riskScore,riskFactors",
    );
    expect(timelineCsv(state).trim()).toBe("timestamp,windowSequence,description,sourceScreenshots");
  });

  it("iocsCsv includes a composite risk score + factors column (#63)", () => {
    const state = emptyState("c1");
    state.iocs.push({
      id: "i1",
      type: "ip",
      value: "9.9.9.9",
      firstSeen: "t0",
      enrichments: [
        { source: "VirusTotal", verdict: "malicious", fetchedAt: "" },
        { source: "AbuseIPDB", verdict: "malicious", fetchedAt: "" },
      ],
    });
    state.forensicTimeline.push({
      id: "e1",
      timestamp: "2026-01-01T00:00:00Z",
      description: "C2 to 9.9.9.9",
      severity: "Critical",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      srcIp: "9.9.9.9",
      sources: ["EDR", "FW"],
    });
    const csv = iocsCsv(state);
    const row = csv.trim().split("\n")[1];
    expect(row).toContain("critical");
    expect(row).toContain("corroborated by");
  });

  it("forensicTimelineCsv emits a header and rows ordered by event time", () => {
    const state = emptyState("c1");
    expect(forensicTimelineCsv(state).trim()).toBe(
      "timestamp,endTimestamp,count,severity,description,mitreTechniques,sources,relatedFindingIds,sourceScreenshots",
    );
    state.forensicTimeline.push(
      {
        id: "e2",
        timestamp: "2026-05-20T15:00:00Z",
        endTimestamp: "2026-05-20T15:30:00Z",
        count: 12,
        description: "later",
        severity: "Critical",
        mitreTechniques: ["T1486"],
        relatedFindingIds: ["f1"],
        sourceScreenshots: ["s2.webp"],
      },
      {
        id: "e1",
        timestamp: "2026-05-20T09:00:00Z",
        description: "earlier",
        severity: "High",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
      },
    );
    const rows = forensicTimelineCsv(state).trim().split("\n");
    expect(rows[1]).toContain("earlier"); // 09:00 sorts before 15:00
    expect(rows[1]).toContain(`,"1",`); // default count = 1 when absent
    expect(rows[2]).toContain("later");
    expect(rows[2]).toContain(`,"12",`); // aggregated count surfaced
  });
});

describe("geoMapCsv (#133)", () => {
  it("emits a header and one row per marker", () => {
    const data: GeoMapData = {
      markers: [
        {
          iocId: "i1",
          ip: "8.8.8.8",
          lat: 37.4,
          lon: -122.1,
          country: "US",
          city: "Mountain View",
          asn: "AS15169",
          severity: "High",
          color: "red",
          verdict: "malicious",
          internal: false,
          falsePositive: false,
          eventCount: 2,
          sources: ["Suricata"],
        },
      ],
      flows: [],
      countries: [],
      stats: {
        totalIps: 1,
        resolved: 1,
        unresolved: 0,
        internal: 0,
        external: 1,
        distinctCountries: 1,
        distinctAsns: 1,
      },
    };
    const csv = geoMapCsv(data);
    const [header, row] = csv.trim().split("\n");
    expect(header).toBe("ip,country,city,lat,lon,asn,severity,verdict,internal,eventCount,approximate");
    expect(row).toContain("8.8.8.8");
    expect(row).toContain("Mountain View");
    expect(row).toContain("AS15169");
    expect(row).toContain('"no"'); // approximate undefined → "no"
  });

  it("emits approximate:yes for a country-level marker", () => {
    const data: GeoMapData = {
      markers: [
        {
          iocId: "i2",
          ip: "1.2.3.4",
          lat: 51.17,
          lon: 10.45,
          country: "Germany",
          asn: undefined,
          severity: "Info",
          color: "gray",
          verdict: undefined,
          internal: false,
          falsePositive: false,
          eventCount: 0,
          sources: [],
          approximate: true,
        },
      ],
      flows: [],
      countries: [],
      stats: {
        totalIps: 1,
        resolved: 1,
        unresolved: 0,
        internal: 0,
        external: 1,
        distinctCountries: 1,
        distinctAsns: 0,
      },
    };
    const [, row] = geoMapCsv(data).trim().split("\n");
    expect(row).toContain('"yes"');
  });
});

describe("the enrichment cell says when the verdict applies (#933 item 19)", () => {
  it("each hit carries the provider's dated facts against the case time, inside the quoted cell", async () => {
    const { iocsCsv } = await import("../../src/reports/csv.js");
    const { emptyState } = await import("../../src/analysis/stateTypes.js");
    const s = emptyState("c1");
    s.forensicTimeline.push({
      id: "e1",
      timestamp: "2021-04-29T21:41:00.000Z",
      description: "outbound to 203.0.113.50",
      severity: "High",
      mitreTechniques: [],
      sources: ["Zeek"],
      relatedFindingIds: [],
      sourceScreenshots: [],
    });
    s.iocs.push({
      id: "i1",
      type: "ip",
      value: "203.0.113.50",
      firstSeen: "2026-04-01T00:00:00.000Z",
      extractedFrom: ["e1"],
      enrichments: [
        {
          source: "VirusTotal",
          verdict: "malicious",
          score: '=1+1 "quoted"',
          fetchedAt: "2026-05-01T12:00:00.000Z",
          temporal: { verdictMeasuredAt: "2026-04-30T10:00:00.000Z" },
        },
      ],
    });
    const csv = iocsCsv(s);
    expect(csv).toContain(
      "{verdict measured by the latest scan on 2026-04-30 — 1,827 days after the case time (2021-04-29)}",
    );
    // the completed cell is still one quoted CSV field: quotes doubled, the words inside it
    const line = csv.split("\n").find((l) => l.includes("203.0.113.50")) ?? "";
    expect(line).toContain(
      '"VirusTotal:malicious (=1+1 ""quoted"") {verdict measured by the latest scan on 2026-04-30',
    );
  });
});
