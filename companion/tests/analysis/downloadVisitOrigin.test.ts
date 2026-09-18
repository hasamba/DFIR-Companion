import { describe, it, expect } from "vitest";
import { corroborateDownloadExecution } from "../../src/analysis/downloadExecution.js";
import {
  BROWSER_VISIT_MARKER,
  REFERRER_VISIT_MARKER,
  VISIT_PRECEDES_MARK_MARKER,
} from "../../src/analysis/downloadVisitOrigin.js";
import { PROVENANCE_NOTE } from "../../src/analysis/ntfsStreams.js";
import type { Severity } from "../../src/analysis/stateTypes.js";

// #985 (browser-origin half): a mark's own download URL or referrer, matched against a
// Velociraptor browser-history "Visited" row for the same URL — T1189's precondition, never the
// technique itself (no mitreTechniques added in any case here).
//
// Split out of downloadExecution.test.ts (#1201): these tests exercise downloadVisitOrigin.ts's
// own regexes (MARK_URL, veloVisitUrl, normalizeUrl), not downloadExecution.ts's, so a regression
// here should fail a suite named for the module that actually broke.

interface Ev {
  id: string;
  timestamp: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  path?: string;
  asset?: string;
  sha256?: string;
  md5?: string;
  sources?: string[];
  commandLine?: string;
  canonical?: { event?: { category?: string; type?: string } };
}

const T = "2026-05-02T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const mark = (over: Partial<Ev> = {}): Ev => ({
  id: "m1",
  timestamp: T,
  description: `MFT: .\\Users\\x\\Downloads\\tool.exe — downloaded from the Internet zone (https://evil.example/tool.exe) — ${PROVENANCE_NOTE}`,
  severity: "Medium",
  mitreTechniques: [],
  path: ".\\Users\\x\\Downloads\\tool.exe",
  sources: ["MFT"],
  ...over,
});
const run = (events: Ev[]) => corroborateDownloadExecution(events);
const find = (out: Ev[], id: string) => out.find((e) => e.id === id)!;

describe("mark → browser visit", () => {
  const visitRow = async (url: string, over: Partial<Ev> = {}): Promise<Ev> => {
    const { parseVelociraptorJson } = await import("../../src/analysis/velociraptorImport.js");
    const { events } = parseVelociraptorJson(
      JSON.stringify([
        {
          _Source: "Windows.Applications.Chrome.History",
          visited_url: url,
          title: "Evil",
          visit_count: 1,
          visit_time: at(-30),
          Fqdn: "WS-01",
        },
      ]),
    );
    return { ...(events[0] as unknown as Ev), id: "v1", ...over };
  };

  it("the mark's own URL, visited: raises to Medium, no technique, both rows noted", async () => {
    const visit = await visitRow("https://evil.example/tool.exe");
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), visit]);
    const m = find(out, "m1");
    expect(m.severity).toBe("Medium");
    expect(m.mitreTechniques).toEqual([]);
    expect(m.description).toContain(BROWSER_VISIT_MARKER);
    expect(m.description).toContain("visited the download URL");
    const v = find(out, "v1");
    expect(v.severity).toBe("Medium");
    expect(v.description).toContain(VISIT_PRECEDES_MARK_MARKER);
  });

  // #1202: veloVisitUrl used to match the FIRST https?://\S+ anywhere in the description — if the
  // page TITLE itself contained a URL-like string, that decoy would be captured instead of the
  // row's real visited URL, which follows it. Anchored to the text after the title now.
  it("captures the row's real visited URL, not a URL-like string embedded in the page title", async () => {
    const { parseVelociraptorJson } = await import("../../src/analysis/velociraptorImport.js");
    const { events } = parseVelociraptorJson(
      JSON.stringify([
        {
          _Source: "Windows.Applications.Chrome.History",
          visited_url: "https://evil.example/tool.exe",
          title: "see https://decoy.example for details",
          visit_count: 1,
          visit_time: at(-30),
          Fqdn: "WS-01",
        },
      ]),
    );
    const visit: Ev = { ...(events[0] as unknown as Ev), id: "v1" };
    expect(visit.description).toContain("https://decoy.example"); // sanity: the decoy is really there
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), visit]);
    expect(find(out, "m1").description).toContain(BROWSER_VISIT_MARKER);
  });

  it("a visit to the referrer page (not the download URL) is noted separately", async () => {
    const visit = await visitRow("https://phish.example/page");
    const out = run([
      mark({
        sources: ["Sysmon"],
        asset: "WS-01",
        description: `MFT: .\\Users\\x\\Downloads\\tool.exe — downloaded from the Internet zone (https://evil.example/tool.exe, referrer https://phish.example/page) — ${PROVENANCE_NOTE}`,
      }),
      visit,
    ]);
    const m = find(out, "m1");
    expect(m.severity).toBe("Medium");
    expect(m.mitreTechniques).toEqual([]);
    expect(m.description).toContain(REFERRER_VISIT_MARKER);
    expect(m.description).toContain("visited the referrer page");
    expect(m.description).not.toContain("visited the download URL");
  });

  it("normalizes scheme/host case and a trailing slash, but not the path", async () => {
    const visit = await visitRow("HTTPS://Evil.Example/tool.exe/");
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), visit]);
    expect(find(out, "m1").description).toContain(BROWSER_VISIT_MARKER);
    const differentPath = await visitRow("https://evil.example/other.exe");
    const miss = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), differentPath]);
    expect(find(miss, "m1").description).not.toContain(BROWSER_VISIT_MARKER);
  });

  it("two named, disagreeing hosts never join", async () => {
    const visit = await visitRow("https://evil.example/tool.exe", { asset: "WS-02" });
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), visit]);
    expect(find(out, "m1").description).not.toContain(BROWSER_VISIT_MARKER);
  });

  it("a non-Velociraptor row with a lookalike 'Visited' description does not spoof a match", () => {
    const out = run([
      mark({ sources: ["Sysmon"], asset: "WS-01" }),
      {
        id: "lookalike1",
        timestamp: at(-30),
        description:
          "Velociraptor [Windows.Applications.Chrome.History]: Visited (1×): https://evil.example/tool.exe - @ WS-01",
        severity: "Info",
        mitreTechniques: [],
        asset: "WS-01",
        sources: ["SomeOtherTool"],
      },
    ]);
    expect(find(out, "m1").description).not.toContain(BROWSER_VISIT_MARKER);
  });

  it("a visit AFTER the mark, or within tolerance, is never labeled 'preceded' and raises nothing", async () => {
    // #985 code review: matching by URL alone is not evidence of order. A revisit, a re-download
    // check, or analyst verification browsing after the file already exists must not corroborate
    // a drive-by story the evidence doesn't support.
    const after = await visitRow("https://evil.example/tool.exe", { timestamp: at(30) });
    const outAfter = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), after]);
    expect(find(outAfter, "m1").description).not.toContain(BROWSER_VISIT_MARKER);
    expect(find(outAfter, "m1").severity).toBe("Medium"); // the mark's own default severity, unraised
    const v = find(outAfter, "v1");
    expect(v.description).not.toContain(VISIT_PRECEDES_MARK_MARKER);
    expect(v.severity).toBe("Info");
    const within = await visitRow("https://evil.example/tool.exe", { timestamp: at(1) });
    const outWithin = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), within]);
    expect(find(outWithin, "m1").description).not.toContain(BROWSER_VISIT_MARKER);
  });

  it("a real Zone.Identifier mark from ntfsStreams.readHost is corroborated by a real visit", async () => {
    // Pinned against the actual mark-producing code, not a hand-typed description (#985 code
    // review, same lesson as the #1196 UserAssist fix): if markWords()'s wording ever drifts,
    // this test — not just the regex it exercises — fails.
    const { readHost } = await import("../../src/analysis/ntfsStreams.js");
    const h = readHost({
      path: ".\\Users\\x\\Downloads\\tool.exe",
      contents: "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil.example/tool.exe\r\n",
    });
    const row = mark({
      sources: ["Sysmon"],
      asset: "WS-01",
      description: `MFT: x — ${[h.words, ...h.qualifiers].join(" — ")}`,
    });
    const visit = await visitRow("https://evil.example/tool.exe");
    expect(find(run([row, visit]), "m1").description).toContain(BROWSER_VISIT_MARKER);
  });

  it("a referrer equal to the download URL after normalization is not double-counted", async () => {
    const visit = await visitRow("https://evil.example/tool.exe");
    const out = run([
      mark({
        sources: ["Sysmon"],
        asset: "WS-01",
        description: `MFT: .\\Users\\x\\Downloads\\tool.exe — downloaded from the Internet zone (https://evil.example/tool.exe, referrer HTTPS://Evil.Example/tool.exe/) — ${PROVENANCE_NOTE}`,
      }),
      visit,
    ]);
    const m = find(out, "m1");
    expect(m.description).toContain("visited the download URL");
    expect(m.description).not.toContain("visited the referrer page");
    const v = find(out, "v1");
    expect(
      v.description.match(new RegExp(VISIT_PRECEDES_MARK_MARKER.replace(/[[\]]/g, "\\$&"), "g")) ?? [],
    ).toHaveLength(1);
  });

  it("a default port (:443 on https) folds; a different explicit port does not", async () => {
    const visit = await visitRow("https://evil.example:443/tool.exe");
    const out = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), visit]);
    expect(find(out, "m1").description).toContain(BROWSER_VISIT_MARKER);
    const otherPort = await visitRow("https://evil.example:8443/tool.exe");
    const miss = run([mark({ sources: ["Sysmon"], asset: "WS-01" }), otherPort]);
    expect(find(miss, "m1").description).not.toContain(BROWSER_VISIT_MARKER);
  });
});
