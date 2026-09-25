import { describe, it, expect } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { backfillActivityWaveFinding, detectGapsWithWaves } from "../../src/analysis/activityWaves.js";
import { backfillSilenceGapFindings } from "../../src/analysis/gapDetect.js";
import { GAP_FINDING_ID_PREFIX, WAVES_FINDING_ID } from "../../src/analysis/responseSchema.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #1603. The GoGoogle lab cases carried f-waves ("5 separate waves spanning 3526d") and four
// "Dwell interval" findings in every synthesis. Every wave edge was a YARA file hit on a mimikatz
// release binary: each copied file kept its release build's Mtime (2013, 2014, 2020, 2022) while
// Btime recorded the drop on 2026-09-24. Dated by Mtime, one afternoon's drop became nine years of
// "returning operator". These tests run the real importer and the real finding passes.

const ARTIFACT = "DetectRaptor.Generic.Detection.YaraFile";
const HOST = "WS-01.example.com";
const RULE = "BINARYALERT_Hacktool_Windows_Mimikatz_Copywrite";

// The mimidrv.sys row shape from the lab collection, sanitized.
function yaraRow(file: string, mtime: string, btime: string): Record<string, unknown> {
  return {
    OSPath: `C:\\e\\mimikatz\\${file}`,
    Size: 30552,
    Mtime: mtime,
    Atime: "2026-09-24T09:44:33.4520952Z",
    Ctime: mtime,
    Btime: btime,
    Rule: RULE,
    Tags: null,
    Meta: { description: "Mimikatz credential dump tool", date: "2017-08-11", modified: "2017-08-11" },
    YaraString: "$s3",
    HitOffset: 30237,
    Fqdn: HOST,
  };
}

// Four release builds, three files each, all dropped in the same second-range on 2026-09-24.
const BUILDS: ReadonlyArray<[string, string]> = [
  ["2013-01-23T01:50:12Z", "Win32"],
  ["2014-12-21T09:10:00Z", "x64"],
  ["2020-09-17T09:04:36Z", "old"],
  ["2022-09-19T23:43:16Z", "new"],
];
const FILES = ["mimidrv.sys", "mimikatz.exe", "mimilib.dll"];

function copiedRows(): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = [];
  BUILDS.forEach(([mtime, dir], b) =>
    FILES.forEach((f, i) => rows.push(yaraRow(`${dir}\\${f}`, mtime, `2026-09-24T08:58:3${b}.${i}531008Z`))),
  );
  return rows;
}

function toEvents(rows: object[], prefix: string): ForensicEvent[] {
  return parseVelociraptorJson(JSON.stringify(rows), { artifact: ARTIFACT }).events.map((e, i) => {
    const { aggKey, ...rest } = e as ForensicEvent & { aggKey?: string };
    void aggKey;
    return {
      ...rest,
      id: `${prefix}e${i + 1}`,
      mitreTechniques: rest.mitreTechniques ?? [],
      relatedFindingIds: rest.relatedFindingIds ?? [],
      sourceScreenshots: rest.sourceScreenshots ?? [],
    };
  });
}

// The two deterministic finding passes synthesis runs over the timeline (synthesisMerge.ts).
function gapAndWaveFindings(events: ForensicEvent[]): InvestigationState {
  const state: InvestigationState = { ...emptyState("C-1603"), forensicTimeline: events };
  const { gaps, pattern } = detectGapsWithWaves(events);
  const ts = "2026-09-25T00:00:00Z";
  return backfillSilenceGapFindings(backfillActivityWaveFinding(state, pattern, ts), gaps, ts);
}

const gapOrWaveIds = (s: InvestigationState): string[] =>
  s.findings.map((f) => f.id).filter((id) => id === WAVES_FINDING_ID || id.startsWith(GAP_FINDING_ID_PREFIX));

describe("copied files and activity waves (#1603)", () => {
  it("dates the mimidrv.sys hit by its creation time and keeps the 2013 modified time beside it", () => {
    const [e] = toEvents(
      [yaraRow("Win32\\mimidrv.sys", "2013-01-23T01:50:12Z", "2026-09-24T08:58:30.6531008Z")],
      "a",
    );
    expect(e.timestamp).toBe("2026-09-24T08:58:30.6531008Z");
    expect(e.fileModified).toBe("2013-01-23T01:50:12Z");
    expect(e.description).toContain("[inherited modified time: 2013-01-23T01:50:12Z predates");
    expect(["High", "Critical"]).toContain(e.severity);
  });

  it("keeps Mtime, and adds no note, for a file edited after it was created", () => {
    const [e] = toEvents(
      [yaraRow("Win32\\mimidrv.sys", "2026-09-24T10:00:00Z", "2026-09-01T08:00:00Z")],
      "b",
    );
    expect(e.timestamp).toBe("2026-09-24T10:00:00Z");
    expect(e.fileModified).toBeUndefined();
    expect(e.description).not.toContain("inherited modified time");
  });

  it("creates no wave or dwell-interval finding for a same-day drop of old release builds", () => {
    const events = toEvents(copiedRows(), "c");
    expect(events.length).toBe(12);
    expect(events.every((e) => e.timestamp.startsWith("2026-09-24"))).toBe(true);
    const { pattern, gaps } = detectGapsWithWaves(events);
    expect(pattern).toBeNull();
    expect(gaps.some((g) => g.betweenWaves)).toBe(false);
    expect(gapOrWaveIds(gapAndWaveFindings(events))).toEqual([]);
  });

  it("the same rows dated by their modified time DO form the false waves (the bug this guards)", () => {
    const events = toEvents(copiedRows(), "d").map((e) => ({ ...e, timestamp: e.fileModified! }));
    expect(detectGapsWithWaves(events).pattern?.waves.length).toBe(4);
    expect(gapOrWaveIds(gapAndWaveFindings(events))).toContain(WAVES_FINDING_ID);
  });

  it("still reports a real two-visit intrusion: two High process bursts weeks apart", () => {
    const burst = (prefix: string, startISO: string): ForensicEvent[] =>
      Array.from({ length: 4 }, (_, i) => ({
        id: `${prefix}${i}`,
        timestamp: new Date(Date.parse(startISO) + i * 60_000).toISOString(),
        description: `Process execution: rclone.exe run ${i}`,
        severity: "High" as const,
        mitreTechniques: ["T1059"],
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: ["Velociraptor"],
        asset: HOST,
        processName: "rclone.exe",
      }));
    const events = [...burst("v1-", "2026-08-01T10:00:00Z"), ...burst("v2-", "2026-08-22T14:00:00Z")];
    const { pattern } = detectGapsWithWaves(events);
    expect(pattern?.waves.length).toBe(2);
    expect(pattern?.intervals[0].attackerGraded).toBe(true);
    const ids = gapOrWaveIds(gapAndWaveFindings(events));
    expect(ids).toContain(WAVES_FINDING_ID);
    expect(ids.some((id) => id.startsWith(GAP_FINDING_ID_PREFIX))).toBe(true);
  });
});
