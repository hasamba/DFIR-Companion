import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { ScopeStore } from "../../src/analysis/scope.js";
import { FalsePositiveStore } from "../../src/analysis/falsePositive.js";
import { ClockSkewStore } from "../../src/analysis/clockSkewStore.js";
import { seedDemoCase } from "../../src/analysis/seedDemoCase.js";
import { upgradeForensicEvent } from "../../src/analysis/canonicalEvent.js";
import { detectGapsWithWaves, gapOptionsFor } from "../../src/analysis/activityWaves.js";
import { buildSwimlaneData, type SwimlaneGroupBy } from "../../src/analysis/swimlane.js";
import { buildIocBlocklist, type IocBlocklistRequestFormat } from "../../src/reports/iocBlocklist.js";
import { buildStixBundle } from "../../src/reports/stix.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import { renderInteractiveHtmlReport } from "../../src/reports/interactiveHtml.js";
import { checkEvidenceSafety } from "../../src/reports/evidenceSafety.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// #2057: timeline gaps, the swimlane, the IOC blocklist, STIX and the interactive report each loaded
// the whole case — canonical provenance included — to answer with a few KB. They now read a lighter
// load with the bulky provenance blocks left in SQLite. That is safe only while none of them reads
// those blocks, so each one is run over both loads here and must answer identically. A projection
// that starts reading provenance fails this test instead of silently changing a report.

const CASE = "lite";
const HOST = "LITE-HOST-01";
let stateStore: StateStore;
let writer: ReportWriter;
let full: InvestigationState;

const row = (id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent =>
  upgradeForensicEvent({
    id,
    timestamp,
    description: `Process started on ${HOST} (${id})`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: HOST,
    ...extra,
  });

/** A burst before a long silence, a boot row on the far edge, and an unstamped edge-observed logon. */
function fixtureRows(): ForensicEvent[] {
  const before = Array.from({ length: 12 }, (_, i) =>
    row(`lite-pre-${i}`, `2026-06-02T08:${String(i * 4).padStart(2, "0")}:00Z`),
  );
  const boot = row("lite-boot", "2026-06-02T16:00:00Z", { description: `System start on ${HOST}` });
  const bootRow = { ...boot, canonical: { ...boot.canonical!, event: { category: "host", type: "boot" } } };
  const logon = row("lite-logon", "2026-06-02T16:05:00Z", {
    description: `Windows Security Successful logon (EID 4624) - CORP\\jdoe - LogonType=3 @ ${HOST}`,
    srcIp: "198.51.100.23",
  });
  const edgeLogon = { ...logon, canonical: { ...logon.canonical!, producer: { importer: "windows-event" } } };
  const after = Array.from({ length: 12 }, (_, i) =>
    row(`lite-post-${i}`, `2026-06-02T16:${String(10 + i * 4).padStart(2, "0")}:00Z`),
  );
  return [...before, bootRow as ForensicEvent, edgeLogon as ForensicEvent, ...after];
}

beforeAll(async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-07-01T00:00:00Z"));
  const root = await mkdtemp(join(tmpdir(), "dfir-lite-"));
  await seedDemoCase(root, { caseId: CASE });
  const cases = new CaseStore(root);
  stateStore = new StateStore(cases);
  const seeded = await stateStore.load(CASE);
  await stateStore.save({ ...seeded, forensicTimeline: [...seeded.forensicTimeline, ...fixtureRows()] });
  const scope = new ScopeStore(cases);
  await scope.save(CASE, { start: "2026-01-01T00:00:00Z", end: "2026-12-31T00:00:00Z" });
  const falsePositives = new FalsePositiveStore(cases);
  await falsePositives.save(CASE, [
    {
      id: "event:lite-pre-3",
      kind: "event",
      ref: "lite-pre-3",
      reason: "known-good-tool",
      note: "",
      markedAt: "2026-06-03T00:00:00Z",
      markedBy: "analyst",
    },
  ]);
  const clockSkew = new ClockSkewStore(cases);
  await clockSkew.save(CASE, {
    ...(await clockSkew.load(CASE)),
    alignEnabled: true,
    overrides: { [HOST]: 90_000 },
  });
  writer = new ReportWriter(cases, stateStore, { scope, falsePositives, clockSkew });
  full = await writer.filteredState(CASE);
}, 60_000);

afterAll(() => {
  vi.useRealTimers();
});

describe("the report-lite load answers the five routes exactly as the full load (#2057)", () => {
  it("the fixture reaches the projections: skew applied, FP row dropped, boot and edge rows kept", () => {
    const ids = full.forensicTimeline.map((e) => e.id);
    expect(ids).toContain("lite-boot");
    expect(ids).not.toContain("lite-pre-3");
    expect(full.forensicTimeline.find((e) => e.id === "lite-boot")?.originalTimestamp).toBe(
      "2026-06-02T16:00:00Z",
    );
    const edge = full.forensicTimeline.find((e) => e.id === "lite-logon");
    expect(edge?.canonical?.network?.source?.provenance).toBe("edge-observed");
  });

  it("lite rows drop the provenance blocks and keep the event, producer and restamp", async () => {
    const lite = await writer.filteredState(CASE, true);
    expect(lite.forensicTimeline.map((e) => e.id)).toEqual(full.forensicTimeline.map((e) => e.id));
    expect(full.forensicTimeline.some((e) => e.canonical?.fieldProvenance)).toBe(true);
    for (const e of lite.forensicTimeline) {
      expect(e.canonical).toBeDefined();
      expect(e.canonical).not.toHaveProperty("fieldProvenance");
      expect(e.canonical).not.toHaveProperty("fieldProvenanceDefaults");
      expect(e.canonical).not.toHaveProperty("evidence");
      expect(e.canonical?.event).toBeDefined();
      expect(e.canonical?.producer).toBeDefined();
    }
    const boot = lite.forensicTimeline.find((e) => e.id === "lite-boot");
    expect(boot?.canonical?.event.type).toBe("boot");
    const edge = lite.forensicTimeline.find((e) => e.id === "lite-logon");
    expect(edge?.canonical?.network?.source?.provenance).toBe("edge-observed");
  });

  it("timeline gaps match, and the boot row is on a gap edge", async () => {
    const expected = detectGapsWithWaves(full.forensicTimeline, gapOptionsFor(full)).gaps;
    const bootAt = Date.parse(full.forensicTimeline.find((e) => e.id === "lite-boot")!.timestamp);
    expect(expected.some((g) => Date.parse(g.endTimestamp) === bootAt)).toBe(true);
    expect(await writer.timelineGaps(CASE)).toEqual(expected);
  });

  it.each<SwimlaneGroupBy>(["asset", "severity", "tactic"])("swimlane by %s matches", async (groupBy) => {
    expect(await writer.swimlane(CASE, groupBy)).toEqual(buildSwimlaneData(full.forensicTimeline, groupBy));
  });

  it.each<IocBlocklistRequestFormat>(["txt", "csv", "stix", "summary"])(
    "IOC blocklist (%s) matches",
    async (format) => {
      const opts = { caseName: "n", generatedAt: "2026-07-01T00:00:00Z" };
      expect(await writer.iocBlocklist(CASE, format, opts)).toEqual(buildIocBlocklist(format, full, opts));
    },
  );

  it("the STIX bundle matches", async () => {
    const meta = emptyReportMeta();
    expect(await writer.stixBundle(CASE)).toEqual(
      buildStixBundle(full, {
        organization: meta.organization,
        producer: meta.companyName,
        incidentId: meta.incidentId,
      }),
    );
  });

  it("the interactive report and its evidence-safety check match", async () => {
    const lite = await writer.filteredState(CASE, true);
    const fromFull = renderInteractiveHtmlReport(full);
    const fromLite = renderInteractiveHtmlReport(lite);
    expect(fromLite).toEqual(fromFull);
    expect(checkEvidenceSafety(lite, fromLite)).toEqual(checkEvidenceSafety(full, fromFull));
  });

  it("the five routes read the lite load; every other report surface keeps the full one", async () => {
    const load = vi.spyOn(stateStore, "load");
    await writer.timelineGaps(CASE);
    await writer.swimlane(CASE);
    await writer.iocBlocklist(CASE, "txt");
    await writer.stixBundle(CASE);
    await writer.filteredState(CASE, true);
    expect(load.mock.calls).toEqual(Array.from({ length: 5 }, () => [CASE, { slimCanonical: true }]));
    load.mockClear();
    await writer.filteredState(CASE);
    await writer.anomalies(CASE);
    await writer.incidentTimelineCsv(CASE);
    expect(load.mock.calls).toEqual([[CASE], [CASE], [CASE]]);
    load.mockRestore();
  });
});
