import { describe, it, expect, vi, beforeAll } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { ScopeStore } from "../../src/analysis/scope.js";
import { FalsePositiveStore } from "../../src/analysis/falsePositive.js";
import { seedDemoCase } from "../../src/analysis/seedDemoCase.js";
import { renderInteractiveHtmlReport } from "../../src/reports/interactiveHtml.js";
import { renderStandalonePresentationChecked } from "../../src/reports/presentationExport.js";

// #1915: concurrent report requests now share ONE filtered-state object. That is safe only while no
// projection writes into it. Every projection here runs over a deep-frozen state, so an in-place
// sort, push or field assignment throws (ES modules are strict) instead of leaking into another
// request's report.

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    deepFreeze((value as Record<PropertyKey, unknown>)[key], seen);
  }
  return Object.freeze(value);
}

vi.mock("../../src/reports/filteredState.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../src/reports/filteredState.js")>();
  return {
    ...real,
    loadFilteredState: async (...args: Parameters<typeof real.loadFilteredState>) =>
      deepFreeze(await real.loadFilteredState(...args)),
  };
});

let writer: ReportWriter;
const CASE = "demo";

beforeAll(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-frozen-"));
  await seedDemoCase(root, { caseId: CASE });
  const cases = new CaseStore(root);
  const state = new StateStore(cases);
  writer = new ReportWriter(cases, state, {
    scope: new ScopeStore(cases),
    falsePositives: new FalsePositiveStore(cases),
  });
  // The seeded demo case must actually reach the projections, or the test proves nothing.
  const filtered = await writer.filteredState(CASE);
  expect(filtered.forensicTimeline.length).toBeGreaterThan(10);
  expect(Object.isFrozen(filtered.forensicTimeline[0])).toBe(true);
}, 60_000);

describe("report projections never write into the shared filtered state (#1915)", () => {
  const projections: Array<[string, () => Promise<unknown>]> = [
    ["swimlane asset", () => writer.swimlane(CASE, "asset")],
    ["swimlane severity", () => writer.swimlane(CASE, "severity")],
    ["swimlane tactic", () => writer.swimlane(CASE, "tactic")],
    ["timelineGaps", () => writer.timelineGaps(CASE)],
    ["anomalies", () => writer.anomalies(CASE)],
    ["phases", () => writer.phases(CASE)],
    ["beaconCandidates", () => writer.beaconCandidates(CASE)],
    ["iocSources", () => writer.iocSources(CASE)],
    ["adversaryHints", () => writer.adversaryHints(CASE)],
    ["hostRanking", () => writer.hostRanking(CASE)],
    ["d3fendCountermeasures", () => writer.d3fendCountermeasures(CASE)],
    ["attackMitigations", () => writer.attackMitigations(CASE)],
    ["mobileSummary", () => writer.mobileSummary(CASE)],
    ["presentation", () => writer.presentation(CASE)],
    ["iocBlocklist txt", () => writer.iocBlocklist(CASE, "txt")],
    ["iocBlocklist csv", () => writer.iocBlocklist(CASE, "csv")],
    ["iocBlocklist stix", () => writer.iocBlocklist(CASE, "stix")],
    ["iocBlocklist summary", () => writer.iocBlocklist(CASE, "summary")],
    ["stixBundle", () => writer.stixBundle(CASE)],
    ["assetGraph", () => writer.assetGraph(CASE)],
    ["evidenceGraph", () => writer.evidenceGraph(CASE)],
    ["lateralPaths", () => writer.lateralPaths(CASE)],
    ["attackLayer", () => writer.attackLayer(CASE)],
    ["incidentTimelineCsv", () => writer.incidentTimelineCsv(CASE)],
    ["timesketchJsonl", () => writer.timesketchJsonl(CASE)],
    ["docx", () => writer.docx(CASE)],
    ["writeAll", () => writer.writeAll(CASE)],
    ["redactedReportContents", () => writer.redactedReportContents(CASE, (v) => v)],
    // Route consumers of filteredState(): the interactive report and the presentation export.
    ["interactive report", async () => renderInteractiveHtmlReport(await writer.filteredState(CASE))],
    [
      "presentation export",
      async () =>
        renderStandalonePresentationChecked(
          await writer.filteredState(CASE),
          await writer.presentation(CASE),
          "n",
        ),
    ],
  ];

  it.each(projections)("%s runs over a frozen state", async (_name, run) => {
    await expect(run()).resolves.toBeDefined();
  });

  it("all of them at once, sharing one state, still succeed", async () => {
    const results = await Promise.allSettled(projections.map(([, run]) => run()));
    expect(results.filter((r) => r.status === "rejected")).toEqual([]);
  });
});
