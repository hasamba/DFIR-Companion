import { describe, it, expect } from "vitest";
import {
  BUILT_IN_DASHBOARD_VIEWS,
  DASHBOARD_SECTION_IDS,
  getDashboardView,
  severityRank,
  meetsMinSeverity,
  builtInReportTemplateIds,
} from "../../src/analysis/dashboardViews.js";

describe("dashboardViews — seed integrity", () => {
  const sectionIds = new Set(DASHBOARD_SECTION_IDS);
  const templateIds = new Set(builtInReportTemplateIds());

  it("ships the seven canonical views with unique ids and names", () => {
    expect(BUILT_IN_DASHBOARD_VIEWS.map((v) => v.id)).toEqual([
      "analyst",
      "lead",
      "executive",
      "triage",
      "report",
      "deep-dive",
      "hunt-prep",
    ]);
    const ids = BUILT_IN_DASHBOARD_VIEWS.map((v) => v.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every view references only valid section ids, with no duplicates", () => {
    for (const view of BUILT_IN_DASHBOARD_VIEWS) {
      expect(view.sections.length, `${view.id} has sections`).toBeGreaterThan(0);
      expect(new Set(view.sections).size, `${view.id} has no duplicate sections`).toBe(view.sections.length);
      for (const id of view.sections) {
        expect(sectionIds.has(id), `${view.id} → ${id} is a known section`).toBe(true);
      }
    }
  });

  it("every view maps onto a built-in report template", () => {
    for (const view of BUILT_IN_DASHBOARD_VIEWS) {
      if (view.reportTemplateId !== undefined) {
        expect(templateIds.has(view.reportTemplateId), `${view.id} → ${view.reportTemplateId}`).toBe(true);
      }
    }
  });

  it("Analyst is the densest view and the default for new cases, in the app's curated order", () => {
    const analyst = getDashboardView("analyst");
    expect(analyst).toBeDefined();
    // Curated to match the default onboarding layout — excludes the handful of sections that are
    // opt-in/secondary (Query Translator, Recommended Next Steps, Investigation Log, Activity
    // Log). Everything else is shown, in the app's canonical reading order.
    const excluded = ["sec-nlquery", "sec-next-steps", "sec-inv-log", "sec-activity"];
    for (const id of excluded) {
      expect(analyst!.sections.includes(id), `analyst excludes ${id}`).toBe(false);
    }
    expect(analyst!.sections).toEqual([
      "sec-ask",
      "sec-exec",
      "sec-narrative",
      "sec-findings",
      "sec-timeline",
      "sec-super-timeline",
      "sec-iocs",
      "sec-playbook",
      "sec-attack-path",
      "sec-kill-chain",
      "sec-phases",
      "sec-hostranking",
      "sec-gaps",
      "sec-evidence-gaps",
      "sec-swimlane",
      "sec-assets",
      "sec-evidence",
      "sec-beacons",
      "sec-anomalies",
      "sec-exposure",
      "sec-questions",
      "sec-threads",
      "sec-mitre",
      "sec-adversary",
      "sec-d3fend",
      "sec-false-positive",
      "sec-hypotheses",
      "sec-notebook",
      "sec-case-details",
    ]);
  });

  it("Lead and Executive filter to High+ severity; Executive caps to a top-N", () => {
    expect(getDashboardView("lead")!.filters?.minSeverity).toBe("High");
    expect(getDashboardView("executive")!.filters?.minSeverity).toBe("High");
    expect(getDashboardView("executive")!.filters?.topN).toBe(5);
    // Triage/Report/Deep-Dive/Hunt-Prep keep all severities visible.
    expect(getDashboardView("triage")!.filters?.minSeverity).toBeUndefined();
    expect(getDashboardView("deep-dive")!.filters?.minSeverity).toBeUndefined();
  });

  it("Executive hides IOCs and process/technical sections", () => {
    const exec = new Set(getDashboardView("executive")!.sections);
    expect(exec.has("sec-iocs")).toBe(false);
    expect(exec.has("sec-mitre")).toBe(false);
    expect(exec.has("sec-evidence")).toBe(false);
  });
});

describe("dashboardViews — severity helpers", () => {
  it("ranks severities most→least severe", () => {
    expect(severityRank("Critical")).toBe(0);
    expect(severityRank("High")).toBe(1);
    expect(severityRank("Info")).toBe(4);
    expect(severityRank("nonsense")).toBe(5); // unknown ranks last
  });

  it("meetsMinSeverity keeps items at or above the threshold", () => {
    expect(meetsMinSeverity("Critical", "High")).toBe(true);
    expect(meetsMinSeverity("High", "High")).toBe(true);
    expect(meetsMinSeverity("Medium", "High")).toBe(false);
    expect(meetsMinSeverity("Low", "Critical")).toBe(false);
  });

  it("fails open — no threshold, unknown threshold, or unknown severity shows the item", () => {
    expect(meetsMinSeverity("Low")).toBe(true);
    expect(meetsMinSeverity("Low", undefined)).toBe(true);
    expect(meetsMinSeverity("Low", "bogus")).toBe(true);
    expect(meetsMinSeverity("weird", "High")).toBe(true);
  });
});

describe("dashboardViews — getDashboardView", () => {
  it("returns the view by id, undefined for unknown", () => {
    expect(getDashboardView("triage")!.name).toBe("Triage");
    expect(getDashboardView("does-not-exist")).toBeUndefined();
  });
});
