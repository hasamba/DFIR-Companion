import { readFileSync } from "node:fs";
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

  it("ships the phase cockpit plus the seven existing canonical views with unique ids and names", () => {
    expect(BUILT_IN_DASHBOARD_VIEWS.map((v) => v.id)).toEqual([
      "now",
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

  it("Now is the focused default while Analyst remains the densest existing workspace", () => {
    expect(getDashboardView("now")!.sections).toEqual(["sec-now"]);
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
      "sec-now",
      "sec-ask",
      "sec-exec",
      "sec-narrative",
      "sec-findings",
      "sec-deep-pass",
      "sec-sessions",
      "sec-timeline",
      "sec-hunt-workbench",
      "sec-super-timeline",
      "sec-iocs",
      "sec-playbook",
      "sec-playbook-match",
      "sec-attack-path",
      "sec-kill-chain",
      "sec-phases",
      "sec-host-scope",
      "sec-hostranking",
      "sec-gaps",
      "sec-evidence-gaps",
      "sec-swimlane",
      "sec-assets",
      "sec-login-graph",
      "sec-evidence",
      "sec-beacons",
      "sec-anomalies",
      "sec-exposure",
      "sec-questions",
      "sec-uncertainties",
      "sec-threads",
      "sec-mitre",
      "sec-adversary",
      "sec-d3fend",
      "sec-compliance",
      "sec-false-positive",
      "sec-source-trust",
      "sec-hypotheses",
      "sec-notebook",
      "sec-custody",
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

describe("sec-collection-plan registration (#347)", () => {
  it("is a registered dashboard section", () => {
    expect(DASHBOARD_SECTION_IDS).toContain("sec-collection-plan");
  });

  it("appears in the Triage and Hunt Prep profiles", () => {
    for (const id of ["triage", "hunt-prep"]) {
      const view = BUILT_IN_DASHBOARD_VIEWS.find((v) => v.id === id)!;
      expect(view.sections, `${id} is missing sec-collection-plan`).toContain("sec-collection-plan");
    }
  });
});

describe("sec-now registration (#375)", () => {
  it("is registered and included in the focused Now and comprehensive Analyst profiles", () => {
    expect(DASHBOARD_SECTION_IDS).toContain("sec-now");
    expect(getDashboardView("now")!.sections).toEqual(["sec-now"]);
    expect(getDashboardView("analyst")!.sections).toContain("sec-now");
  });
});

describe("sec-sessions registration (#229)", () => {
  it("is a registered dashboard section", () => {
    expect(DASHBOARD_SECTION_IDS).toContain("sec-sessions");
  });

  it("appears in the Analyst and Deep-Dive profiles", () => {
    for (const id of ["analyst", "deep-dive"]) {
      const view = BUILT_IN_DASHBOARD_VIEWS.find((v) => v.id === id)!;
      expect(view.sections, `${id} is missing sec-sessions`).toContain("sec-sessions");
    }
  });
});

describe("sec-playbook-match registration (#230)", () => {
  it("is a registered dashboard section", () => {
    expect(DASHBOARD_SECTION_IDS).toContain("sec-playbook-match");
  });

  it("appears in the Analyst and Hunt Prep profiles", () => {
    for (const id of ["analyst", "hunt-prep"]) {
      const view = BUILT_IN_DASHBOARD_VIEWS.find((v) => v.id === id)!;
      expect(view.sections, `${id} is missing sec-playbook-match`).toContain("sec-playbook-match");
    }
  });
});

describe("sec-host-scope registration (#553)", () => {
  it("is a registered dashboard section", () => {
    expect(DASHBOARD_SECTION_IDS).toContain("sec-host-scope");
  });

  // Registering the id is only half of it. A view's `sections` list IS what it shows, so a section
  // in no view is a section nobody sees: #553 shipped the panel, the markup and SECTION_DEFS entry
  // but put it in no profile, and every analyst on a built-in view got an empty slot where Scope &
  // Clearance should be. Same convention as #347 / #229 / #230.
  it("appears in the Analyst, Lead, Deep-Dive and Report profiles", () => {
    for (const id of ["analyst", "lead", "deep-dive", "report"]) {
      const view = BUILT_IN_DASHBOARD_VIEWS.find((v) => v.id === id)!;
      expect(view.sections, `${id} is missing sec-host-scope`).toContain("sec-host-scope");
    }
  });
});

// Regression: DASHBOARD_SECTION_IDS must mirror the page's SECTION_DEFS exactly.
//
// The spot-checks above are one `toContain` per section, added by whoever remembered. Five sections
// were added without one — sec-host-scope (#553), sec-geomap, sec-huntprofile, sec-velohunts and
// sec-mcp — and every one of them was silently unsaveable: `normalizeDashboardView` drops unknown
// ids without complaint, so the views editor offered a checkbox that unticked itself on save, and
// `applyViewLayout` (which rewrites SECTIONS_VIS_KEY from the active view on every page load) wiped
// the Settings → section-visibility checkbox on every refresh.
//
// Derived from the page rather than hand-listed, so a section added tomorrow fails HERE instead of
// silently losing its checkbox. Reported while testing #553 on 2026-08-14.
describe("dashboardViews — section registry mirrors the page", () => {
  const dashboardHtml = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");

  const sectionDefIds = (): string[] => {
    const block = dashboardHtml.match(/const SECTION_DEFS = \[([\s\S]*?)\n {4}\];/);
    expect(block, "SECTION_DEFS block in dashboard.html").toBeTruthy();
    return [...block![1].matchAll(/id: "(sec-[a-z0-9-]+)"/g)].map((m) => m[1]);
  };

  it("registers every section the visibility editor offers, so none silently unticks on save", () => {
    const defs = sectionDefIds();
    expect(defs.length).toBeGreaterThan(30); // sanity: the scrape actually found the list
    const registered = new Set(DASHBOARD_SECTION_IDS);
    const unsaveable = defs.filter((id) => !registered.has(id));
    expect(
      unsaveable,
      `offered in SECTION_DEFS but dropped by normalizeDashboardView: ${unsaveable.join(", ")}`,
    ).toEqual([]);
  });

  it("registers nothing the page does not render, so a view cannot reference a dead section", () => {
    const defs = new Set(sectionDefIds());
    const orphans = DASHBOARD_SECTION_IDS.filter((id) => !defs.has(id));
    expect(orphans, `registered but absent from SECTION_DEFS: ${orphans.join(", ")}`).toEqual([]);
  });
});
