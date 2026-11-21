import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import {
  BUILT_IN_REPORT_TEMPLATES,
  HUNT_REPORT_TEMPLATE,
  defaultReportTemplate,
} from "../../src/reports/reportTemplate.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { HuntReportData } from "../../src/analysis/huntReport.js";

const ev = (id: string, severity: ForensicEvent["severity"]): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: id,
  severity,
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const hunt = (p: Partial<HuntReportData> = {}): HuntReportData => ({
  coverage: { known: false, reason: "coverage unknown: no Companion-launched hunt was collected" },
  hunts: [],
  items: [],
  pending: [],
  comparison: null,
  ...p,
});

const render = (state = emptyState("c1"), data?: HuntReportData, template = HUNT_REPORT_TEMPLATE) =>
  renderMarkdownReport(
    state,
    emptyReportMeta(),
    undefined,
    undefined,
    undefined,
    undefined,
    template,
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    data,
  );

describe("Threat hunt summary report (#2670)", () => {
  it("is a built-in template, off in every other template", () => {
    expect(BUILT_IN_REPORT_TEMPLATES.map((t) => t.id)).toContain("threat-hunt-summary");
    for (const t of BUILT_IN_REPORT_TEMPLATES.filter((x) => x.id !== "threat-hunt-summary"))
      expect(t.sections.find((s) => s.key === "huntSummary")?.enabled, t.id).toBe(false);
    expect(render(emptyState("c1"), hunt(), defaultReportTemplate())).not.toContain("Threat hunt summary");
  });

  it("puts the hunt summary straight after the executive summary and drops the incident chapters", () => {
    const keys = HUNT_REPORT_TEMPLATE.sections.filter((s) => s.enabled).map((s) => s.key);
    expect(keys.indexOf("huntSummary")).toBe(keys.indexOf("executiveSummary") + 1);
    expect(keys).not.toContain("sessions");
    expect(keys).not.toContain("d3fend");
  });

  it("says plainly when there is nothing to compare, and that coverage is unknown", () => {
    const md = render(emptyState("c1"), hunt());
    expect(md).toContain("## Threat hunt summary");
    expect(md).toContain("Nothing to compare yet");
    expect(md).toContain("coverage unknown");
    expect(md).toContain("**No compromise found**, within coverage.");
  });

  it("qualifies the verdict by coverage and escalates on a High row", () => {
    const state = { ...emptyState("c1"), forensicTimeline: [ev("x", "High")] };
    const md = render(
      state,
      hunt({
        coverage: {
          known: true,
          answered: 287,
          targeted: 300,
          notAnswered: 13,
          huntsWithCoverage: 1,
          huntsWithoutCoverage: 0,
          partialArtifacts: 0,
          partialArtifactNames: [],
          collectedArtifactNames: [],
          answeredHosts: [{ clientId: "C.1", hostname: "ws-1" }],
        },
      }),
    );
    expect(md).toContain("**Compromise suspected");
    expect(md).toContain("287 host(s) of 300 targeted answered cleanly; 13 did not answer");
  });

  it("lists graded items with their hosts and escapes client-supplied text", () => {
    const md = render(
      emptyState("c1"),
      hunt({
        items: [
          {
            kind: "rare",
            label: "evil|tool.exe",
            hosts: ["ws-1"],
            moreHosts: 2,
            hostCount: 3,
            severity: "Medium",
            reason: "on 3 of 300 answering hosts",
          },
        ],
        pending: [{ label: "7zip", hostCount: 4, firstSeen: "2026-01-01", huntsUnconfirmed: 2 }],
      }),
    );
    expect(md).toContain("#### Rare across the hosts that answered");
    expect(md).toContain("evil\\|tool.exe");
    expect(md).toContain("(+2 more)");
    expect(md).toContain("**Anomalies need follow-up");
    expect(md).toContain("| 7zip | 4 | 2026-01-01 | 2 hunt(s) |");
  });
});
