import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState, type Finding } from "../../src/analysis/stateTypes.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import {
  normalizeReportTemplate,
  REPORT_SECTION_DEFS,
  BUILT_IN_REPORT_TEMPLATES,
} from "../../src/reports/reportTemplate.js";

// #1406: the Handoff brief report section — off by default, on in Technical Detail, rendered from
// the same brief the dashboard shows, with the outgoing analyst's notebook note.

const finding = {
  id: "f1",
  title: "Beacon on WS-01",
  description: "d",
  severity: "High",
  status: "open",
  confidence: 70,
  relatedIocs: [],
  relatedEventIds: [],
  mitreTechniques: [],
  sourceScreenshots: [],
} as unknown as Finding;

const notes = [
  {
    id: "n1",
    timestamp: "2026-09-19T09:30:00Z",
    text: "Check WS-03 first.",
    type: "handoff" as const,
    author: "alice",
  },
];

describe("handoff brief report section", () => {
  it("is registered, off by default, and on in the Technical Detail template", () => {
    const def = REPORT_SECTION_DEFS.find((d) => d.key === "handoffBrief");
    expect(def && "alwaysOptIn" in def && def.alwaysOptIn).toBe(true);
    // Standard ("every section") does not carry it: opt-in everywhere, like remediation checks.
    const standard = BUILT_IN_REPORT_TEMPLATES.find((t) => t.id === "standard")!;
    expect(standard.sections.find((s) => s.key === "handoffBrief")?.enabled).toBe(false);
    const technical = BUILT_IN_REPORT_TEMPLATES.find((t) => t.id === "technical-detailed")!;
    expect(technical.sections.find((s) => s.key === "handoffBrief")?.enabled).toBe(true);
    // The client-facing brief never carries it; Standard ("every section") does, like every other section.
    const executive = BUILT_IN_REPORT_TEMPLATES.find((t) => t.id === "executive-brief")!;
    expect(executive.sections.find((s) => s.key === "handoffBrief")?.enabled).toBe(false);
  });

  it("renders the brief with the handoff note when enabled, and nothing when not", () => {
    const state = { ...emptyState("c1"), findings: [finding] };
    // Every other section off: the stub hypothesis below is only what the brief reads (title, status).
    const on = normalizeReportTemplate({
      id: "t",
      name: "t",
      sections: REPORT_SECTION_DEFS.map((d) => ({ key: d.key, enabled: d.key === "handoffBrief" })),
    });
    const md = renderMarkdownReport(
      state,
      emptyReportMeta(),
      undefined,
      undefined,
      notes,
      undefined,
      on,
      undefined,
      [{ title: "Phishing entry", status: "open" } as never],
    );
    expect(md).toContain("## Handoff Brief — c1");
    expect(md).toContain("Check WS-03 first.");
    expect(md).toContain("[High] Beacon on WS-01 `f1`");
    expect(md).toContain("- Phishing entry");
    expect(md).toContain("Finding owners and the last import are on the dashboard");
    const off = renderMarkdownReport(state, emptyReportMeta(), undefined, undefined, notes);
    expect(off).not.toContain("## Handoff Brief");
  });
});
