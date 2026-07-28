import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import { normalizeReportTemplate, REPORT_SECTION_DEFS } from "../../src/reports/reportTemplate.js";

// Clock-skew alignment (#228) in the REPORT. A reader who is handed a document has no way to know a
// timestamp was corrected rather than recorded, so an aligned report must say so and must keep the
// recorded time — the actual evidence — on the page.

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id, timestamp,
    description: extra.description ?? "an event",
    severity: extra.severity ?? "Info",
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    ...extra,
  };
}

const timelineOnly = normalizeReportTemplate({
  id: "t",
  name: "timeline only",
  sections: REPORT_SECTION_DEFS.map((s) => ({ key: s.key, enabled: s.key === "timeline" })),
});

function render(forensicTimeline: ForensicEvent[]) {
  return renderMarkdownReport(
    { ...emptyState("c1"), forensicTimeline },
    emptyReportMeta(),
    undefined, undefined, undefined, undefined,
    timelineOnly,
  );
}

describe("clock-skew alignment in the report", () => {
  it("says nothing when no event was aligned", () => {
    const md = render([ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01" })]);
    expect(md).not.toContain("Clock-skew alignment");
    expect(md).not.toContain("Recorded");
  });

  it("discloses the alignment, names the hosts, and keeps the recorded time", () => {
    const md = render([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01" }),
      ev("e2", "2026-05-20T14:01:00Z", {
        asset: "WS-01", originalTimestamp: "2026-05-20T14:03:00Z", skewOffsetMs: 120_000,
      }),
    ]);
    expect(md).toContain("**Clock-skew alignment is ON.**");
    expect(md).toContain("WS-01");
    expect(md).toContain("which is the evidence");
    // The recorded time gets its own column, and the unaligned row leaves it blank.
    expect(md).toContain("| Time | Recorded | Host |");
    expect(md).toContain("2026-05-20T14:03:00Z");
  });
});
