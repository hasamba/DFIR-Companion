import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import {
  normalizeReportTemplate,
  BUILT_IN_REPORT_TEMPLATES,
  REPORT_SECTION_DEFS,
} from "../../src/reports/reportTemplate.js";

// The Attacker Sessions report section (#343). segmentSessions has its own unit tests; what matters
// here is what a reader of the DOCUMENT sees — that the chapters are numbered and ordered, that the
// unknown-host bucket is never dressed up as a machine name, and that the section respects the
// template toggle.

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: extra.description ?? "",
    severity: extra.severity ?? "Info",
    mitreTechniques: extra.mitreTechniques ?? [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

// A template with ONLY the sessions section, so assertions can't match a neighbouring section.
const sessionsOnly = normalizeReportTemplate({
  id: "t",
  name: "sessions only",
  sections: REPORT_SECTION_DEFS.map((s) => ({ key: s.key, enabled: s.key === "sessions" })),
});

function render(forensicTimeline: ForensicEvent[], template = sessionsOnly) {
  return renderMarkdownReport(
    { ...emptyState("c1"), forensicTimeline },
    emptyReportMeta(),
    undefined,
    undefined,
    undefined,
    undefined,
    template,
  );
}

describe("Attacker Sessions report section", () => {
  it("renders the sessions as numbered chapters in chronological order", () => {
    const md = render([
      ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01", mitreTechniques: ["T1566"] }),
      ev("e2", "2026-05-20T14:01:00Z", { asset: "DC01" }),
      ev("e3", "2026-05-20T20:00:00Z", { asset: "WS02" }),
    ]);

    expect(md).toContain("## Attacker Sessions");
    expect(md).toContain("2 session(s) across 2 host(s)");
    expect(md).toContain("| 1 | DC01 |");
    expect(md).toContain("| 2 | WS02 |");
    // Chapter 1 must precede chapter 2 in the document, not merely both be present.
    expect(md.indexOf("| 1 | DC01 |")).toBeLessThan(md.indexOf("| 2 | WS02 |"));
    expect(md).toContain("Initial Access");
  });

  it("names the account when a logon established one", () => {
    const md = render([
      ev("e1", "2026-05-20T14:00:00Z", {
        asset: "SRV-01",
        description: "Windows Security Successful logon (EID 4624) - CORP\\jdoe - LogonType=10 @ SRV-01",
      }),
    ]);
    expect(md).toContain("CORP\\jdoe");
  });

  it("never presents the unknown-host bucket as a machine name", () => {
    const md = render([ev("e1", "2026-05-20T14:00:00Z")]); // no asset

    expect(md).toContain("_(host not recorded)_");
    expect(md).not.toContain("(unknown host)");
    // And the caveat must ship with it — a reader must not take that row for one machine.
    expect(md).toMatch(/grouped by time alone and may span more than one machine/);
  });

  it("omits the unknown-host caveat when every session has a real host", () => {
    const md = render([ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01" })]);
    expect(md).not.toMatch(/may span more than one machine/);
  });

  it("says so plainly when there are no dated events", () => {
    const md = render([]);
    expect(md).toContain("## Attacker Sessions");
    expect(md).toContain("_No dated events in scope");
  });

  it("escapes a pipe in a host name so it cannot break the table", () => {
    const md = render([ev("e1", "2026-05-20T14:00:00Z", { asset: "we|rd" })]);
    expect(md).toContain("we\\|rd");
  });

  it("is omitted entirely when the template disables it", () => {
    const off = normalizeReportTemplate({
      id: "t",
      name: "no sessions",
      sections: REPORT_SECTION_DEFS.map((s) => ({ key: s.key, enabled: s.key !== "sessions" })),
    });
    const md = render([ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01" })], off);
    expect(md).not.toContain("## Attacker Sessions");
  });

  it("is on for the technical template and off for the executive brief", () => {
    const tech = BUILT_IN_REPORT_TEMPLATES.find((t) => t.id === "technical-detailed")!;
    const brief = BUILT_IN_REPORT_TEMPLATES.find((t) => t.id === "executive-brief")!;
    const events = [ev("e1", "2026-05-20T14:00:00Z", { asset: "DC01" })];

    expect(render(events, tech)).toContain("## Attacker Sessions");
    expect(render(events, brief)).not.toContain("## Attacker Sessions");
  });
});
