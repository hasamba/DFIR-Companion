import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState, type Finding } from "../../src/analysis/stateTypes.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import {
  normalizeReportTemplate,
  BUILT_IN_REPORT_TEMPLATES,
  REPORT_SECTION_DEFS,
} from "../../src/reports/reportTemplate.js";

// The Compliance Impact report section (#336). The mapping and the deadline maths have their own
// unit tests; what matters here is what a reader of the DOCUMENT sees — above all that the
// not-legal-advice disclaimer is inside the section, since report sections get copied out on
// their own, and that no deadline appears unless the analyst set a discovery date.

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "f1",
    severity: "High",
    title: "Ransomware deployed",
    description: "Files encrypted on VICTIM-PC",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: ["T1486"],
    firstSeen: "2026-01-01T00:00:00.000Z",
    lastUpdated: "2026-01-01T00:00:00.000Z",
    status: "confirmed",
    ...overrides,
  };
}

// A template with ONLY the compliance section, so assertions can't accidentally match text from
// a neighbouring section.
const complianceOnly = normalizeReportTemplate({
  id: "t",
  name: "compliance only",
  sections: REPORT_SECTION_DEFS.map((s) => ({ key: s.key, enabled: s.key === "compliance" })),
});

function render(findings: Finding[], control?: { discoveredAt?: string; frameworks?: string[] }) {
  return renderMarkdownReport(
    { ...emptyState("c1"), findings },
    emptyReportMeta(),
    undefined,
    undefined,
    undefined,
    undefined,
    complianceOnly,
    undefined,
    undefined,
    [],
    undefined,
    undefined,
    undefined,
    control,
  );
}

describe("Compliance Impact report section", () => {
  it("renders control failures and obligations for a confirmed finding", () => {
    const md = render([makeFinding({})]);

    expect(md).toContain("## Compliance Impact");
    expect(md).toContain("T1486");
    expect(md).toContain("**GDPR**");
    expect(md).toContain("Art. 33");
    expect(md).toContain("Notification of a personal data breach to the supervisory authority");
  });

  it("prints the disclaimer inside the section, not only at the top of the report", () => {
    const md = render([makeFinding({})]);
    expect(md).toContain("**Not legal advice.**");
    expect(md).toMatch(/not legal advice/i);
    // And the framework editions, so a reader can tell which revision a control id belongs to.
    expect(md).toContain("ISO 27001 ISO/IEC 27001:2022 Annex A");
  });

  it("keeps the disclaimer even when nothing maps", () => {
    // The empty state is exactly where a reader might assume "no obligations" — the caveat has to
    // survive the early return.
    const md = render([makeFinding({ mitreTechniques: ["T9999"] })]);
    expect(md).toContain("## Compliance Impact");
    expect(md).toMatch(/not legal advice/i);
  });

  it("says so when there are no confirmed findings rather than implying no obligations", () => {
    const md = render([makeFinding({ status: "open" })]);
    expect(md).toContain("derived from confirmed findings only");
  });

  it("states each clock's legal trigger and computes no deadline without a discovery date", () => {
    const md = render([makeFinding({})]);

    expect(md).toContain("No incident-discovery date is set");
    expect(md).toContain("from becoming aware of the personal data breach");
    expect(md).not.toContain("_Computed deadline:_");
  });

  it("computes deadlines once a discovery date is set, and labels the unit", () => {
    const md = render([makeFinding({})], { discoveredAt: "2026-03-05T00:00:00.000Z" });

    expect(md).toContain("_Computed deadline:_ 2026-03-08T00:00:00.000Z"); // GDPR, +72 calendar hours
    expect(md).toContain("_Computed deadline:_ 2026-03-11T00:00:00.000Z"); // 8-K, 4 business days
    expect(md).toContain("P4D (business days)");
    expect(md).toContain("PT72H (calendar time)");
  });

  it("renders no deadline line for a control cadence", () => {
    const md = render([makeFinding({})], { discoveredAt: "2026-03-05T00:00:00.000Z" });

    // CP-9 (backups) is a control, not a notification clock — it must carry neither.
    const cp9 = md.split("\n").findIndex((l) => l.includes("**CP-9**"));
    expect(cp9).toBeGreaterThan(-1);
    expect(
      md
        .split("\n")
        .slice(cp9, cp9 + 3)
        .join("\n"),
    ).not.toContain("Notification clock");
  });

  it("honours the framework filter", () => {
    const md = render([makeFinding({})], { frameworks: ["GDPR"] });
    expect(md).toContain("**GDPR**");
    expect(md).not.toContain("**PCI-DSS**");
  });
});

describe("compliance section registration", () => {
  it("is a canonical section, so saved templates pick it up instead of silently hiding it", () => {
    expect(REPORT_SECTION_DEFS.map((s) => s.key)).toContain("compliance");
    // normalizeSections appends unknown-to-the-template canonical keys as enabled.
    const legacy = normalizeReportTemplate({
      id: "old",
      name: "saved before #336",
      sections: [{ key: "titlePage", enabled: true }],
    });
    expect(legacy.sections.find((s) => s.key === "compliance")).toEqual({ key: "compliance", enabled: true });
  });

  it("is enabled in the built-in templates that should carry it", () => {
    const byId = Object.fromEntries(BUILT_IN_REPORT_TEMPLATES.map((t) => [t.id, t]));
    const enabled = (id: string) => byId[id].sections.find((s) => s.key === "compliance")?.enabled;
    expect(enabled("standard")).toBe(true);
    expect(enabled("technical-detailed")).toBe(true);
    // The exec brief is precisely where "are we obligated to report this?" gets asked (#234).
    expect(enabled("executive-brief")).toBe(true);
  });
});
