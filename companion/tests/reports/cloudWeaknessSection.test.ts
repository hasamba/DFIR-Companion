// #2560: the "AWS account weaknesses" report section, its template wiring, and its CSV.
import { describe, expect, it } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { renderHtmlReport } from "../../src/reports/html.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import {
  BUILT_IN_REPORT_TEMPLATES,
  normalizeReportTemplate,
  normalizeSections,
  REPORT_SECTION_DEFS,
  type ReportTemplate,
} from "../../src/reports/reportTemplate.js";
import { cloudWeaknessCsv } from "../../src/reports/cloudWeaknessSection.js";
import { summarizeWeaknesses, type WeaknessSummary } from "../../src/analysis/awsAccountWeaknessSummary.js";
import { FILTERED_STATE_SIDE_FILES } from "../../src/reports/filteredState.js";
import type { WeaknessFile } from "../../src/analysis/awsAccountWeakness.js";

const HOSTILE = "evil|`x`[click](javascript:alert(1))<script>alert(1)</script>\n## Forged";

function fileWith(bucket: string): WeaknessFile {
  return {
    accounts: [
      {
        account: "111122223333",
        objectLock: {
          buckets: [{ bucket, cite: { eventId: "ev-1", time: "2026-03-01T10:00:00Z" } }],
          overflow: false,
        },
      },
    ],
    accountsOverflow: false,
  };
}

const only = normalizeReportTemplate({
  id: "t",
  name: "weaknesses only",
  sections: REPORT_SECTION_DEFS.map((s) => ({ key: s.key, enabled: s.key === "cloudWeaknesses" })),
});

const stateWith = (summary?: WeaknessSummary): InvestigationState => ({
  ...emptyState("INC-1"),
  ...(summary ? { cloudWeaknesses: summary } : {}),
});
const md = (state: InvestigationState, template: ReportTemplate = only): string =>
  renderMarkdownReport(state, emptyReportMeta(), undefined, undefined, undefined, undefined, template);

describe("cloudWeaknesses report section (#2560)", () => {
  it("is on in Standard and Technical Detail, off in the Executive Brief and in existing saved templates", () => {
    const enabled = (id: string) =>
      BUILT_IN_REPORT_TEMPLATES.find((t) => t.id === id)!.sections.find((s) => s.key === "cloudWeaknesses")
        ?.enabled;
    expect(enabled("standard")).toBe(true);
    expect(enabled("technical-detailed")).toBe(true);
    expect(enabled("executive-brief")).toBe(false);
    expect(
      normalizeSections([{ key: "titlePage", enabled: true }]).find((s) => s.key === "cloudWeaknesses")
        ?.enabled,
    ).toBe(false);
  });

  it("renders nothing for a case with no weakness file, so a non-cloud report is unchanged", () => {
    expect(md(stateWith())).not.toMatch(/AWS account weaknesses/);
    expect(md(stateWith(summarizeWeaknesses(null)))).not.toMatch(/AWS account weaknesses/);
  });

  it("says none matched when the file exists but holds no weakness, and always states the limits", () => {
    const out = md(stateWith(summarizeWeaknesses({ accounts: [], accountsOverflow: false })));
    expect(out).toMatch(/## AWS account weaknesses/);
    expect(out).toMatch(/None of the checks matched the CloudTrail records read so far/);
    expect(out).toMatch(/Records already in the case are not read again/);
  });

  it("keeps an adversary bucket name literal in Markdown: no live link, heading or table break", () => {
    const out = md(stateWith(summarizeWeaknesses(fileWith(HOSTILE))));
    const line = out.split("\n").find((l) => l.includes("Bucket has no Object Lock"))!;
    expect(line).toMatch(/bucket ``+ evil\|/); // a code span longer than the inner backtick run
    expect(line).toContain("` ev-1 `");
    expect(out).not.toMatch(/^## Forged/m);
  });

  it("escapes the bucket name in the HTML export", () => {
    const html = renderHtmlReport(
      stateWith(summarizeWeaknesses(fileWith(HOSTILE))),
      emptyReportMeta(),
      undefined,
      undefined,
      undefined,
      undefined,
      only,
    );
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toMatch(/href="javascript:/i);
    expect(html).toMatch(/&lt;script&gt;/);
  });

  it("formula-guards the CSV and keeps one row per cited record", () => {
    const csv = cloudWeaknessCsv(summarizeWeaknesses(fileWith('=HYPERLINK("http://x")')));
    const lines = csv.trim().split("\n");
    expect(lines[0]).toBe('"kind","title","account","bucket","detail","record_role","event_id","event_time"');
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain(`"'=HYPERLINK(""http://x"")"`);
  });

  it("is a report-lite cache input", () => {
    expect(FILTERED_STATE_SIDE_FILES).toContain("cloud-weaknesses.json");
  });
});
