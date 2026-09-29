import { describe, it, expect } from "vitest";
import { diffReportText, reportMetaHash } from "../../src/reports/reportTextDiff.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";

// #1779: the version / release diff compared only findings, IOCs and the forensic timeline, so a
// version that differed only in Case Details (report-meta) or report text read "no differences".

function record(overrides: { contentHash?: string; markdown?: string; meta?: unknown } = {}) {
  return {
    contentHash: "hash-a",
    markdown: "# report",
    meta: emptyReportMeta(),
    ...overrides,
  };
}

describe("diffReportText", () => {
  it("reports no change for identical records", () => {
    expect(diffReportText(record(), record())).toEqual({ textChanged: false, caseDetailsChanged: [] });
  });

  it("flags a text change from the content hash", () => {
    const result = diffReportText(record(), record({ contentHash: "hash-b", markdown: "# other" }));
    expect(result.textChanged).toBe(true);
    expect(result.caseDetailsChanged).toEqual([]);
  });

  it("falls back to the markdown when a record carries no content hash", () => {
    const from = { markdown: "# one", meta: emptyReportMeta() };
    expect(diffReportText(from, { markdown: "# two", meta: emptyReportMeta() }).textChanged).toBe(true);
    expect(diffReportText(from, { markdown: "# one", meta: emptyReportMeta() }).textChanged).toBe(false);
  });

  it("lists every changed Case Details key in schema order", () => {
    const from = record();
    const to = record({
      meta: {
        ...emptyReportMeta(),
        recommendations: ["Rotate credentials"],
        organization: "Example Org",
        companyName: "Example Firm",
        investigators: ["Analyst One"],
      },
    });
    expect(diffReportText(from, to).caseDetailsChanged).toEqual([
      "companyName",
      "organization",
      "investigators",
      "recommendations",
    ]);
  });

  it("treats a key missing from an older record as its default value", () => {
    const { companyLogo: _logo, ...partial } = emptyReportMeta();
    expect(diffReportText(record({ meta: partial }), record()).caseDetailsChanged).toEqual([]);
  });

  it("detects a nested change inside an array field", () => {
    const base = { ...emptyReportMeta(), distribution: [{ name: "A", role: "CISO", method: "email" }] };
    const next = { ...emptyReportMeta(), distribution: [{ name: "A", role: "CIO", method: "email" }] };
    expect(diffReportText(record({ meta: base }), record({ meta: next })).caseDetailsChanged).toEqual([
      "distribution",
    ]);
  });
});

describe("reportMetaHash", () => {
  it("is stable for equal meta and differs when a field changes", () => {
    const a = reportMetaHash(emptyReportMeta());
    expect(reportMetaHash(emptyReportMeta())).toBe(a);
    expect(reportMetaHash({ ...emptyReportMeta(), organization: "Example Org" })).not.toBe(a);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
  });
});
