import { describe, it, expect } from "vitest";
import { marked } from "marked";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import { normalizeReportTemplate, REPORT_SECTION_DEFS } from "../../src/reports/reportTemplate.js";
import type { CustodyRecord } from "../../src/analysis/custody.js";

// The "Chain of Custody" report appendix (#231 item 4). The custody store and its verification have
// their own tests; what matters here is what a reader of the DOCUMENT sees — that each artifact is
// listed with its hash and every event that touched it, and that an empty case does not leave a
// bare heading behind in a court-facing deliverable.

function record(over: Partial<CustodyRecord> = {}): CustodyRecord {
  return {
    artifactPath: "/cases/INC-1/imports/0001_evidence.csv",
    sha256: "a".repeat(64),
    collectedBy: "alice",
    collectedAt: "2026-07-28T10:00:00.000Z",
    source: "WORKSTATION-7",
    trigger: "import",
    caseId: "INC-1",
    event: "collected",
    seq: 1,
    prevHash: "",
    ...over,
  };
}

// A template with ONLY the custody section, so assertions cannot match a neighbouring section.
const custodyOnly = normalizeReportTemplate({
  id: "t",
  name: "custody only",
  sections: REPORT_SECTION_DEFS.map((s) => ({ key: s.key, enabled: s.key === "chainOfCustody" })),
});

const render = (custody?: CustodyRecord[]): string =>
  renderMarkdownReport(
    emptyState("INC-1"),
    emptyReportMeta(),
    undefined,
    undefined,
    undefined,
    undefined,
    custodyOnly,
    undefined,
    undefined,
    [],
    null,
    undefined,
    null,
    undefined,
    custody,
  );

describe("chain of custody appendix", () => {
  it("is offered as a toggleable report section", () => {
    expect(REPORT_SECTION_DEFS.map((s) => s.key)).toContain("chainOfCustody");
  });

  it("lists each artifact with its hash", () => {
    const text = render([record()]);

    expect(text).toContain("Chain of Custody");
    expect(text).toContain("0001_evidence.csv");
    expect(text).toContain("a".repeat(64));
  });

  it("lists every event that touched an artifact, in order", () => {
    const text = render([
      record(),
      record({
        event: "transferred",
        collectedBy: "bob",
        collectedAt: "2026-07-28T11:00:00.000Z",
        source: "lab-3",
        seq: 2,
      }),
      record({
        event: "exported",
        collectedBy: "alice",
        collectedAt: "2026-07-28T12:00:00.000Z",
        source: "encrypted archive",
        seq: 3,
      }),
    ]);

    expect(text.indexOf("collected")).toBeLessThan(text.indexOf("transferred"));
    expect(text.indexOf("transferred")).toBeLessThan(text.indexOf("exported"));
    expect(text).toContain("bob");
    expect(text).toContain("lab-3");
  });

  it("groups events under the artifact they belong to", () => {
    const text = render([
      record(),
      record({ artifactPath: "/cases/INC-1/screenshots/000001_shot.webp", sha256: "b".repeat(64), seq: 2 }),
    ]);

    expect(text).toContain("0001_evidence.csv");
    expect(text).toContain("000001_shot.webp");
    expect(text).toContain("b".repeat(64));
  });

  it("says so plainly when nothing was recorded, rather than leaving a bare heading", () => {
    const text = render([]);

    expect(text).toContain("Chain of Custody");
    expect(text).toMatch(/no custody records/i);
  });

  it("renders nothing at all when the section is disabled", () => {
    const withoutCustody = normalizeReportTemplate({
      id: "t2",
      name: "no custody",
      sections: REPORT_SECTION_DEFS.map((s) => ({ key: s.key, enabled: s.key !== "chainOfCustody" })),
    });

    const text = renderMarkdownReport(
      emptyState("INC-1"),
      emptyReportMeta(),
      undefined,
      undefined,
      undefined,
      undefined,
      withoutCustody,
      undefined,
      undefined,
      [],
      null,
      undefined,
      null,
      undefined,
      [record()],
    );

    expect(text).not.toContain("Chain of Custody");
  });

  it("does not break a report rendered without any custody data at all", () => {
    expect(() => render(undefined)).not.toThrow();
  });
});

// #2052 — the artifact path is attacker-chosen (a filename on mounted evidence, an uploaded evidence
// file). It must stay inside its own code span on its own list item: a newline must not start a
// forged section, and a backtick must not close the span early and let the rest render as Markdown.
describe("chain of custody appendix — hostile artifact paths (#2052)", () => {
  const lineStarting = (text: string, prefix: string): string =>
    text.split("\n").find((l) => l.startsWith(prefix)) ?? "";
  const toHtml = (md: string): string => marked.parse(md, { async: false });

  it("does not let a newline in the path forge a report heading", () => {
    const text = render([record({ artifactPath: "/ev/evil\n## 5 Conclusion\nx.bin" })]);

    expect(text.split("\n").some((l) => /^#{1,6}\s*5 Conclusion/.test(l))).toBe(false);
    expect(lineStarting(text, "- Path:")).toContain("/ev/evil ## 5 Conclusion x.bin");
    expect(toHtml(text)).not.toMatch(/<h\d[^>]*>\s*5 Conclusion/);
  });

  it("keeps a path containing backticks inside one code span", () => {
    const text = render([record({ artifactPath: "/ev/a`b **bold** `c.bin" })]);
    const pathLine = lineStarting(text, "- Path:");

    expect(pathLine).toBe("- Path: `` /ev/a`b **bold** `c.bin ``");
    const html = toHtml(pathLine);
    expect(html).toContain("<code>/ev/a`b **bold** `c.bin</code>");
    expect(html).not.toContain("<strong>");
  });

  it("renders an ordinary path as the same inline code it always was", () => {
    const html = toHtml(lineStarting(render([record()]), "- Path:"));

    expect(html).toContain("<code>/cases/INC-1/imports/0001_evidence.csv</code>");
  });

  it("keeps a forged hash value inside its code span on one line", () => {
    const text = render([record({ sha256: "ab`c\n## Forged" })]);

    expect(text.split("\n").some((l) => /^#{1,6}\s*Forged/.test(l))).toBe(false);
    expect(lineStarting(text, "- SHA-256:")).toBe("- SHA-256: `` ab`c ## Forged ``");
  });

  it("keeps the artifact heading on one trimmed line", () => {
    const text = render([record({ artifactPath: "/ev/name with  trailing\r\n" })]);

    expect(lineStarting(text, "### ")).toBe("### name with  trailing");
  });
});
