// #2543: the IOC tables carry the importer's context note and the analyst's label, safely; the
// block-list leaves an ours/responder value out and says why; a cloud `other` IOC never enters it.
import { describe, expect, it } from "vitest";
import { emptyState, type InvestigationState, type IOC } from "../../src/analysis/stateTypes.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { renderHtmlReport } from "../../src/reports/html.js";
import { iocsCsv } from "../../src/reports/csv.js";
import { buildIocBlocklist, type BlocklistSummary } from "../../src/reports/iocBlocklist.js";
import { buildStixBundle } from "../../src/reports/stix.js";
import { FILTERED_STATE_SIDE_FILES } from "../../src/reports/filteredState.js";

const FORMULA = '=HYPERLINK("http://x")';
const HOSTILE = "pol|icy <script>alert(1)</script>";
const malicious = [
  { source: "vt", verdict: "malicious" as const, fetchedAt: "2026-11-10T00:00:00Z", status: "live" as const },
];

function caseState(): InvestigationState {
  const iocs: IOC[] = [
    {
      id: "i001",
      type: "ip",
      value: "203.0.113.10",
      firstSeen: "t",
      enrichments: malicious,
      attribution: "ours",
    },
    {
      id: "i002",
      type: "ip",
      value: "198.51.100.23",
      firstSeen: "t",
      enrichments: malicious,
      attribution: "attacker",
    },
    {
      id: "i003",
      type: "ip",
      value: "198.51.100.99",
      firstSeen: "t",
      enrichments: malicious,
      attribution: "responder",
    },
    { id: "i006", type: "ip", value: "192.0.2.7", firstSeen: "t", enrichments: malicious },
    {
      id: "i007",
      type: "other",
      value: "quiet-policy",
      firstSeen: "t",
      note: "AWS IAM policy — created by PutUserPolicy",
    },
    {
      id: "i004",
      type: "other",
      value: FORMULA,
      firstSeen: "t",
      attribution: "attacker",
      note: `AWS IAM policy — created by ${FORMULA}`,
      extractedFrom: ["e1"],
    },
    {
      id: "i005",
      type: "other",
      value: HOSTILE,
      firstSeen: "t",
      attribution: "unknown",
      note: `note ${HOSTILE}`,
      extractedFrom: ["e1"],
    },
  ];
  return {
    ...emptyState("c1"),
    iocs,
    forensicTimeline: [
      {
        id: "e1",
        timestamp: "2021-07-29T13:06:49Z",
        severity: "Critical",
        description: `AWS PutUserPolicy (iam) by dev-user ${FORMULA} ${HOSTILE}`,
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: ["AWS CloudTrail"],
      } as never,
    ],
  };
}

describe("IOC tables: label and context (#2543)", () => {
  const md = renderMarkdownReport(caseState());
  const table = md.slice(md.indexOf("### 4.4"), md.indexOf("\n\n", md.indexOf("| ID |")));

  it("the Markdown table has Label and Context columns; an unset label reads —", () => {
    expect(table).toContain("| ID | Type | Value | First seen | Sources | Risk | Label | Context |");
    expect(table).toMatch(/\| i001 \|.*\| ours \|/);
    expect(table).toMatch(/\| i002 \|.*\| attacker \|/);
    expect(table).toMatch(/\| i006 \|.*\| — \| {2}\|$/m);
    expect(table).toMatch(/\| i004 \|.*\| attacker \| AWS IAM policy — created by/);
  });

  it("a labelled IOC is listed even with no threat signal; an unlabelled quiet one stays an observation", () => {
    expect(table).toMatch(/\| i005 \|/);
    expect(table).not.toMatch(/\| i007 \|/);
  });

  it("a pipe in the value and the note stays inside its cell (one row, eight cells)", () => {
    const row = table.split("\n").find((l) => l.startsWith("| i005 |"));
    expect(row).toBeDefined();
    expect(row).toContain("pol\\|icy");
    const cells = row!.replace(/\\\|/g, "").split("|").length - 2;
    expect(cells).toBe(8);
  });

  it("the HTML report escapes a <script> value and note", () => {
    const html = renderHtmlReport(caseState());
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("<td>ours</td>");
  });

  it("the CSV neutralises a formula-shaped value and note and carries note + attribution columns", () => {
    const csv = iocsCsv(caseState());
    const [header, ...rows] = csv.trim().split("\n");
    expect(header.endsWith(",provenance,note,attribution")).toBe(true);
    const formulaRow = rows.find((r) => r.startsWith('"i004"'))!;
    expect(formulaRow).toContain(`"'=HYPERLINK(""http://x"")"`);
    expect(formulaRow).not.toMatch(/(^|,)"=HYPERLINK/);
    expect(rows.find((r) => r.startsWith('"i001"'))).toMatch(/,"ours"$/);
  });

  it("STIX omits a policy-name `other` IOC rather than emitting a pattern from it", () => {
    const patterns = buildStixBundle(caseState())
      .objects.map((o) => String((o as { pattern?: string }).pattern ?? ""))
      .join("\n");
    expect(patterns).not.toContain("HYPERLINK");
    expect(patterns).not.toContain("<script>");
  });
});

describe("block-list and the analyst label (#2543)", () => {
  it("drops ours and responder values, keeps attacker, and says why in the summary", () => {
    const opts = { minSeverity: "Medium" as const };
    const summary = buildIocBlocklist("summary", caseState(), opts) as BlocklistSummary;
    expect(summary.matched).toBe(2); // the attacker address and the unlabelled one
    expect(summary.excluded["labelled-ours"]).toBe(2);
    const txt = buildIocBlocklist("txt", caseState(), opts) as string;
    expect(txt).toContain("198.51.100.23");
    expect(txt).not.toMatch(/^203\.0\.113\.10$/m);
    expect(txt).not.toMatch(/^198\.51\.100\.99$/m);
    expect(txt).toContain("2 labelled ours or responder by the analyst");
  });

  it("an un-enriched ours address is reported as labelled, not as missing intel", () => {
    const s = caseState();
    const state = { ...s, iocs: [{ ...s.iocs[0], enrichments: undefined }] };
    const summary = buildIocBlocklist("summary", state, {}) as BlocklistSummary;
    expect(summary.excluded["labelled-ours"]).toBe(1);
    expect(summary.excluded["no-actionable-intel"]).toBe(0);
  });

  it("a cloud identity (`other`) stays out whatever its label, even attacker", () => {
    const s = caseState();
    const formula = s.iocs.find((i) => i.id === "i004")!;
    const state = { ...s, iocs: [{ ...formula, attribution: "attacker" as const, enrichments: malicious }] };
    const summary = buildIocBlocklist("summary", state, {}) as BlocklistSummary;
    expect(summary.matched).toBe(0);
    expect(summary.excluded["ineligible-type"]).toBe(1);
  });

  it("the report-lite cache keys on the label file", () => {
    expect(FILTERED_STATE_SIDE_FILES).toContain("ioc-attribution.json");
  });
});
