// #2543: a cloud identity IOC (`other`) never gets a threat-intel verdict, so the risk score calls it
// an observation and the report IOC table left it out unless labelled. The user's rule: an IOC
// extracted from a High/Critical event (its `extractedFrom` link) is listed. One linked only to a
// Low event, or not linked at all, is still an observation.
import { describe, expect, it } from "vitest";
import {
  emptyState,
  type ForensicEvent,
  type InvestigationState,
  type IOC,
} from "../../src/analysis/stateTypes.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { renderHtmlReport } from "../../src/reports/html.js";
import { iocsLinkedToHighEvent } from "../../src/analysis/iocHighLink.js";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { CREATED_KEY, LAB_ACCOUNT, sans504Upload } from "../analysis/fixtures/sans504Lab.js";

const FORMULA = '=HYPERLINK("http://x")';
const HOSTILE = "arn:aws:iam::111122223333:user/a|b<script>alert(1)</script>";

function event(id: string, severity: ForensicEvent["severity"]): ForensicEvent {
  return {
    id,
    timestamp: "2021-07-29T13:06:49Z",
    severity,
    description: `AWS row ${id}`,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["AWS CloudTrail"],
  };
}

function caseState(): InvestigationState {
  const iocs: IOC[] = [
    {
      id: "i001",
      type: "other",
      value: HOSTILE,
      firstSeen: "t",
      note: "AWS IAM principal",
      extractedFrom: ["eHigh"],
    },
    {
      id: "i002",
      type: "other",
      value: FORMULA,
      firstSeen: "t",
      note: "AWS IAM policy",
      extractedFrom: ["eCrit"],
    },
    { id: "i003", type: "other", value: "low-linked-key", firstSeen: "t", extractedFrom: ["eLow"] },
    { id: "i004", type: "other", value: "unlinked-policy", firstSeen: "t" },
    { id: "i005", type: "other", value: "missing-event", firstSeen: "t", extractedFrom: ["eGone"] },
  ];
  return {
    ...emptyState("c1"),
    iocs,
    forensicTimeline: [event("eHigh", "High"), event("eCrit", "Critical"), event("eLow", "Low")],
  };
}

describe("iocsLinkedToHighEvent", () => {
  it("returns the IOCs whose extractedFrom names a High or Critical event, nothing else", () => {
    const s = caseState();
    expect([...iocsLinkedToHighEvent(s.iocs, s.forensicTimeline)].sort()).toEqual(["i001", "i002"]);
  });
});

describe("report IOC table lists IOCs extracted from a High event (#2543)", () => {
  const md = renderMarkdownReport(caseState());
  const table = md.slice(md.indexOf("### 4.4"), md.indexOf("\n\n", md.indexOf("| ID |")));

  it("Markdown lists the High- and Critical-linked IOCs, escaped, and not the Low-linked or unlinked", () => {
    const row = table.split("\n").find((l) => l.startsWith("| i001 |"));
    expect(row).toBeDefined();
    expect(row).toContain("a\\|b");
    expect(row!.replace(/\\\|/g, "").split("|").length - 2).toBe(8);
    expect(table).toMatch(/\| i002 \|/);
    expect(table).not.toMatch(/\| i003 \|/);
    expect(table).not.toMatch(/\| i004 \|/);
    expect(table).not.toMatch(/\| i005 \|/);
    expect(md).toContain("_Plus 3 observation(s)");
  });

  it("HTML lists them with the value escaped", () => {
    const html = renderHtmlReport(caseState());
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("<td>i001</td>");
    expect(html).toContain("<td>i002</td>");
    expect(html).not.toContain("<td>i003</td>");
    expect(html).not.toContain("<td>i004</td>");
  });
});

// The same rule on a real merged case: the SANS 504 lab through the non-streamed CloudTrail import.
describe("SANS 504 lab: the principal and the issued key reach the report table (#2543)", () => {
  it("lists the High-linked identity IOCs in the Markdown IOC table", async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-iochigh-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "{}"),
      stateStore: new StateStore(cases),
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const state = await pipeline.importAws("c1", sans504Upload(), {
      label: "trail.json",
      idPrefix: "a1",
      importedAt: "2026-11-10T00:00:00Z",
    });
    const linked = iocsLinkedToHighEvent(state.iocs, state.forensicTimeline);
    const md = renderMarkdownReport(state);
    const table = md.slice(md.indexOf("### 4.4"), md.indexOf("\n\n", md.indexOf("| ID |")));
    for (const v of [`arn:aws:iam::${LAB_ACCOUNT}:user/example-user`, CREATED_KEY]) {
      const ioc = state.iocs.find((i) => i.value === v);
      expect(ioc, v).toBeDefined();
      expect(linked.has(ioc!.id), v).toBe(true);
      expect(table, v).toContain(v);
    }
  }, 60_000);
});
