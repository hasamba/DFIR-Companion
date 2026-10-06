import { describe, it, expect } from "vitest";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";
import { buildSecondOpinionDeltas, buildReconcilePrompt } from "../../src/analysis/secondOpinion.js";
import { renderEventLine, renderTaggedEventLine } from "../../src/analysis/ai/eventLine.js";
import { renderStructuredTags } from "../../src/analysis/synthEvidence.js";

// #1960: the referee reads the same structured row tags synthesis reads. Without them a build-time
// row, a network connection or a long cut command line reached the referee as bare prose, and it
// judged the two models' disagreement with less than either model saw.

function finding(over: Partial<Finding> & Pick<Finding, "id" | "title" | "severity">): Finding {
  return {
    confidence: 80,
    description: `${over.title} description`,
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "2026-06-01T00:00:00.000Z",
    lastUpdated: "2026-06-01T00:00:00.000Z",
    status: "open",
    ...over,
  };
}

function event(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-06-01T10:00:00.000Z",
    description: `${id} happened`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

function stateWith(over: Partial<InvestigationState>): InvestigationState {
  return { ...emptyState("c1"), ...over };
}

const LONG_DESC = `Process Create: ${"x".repeat(400)} @ WS01`;
const ROWS: ForensicEvent[] = [
  event("bt1", {
    asset: "WS01",
    description: "Security log cleared",
    buildTime: { marker: "host build 2026-05-30", window: "w1" },
  }),
  event("net1", {
    asset: "WS01",
    description: "Network connection",
    processName: "rundll32.exe",
    srcIp: "10.0.0.5",
    dstIp: "203.0.113.9",
    port: 443,
  }),
  event("cmd1", {
    description: LONG_DESC,
    processName: "powershell.exe",
    commandLine: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi",
  }),
  event("bare1", { description: "plain row" }),
];

const A = stateWith({
  findings: [
    finding({
      id: "f1",
      title: "Log clearing",
      severity: "High",
      relatedEventIds: ["bt1", "net1", "cmd1", "bare1"],
    }),
  ],
  forensicTimeline: ROWS,
});
const B = stateWith({
  findings: [finding({ id: "g1", title: "Log clearing", severity: "Low" })],
  forensicTimeline: ROWS,
});

const prompt = buildReconcilePrompt(A, B, buildSecondOpinionDeltas(A, B));
const lineFor = (id: string) => prompt.split("\n").find((l) => l.includes(`[${id}]`)) ?? "";

describe("referee event lines carry the synthesis structured tags (#1960)", () => {
  it("renders <build-time:…> on a build-time row", () => {
    expect(lineFor("bt1")).toContain("<build-time:host build 2026-05-30>");
  });

  it("renders <net:…> and <proc:…> on a network row", () => {
    const line = lineFor("net1");
    expect(line).toContain("<net:10.0.0.5→203.0.113.9:443>");
    expect(line).toContain("<proc:rundll32.exe>");
  });

  it("renders <cmd:…> when the description render cuts the command line", () => {
    expect(lineFor("cmd1")).toContain("<cmd:-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi>");
  });

  it("uses the <host:…> tag instead of the bare asset form", () => {
    expect(lineFor("bt1")).toContain("<host:WS01>");
    expect(lineFor("bt1")).not.toContain("] <WS01>");
  });

  it("renders a row with no asset and no tags exactly as before", () => {
    const bare = ROWS[3];
    expect(lineFor("bare1").endsWith(` ${renderEventLine(bare)}`)).toBe(true);
    expect(renderTaggedEventLine(bare)).toBe(renderEventLine(bare));
  });

  // #1980: tags also come from description text, so "no structured fields" is not enough.
  it("differs from renderEventLine for a no-asset row whose description holds a URL", () => {
    const url = event("url1", {
      description: "Download from https://files.example.com/a.ps1",
    });
    const tags = renderStructuredTags(url);
    expect(tags).not.toBe("");
    expect(renderTaggedEventLine(url)).not.toBe(renderEventLine(url));
    expect(renderTaggedEventLine(url)).toBe(`${renderEventLine(url)}${tags}`);
  });

  it("is renderEventLine without the asset, plus renderStructuredTags, for every row", () => {
    for (const e of ROWS) {
      const plain = renderEventLine({ ...e, asset: undefined });
      expect(renderTaggedEventLine(e)).toBe(`${plain}${renderStructuredTags(e)}`);
      expect(renderTaggedEventLine(e) === renderEventLine(e)).toBe(renderStructuredTags(e) === "");
    }
  });
});

describe("renderEventLine (gap-hypothesis shape) is unchanged", () => {
  it("keeps the bare <asset> form and adds no tags", () => {
    expect(renderEventLine(ROWS[1])).toBe(
      "[net1] 2026-06-01T10:00:00.000Z [Medium] <WS01> Network connection",
    );
    expect(renderEventLine(ROWS[0])).not.toContain("<build-time:");
  });
});
