import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// #959 AC3: two events that share a 300-character prefix and differ only in the tail reach the
// model as two distinct lines — through normal synthesis, explainEvent and viewSummary.

class CapturingProvider implements AIProvider {
  readonly name = "capture";
  readonly model = "mock-model";
  prompts: string[] = [];
  constructor(private readonly body: object) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.prompts.push(req.userPrompt ?? "");
    return { rawText: JSON.stringify(this.body) };
  }
}

const SYNTH_OK = {
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "",
};
const EXPLAIN_OK = {
  summary: "s",
  whyItMatters: "w",
  normalContext: "n",
  suspiciousIndicators: "i",
  attackMapping: "a",
  pivotQueries: [],
  evidenceFor: "f",
  evidenceAgainst: "g",
  relatedEventIds: [],
};
const MARKDOWN_OK = { markdown: "# r\n\nb" };

const PREFIX = "M365 FileDownloaded by user@x — /sites/Finance/Shared Documents/" + "Sub/".repeat(70);
const ev = (id: string, tail: string): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: `${PREFIX}${tail}`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "HOST",
  sources: ["M365"],
});

async function harness(body: object, opts: { raw?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-desc-paths-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const superTimelineStore = new SuperTimelineStore(cases);
  const s = emptyState("c1");
  const pair = [ev("e1", "Q3-forecast.xlsx"), ev("e2", "Q4-forecast.xlsx")];
  if (opts.raw) await superTimelineStore.append("c1", pair);
  else s.forensicTimeline = pair;
  await stateStore.save(s);
  const provider = new CapturingProvider(body);
  const pipeline = new AnalysisPipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    superTimelineStore,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  return { pipeline, provider };
}

// The line the model saw for one event id — or, for id-less rows, every line carrying the prefix.
const linesWith = (prompt: string, needle: string): string[] =>
  prompt.split("\n").filter((l) => l.includes(needle));

describe("two events differing only past the cut are two lines to the model", () => {
  it("in normal synthesis", async () => {
    const { pipeline, provider } = await harness(SYNTH_OK);
    await pipeline.synthesize("c1").catch(() => undefined);
    const prompt = provider.prompts.at(-1) ?? "";
    const l1 = linesWith(prompt, "[e1]");
    const l2 = linesWith(prompt, "[e2]");
    expect(l1.length).toBeGreaterThan(0);
    expect(l2.length).toBeGreaterThan(0);
    expect(l1[0]).toContain("Q3-forecast.xlsx");
    expect(l2[0]).toContain("Q4-forecast.xlsx");
  });

  it("in explainEvent", async () => {
    const { pipeline, provider } = await harness(EXPLAIN_OK);
    await pipeline.explainEvent("c1", "e1");
    const prompt = provider.prompts.at(-1) ?? "";
    expect(linesWith(prompt, "[e1]")[0]).toContain("Q3-forecast.xlsx");
    expect(linesWith(prompt, "[e2]")[0]).toContain("Q4-forecast.xlsx");
  });

  it("in viewSummary", async () => {
    const { pipeline, provider } = await harness(MARKDOWN_OK, { raw: true });
    await pipeline.viewSummary("c1", {});
    const prompt = provider.prompts.at(-1) ?? "";
    const rows = linesWith(prompt, "M365 FileDownloaded");
    expect(rows).toHaveLength(2);
    expect(rows.join("\n")).toContain("Q3-forecast.xlsx");
    expect(rows.join("\n")).toContain("Q4-forecast.xlsx");
    expect(rows[0]).not.toBe(rows[1]);
  });
});
