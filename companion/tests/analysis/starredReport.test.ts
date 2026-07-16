import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

class CapturingProvider implements AIProvider {
  readonly name = "capture";
  lastReq?: AnalyzeRequest;
  private readonly response: object;
  constructor(response: object = { markdown: "# Starred Events Report\n\nreport body" }) { this.response = response; }
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.lastReq = req;
    return { rawText: JSON.stringify(this.response) };
  }
}

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return { timestamp: "2026-01-01T00:00:00Z", description: "", severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}

async function makePipeline(forensic: ForensicEvent[], superEvents: ForensicEvent[] = []) {
  const root = await mkdtemp(join(tmpdir(), "dfir-starredrep-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline = forensic;
  await stateStore.save(s);
  const superTimelineStore = new SuperTimelineStore(cases);
  if (superEvents.length) await superTimelineStore.append("c1", superEvents);
  const provider = new CapturingProvider();
  const pipeline = new AnalysisPipeline({ provider, stateStore, superTimelineStore, imageLoader: async () => ({ base64: "", mimeType: "image/webp" }) });
  return { pipeline, provider };
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("starredReport()", () => {
  it("reports over exactly the starred ids, with an accurate provenance count", async () => {
    const { pipeline, provider } = await makePipeline([
      ev({ id: "e1", description: "mimikatz.exe executed", severity: "Critical", asset: "WS01", timestamp: "2026-01-01T01:00:00Z" }),
      ev({ id: "e2", description: "benign chrome update", severity: "Info", timestamp: "2026-01-01T02:00:00Z" }),
      ev({ id: "e3", description: "RDP logon from 10.9.9.9", severity: "High", asset: "DC01", timestamp: "2026-01-01T03:00:00Z" }),
    ]);
    const result = await pipeline.starredReport("c1", ["e1", "e3"]);
    expect(result.markdown).toContain("# Starred Events Report");
    expect(result.eventCount).toBe(2);
    expect(result.usedEvents).toBe(2);
    expect(result.truncated).toBe(false);
    const prompt = provider.lastReq!.userPrompt;
    expect(prompt).toContain("mimikatz.exe executed");
    expect(prompt).toContain("RDP logon from 10.9.9.9");
    expect(prompt).not.toContain("benign chrome update");     // unstarred events never leak in
    expect(prompt).toContain("based on 2 (deduplicated) starred events");
  });

  it("resolves starred events that exist ONLY in the super-timeline store", async () => {
    const { pipeline, provider } = await makePipeline([], [
      ev({ id: "super1", description: "prefetch: EVIL.EXE executed", asset: "TRIAGE-HOST" }),
    ]);
    const result = await pipeline.starredReport("c1", ["super1"]);
    expect(result.eventCount).toBe(1);
    expect(provider.lastReq!.userPrompt).toContain("prefetch: EVIL.EXE executed");
  });

  it("throws when no starred id resolves to an event", async () => {
    const { pipeline } = await makePipeline([ev({ id: "e1", description: "x" })]);
    await expect(pipeline.starredReport("c1", ["ghost"])).rejects.toThrow("no starred events");
  });

  it("truncates to the event budget and says so in the provenance line", async () => {
    vi.stubEnv("DFIR_AI_SYNTH_MAX_EVENTS", "2");
    const { pipeline, provider } = await makePipeline([
      ev({ id: "e1", description: "critical hit one", severity: "Critical", timestamp: "2026-01-01T01:00:00Z" }),
      ev({ id: "e2", description: "high hit two", severity: "High", timestamp: "2026-01-01T02:00:00Z" }),
      ev({ id: "e3", description: "info row three", severity: "Info", timestamp: "2026-01-01T03:00:00Z" }),
    ]);
    const result = await pipeline.starredReport("c1", ["e1", "e2", "e3"]);
    expect(result.eventCount).toBe(3);
    expect(result.usedEvents).toBe(2);
    expect(result.truncated).toBe(true);
    expect(provider.lastReq!.userPrompt).toContain("2 most significant of 3");
  });

  it("prefers the re-graded FORENSIC copy when the same id exists in both stores", async () => {
    const { pipeline, provider } = await makePipeline(
      [ev({ id: "dup1", description: "regraded suspicious logon (forensic copy)", severity: "High", asset: "DC01" })],
      [ev({ id: "dup1", description: "raw logon row (super copy)", severity: "Info", asset: "DC01" })],
    );
    const result = await pipeline.starredReport("c1", ["dup1"]);
    expect(result.eventCount).toBe(1);
    const prompt = provider.lastReq!.userPrompt;
    expect(prompt).toContain("regraded suspicious logon (forensic copy)");
    expect(prompt).toContain("[High]");
    expect(prompt).not.toContain("raw logon row (super copy)");
  });

  it("sends the starred-report system prompt", async () => {
    const { pipeline, provider } = await makePipeline([ev({ id: "e1", description: "x" })]);
    await pipeline.starredReport("c1", ["e1"]);
    expect(provider.lastReq!.systemPrompt).toContain("Starred Events Report");
  });
});

describe("viewSummary()", () => {
  it("summarizes exactly the events matching the passed filters + label map", async () => {
    const { pipeline, provider } = await makePipeline([], [
      ev({ id: "v1", description: "psexec lateral hop", timestamp: "2026-01-01T01:00:00Z" }),
      ev({ id: "v2", description: "normal dns chatter", timestamp: "2026-01-01T02:00:00Z" }),
    ]);
    const result = await pipeline.viewSummary("c1", { labels: ["exfil"] }, { v1: ["exfil"] });
    expect(result.eventCount).toBe(1);
    const prompt = provider.lastReq!.userPrompt;
    expect(prompt).toContain("psexec lateral hop");
    expect(prompt).not.toContain("normal dns chatter");
  });

  it("applies the starred filter through the label map", async () => {
    const { pipeline, provider } = await makePipeline([], [
      ev({ id: "v1", description: "starred row" }),
      ev({ id: "v2", description: "plain row" }),
    ]);
    await pipeline.viewSummary("c1", { starred: true }, { v1: ["starred"] });
    expect(provider.lastReq!.userPrompt).toContain("starred row");
    expect(provider.lastReq!.userPrompt).not.toContain("plain row");
  });

  it("throws when the filters match nothing", async () => {
    const { pipeline } = await makePipeline([], [ev({ id: "v1", description: "x" })]);
    await expect(pipeline.viewSummary("c1", { labels: ["nope"] }, {})).rejects.toThrow("no events match the current filters");
  });

  it("sends the view-summary system prompt", async () => {
    const { pipeline, provider } = await makePipeline([], [ev({ id: "v1", description: "some row" })]);
    await pipeline.viewSummary("c1", {}, {});
    expect(provider.lastReq!.systemPrompt).toContain("Summarize the following security events");
  });

  it("throws when the super-timeline store is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-starredrep-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save(emptyState("c1"));
    const pipeline = new AnalysisPipeline({ provider: new CapturingProvider(), stateStore, imageLoader: async () => ({ base64: "", mimeType: "image/webp" }) });
    await expect(pipeline.viewSummary("c1", {}, {})).rejects.toThrow("super-timeline not configured");
  });
});
