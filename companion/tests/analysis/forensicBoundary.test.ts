import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AnalysisPipeline, VIEW_SUMMARY_MAX_ROWS } from "../../src/analysis/pipeline.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// THE FORENSIC / SUPER-TIMELINE RULE, made executable (#384).
//
// forensicGate.ts splits imported events by severity: Low+ into the forensic timeline, Info into the
// raw super-timeline. The model reads the forensic timeline. The rule exists because a real case
// carries tens of thousands of raw rows, and letting them into automatic analysis exhausts the token
// budget and drowns the signal that earned the forensic cut.
//
// Three analyst-initiated paths touch the raw record. Two now PROMOTE before asking, so the rule
// holds literally. The third is a documented exception. These tests are the difference between that
// being a policy in a comment and a policy the code obeys.

// starredReport and viewSummary both parse `{ markdown }`; they are report writers, not extractors.
const VALID = JSON.stringify({ markdown: "# Report\n\nBody." });

class CapturingProvider implements AIProvider {
  name = "capturing";
  model = "test";
  lastReq: AnalyzeRequest | null = null;
  constructor(private readonly body: string) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.lastReq = req;
    return { rawText: this.body };
  }
}

const ev = (over: Partial<ForensicEvent>): ForensicEvent =>
  ({
    id: "e1",
    timestamp: "2026-01-01T00:00:00Z",
    description: "d",
    severity: "Info",
    sources: [],
    ...over,
  }) as ForensicEvent;

async function harness(rawEvents: ForensicEvent[]) {
  const root = await mkdtemp(join(tmpdir(), "dfir-forensic-rule-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save(emptyState("c1"));
  const superTimelineStore = new SuperTimelineStore(cases);
  if (rawEvents.length) await superTimelineStore.append("c1", rawEvents);
  const provider = new CapturingProvider(VALID);
  const pipeline = new AnalysisPipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    superTimelineStore,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  return { pipeline, stateStore, superTimelineStore, provider };
}

describe("starredReport promotes before the model reads", () => {
  it("moves starred raw events into the forensic timeline first", async () => {
    const { pipeline, stateStore, provider } = await harness([
      ev({ id: "raw1", description: "prefetch: EVIL.EXE", asset: "HOST" }),
      ev({ id: "raw2", description: "amcache: EVIL.EXE", asset: "HOST" }),
      ev({ id: "raw3", description: "unstarred noise", asset: "HOST" }),
    ]);

    await pipeline.starredReport("c1", ["raw1", "raw2"]);

    // Exactly what the analyst starred, and nothing else. Starring is the judgement; promotion is
    // that judgement recorded, which is what makes showing it to the model legal.
    const after = await stateStore.load("c1");
    expect(after.forensicTimeline.map((e) => e.id).sort()).toEqual(["raw1", "raw2"]);
    expect(after.forensicTimeline.map((e) => e.id)).not.toContain("raw3");

    // The prompt renders event DESCRIPTIONS, not ids, so assert on what the model actually sees.
    const prompt = provider.lastReq!.userPrompt;
    expect(prompt).toContain("prefetch: EVIL.EXE");
    expect(prompt).not.toContain("unstarred noise");
  });

  it("records why the promotion happened", async () => {
    const { pipeline, stateStore } = await harness([ev({ id: "raw1", description: "prefetch" })]);
    await pipeline.starredReport("c1", ["raw1"]);
    const after = await stateStore.load("c1");
    // A promoted event that cannot be traced back to a reason is indistinguishable from an import
    // bug six months later.
    const notes = JSON.stringify(after);
    expect(notes).toContain("starred raw event");
  });
});

describe("viewSummary is the documented exception", () => {
  it("reads the raw record WITHOUT promoting anything", async () => {
    const { pipeline, stateStore } = await harness([
      ev({ id: "raw1", description: "row one" }),
      ev({ id: "raw2", description: "row two" }),
    ]);

    await pipeline.viewSummary("c1", {});

    // The exception is bounded by being ephemeral: it may READ the raw record, but nothing it reads
    // enters the case. Promoting here would write thousands of Info rows into the forensic timeline
    // and cause exactly the harm the rule prevents.
    const after = await stateStore.load("c1");
    expect(after.forensicTimeline).toEqual([]);
  });

  it("caps how much of the raw record one call can read", async () => {
    const many = Array.from({ length: VIEW_SUMMARY_MAX_ROWS + 250 }, (_, i) =>
      ev({ id: `bulk${i}`, description: `row ${i}` }),
    );
    const { pipeline, provider } = await harness(many);

    await pipeline.viewSummary("c1", {});

    const prompt = provider.lastReq!.userPrompt;
    // The cap was 10,000 -- more than a model summarises usefully and more than an analyst can
    // check, which made this the widest path into the raw record in the codebase.
    const m = /EVENTS \((\d+) of (\d+)/.exec(prompt);
    expect(m).toBeTruthy();
    expect(Number(m![2])).toBeLessThanOrEqual(VIEW_SUMMARY_MAX_ROWS);
  });

  it("tells the analyst when the cap truncated their view", async () => {
    const many = Array.from({ length: VIEW_SUMMARY_MAX_ROWS + 250 }, (_, i) =>
      ev({ id: `bulk${i}`, description: `row ${i}` }),
    );
    const { pipeline, provider } = await harness(many);

    await pipeline.viewSummary("c1", {});

    // Silently summarising a slice of a 40,000-row filter would read as covering everything.
    expect(provider.lastReq!.userPrompt).toContain("capped at");
    expect(provider.lastReq!.userPrompt).toContain(String(VIEW_SUMMARY_MAX_ROWS));
  });

  it("says nothing about capping when the whole view fit", async () => {
    const { pipeline, provider } = await harness([ev({ id: "raw1" }), ev({ id: "raw2" })]);
    await pipeline.viewSummary("c1", {});
    expect(provider.lastReq!.userPrompt).not.toContain("capped at");
  });

  // The two tests above assert the MODEL is told about the cap. For a long time nothing asserted the
  // ANALYST was, and they were not: the result reported `eventCount: matched.length` — the capped
  // count, not the matched one — so a 750-row filter rendered as "500 matching events" with
  // `truncated: false` whenever those 500 fit the AI budget. The dashboard caption and the Activity
  // Log line both read from these fields, so the 250 excluded rows disappeared from every surface
  // the analyst sees. Disclosing a cap to the model and hiding it from the investigator is the
  // silent-slice failure with an extra step.
  it("reports the TRUE matched count to the analyst, not the capped one", async () => {
    const overCap = VIEW_SUMMARY_MAX_ROWS + 250;
    const { pipeline } = await harness(
      Array.from({ length: overCap }, (_, i) => ev({ id: `bulk${i}`, description: `row ${i}` })),
    );

    const result = await pipeline.viewSummary("c1", {});

    expect(result.eventCount).toBe(overCap); // what MATCHED, not what the cap let through
    expect(result.usedEvents).toBeLessThanOrEqual(VIEW_SUMMARY_MAX_ROWS);
    expect(result.truncated).toBe(true); // true even when every read row fit the AI budget
  });

  it("reports no truncation when the whole matched view was read", async () => {
    // Distinct descriptions: the store folds rows that share a timestamp AND description, so two
    // bare ev() calls would land as one row and the assertion would be measuring the dedupe.
    const { pipeline } = await harness([
      ev({ id: "raw1", description: "prefetch: ONE.EXE" }),
      ev({ id: "raw2", description: "amcache: TWO.EXE" }),
    ]);

    const result = await pipeline.viewSummary("c1", {});

    expect(result.eventCount).toBe(2);
    expect(result.usedEvents).toBe(2);
    expect(result.truncated).toBe(false);
  });
});
