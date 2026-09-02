import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ScopeStore } from "../../src/analysis/scope.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { FalsePositiveStore, markerId } from "../../src/analysis/falsePositive.js";
import { HuntOutcomeStore } from "../../src/analysis/huntOutcomeStore.js";
import { IncidentTypeStore } from "../../src/analysis/incidentTypeStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import type { AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { projectScope } from "../../src/analysis/scopeProject.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

/**
 * Characterisation tests for synthesize (#418).
 *
 * `synthesize` is 695 lines and its output is a MODEL CALL, so "unchanged behaviour" cannot be
 * proved the way #384 proved its two extractions — no prompt hash, no five-member interface. These
 * tests are the substitute: they pin the ORCHESTRATION around the model call, which is what an
 * extraction actually moves. Four seams, named by the issue:
 *
 *   1. scope selection  — which events reach the prompt, and how each omission is attributed
 *   2. the delta merge  — what survives the wholesale findings rewrite, and the lost-update guard
 *   3. second-look      — covered end-to-end in secondLookLoop.test.ts; not repeated here
 *   4. skip-when-unchanged — exactly which inputs are in the hash
 *
 * Everything here asserts on state the pipeline persisted or on the prompt text it sent, never on a
 * private method, so the same assertions hold after synthesize becomes a free function.
 */

let caseStore: CaseStore;
let stateStore: StateStore;

// Medium by default: high enough to earn a prompt seat, low enough that the Critical/High backfill
// stays out of the way. A test that wants the backfill asks for Critical explicitly.
function event(
  id: string,
  timestamp: string,
  description: string,
  severity: ForensicEvent["severity"] = "Medium",
  extra: Partial<ForensicEvent> = {},
): ForensicEvent {
  return {
    id,
    timestamp,
    description,
    severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

// A synthesis delta that returns ONE finding and nothing else, so every assertion below is about
// what the pipeline preserved around the model rather than what the model said.
function delta(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    findings: [
      {
        id: "f1",
        severity: "High",
        title: "synth finding",
        description: "d",
        relatedIocs: [],
        mitreTechniques: [],
        status: "open",
        relatedEventIds: [],
      },
    ],
    iocs: [],
    mitreTechniques: [],
    attackerPath: "p",
    summary: "s",
    forensicEvents: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    ...overrides,
  });
}

// A provider that records the prompt it was sent and can run a side effect DURING the call — the
// only way to exercise the lost-update guard, which exists precisely for writes that land while the
// model is thinking.
function spyProvider(rawText: string, during?: () => Promise<void>) {
  const sent: string[] = [];
  const provider = {
    name: "spy",
    model: "spy-model",
    analyze: async (req: AnalyzeRequest): Promise<AnalyzeResult> => {
      sent.push(req.userPrompt);
      if (during) await during();
      return { rawText };
    },
  };
  return { provider, sent };
}

// Env stubs are undone here, not at the end of the test that set them: an assertion failure throws
// past an inline `unstubAllEnvs`, leaking a stubbed DFIR_* into every test that runs after it.
afterEach(() => {
  vi.unstubAllEnvs();
});

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-synth-char-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(caseStore);
});

describe("synthesize — scope selection", () => {
  it("attributes each omitted event to its own coverage bucket: scope, legitimate, then Info", async () => {
    // One event per omission reason plus one that reaches the prompt, so every bucket is non-zero
    // and a mis-attribution shows up as a specific number rather than a total that happens to match.
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      event("out", "2024-01-01T00:00:00.000Z", "before the window"),
      event("fp", "2026-01-02T00:00:00.000Z", "analyst says benign"),
      event("info", "2026-01-03T00:00:00.000Z", "routine chatter", "Info"),
      event("keep", "2026-01-04T00:00:00.000Z", "the real lead"),
    );
    await stateStore.save(seeded);

    const scopeStore = new ScopeStore(caseStore);
    await scopeStore.save("c1", { start: "2026-01-01T00:00:00.000Z", end: "2026-12-31T00:00:00.000Z" });
    const falsePositiveStore = new FalsePositiveStore(caseStore);
    await falsePositiveStore.save("c1", [
      {
        id: markerId("event", "fp"),
        kind: "event",
        ref: "fp",
        reason: "known-good-tool",
        note: "",
        markedAt: "2026-01-05T00:00:00.000Z",
        markedBy: "analyst",
      },
    ]);
    const synthMetaStore = new SynthMetaStore(caseStore);

    const { provider, sent } = spyProvider(delta());
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      scopeStore,
      falsePositiveStore,
      synthMetaStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1");

    expect(sent[0]).toContain("the real lead");
    expect(sent[0]).not.toContain("before the window");
    expect(sent[0]).not.toContain("analyst says benign");
    expect(sent[0]).not.toContain("routine chatter");

    const coverage = (await synthMetaStore.load("c1")).coverage!;
    expect(coverage.omittedScope).toBe(1); // the scope filter dropped "out"
    expect(coverage.omittedLegitimate).toBe(1); // the false-positive filter dropped "fp"
    expect(coverage.omittedInfo).toBe(1); // Info gets no prompt seat …
    expect(coverage.omittedBudget).toBe(0); // … and is NOT blamed on the size limit
    expect(coverage.considered).toBe(1);
    expect(coverage.inWindow).toBe(3);
  });

  it("keeps Info events in the case even though they never reach the prompt", async () => {
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      event("i1", "2026-01-01T00:00:00.000Z", "routine chatter", "Info"),
      event("h1", "2026-01-02T00:00:00.000Z", "the real lead"),
    );
    await stateStore.save(seeded);

    const { provider, sent } = spyProvider(delta());
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1");

    expect(sent[0]).not.toContain("routine chatter");
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.map((e) => e.id).sort()).toEqual(["h1", "i1"]);
  });

  it("counts an in-scope Critical event the prompt could not fit as an omittedHighSeverity, and still gives it a finding", async () => {
    // A cap of one prompt seat forces the second Critical out of the prompt. The backfill is the
    // safety net that makes capping the prompt safe, so the two are asserted together.
    vi.stubEnv("DFIR_AI_SYNTH_MAX_EVENTS", "1");
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      event("c1e", "2026-01-01T00:00:00.000Z", "ransomware note dropped", "Critical"),
      event("c2e", "2026-01-02T00:00:00.000Z", "shadow copies deleted", "Critical"),
    );
    await stateStore.save(seeded);
    const synthMetaStore = new SynthMetaStore(caseStore);

    const { provider, sent } = spyProvider(delta());
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      synthMetaStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    const state = await pipeline.synthesize("c1");

    const shown = ["ransomware note dropped", "shadow copies deleted"].filter((d) => sent[0].includes(d));
    expect(shown).toHaveLength(1);
    const coverage = (await synthMetaStore.load("c1")).coverage!;
    expect(coverage.considered).toBe(1);
    expect(coverage.omittedHighSeverity).toBe(1);
    // The model returned one finding; the omitted Critical got one from the deterministic backfill.
    expect(state.findings.length).toBeGreaterThan(1);
  });
});

describe("synthesize — the delta merge", () => {
  it("preserves IOCs the model did not re-derive, while replacing findings wholesale", async () => {
    // The asymmetry is the point: findings are CONCLUSIONS (rewritten every run) but IOCs are
    // OBSERVED INDICATORS a text-only synthesis cannot re-derive from a truncated timeline.
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(event("e1", "2026-01-01T00:00:00.000Z", "beacon to 203.0.113.9"));
    seeded.iocs.push({ id: "i1", type: "ip", value: "203.0.113.9", firstSeen: "2026-01-01T00:00:00.000Z" });
    seeded.findings.push({
      id: "stale",
      severity: "Low",
      title: "previous run's conclusion",
      description: "",
      relatedIocs: [],
      mitreTechniques: [],
      sourceScreenshots: [],
      firstSeen: "",
      lastUpdated: "",
      status: "open",
    });
    await stateStore.save(seeded);

    const { provider } = spyProvider(delta());
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    const state = await pipeline.synthesize("c1");

    expect(state.iocs.map((i) => i.value)).toEqual(["203.0.113.9"]); // preserved
    expect(state.findings.map((f) => f.title)).toEqual(["synth finding"]); // replaced
  });

  it("carries forward an event, IOC and thread added DURING the AI call instead of clobbering them", async () => {
    // The lost-update guard. `next` is derived from a snapshot taken before a call that takes
    // seconds; without the re-read, everything an import or a manual add wrote in that window is
    // lost on save. Nothing else in the suite covers this.
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(event("e1", "2026-01-01T00:00:00.000Z", "the analyzed event"));
    await stateStore.save(seeded);

    const concurrentWrite = async (): Promise<void> => {
      const live = await stateStore.load("c1");
      live.forensicTimeline.push(event("late", "2026-01-02T00:00:00.000Z", "imported mid-call"));
      live.iocs.push({
        id: "lateIoc",
        type: "domain",
        value: "late.example",
        firstSeen: "2026-01-02T00:00:00.000Z",
      });
      live.openThreads.push({
        id: "lateThread",
        description: "opened mid-call",
        status: "open",
        openedAt: "2026-01-02T00:00:00.000Z",
        closedAt: null,
      });
      await stateStore.save(live);
    };

    const { provider } = spyProvider(delta(), concurrentWrite);
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1");

    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.map((e) => e.id)).toContain("late");
    expect(state.iocs.map((i) => i.id)).toContain("lateIoc");
    expect(state.openThreads.map((t) => t.id)).toContain("lateThread");
    expect(state.forensicTimeline.map((e) => e.id)).toContain("e1"); // and the analyzed event stays
  });

  it("unions the techniques the timeline already carries into the synthesized MITRE table", async () => {
    // Importers tag Info/Low discovery activity with techniques the model never echoes back. If the
    // union is lost the case's MITRE table silently shrinks to whatever the model happened to name.
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      event("e1", "2026-01-01T00:00:00.000Z", "whoami /all", "Low", { mitreTechniques: ["T1033"] }),
    );
    await stateStore.save(seeded);

    const { provider } = spyProvider(
      delta({ mitreTechniques: [{ id: "T1059", name: "Command Interpreter" }] }),
    );
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    const state = await pipeline.synthesize("c1");

    expect(state.mitreTechniques.map((t) => t.id).sort()).toEqual(["T1033", "T1059"]);
  });

  it("dryRun returns the conclusions without persisting them or arming the skip hash", async () => {
    // Second-opinion Pass 1 runs through here. If a dry run persisted, model B's independent
    // opinion would overwrite the case; if it armed the hash, the next real run would skip.
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(event("e1", "2026-01-01T00:00:00.000Z", "the analyzed event"));
    await stateStore.save(seeded);

    const provider = new MockProvider("mock", delta());
    const analyze = vi.spyOn(provider, "analyze");
    const synthMetaStore = new SynthMetaStore(caseStore);
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      synthMetaStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    const dry = await pipeline.synthesize("c1", { dryRun: true });
    expect(dry.findings.map((f) => f.title)).toEqual(["synth finding"]);

    expect((await stateStore.load("c1")).findings).toHaveLength(0); // nothing written
    expect((await synthMetaStore.load("c1")).lastSynthesizedAt).toBeFalsy();

    await pipeline.synthesize("c1"); // a real run still happens
    expect(analyze).toHaveBeenCalledTimes(2);
    expect((await stateStore.load("c1")).findings).toHaveLength(1);
  });
});

describe("synthesize — narrowing the scope (#751)", () => {
  // A wider run's deterministic findings used to be DELETED by a narrower one: the run rebuilds its
  // findings from an empty base, the backfills only see in-window events, and StateStore.save
  // overwrites the rows. Widening the window again did not bring them back. Scope has to be a lens.
  const NARROW = { start: "2026-01-01T00:00:00.000Z", end: "2026-12-31T00:00:00.000Z" };

  // Two Critical events far apart in time, neither covered by the model, so the backfill mints one
  // f-auto finding per event. The 2024 one is what the narrow window later excludes.
  async function seedTwoBackfilledFindings(): Promise<void> {
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      event("old", "2024-06-01T00:00:00.000Z", "ransomware note dropped", "Critical"),
      event("in", "2026-06-01T00:00:00.000Z", "shadow copies deleted", "Critical"),
    );
    await stateStore.save(seeded);
  }

  it("keeps the deterministic findings the new window excludes, and hides them by projection", async () => {
    await seedTwoBackfilledFindings();
    const scopeStore = new ScopeStore(caseStore);
    const { provider } = spyProvider(delta({ findings: [] }));
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      scopeStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    const wide = await pipeline.synthesize("c1");
    expect(wide.findings.map((f) => f.id).sort()).toEqual(["f-auto-in", "f-auto-old"]);

    await scopeStore.save("c1", NARROW);
    const narrow = await pipeline.synthesize("c1"); // the scope change re-arms the skip hash

    // Still PERSISTED — the whole point. f-auto-in is re-derived from the window, f-auto-old carried.
    expect(narrow.findings.map((f) => f.id).sort()).toEqual(["f-auto-in", "f-auto-old"]);
    // …and its back-link is restored, which is what lets the projection recognise it as out of window.
    expect(narrow.forensicTimeline.find((e) => e.id === "old")!.relatedFindingIds).toEqual(["f-auto-old"]);

    // HIDDEN, not deleted: every view runs the projection, and widening the window brings it back.
    expect(projectScope(narrow, NARROW).findings.map((f) => f.id)).toEqual(["f-auto-in"]);
    expect(
      projectScope(narrow, { start: null, end: null })
        .findings.map((f) => f.id)
        .sort(),
    ).toEqual(["f-auto-in", "f-auto-old"]);
  });

  it("still replaces a MODEL finding the new window no longer supports", async () => {
    // The carry-forward is for the deterministic backfills only. Synthesis replacing its own
    // conclusions wholesale is the invariant the fold exists to protect, so a model finding backed
    // only by out-of-window events must still go.
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      event("old", "2024-06-01T00:00:00.000Z", "ancient event", "Medium", {
        relatedFindingIds: ["f-model"],
      }),
      event("in", "2026-06-01T00:00:00.000Z", "in-window event"),
    );
    seeded.findings.push({
      id: "f-model",
      severity: "High",
      title: "a previous run's conclusion",
      description: "",
      relatedIocs: [],
      mitreTechniques: [],
      sourceScreenshots: [],
      firstSeen: "",
      lastUpdated: "",
      status: "open",
      relatedEventIds: ["old"],
    });
    await stateStore.save(seeded);

    const scopeStore = new ScopeStore(caseStore);
    await scopeStore.save("c1", NARROW);
    const { provider } = spyProvider(delta());
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      scopeStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    const state = await pipeline.synthesize("c1");
    expect(state.findings.map((f) => f.id)).toEqual(["f1"]); // f-model dropped, this run's finding stands
  });

  it("does not bring back a finding whose events the analyst confirmed benign", async () => {
    // The false-positive filter excludes events too, and its exclusions must stay exclusions. The
    // carry-forward tests the PRE-false-positive in-window set for exactly this reason.
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      event("fp", "2026-06-01T00:00:00.000Z", "ransomware note dropped", "Critical"),
      event("keep", "2026-06-02T00:00:00.000Z", "the real lead"),
    );
    await stateStore.save(seeded);

    const falsePositiveStore = new FalsePositiveStore(caseStore);
    const { provider } = spyProvider(delta({ findings: [] }));
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      falsePositiveStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    expect((await pipeline.synthesize("c1")).findings.map((f) => f.id)).toEqual(["f-auto-fp"]);

    await falsePositiveStore.save("c1", [
      {
        id: markerId("event", "fp"),
        kind: "event",
        ref: "fp",
        reason: "known-good-tool",
        note: "",
        markedAt: "2026-06-03T00:00:00.000Z",
        markedBy: "analyst",
      },
    ]);

    expect((await pipeline.synthesize("c1")).findings).toEqual([]);
  });

  it("does not carry a finding backed only by events the analyst confirmed benign", async () => {
    // The false-positive EVENT marker is the case applyFalsePositive does not cover: it matches
    // finding titles and IOC values, never event ids. Without dropping benign events from the
    // backing set, an out-of-window finding built entirely on rejected events would survive every
    // narrow run and reappear the moment the analyst widened the window again.
    await seedTwoBackfilledFindings();
    const scopeStore = new ScopeStore(caseStore);
    const falsePositiveStore = new FalsePositiveStore(caseStore);
    const { provider } = spyProvider(delta({ findings: [] }));
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      scopeStore,
      falsePositiveStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    expect((await pipeline.synthesize("c1")).findings.map((f) => f.id).sort()).toEqual([
      "f-auto-in",
      "f-auto-old",
    ]);

    // Reject the 2024 event AND narrow past it, so the window can no longer do the rejecting.
    await falsePositiveStore.save("c1", [
      {
        id: markerId("event", "old"),
        kind: "event",
        ref: "old",
        reason: "known-good-tool",
        note: "",
        markedAt: "2026-07-01T00:00:00.000Z",
        markedBy: "analyst",
      },
    ]);
    await scopeStore.save("c1", NARROW);

    const state = await pipeline.synthesize("c1");
    expect(state.findings.map((f) => f.id)).toEqual(["f-auto-in"]);
    expect(state.forensicTimeline.find((e) => e.id === "old")!.relatedFindingIds).toEqual([]);
  });

  it("carries an out-of-window finding on its remaining support when only SOME of it is benign", async () => {
    // Same shortTitle, so the backfill groups both events under one finding. Rejecting one event is
    // not rejecting the finding — the other still backs it, and the link to the rejected event goes.
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      event("old1", "2024-06-01T00:00:00.000Z", "ransomware note dropped", "Critical"),
      event("old2", "2024-06-02T00:00:00.000Z", "ransomware note dropped", "Critical"),
      event("in", "2026-06-01T00:00:00.000Z", "the real lead"),
    );
    await stateStore.save(seeded);

    const scopeStore = new ScopeStore(caseStore);
    const falsePositiveStore = new FalsePositiveStore(caseStore);
    const { provider } = spyProvider(delta({ findings: [] }));
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      scopeStore,
      falsePositiveStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    expect((await pipeline.synthesize("c1")).findings.map((f) => f.id)).toEqual(["f-auto-old1"]);

    await falsePositiveStore.save("c1", [
      {
        id: markerId("event", "old2"),
        kind: "event",
        ref: "old2",
        reason: "known-good-tool",
        note: "",
        markedAt: "2026-07-01T00:00:00.000Z",
        markedBy: "analyst",
      },
    ]);
    await scopeStore.save("c1", NARROW);

    const state = await pipeline.synthesize("c1");
    expect(state.findings.map((f) => f.id)).toEqual(["f-auto-old1"]);
    expect(state.forensicTimeline.find((e) => e.id === "old1")!.relatedFindingIds).toEqual(["f-auto-old1"]);
    expect(state.forensicTimeline.find((e) => e.id === "old2")!.relatedFindingIds).toEqual([]);
  });

  it("changes nothing when no scope is set", async () => {
    // With no window every event is in-window, so no prior finding can qualify as out of it. A
    // re-synthesis that drops a stale deterministic finding must keep dropping it.
    await seedTwoBackfilledFindings();
    const { provider } = spyProvider(delta({ findings: [] }));
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1");
    // Remove the event behind f-auto-old; the finding it backed has to go with it.
    const live = await stateStore.load("c1");
    live.forensicTimeline = live.forensicTimeline.filter((e) => e.id !== "old");
    await stateStore.save(live);

    const state = await pipeline.synthesize("c1", { force: true });
    expect(state.findings.map((f) => f.id)).toEqual(["f-auto-in"]);
  });
});

describe("synthesize — a model may not mint a deterministic finding id (#787)", () => {
  const pipelineWith = (rawText: string): AnalysisPipeline =>
    new AnalysisPipeline({
      provider: spyProvider(rawText).provider,
      stateStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

  const modelFinding = (id: string, title: string, relatedEventIds: string[]): Record<string, unknown> => ({
    id,
    severity: "Critical",
    title,
    description: "d",
    relatedIocs: [],
    mitreTechniques: [],
    status: "open",
    relatedEventIds,
  });

  it("renames an id the model invented, and the backfill still creates its own finding", async () => {
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      event("e1", "2026-06-01T00:00:00.000Z", "ransomware note dropped", "Critical"),
    );
    await stateStore.save(seeded);

    // The model claims a backfill id for a finding no backfill ever made, and does not cite e1 —
    // so if the claim were believed, e1 would stay uncovered AND the impostor would look automatic.
    const state = await pipelineWith(
      delta({ findings: [modelFinding("f-auto-invented", "model claim", [])] }),
    ).synthesize("c1");

    expect(state.findings.map((f) => f.id).sort()).toEqual(["f-auto-e1", "f-model-f-auto-invented"]);
    expect(state.findings.find((f) => f.id === "f-auto-e1")!.title).not.toBe("model claim");
  });

  it("keeps the id when the model updates a deterministic finding the case really holds", async () => {
    // The prompts echo every prior finding as `[id] title` and tell the model to update BY ID. A
    // model doing exactly that must not have its update turned into a second, unprotected finding —
    // that would drop the real one out of the class carryOutOfWindowFindings protects (#751).
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      event("e1", "2026-06-01T00:00:00.000Z", "ransomware note dropped", "Critical"),
    );
    await stateStore.save(seeded);

    expect((await pipelineWith(delta({ findings: [] })).synthesize("c1")).findings.map((f) => f.id)).toEqual([
      "f-auto-e1",
    ]);

    const state = await pipelineWith(
      delta({ findings: [modelFinding("f-auto-e1", "refined by the model", ["e1"])] }),
    ).synthesize("c1", { force: true });

    expect(state.findings.map((f) => f.id)).toEqual(["f-auto-e1"]);
    expect(state.findings[0].title).toBe("refined by the model");
  });
});

describe("synthesize — skip-when-unchanged", () => {
  async function seedOneEvent(): Promise<void> {
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(event("e1", "2026-01-01T00:00:00.000Z", "the analyzed event"));
    await stateStore.save(seeded);
  }

  it("re-synthesizes when a hunt outcome is collected, even though the timeline is identical", async () => {
    // Prior-work feedback is a pure INPUT: a hunt that came back empty is negative knowledge the
    // model has not seen yet. Leaving it out of the hash would skip the run that folds it in.
    await seedOneEvent();
    const huntOutcomeStore = new HuntOutcomeStore(caseStore);
    const provider = new MockProvider("mock", delta());
    const analyze = vi.spyOn(provider, "analyze");
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      huntOutcomeStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1");
    await pipeline.synthesize("c1");
    expect(analyze).toHaveBeenCalledTimes(1); // unchanged → skipped

    await huntOutcomeStore.save("c1", [
      {
        id: "h1",
        source: "fleet",
        title: "Hunt for staged archives",
        vqlFingerprint: "abc",
        vqlPreview: "SELECT * FROM glob()",
        mitreTechniques: ["T1560"],
        deployedAt: "2026-01-02T00:00:00.000Z",
        status: "collected",
        foundEvidence: false,
        resultSummary: "no results",
      },
    ]);

    await pipeline.synthesize("c1");
    expect(analyze).toHaveBeenCalledTimes(2);
  });

  it("re-synthesizes when the analyst re-picks the incident type", async () => {
    await seedOneEvent();
    const incidentTypeStore = new IncidentTypeStore(
      caseStore,
      join(caseStore.stateDir("c1"), "incident-types"),
    );
    const provider = new MockProvider("mock", delta());
    const analyze = vi.spyOn(provider, "analyze");
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      incidentTypeStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1");
    await pipeline.synthesize("c1");
    expect(analyze).toHaveBeenCalledTimes(1);

    await incidentTypeStore.saveRecord("c1", "ransomware");

    await pipeline.synthesize("c1");
    expect(analyze).toHaveBeenCalledTimes(2);
  });

  it("re-synthesizes when a new in-scope event lands, even though nothing else changed", async () => {
    // The skip-hash's PRIMARY job, and the one case the suite did not pin (#453). Every other test
    // here covers a secondary input — a hunt outcome, an incident type — so the hash could have
    // dropped the timeline itself and stayed green, which is the one omission that would make
    // synthesis blind to new evidence: import events, get told "inputs unchanged", never re-run.
    await seedOneEvent();
    const provider = new MockProvider("mock", delta());
    const analyze = vi.spyOn(provider, "analyze");
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1");
    await pipeline.synthesize("c1");
    expect(analyze).toHaveBeenCalledTimes(1); // unchanged → skipped

    const withNewEvent: InvestigationState = await stateStore.load("c1");
    withNewEvent.forensicTimeline.push(
      event("e2", "2026-01-01T01:00:00.000Z", "a second event imported after the first run"),
    );
    await stateStore.save(withNewEvent);

    await pipeline.synthesize("c1");
    expect(analyze).toHaveBeenCalledTimes(2);
  });

  it("skips on a re-run whose only difference is a finding synthesis itself wrote", async () => {
    // The other half of the hash contract: findings/MITRE/threads/summary are OUTPUTS. Hashing them
    // would make two consecutive runs differ and the skip would never fire at all.
    await seedOneEvent();
    const provider = new MockProvider("mock", delta());
    const analyze = vi.spyOn(provider, "analyze");
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1");
    const afterFirst: InvestigationState = await stateStore.load("c1");
    expect(afterFirst.findings).toHaveLength(1); // the run DID change stored state …

    await pipeline.synthesize("c1");
    expect(analyze).toHaveBeenCalledTimes(1); // … and the next run still skips
  });
});
