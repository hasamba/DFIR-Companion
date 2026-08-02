import { describe, it, expect, beforeEach, vi } from "vitest";
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
    vi.unstubAllEnvs();
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
