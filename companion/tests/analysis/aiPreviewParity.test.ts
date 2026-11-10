import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../../src/analysis/anonDiscovered.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { SecondOpinionStore } from "../../src/analysis/secondOpinionStore.js";
import { HypothesisStore } from "../../src/analysis/hypothesisStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { segmentSessions } from "../../src/analysis/sessionSegmentation.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { runAiPreview, type AiPreviewCapture } from "../../src/analysis/ai/aiPreviewScope.js";
import { AI_PREVIEW_ACTIONS } from "../../src/routes/aiPreviewActions.js";
import type { RouteContext } from "../../src/routes/context.js";
import type { Logger } from "../../src/logging/logger.js";
import { ReadOnlyScopeWriteError } from "../../src/storage/readOnlyScope.js";
import type { PresidioClient } from "../../src/analysis/presidio.js";

// #2491 — "Preview what the AI will see" must show EXACTLY what the provider receives. For every
// covered action this runs the preview first (no provider call, no file in the case changes), then the
// real action with a recording provider, and compares the first request byte for byte.

const HOST = "ACME-DC01"; // a custom entity: masked in the prompt, so masked ≠ clear
const USER = "jdoe-secret";

class RecordingProvider implements AIProvider {
  readonly name = "recording";
  readonly model = "rec-model";
  readonly sent: AnalyzeRequest[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    throw new Error("recording provider: stop after the first request");
  }
}

const ev = (id: string, ts: string, over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: ts,
  description: `powershell.exe -enc AAA on ${HOST} by ${USER}`,
  severity: "High",
  sources: ["Hayabusa"],
  asset: HOST,
  mitreTechniques: ["T1059.001"],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});

function seedState(caseId: string): InvestigationState {
  return {
    ...emptyState(caseId),
    forensicTimeline: [
      ev("e1", "2026-01-01T10:00:00Z"),
      ev("e2", "2026-01-01T10:01:00Z", { severity: "Medium", description: `net use \\\\${HOST}\\c$` }),
      ev("e3", "2026-01-01T10:02:00Z", {
        sources: ["Volatility"],
        description: `Volatility malfind: injected code in lsass.exe on ${HOST}`,
      }),
      // A long silence on the same host, so the gap detector has something to hypothesize about.
      ev("e4", "2026-01-03T10:00:00Z", { description: `cmd.exe /c whoami on ${HOST}` }),
      ev("e5", "2026-01-03T10:01:00Z", { description: `rundll32 on ${HOST}` }),
    ],
    findings: [
      {
        id: "f1",
        title: `Encoded PowerShell on ${HOST}`,
        severity: "High",
        description: `PowerShell run by ${USER}`,
        relatedEventIds: ["e1"],
        mitreTechniques: ["T1059.001"],
        relatedIocs: [],
        sourceScreenshots: [],
        firstSeen: "2026-01-01T10:00:00Z",
        lastUpdated: "2026-01-01T10:00:00Z",
        status: "open",
      },
      {
        id: "f2",
        title: `Lateral movement to ${HOST}`,
        severity: "Medium",
        description: "SMB",
        relatedEventIds: ["e2"],
        mitreTechniques: ["T1021.002"],
        relatedIocs: [],
        sourceScreenshots: [],
        firstSeen: "2026-01-01T10:01:00Z",
        lastUpdated: "2026-01-01T10:01:00Z",
        status: "open",
      },
    ],
  };
}

async function harness(extra: Record<string, unknown> = {}) {
  const caseId = "c1";
  const root = await mkdtemp(join(tmpdir(), "dfir-ai-preview-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save(seedState(caseId));
  const superTimelineStore = new SuperTimelineStore(cases);
  // A raw row only in the super-timeline: explain/starred promote it before asking (§7).
  await superTimelineStore.append(caseId, [
    ev("raw1", "2026-01-01T10:03:00Z", { severity: "Info", description: `reg query on ${HOST} by ${USER}` }),
  ]);
  const customEntitiesStore = new CustomEntitiesStore(cases);
  await customEntitiesStore.save(caseId, [
    { value: HOST, category: "HOST" },
    { value: USER, category: "USER" },
  ]);
  const tagsStore = new TagsStore(cases);
  await tagsStore.add(caseId, { targetType: "event", targetId: "raw1", author: "a", label: "starred" });
  const hypothesisStore = new HypothesisStore(cases);
  await hypothesisStore.add(caseId, { title: `Attacker pivoted through ${HOST}` });
  await superTimelineStore.query(caseId, {}); // the case has been opened once: storage upkeep is done
  const secondOpinionStore = new SecondOpinionStore(cases);
  // A second opinion whose referee failed: the referee-only re-run replays its saved prompt.
  await secondOpinionStore.save(caseId, {
    generatedAt: "2026-01-04T00:00:00.000Z",
    modelA: "a",
    modelB: "b",
    referee: "",
    summary: "",
    agreementCount: 0,
    deltas: [],
    refereeError: { referee: "a", message: "timeout", at: "2026-01-04T00:00:00.000Z" },
    refereePrompt: `Judge the disagreement about ${HOST}.`,
  });
  const presidioPendingStore = new PresidioPendingStore(cases);
  const logged: string[] = [];
  const logger: Logger = {
    debug: (m) => void logged.push(m),
    info: (m) => void logged.push(m),
    warn: (m) => void logged.push(m),
    error: (m) => void logged.push(m),
    getLevel: () => "debug",
    setLevel: () => undefined,
    close: async () => undefined,
  };
  const provider = new RecordingProvider();
  const secondProvider = new RecordingProvider();
  const pipeline = new AnalysisPipeline({
    provider,
    synthesisProvider: provider,
    secondOpinionProvider: secondProvider,
    secondOpinionStore,
    stateStore,
    superTimelineStore,
    anonStore: new AnonControlStore(cases),
    customEntitiesStore,
    discoveredStore: new DiscoveredEntitiesStore(cases),
    presidioPendingStore,
    synthMetaStore: new SynthMetaStore(cases),
    hypothesisStore,
    retries: 0,
    backoffMs: 0,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    logger,
    ...extra,
  });
  const options = {
    pipeline,
    stateStore,
    superTimelineStore,
    tagsStore,
    secondOpinionEnabled: true,
  } as unknown as RouteContext["options"];
  return { caseId, root, cases, pipeline, options, provider, secondProvider, presidioPendingStore, logged };
}

/**
 * Every file under the cases root, by content hash — the preview must leave it identical. SQLite's
 * shared-memory index (-shm) is created by any reader and is not data; its write-ahead log (-wal) is
 * data, so it is kept, and an empty one is the same as none.
 */
async function snapshot(dir: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const entry of await readdir(dir, { withFileTypes: true, recursive: true })) {
    if (!entry.isFile() || entry.name.endsWith("-shm")) continue;
    const path = join(entry.parentPath, entry.name);
    const bytes = await readFile(path);
    if (entry.name.endsWith("-wal") && bytes.length === 0) continue;
    out[path] = createHash("sha256").update(bytes).digest("hex");
  }
  return out;
}

const PARAMS: Record<string, (h: Awaited<ReturnType<typeof harness>>) => Record<string, unknown>> = {
  "deep-pass": () => ({ minSeverity: "Medium" }),
  "explain-event": () => ({ eventId: "raw1" }),
  "session-summary": () => ({ sessionId: segmentSessions(seedState("c1").forensicTimeline)[0].id }),
  ask: () => ({ question: `Did ${USER} exfiltrate data from ${HOST}?` }),
  "technique-hunt": () => ({ techniqueId: "T1021.002", techniqueName: "SMB" }),
  "translate-query": () => ({ request: `logons on ${HOST}` }),
  "tagger-rule": () => ({ description: `flag ${HOST} admin shares` }),
  "fp-similar": () => ({ kind: "event", ref: "e1" }),
};

// Prompts that carry no case value at all (a technique id and the hunt platforms only).
const NO_CASE_TEXT = new Set(["technique-hunt"]);

async function firstSent(
  provider: RecordingProvider,
  other: RecordingProvider,
): Promise<AnalyzeRequest | null> {
  return provider.sent[0] ?? other.sent[0] ?? null;
}

describe("AI preview == as-sent request, for every covered action (#2491)", () => {
  for (const [key, action] of Object.entries(AI_PREVIEW_ACTIONS)) {
    it(key, async () => {
      const h = await harness();
      const params = PARAMS[key]?.(h) ?? {};

      const before = await snapshot(h.root);
      const prepared = await action.prepare(h.pipeline, h.options, h.caseId, params);
      expect(typeof prepared, String(prepared)).toBe("function");
      const preview = await runAiPreview(prepared as () => Promise<unknown>);
      expect(h.provider.sent).toHaveLength(0); // nothing sent during the preview
      expect(h.secondProvider.sent).toHaveLength(0);
      expect(await snapshot(h.root)).toEqual(before); // nothing in the case changed
      expect(await h.presidioPendingStore.load(h.caseId)).toEqual([]);
      // The clear text never reaches a log line.
      expect(h.logged.filter((l) => l.includes(USER) || l.includes(HOST))).toEqual([]);

      const real = await action.prepare(h.pipeline, h.options, h.caseId, params);
      await (real as () => Promise<unknown>)().catch(() => undefined);
      const sent = await firstSent(h.provider, h.secondProvider);

      expect(
        preview.outcome,
        preview.outcome === "error" ? String((preview.error as Error)?.stack ?? preview.error) : "",
      ).toBe("captured");
      expect(sent).not.toBeNull();
      const call = (preview as { call: AiPreviewCapture }).call;
      expect(call.maskedPrompt).toBe(sent!.userPrompt);
      expect(call.systemPrompt).toBe(sent!.systemPrompt);
      expect(call.anonymized).toBe(true);
      // The masking really ran: the custom entities are in the clear text and not in the masked text.
      expect(call.maskedPrompt).not.toContain(HOST);
      if (NO_CASE_TEXT.has(key)) return;
      expect(call.clearPrompt).toContain(HOST);
      expect(call.clearPrompt).not.toBe(call.maskedPrompt);
    });
  }
});

async function previewSynthesis(h: Awaited<ReturnType<typeof harness>>) {
  const prepared = await AI_PREVIEW_ACTIONS.synthesis.prepare(h.pipeline, h.options, h.caseId, {});
  return runAiPreview(prepared as () => Promise<unknown>);
}

describe("AI preview — anonymization off and Presidio (#2491)", () => {
  it("anonymization off: the masked text IS the clear text, and the preview says so", async () => {
    const h = await harness();
    const anon = new AnonControlStore(h.cases);
    await anon.save(h.caseId, { ...(await anon.load(h.caseId)), enabled: false });
    const preview = await previewSynthesis(h);
    expect(preview.outcome).toBe("captured");
    const call = (preview as { call: AiPreviewCapture }).call;
    expect(call.anonymized).toBe(false);
    expect(call.maskedPrompt).toBe(call.clearPrompt);
    expect(call.maskedPrompt).toContain(HOST);
    expect(call.presidio.state).toBe("off");
  });

  it("lists what Presidio would hold, without saving a pending approval", async () => {
    const client: PresidioClient = {
      analyze: async () => [{ entityType: "PERSON", score: 0.99, value: "Zed Quill" }],
    };
    const h = await harness({ presidio: { client, url: "http://presidio.test", minScore: 0.5 } });
    const before = await snapshot(h.root);
    const preview = await previewSynthesis(h);
    const call = (preview as { call: AiPreviewCapture }).call;
    expect(call.presidio.state).toBe("would-hold");
    expect(call.presidio.held.map((e) => e.value)).toContain("Zed Quill");
    expect(await h.presidioPendingStore.load(h.caseId)).toEqual([]);
    expect(await snapshot(h.root)).toEqual(before);
  });

  it("an unreachable Presidio is reported as the real call's stop, not a crash", async () => {
    const client: PresidioClient = {
      analyze: async () => {
        throw new Error("ECONNREFUSED");
      },
    };
    const h = await harness({ presidio: { client, url: "http://presidio.test", minScore: 0.5 } });
    const preview = await previewSynthesis(h);
    const call = (preview as { call: AiPreviewCapture }).call;
    expect(call.presidio.state).toBe("scan-failed");
    expect(call.presidio.message).toMatch(/not reachable/);
    expect(h.provider.sent).toHaveLength(0);
  });
});

describe("AI preview — storage upkeep is never run by a preview (#2491)", () => {
  it("a super-timeline migration that is due (it can evict rows) is refused, and the case is untouched", async () => {
    const h = await harness();
    const tags = (h.options as unknown as { tagsStore: TagsStore }).tagsStore;
    // A tag change after the last read leaves the super-timeline's derived state due for upkeep.
    await tags.add(h.caseId, { targetType: "event", targetId: "raw1", author: "a", label: "triage" });
    const before = await snapshot(h.root);
    const prepared = await AI_PREVIEW_ACTIONS["view-summary"].prepare(h.pipeline, h.options, h.caseId, {});
    const preview = await runAiPreview(prepared as () => Promise<unknown>);
    expect(await snapshot(h.root)).toEqual(before);
    expect(h.provider.sent).toHaveLength(0);
    expect(preview.outcome).toBe("error");
    expect((preview as { error: unknown }).error).toBeInstanceOf(ReadOnlyScopeWriteError);
  });
});
