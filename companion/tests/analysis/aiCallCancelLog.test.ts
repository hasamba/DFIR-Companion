// #2779: when the analyst stops an AI call, the provider throws an AbortError. The server log must
// say the call was cancelled, at info level, not warn that the call failed or timed out. A real
// failure (a timeout the analyst did not ask for) keeps its warning.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { ProviderError } from "../../src/providers/provider.js";

let stateStore: StateStore;
let synthMetaStore: SynthMetaStore;
let warns: string[];
let infos: string[];

const logger = {
  debug: () => undefined,
  info: (msg: string) => void infos.push(msg),
  warn: (msg: string) => void warns.push(msg),
  error: () => undefined,
};

function ev(id: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "LSASS access",
    severity: "Critical",
    mitreTechniques: ["T1003.001"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    sources: ["Sysmon"],
  };
}

function pipelineThrowing(err: Error): AnalysisPipeline {
  const analyze = vi.fn(async () => {
    throw err;
  });
  const provider = { name: "fake", model: "m", analyze };
  return new AnalysisPipeline({
    stateStore,
    synthMetaStore,
    provider,
    synthesisProvider: provider,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    logger: logger as never,
    retries: 0,
    backoffMs: 0,
  });
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-ai-cancel-log-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  synthMetaStore = new SynthMetaStore(cases);
  warns = [];
  infos = [];
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("a"), ev("b"));
  await stateStore.save(s);
});

describe("AI call log line for a cancelled call (#2779)", () => {
  it("logs a cancelled call at info, with no failure warning", async () => {
    const abort = Object.assign(new Error("Claude Code call cancelled by the analyst"), {
      name: "AbortError",
    });
    const p = pipelineThrowing(abort);

    await expect(p.synthesize("c1")).rejects.toMatchObject({ name: "AbortError" });

    expect(warns.filter((w) => w.startsWith("AI call ["))).toEqual([]);
    expect(infos.some((m) => m.startsWith("AI call [") && m.includes("cancelled"))).toBe(true);
  });

  it("keeps the warning for a real timeout", async () => {
    const p = pipelineThrowing(new ProviderError("Claude Code timed out after 800000ms", "timeout"));

    await expect(p.synthesize("c1")).rejects.toMatchObject({ kind: "timeout" });

    expect(warns.some((w) => w.startsWith("AI call [") && w.includes("kind=timeout"))).toBe(true);
  });
});
