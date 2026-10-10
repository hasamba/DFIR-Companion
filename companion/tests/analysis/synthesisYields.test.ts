import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #2058: the CPU-bound phases of a synthesis run (prompt build, delta fold, grading, session-command
// notes) ran back to back with no macrotask between them, so on a 70k-event case /health and every
// other case stopped answering for tens of seconds. Each phase boundary now yields to the event loop.

const yieldSpy = vi.hoisted(() => ({ count: 0 }));
vi.mock("../../src/analysis/yieldToEventLoop.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../src/analysis/yieldToEventLoop.js")>();
  return {
    ...real,
    yieldToEventLoop: () => {
      yieldSpy.count++;
      return real.yieldToEventLoop();
    },
  };
});

let stateStore: StateStore;

function ev(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-08-28T09:00:00Z",
    description: `Sigma: suspicious file write ${id}`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    sources: ["Chainsaw"],
    ...over,
  };
}

function pipeline(): AnalysisPipeline {
  const analyze = vi.fn(async () => ({
    rawText: JSON.stringify({
      findings: [],
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
    }),
  }));
  return new AnalysisPipeline({
    stateStore,
    synthesisProvider: { name: "fake", analyze } as never,
    retries: 0,
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
  });
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-synth-yields-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("e1"), ev("e2", { timestamp: "2026-08-28T09:05:00Z" }));
  await stateStore.save(s);
  yieldSpy.count = 0;
});

describe("synthesis yields to the event loop between its phases (#2058)", () => {
  it("awaits the shared yield helper at each phase boundary", async () => {
    await pipeline().synthesize("c1", { force: true });
    // load, prepare, prompt (selection → blocks), fold (conclusions, backfills), fold done,
    // grading, findings final, session-command notes.
    expect(yieldSpy.count).toBeGreaterThanOrEqual(6);
  });

  it("lets a timer queued at the start fire before the run resolves", async () => {
    let fired = false;
    setTimeout(() => {
      fired = true;
    }, 0);
    const run = pipeline().synthesize("c1", { force: true });
    await run;
    expect(fired).toBe(true);
  });
});
