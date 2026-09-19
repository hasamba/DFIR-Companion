import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { FindingTaskStore } from "../../../src/analysis/findingTaskStore.js";
import { findingSourceHash } from "../../../src/analysis/findingTasks.js";
import {
  buildFindingTaskPrompt,
  selectFindingTaskCandidates,
  writeFindingTasks,
  type FindingTaskPassContext,
} from "../../../src/analysis/ai/findingTaskPass.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest } from "../../../src/providers/provider.js";

const NOW = "2026-06-10T00:00:00.000Z";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    severity: "Critical",
    title: "secretsdump.exe used on WS-042",
    description: "Credential dump.",
    relatedIocs: ["i1"],
    sourceScreenshots: [],
    mitreTechniques: ["T1003.002"],
    firstSeen: NOW,
    lastUpdated: NOW,
    status: "open",
    relatedEventIds: ["e1"],
    ...over,
  };
}
function event(over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id: "e1",
    timestamp: "2026-06-09T14:02:00.000Z",
    description: "secretsdump.exe spawned by powershell.exe as svc-backup",
    severity: "Critical",
    mitreTechniques: [],
    relatedFindingIds: ["f1"],
    sourceScreenshots: [],
    asset: "WS-042",
    commandLine: "secretsdump.exe -sam sam.hive -system system.hive LOCAL",
    ...over,
  };
}
function stateWith(findings: Finding[], events: ForensicEvent[] = [event()]): InvestigationState {
  return {
    ...emptyState("c1"),
    findings,
    forensicTimeline: events,
    iocs: [{ id: "i1", type: "hash", value: "abc123", firstSeen: NOW }],
  };
}

let cases: CaseStore;
let store: FindingTaskStore;
let calls: Array<{ systemPrompt: string; userPrompt: string }>;
let response: unknown;
let fail: Error | undefined;
let warnings: string[];

const provider = { name: "stub" } as unknown as AIProvider;

function ctx(over: Partial<FindingTaskPassContext["opts"]> = {}): FindingTaskPassContext {
  return {
    opts: {
      synthesisProvider: provider,
      stateStore: {} as never,
      findingTaskStore: store,
      retries: 0,
      backoffMs: 0,
      ...over,
    },
    log: { warn: (m: string, c: unknown) => warnings.push(`${m} ${JSON.stringify(c)}`) },
    requireProvider: () => provider,
    getKevCatalog: async () => undefined,
    withRetry: async (_c: string, _l: string, fn: () => Promise<unknown>) => fn(),
    analyzeRestored: async (_c: string, _s: unknown, _p: unknown, req: AnalyzeRequest) => {
      calls.push({ systemPrompt: req.systemPrompt, userPrompt: req.userPrompt });
      if (fail) throw fail;
      return response;
    },
  } as unknown as FindingTaskPassContext;
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-finding-task-pass-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new FindingTaskStore(cases);
  calls = [];
  warnings = [];
  fail = undefined;
  response = {
    tasks: [
      {
        findingId: "f1",
        title: "Confirm secretsdump ran on WS-042",
        steps: ["Pull prefetch"],
        doneWhen: "confirmed",
      },
    ],
  };
});

describe("selectFindingTaskCandidates", () => {
  it("keeps non-dismissed Critical/High findings, Critical first, and skips one whose stored task is current", () => {
    const f1 = finding({ id: "f1", severity: "High" });
    const f2 = finding({ id: "f2", severity: "Critical" });
    const f3 = finding({ id: "f3", severity: "Medium" });
    const f4 = finding({ id: "f4", severity: "Critical", status: "dismissed" });
    const f5 = finding({ id: "f5", severity: "High" });
    const stored = {
      f5: {
        title: "t",
        steps: ["s"],
        doneWhen: "d",
        sourceHash: findingSourceHash(f5),
        writtenAt: NOW,
        engine: "ai" as const,
      },
    };
    expect(selectFindingTaskCandidates([f1, f2, f3, f4, f5], stored, 25).map((f) => f.id)).toEqual([
      "f2",
      "f1",
    ]);
  });

  it("re-selects a finding whose text changed since its task was written", () => {
    const f = finding({ id: "f1" });
    const stored = {
      f1: {
        title: "t",
        steps: ["s"],
        doneWhen: "d",
        sourceHash: "stale",
        writtenAt: NOW,
        engine: "ai" as const,
      },
    };
    expect(selectFindingTaskCandidates([f], stored, 25).map((x) => x.id)).toEqual(["f1"]);
  });

  it("caps the candidate list", () => {
    const many = Array.from({ length: 5 }, (_, i) => finding({ id: `f${i}` }));
    expect(selectFindingTaskCandidates(many, {}, 3)).toHaveLength(3);
  });
});

describe("buildFindingTaskPrompt", () => {
  it("renders each finding with its cited events and indicator values, and nothing from uncited events", () => {
    const state = stateWith(
      [finding()],
      [event(), event({ id: "e9", description: "unrelated noise", asset: "OTHER-HOST" })],
    );
    const text = buildFindingTaskPrompt(state, [finding()]);
    expect(text).toContain("[f1] [Critical] secretsdump.exe used on WS-042");
    expect(text).toContain("T1003.002");
    expect(text).toContain("2026-06-09T14:02:00.000Z");
    expect(text).toContain("WS-042");
    expect(text).toContain("svc-backup");
    expect(text).toContain("secretsdump.exe -sam sam.hive");
    expect(text).toContain("abc123");
    expect(text).not.toContain("unrelated noise");
    expect(text).not.toContain("OTHER-HOST");
  });
});

describe("writeFindingTasks", () => {
  it("calls the model once for the candidates and persists the sanitized tasks with the finding hash", async () => {
    const f = finding();
    await writeFindingTasks(ctx(), "c1", stateWith([f]));
    expect(warnings).toEqual([]);
    expect(calls).toHaveLength(1);
    expect(calls[0].userPrompt).toContain("[f1]");
    const stored = await store.load("c1");
    expect(stored.f1).toMatchObject({
      title: "Confirm secretsdump ran on WS-042",
      steps: ["Pull prefetch"],
      engine: "ai",
      sourceHash: findingSourceHash(f),
    });
  });

  it("makes no call when every Critical/High finding already has a current task", async () => {
    const f = finding();
    await writeFindingTasks(ctx(), "c1", stateWith([f]));
    calls = [];
    await writeFindingTasks(ctx(), "c1", stateWith([f]));
    expect(calls).toHaveLength(0);
  });

  it("makes no call when there are no Critical/High findings, and none when no store is wired", async () => {
    await writeFindingTasks(ctx(), "c1", stateWith([finding({ severity: "Medium" })]));
    await writeFindingTasks(ctx({ findingTaskStore: undefined }), "c1", stateWith([finding()]));
    expect(calls).toHaveLength(0);
  });

  it("is best-effort: a provider failure leaves the store untouched and does not throw", async () => {
    fail = new Error("boom");
    await expect(writeFindingTasks(ctx(), "c1", stateWith([finding()]))).resolves.toBeUndefined();
    expect(await store.load("c1")).toEqual({});
  });

  it("drops a task for a finding it did not offer", async () => {
    response = { tasks: [{ findingId: "f-invented", title: "x", steps: ["y"], doneWhen: "z" }] };
    await writeFindingTasks(ctx(), "c1", stateWith([finding()]));
    expect(await store.load("c1")).toEqual({});
  });

  it("prunes a stored task whose finding is gone from the case", async () => {
    await writeFindingTasks(ctx(), "c1", stateWith([finding()]));
    response = { tasks: [{ findingId: "f2", title: "t2", steps: ["s"], doneWhen: "d" }] };
    await writeFindingTasks(ctx(), "c1", stateWith([finding({ id: "f2" })]));
    expect(Object.keys(await store.load("c1"))).toEqual(["f2"]);
  });
});
