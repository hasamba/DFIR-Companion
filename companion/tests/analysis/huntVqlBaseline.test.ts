import { createHash } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { HUNT_SUGGEST_PROMPT, PLAYBOOK_HUNT_PROMPT } from "../../src/analysis/ai/prompts/index.js";
import type { PlaybookTask } from "../../src/analysis/playbook.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #2559: the VQL path must stay BYTE-IDENTICAL when the case's hunt language is VQL. This file was
// written against the code BEFORE the main-source routing existed and pins what the model is sent
// for a Velociraptor-only case: both system prompts (hashed) and both user prompts (snapshotted).
// The main-source dispatcher (suggestCaseHunts / suggestCasePlaybookHunts) is asserted to send the
// very same requests on such a case.

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

let cases: CaseStore;
let stateStore: StateStore;
let requests: Array<{ systemPrompt: string; userPrompt: string }>;

function ev(id: string, artifact: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: `Suspicious ${artifact} row`,
    severity: "High",
    mitreTechniques: ["T1059.001"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    sources: ["Velociraptor"],
    artifactName: artifact,
    importBatchId: "batch-1",
  };
}

const task: PlaybookTask = {
  id: "t1",
  title: "Collect PowerShell history from WS01",
  description: "",
  status: "todo",
  priority: "high",
  source: "custom",
  order: 0,
  createdAt: "2026-04-22T11:41:00Z",
  updatedAt: "2026-04-22T11:41:00Z",
};

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-huntvql-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  requests = [];
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("e1", "Windows.EventLogs.Evtx"), ev("e2", "Windows.System.Pslist"));
  s.findings.push({
    id: "f1",
    title: "PowerShell download cradle",
    description: "Encoded PowerShell on WS01",
    severity: "High",
    mitreTechniques: ["T1059.001"],
    relatedEventIds: ["e1"],
    relatedIocs: [],
    status: "open",
  } as never);
  await stateStore.save(s);
});

function buildCapturingPipeline(store: StateStore): AnalysisPipeline {
  const analyze = vi.fn(async (req: { systemPrompt: string; userPrompt: string }) => {
    requests.push({ systemPrompt: req.systemPrompt, userPrompt: req.userPrompt });
    return { rawText: JSON.stringify({ suggestions: [] }) };
  });
  return new AnalysisPipeline({
    stateStore: store,
    synthesisProvider: { name: "fake", analyze } as never,
    imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
  });
}

describe("VQL hunt baseline (#2559)", () => {
  it("keeps both VQL system prompts byte-identical", () => {
    expect(sha(HUNT_SUGGEST_PROMPT)).toMatchSnapshot("HUNT_SUGGEST_PROMPT sha256");
    expect(sha(PLAYBOOK_HUNT_PROMPT)).toMatchSnapshot("PLAYBOOK_HUNT_PROMPT sha256");
  });

  it("sends the same fleet-hunt user prompt for a Velociraptor case", async () => {
    await buildCapturingPipeline(stateStore).suggestHunts("c1");
    expect(requests).toHaveLength(1);
    expect(requests[0].systemPrompt).toBe(HUNT_SUGGEST_PROMPT);
    expect(requests[0].userPrompt).toMatchSnapshot("fleet user prompt");
  });

  it("sends the same playbook-hunt user prompt for a Velociraptor case", async () => {
    await buildCapturingPipeline(stateStore).suggestPlaybookHunts("c1", [task], ["Windows.System.Pslist"]);
    expect(requests).toHaveLength(1);
    expect(requests[0].systemPrompt).toBe(PLAYBOOK_HUNT_PROMPT);
    expect(requests[0].userPrompt).toMatchSnapshot("playbook user prompt");
  });
});
