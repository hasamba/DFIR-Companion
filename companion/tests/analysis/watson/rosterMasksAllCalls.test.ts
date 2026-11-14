import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type Finding, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import { buildRuntimePipeline } from "../../../src/composition/aiProviders.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { jevMasking } from "../../../src/routes/jevMasking.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// Final review H3 (review I2 probes 2/3): a raw-only name Watson wrote into an applied item reaches
// synthesis and the other AI calls on the case. Every masker on the case loads the Watson chat's
// masking roster, so those names are masked there too, not only in Watson's own calls.

const CASE = "c1";
const TS = "2026-06-01T00:00:00.000Z";
const LEAK = /FINSRV-07|svc_backup/i;

const SYNTH = JSON.stringify({
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "s",
  forensicEvents: [],
  attackerPath: "",
  keyQuestions: [],
  nextSteps: [],
});

class CapturingProvider implements AIProvider {
  readonly name = "capture";
  readonly model = "capture-model";
  readonly sent: AnalyzeRequest[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    return { rawText: SYNTH };
  }
}

const e1: ForensicEvent = {
  id: "e1",
  timestamp: TS,
  description: "rclone copy on HOST-A",
  severity: "High",
  asset: "HOST-A",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
};

const watsonFinding: Finding = {
  id: "f-watson-1a2b3c4d",
  severity: "High",
  confidence: 90,
  title: "Exfiltration with rclone",
  description: "rclone on HOST-A; the same copy also ran on FINSRV-07 as svc_backup",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: ["T1567"],
  relatedEventIds: ["e1"],
  firstSeen: TS,
  lastUpdated: TS,
  status: "open",
  author: "watson",
};

async function seeded() {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-roster-mask-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save({ ...emptyState(CASE), forensicTimeline: [e1], findings: [watsonFinding] });
  const anon = new AnonControlStore(store);
  await anon.save(CASE, { ...(await anon.load(CASE)), enabled: true });
  await new WatsonChatStore(store).update(CASE, (c) => ({
    ...c,
    maskRoster: { hosts: ["finsrv-07"], users: ["svc_backup"], ips: [] },
  }));
  return { store, stateStore };
}

describe("the Watson masking roster reaches every AI call on the case (H3)", () => {
  it("synthesis: the WATSON FINDINGS block never sends a raw-only host or account in clear", async () => {
    const { store, stateStore } = await seeded();
    const provider = new CapturingProvider();
    const pipeline = buildRuntimePipeline({
      provider,
      synthesisProvider: provider,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    await pipeline.synthesize(CASE, { force: true });
    const prompts = provider.sent.map((r) => r.userPrompt);
    expect(prompts.some((p) => p.includes("WATSON FINDINGS"))).toBe(true);
    expect(prompts.join("\n")).toContain("rclone");
    expect(prompts.join("\n")).not.toMatch(LEAK);
    expect(prompts.join("\n")).not.toContain("HOST-A");
  });

  it("the Jev routes' masker masks them too", async () => {
    const { store, stateStore } = await seeded();
    const { masker } = await jevMasking(store, CASE, await stateStore.load(CASE));
    const out = masker.mask(watsonFinding.description);
    expect(out).toContain("rclone");
    expect(out).not.toMatch(LEAK);
  });
});
