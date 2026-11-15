import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { vi } from "vitest";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import { CustomEntitiesStore } from "../../../src/analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../../../src/analysis/anonDiscovered.js";
import { PresidioPendingStore } from "../../../src/analysis/presidioPending.js";
import type { PresidioClient } from "../../../src/analysis/presidio.js";
import { emptyState, type InvestigationState } from "../../../src/analysis/stateTypes.js";
import { createConsoleLogger } from "../../../src/logging/logger.js";
import type { AiCostStore } from "../../../src/analysis/aiCost.js";
import type { AIProvider, AnalyzeResult } from "../../../src/providers/provider.js";
import type { ConverseRequest, ConverseResult, ToolTurn } from "../../../src/providers/toolCalling.js";
import type { ConverseSession } from "../../../src/analysis/ai/converseRestored.js";
import type { ProviderCallContext } from "../../../src/analysis/ai/providerCall.js";

// Shared fixtures for the converseRestored tests (Watson phase 5, Task 4): a recording fake provider
// with converse(), a case on disk with the anonymizer on, and request/transcript builders.

export const HOST = "ws-01.corp.local";
// Longer than HOST, so the known list sorts it FIRST: only the seed keeps it from taking token 1.
export const NEW_HOST = "aa-new-host-longer-name";

export class FakeConverser implements AIProvider {
  readonly name = "fake";
  readonly model = "fake-model";
  readonly supportsTools = true;
  readonly sent: ConverseRequest[] = [];
  /** Per send: the readable reasoning the adapter reports it will echo (echoing fakes only). */
  readonly kept: Array<string[] | null> = [];
  /** Present only with `echoes`: reports kept opaque text, dropping what the caller withholds. */
  readonly echoedReadableText?: (req: ConverseRequest) => string[];
  constructor(
    private readonly replies: ConverseResult[],
    o: { echoes?: boolean } = {},
  ) {
    if (o.echoes)
      this.echoedReadableText = (req) =>
        req.transcript.flatMap((t) =>
          t.role === "assistant" ? (t.opaqueText ?? []).filter((x) => !req.withhold?.(x)) : [],
        );
  }
  async analyze(): Promise<AnalyzeResult> {
    throw new Error("analyze is not used in tool mode");
  }
  async converse(req: ConverseRequest): Promise<ConverseResult> {
    const { signal: _signal, withhold: _withhold, ...wire } = req;
    this.sent.push(structuredClone(wire));
    this.kept.push(this.echoedReadableText?.(req) ?? null);
    const next = this.replies.shift();
    if (!next) throw new Error("no scripted reply");
    return next;
  }
}

function state(caseId: string): InvestigationState {
  return {
    ...emptyState(caseId),
    forensicTimeline: [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00Z",
        description: `logon on ${HOST}`,
        severity: "High",
        sources: ["x"],
        asset: HOST,
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
      },
    ],
  };
}

let caseSeq = 0;
export async function setup(o: { presidio?: PresidioClient; anonOff?: boolean; roster?: string[] } = {}) {
  const caseId = `cv${++caseSeq}-${Date.now()}`;
  const root = await mkdtemp(join(tmpdir(), "dfir-converse-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  const anonStore = new AnonControlStore(cases);
  if (o.anonOff) await anonStore.save(caseId, { ...(await anonStore.load(caseId)), enabled: false });
  const cost = { record: vi.fn(async () => undefined) };
  const ctx: ProviderCallContext = {
    log: createConsoleLogger("error"),
    opts: {
      anonStore,
      customEntitiesStore: new CustomEntitiesStore(cases),
      discoveredStore: new DiscoveredEntitiesStore(cases),
      presidioPendingStore: new PresidioPendingStore(cases),
      aiCostStore: cost as unknown as AiCostStore,
      ...(o.roster ? { rawNamesStore: { load: async () => ({ hosts: o.roster!, usernames: [] }) } } : {}),
      ...(o.presidio ? { presidio: { client: o.presidio, url: "http://presidio.test", minScore: 0.5 } } : {}),
    },
  };
  return { caseId, ctx, cost, anonStore, st: state(caseId) };
}

export const req = (transcript: ToolTurn[] = [], userPrompt = `What happened on ${HOST}?`) => ({
  systemPrompt: "sys",
  userPrompt,
  transcript,
  tools: [{ name: "lookup", description: "d", parameters: { type: "object" } }],
  toolChoice: "auto" as const,
});

export const final = (text = '{"ok":true}'): ConverseResult => ({ text, calls: [] });
export const newSession = (): ConverseSession => ({ pairs: [] });
export const tokenFor = (session: ConverseSession, value: string) =>
  session.pairs.find((p) => p.value === value)?.token;

export function transcriptWith(o: {
  args: Record<string, unknown>;
  result: string;
  opaque?: unknown;
}): ToolTurn[] {
  return [
    {
      role: "assistant",
      text: `checking ${HOST}`,
      calls: [{ id: "c1", name: "lookup", input: o.args }],
      ...(o.opaque ? { opaque: o.opaque, opaqueText: ["thinking about ANON_HOST_1"] } : {}),
    },
    { role: "tool", results: [{ id: "c1", name: "lookup", content: o.result }] },
  ];
}
