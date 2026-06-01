import type { AIProvider, AnalyzeImage } from "../providers/provider.js";
import type { CaptureMetadata } from "../types.js";
import type { StateStore } from "./stateStore.js";
import type { InvestigationState } from "./stateTypes.js";
import { deltaSchema } from "./responseSchema.js";
import { buildStateSummary } from "./summary.js";
import { mergeDelta } from "./stateMerge.js";
import { extractJsonText } from "./extractJson.js";

export const SYSTEM_PROMPT = [
  "You are a DFIR analyst assistant. You are shown screenshots from a forensic investigation",
  "(Velociraptor, VirusTotal, etc.) plus a summary of findings already recorded.",
  "Update existing findings by their id; never create a duplicate finding for a topic already",
  "listed. Open a thread for any lead you start chasing and close it by id when resolved.",
  "",
  "CRITICAL — FORENSIC TIMELINE: forensic artifacts on screen carry REAL timestamps (process",
  "create time, file MAC times, logon time, prefetch run time, scheduled-task time, registry",
  "write time, etc.). For every dated incident event you can read, emit a forensicEvents entry",
  "with that artifact's ACTUAL timestamp (ISO-8601 if possible, e.g. 2026-05-20T14:03:00Z) — NOT",
  "the screenshot's capture time. These reconstruct WHEN the attack happened.",
  "",
  "ATTACKER PATH: in 'attackerPath', narrate the adversary's progression in kill-chain order",
  "(initial access → execution → persistence → priv-esc → lateral movement → C2 → exfil/impact),",
  "citing finding ids and event times. Refine it as new evidence arrives.",
  "",
  "Return ONLY raw JSON (no markdown code fences, no prose) with EXACTLY this shape — every",
  "finding/ioc/technique/thread/event MUST be an OBJECT with these keys, never a bare string:",
  "",
  JSON.stringify(
    {
      findings: [
        {
          id: "f1",
          severity: "Critical|High|Medium|Low|Info",
          title: "short title",
          description: "what was observed and why it matters",
          relatedIocs: ["i1"],
          mitreTechniques: ["T1059"],
          status: "open|confirmed|dismissed",
        },
      ],
      iocs: [{ id: "i1", type: "ip|domain|hash|file|process|url|other", value: "the indicator" }],
      mitreTechniques: [{ id: "T1059", name: "Command and Scripting Interpreter" }],
      forensicEvents: [
        {
          id: "e1",
          timestamp: "2026-05-20T14:03:00Z",
          description: "powershell.exe spawned encoded command (from prefetch run time)",
          severity: "Critical|High|Medium|Low|Info",
          mitreTechniques: ["T1059.001"],
          relatedFindingIds: ["f1"],
        },
      ],
      threadsOpened: [{ id: "t1", description: "lead being chased" }],
      threadsClosed: ["t0"],
      timelineNote: "one sentence on what you reviewed in this batch of screenshots",
      attackerPath: "kill-chain narrative of how the attacker progressed, citing finding ids and times",
      summary: "running executive summary of the whole investigation so far",
    },
    null,
    2,
  ),
  "",
  "If a section has nothing new, return it as an empty array (or empty string for text fields).",
].join("\n");

export interface PipelineOptions {
  provider: AIProvider;
  stateStore: StateStore;
  imageLoader: (caseId: string, screenshotFile: string) => Promise<AnalyzeImage>;
  retries?: number;
  backoffMs?: number;
  onState?: (state: InvestigationState) => void;
}

async function withRetry<T>(fn: () => Promise<T>, retries: number, backoffMs: number): Promise<T> {
  let attempt = 0;
  for (;;) {
    try {
      return await fn();
    } catch (err) {
      if (attempt >= retries) throw err;
      await new Promise((r) => setTimeout(r, backoffMs * 2 ** attempt));
      attempt++;
    }
  }
}

export class AnalysisPipeline {
  constructor(private readonly opts: PipelineOptions) {}

  async analyzeWindow(caseId: string, captures: CaptureMetadata[]): Promise<InvestigationState> {
    const analyzable = captures.filter((c) => !c.isDuplicate);
    if (analyzable.length === 0) return this.opts.stateStore.load(caseId);

    const state = await this.opts.stateStore.load(caseId);
    const images = await Promise.all(
      analyzable.map((c) => this.opts.imageLoader(caseId, c.screenshotFile)),
    );
    const contextLines = analyzable
      .map((c) => `Screenshot ${c.screenshotFile} — ${c.tabTitle} (${c.url}) at ${c.timestamp}`)
      .join("\n");
    const userPrompt = `${buildStateSummary(state)}\n\nNEW SCREENSHOTS:\n${contextLines}\n\nReturn the JSON delta.`;

    const retries = this.opts.retries ?? 3;
    const backoffMs = this.opts.backoffMs ?? 500;

    const delta = await withRetry(async () => {
      const result = await this.opts.provider.analyze({ systemPrompt: SYSTEM_PROMPT, userPrompt, images });
      // Models often wrap JSON in markdown fences / prose — extract it first.
      return deltaSchema.parse(JSON.parse(extractJsonText(result.rawText)));
    }, retries, backoffMs);

    const windowSequence = analyzable[analyzable.length - 1].sequenceNumber;
    const next = mergeDelta(state, delta, {
      windowSequence,
      timestamp: analyzable[analyzable.length - 1].timestamp,
      sourceScreenshots: analyzable.map((c) => c.screenshotFile),
    });
    await this.opts.stateStore.save(next);
    this.opts.onState?.(next);
    return next;
  }
}
