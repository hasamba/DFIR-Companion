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
  "write time, network connection time, etc.). For every dated incident event you can read, emit",
  "a forensicEvents entry whose timestamp is read FROM THAT ROW's OWN time column in the image",
  "(e.g. the 'Timestamp'/'EventTime' column of the results table), in ISO-8601 if possible.",
  "NEVER use the screenshot capture time or the current time. If a row has no visible event time,",
  "set its timestamp to an empty string \"\" — do NOT substitute the capture/current time.",
  "These reconstruct WHEN the attack happened on the SYSTEM(S) UNDER INVESTIGATION.",
  "",
  "IMPORTANT — Velociraptor IS the evidence source. The DATA shown inside it (notebook/query",
  "RESULTS: tables of processes, logons, network connections, event-log rows, services, scheduled",
  "tasks, file listings with MAC times, registry values) IS the evidence — EXTRACT those rows as",
  "forensicEvents using the timestamp in each row. The tool is how you SEE the evidence; the rows",
  "ARE the evidence.",
  "EXCLUDE only the act of OPERATING the tool / navigating the UI (no incident data): hunts",
  "created/started/expired, a notebook or page or section 'accessed', a query/VQL/search being run,",
  "'EventLog analysis performed', 'Response and Monitoring accessed', clicking/scrolling. Those are",
  "the analyst's work log. Rule of thumb: a row of artifact DATA with a real timestamp = forensic",
  "event; a sentence about you using the tool = skip. If a screenshot shows only the app chrome or",
  "an empty/loading panel with no data rows, return no forensicEvents for it.",
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

// Holistic synthesis: turn the accumulated forensic timeline into analytic
// conclusions (findings, MITRE, attacker path). Findings/attacker-path need the
// WHOLE picture, which a single window can't see — so this runs once over the
// full timeline after per-window extraction.
export const SYNTHESIS_PROMPT = [
  "You are a senior DFIR analyst writing the CONCLUSIONS of an investigation.",
  "You are given the full forensic timeline of dated events already extracted from the evidence.",
  "Do NOT invent new events and do NOT return forensicEvents — synthesize what is given into analysis.",
  "",
  "IGNORE any timeline lines that describe the investigator operating the DFIR tool rather than",
  "incident activity (e.g. Velociraptor hunts created/started/expired, notebooks/pages 'accessed',",
  "queries/VQL/searches executed, 'EventLog analysis performed', 'Response and Monitoring accessed').",
  "Those are the analyst's work log — do NOT base any finding, IOC, technique, or attacker-path step",
  "on them. Base conclusions ONLY on real host/attacker activity (executions, logons, file/registry",
  "/network/persistence changes).",
  "",
  "Produce:",
  "- findings: produce a SEPARATE finding for EACH distinct attacker technique, tool, or behavior",
  "  observed — e.g. Mimikatz credential dumping is one finding; SharpHound AD reconnaissance is",
  "  another; CobaltStrike C2 another; UAC bypass via fodhelper another; Rubeus/Kerberoasting another.",
  "  Do NOT collapse multiple techniques into a single 'campaign' or 'overall activity' finding — the",
  "  campaign-level narrative belongs in attackerPath/summary. Aim for roughly one finding per material",
  "  technique in the timeline (often 8-20 findings for a busy case), each a CONCLUSION (not a raw log",
  "  line) with its own severity and the MITRE techniques it maps to.",
  "- iocs: concrete indicators (ips, domains, hashes, malicious files/processes) seen in the timeline.",
  "- mitreTechniques: the ATT&CK techniques observed, aggregated.",
  "- attackerPath: a chronological narrative of the intrusion in kill-chain order (initial access →",
  "  execution → persistence → priv-esc → lateral movement → C2 → exfil/impact), citing event times.",
  "- summary: a 2-3 sentence executive overview.",
  "- threadsOpened: open an investigative thread (id + description) for each UNRESOLVED question the",
  "  evidence raises and that still needs follow-up (e.g. 'determine how the attacker obtained the",
  "  Administrator credential', 'identify the C2 domain'). Do not re-open a thread already listed below.",
  "- threadsClosed: the ids of any currently-open threads (listed below) that the evidence now RESOLVES.",
  "",
  "Return ONLY raw JSON (no markdown fences). Set forensicEvents to [] and timelineNote to \"\".",
  "Every finding/ioc/technique/thread MUST be an object, never a bare string. Shape:",
  "",
  JSON.stringify(
    {
      findings: [{ id: "f1", severity: "Critical|High|Medium|Low|Info", title: "conclusion", description: "why", relatedIocs: ["i1"], mitreTechniques: ["T1562.001"], status: "open|confirmed|dismissed" }],
      iocs: [{ id: "i1", type: "ip|domain|hash|file|process|url|other", value: "the indicator" }],
      mitreTechniques: [{ id: "T1562.001", name: "Impair Defenses: Disable or Modify Tools" }],
      attackerPath: "Initial access at <time> via …; then execution of …; persistence via …; impact at <time>.",
      summary: "executive summary",
      threadsOpened: [{ id: "t1", description: "unresolved question to chase next" }],
      threadsClosed: ["t0"],
      forensicEvents: [],
      timelineNote: "",
    },
    null,
    2,
  ),
].join("\n");

export interface PipelineOptions {
  provider: AIProvider;
  // Optional stronger model for the holistic synthesis pass. Per-window extraction
  // can use a cheap model while synthesis (one text-only call) uses a better one.
  synthesisProvider?: AIProvider;
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
    // Note: we deliberately do NOT put the capture time on these lines — the model
    // would otherwise copy it into forensicEvents instead of reading the artifact's
    // own timestamp column shown in the image.
    const contextLines = analyzable
      .map((c) => `Screenshot ${c.screenshotFile} — ${c.tabTitle} (${c.url})`)
      .join("\n");
    const userPrompt =
      `${buildStateSummary(state)}\n\nNEW SCREENSHOTS (read each artifact's OWN timestamp column ` +
      `for event times — do not use any capture/current time):\n${contextLines}\n\nReturn the JSON delta.`;

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

  // Holistic pass: read the whole forensic timeline and produce findings, MITRE
  // mapping, and the attacker-path narrative. Text-only (no images), one call.
  async synthesize(caseId: string): Promise<InvestigationState> {
    const state = await this.opts.stateStore.load(caseId);
    if (state.forensicTimeline.length === 0) return state;

    const timelineText = state.forensicTimeline
      .map((e) => `${e.timestamp || "(undated)"} [${e.severity}] ${e.description}`)
      .join("\n");
    const existingFindings = state.findings.map((f) => `[${f.id}] ${f.title}`).join("\n") || "(none yet)";
    const openThreads = state.openThreads
      .filter((t) => t.status === "open")
      .map((t) => `[${t.id}] ${t.description}`)
      .join("\n") || "(none open)";
    const userPrompt =
      `FORENSIC TIMELINE (${state.forensicTimeline.length} dated events):\n${timelineText}\n\n` +
      `EXISTING FINDINGS (update by id, do not duplicate):\n${existingFindings}\n\n` +
      `CURRENTLY OPEN THREADS (close by id in threadsClosed when the evidence resolves them):\n${openThreads}\n\n` +
      `Running notes: ${state.lastSummary || "(none)"}\n\nReturn the JSON conclusions.`;

    const retries = this.opts.retries ?? 3;
    const backoffMs = this.opts.backoffMs ?? 500;
    const synthProvider = this.opts.synthesisProvider ?? this.opts.provider;

    const delta = await withRetry(async () => {
      const result = await synthProvider.analyze({ systemPrompt: SYNTHESIS_PROMPT, userPrompt, images: [] });
      return deltaSchema.parse(JSON.parse(extractJsonText(result.rawText)));
    }, retries, backoffMs);

    // Anchor finding timestamps to the last real event time (fallback: existing state time).
    const ts = state.forensicTimeline[state.forensicTimeline.length - 1]?.timestamp || state.updatedAt;
    const next = mergeDelta(state, delta, { windowSequence: 0, timestamp: ts, sourceScreenshots: [] });
    await this.opts.stateStore.save(next);
    this.opts.onState?.(next);
    return next;
  }
}
