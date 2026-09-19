import type { AIProvider } from "../../providers/provider.js";
import type { Logger } from "../../logging/logger.js";
import { z } from "zod";
import type { FindingTaskStore } from "../findingTaskStore.js";
import {
  findingSourceHash,
  rawFindingTaskSchema,
  sanitizeFindingTasks,
  type StoredFindingTask,
} from "../findingTasks.js";
import { estimateTokens, inputTokenBudget, fitItemsToBudget } from "../promptBudget.js";
import type { Finding, ForensicEvent, InvestigationState } from "../stateTypes.js";
import { getFindingTaskPrompt } from "./prompts/index.js";
import { callAiJson, type AiCallContext } from "./aiContext.js";

/**
 * The per-finding analyst-task pass (#1418). Runs once after synthesis, over the Critical/High
 * findings that have no current task, and writes one AI-authored task per finding into
 * FindingTaskStore. The playbook derivation (playbook.ts) reads the store by finding id; a finding
 * this pass never reached gets the deterministic fallback there, so the card is a task either way.
 *
 * Reads only the forensic timeline — each finding's own cited events — never the super-timeline
 * (CLAUDE.md §7). Best-effort throughout: a provider error or a rejected response leaves the store
 * as it was and never fails the synthesis that triggered it.
 */

export interface FindingTaskPassContext extends AiCallContext {
  readonly log?: Logger;
  readonly opts: AiCallContext["opts"] & { findingTaskStore?: FindingTaskStore };
}

export const FINDING_TASKS_MAX_DEFAULT = 25;
const EVENTS_PER_FINDING = 8;
const IOCS_PER_FINDING = 6;
const AI_KIND = "finding-tasks";

const responseSchema = z.object({ tasks: z.array(rawFindingTaskSchema).catch([]) });

const SEVERITY_RANK: Record<string, number> = { Critical: 0, High: 1 };

// Non-dismissed Critical/High findings whose stored task is missing or written against different
// text, Critical first then by confidence, capped. Same severity filter as the playbook derivation.
export function selectFindingTaskCandidates(
  findings: readonly Finding[],
  stored: Readonly<Record<string, StoredFindingTask>>,
  max: number,
): Finding[] {
  return findings
    .filter((f) => f.status !== "dismissed" && f.severity in SEVERITY_RANK)
    .filter((f) => stored[f.id]?.sourceHash !== findingSourceHash(f))
    .sort(
      (a, b) =>
        SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || (b.confidence ?? 0) - (a.confidence ?? 0),
    )
    .slice(0, Math.max(1, max));
}

function renderEvent(e: ForensicEvent): string {
  const parts = [e.timestamp, e.asset ? `[${e.asset}]` : "", e.description];
  if (e.path) parts.push(`path=${e.path}`);
  if (e.commandLine) parts.push(`cmd=${e.commandLine}`);
  else if (e.processName) parts.push(`process=${e.processName}`);
  return `    - ${parts.filter(Boolean).join(" ")}`;
}

function renderFinding(state: InvestigationState, f: Finding): string {
  const byId = new Map(state.forensicTimeline.map((e) => [e.id, e] as const));
  const events = (f.relatedEventIds ?? [])
    .map((id) => byId.get(id))
    .filter((e): e is ForensicEvent => Boolean(e))
    .slice(0, EVENTS_PER_FINDING);
  const iocValues = new Map(state.iocs.map((i) => [i.id, `${i.type}:${i.value}`] as const));
  const iocs = (f.relatedIocs ?? [])
    .map((id) => iocValues.get(id))
    .filter(Boolean)
    .slice(0, IOCS_PER_FINDING);
  const mitre = f.mitreTechniques?.length ? ` ATT&CK: ${f.mitreTechniques.join(", ")}` : "";
  const desc = (f.description ?? "").replace(/\s+/g, " ").trim();
  return [
    `[${f.id}] [${f.severity}] ${f.title}${mitre}`,
    desc ? `  ${desc}` : "",
    events.length ? "  Cited events:" : "  Cited events: (none)",
    ...events.map(renderEvent),
    iocs.length ? `  Indicators: ${iocs.join("; ")}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

// One block per finding, fitted to the input budget so a case with many findings drops the
// lowest-ranked ones rather than overflowing the model.
export function buildFindingTaskPrompt(state: InvestigationState, candidates: readonly Finding[]): string {
  const budget = Math.max(0, inputTokenBudget() - estimateTokens(getFindingTaskPrompt()) - 300);
  const blocks = candidates.map((f) => renderFinding(state, f));
  const keep = fitItemsToBudget(blocks, (b) => b, budget);
  return ["FINDINGS:", ...blocks.slice(0, keep)].join("\n\n");
}

function maxCandidates(): number {
  const n = Number(process.env.DFIR_FINDING_TASKS_MAX);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : FINDING_TASKS_MAX_DEFAULT;
}

export async function writeFindingTasks(
  ctx: FindingTaskPassContext,
  caseId: string,
  state: InvestigationState,
  opts: { provider?: AIProvider } = {},
): Promise<void> {
  const store = ctx.opts.findingTaskStore;
  if (!store) return;
  const provider = opts.provider ?? ctx.opts.synthesisProvider;
  if (!provider) return;
  try {
    const stored = await store.load(caseId);
    const candidates = selectFindingTaskCandidates(state.findings ?? [], stored, maxCandidates());
    if (!candidates.length) return;
    const offered = new Set(candidates.map((f) => f.id));
    const tasks = await callAiJson(
      ctx,
      caseId,
      state,
      provider,
      AI_KIND,
      getFindingTaskPrompt,
      buildFindingTaskPrompt(state, candidates),
      (raw) => sanitizeFindingTasks(responseSchema.parse(raw).tasks, offered),
    );
    const writtenAt = new Date().toISOString();
    const byId = new Map(candidates.map((f) => [f.id, f] as const));
    const fresh: Record<string, StoredFindingTask> = {};
    for (const [id, task] of Object.entries(tasks)) {
      fresh[id] = { ...task, sourceHash: findingSourceHash(byId.get(id)!), writtenAt, engine: "ai" };
    }
    await store.upsert(
      caseId,
      fresh,
      (state.findings ?? []).map((f) => f.id),
    );
  } catch (err) {
    ctx.log?.warn(
      `finding-task pass failed; playbook keeps the deterministic tasks: ${(err as Error).message}`,
      {
        caseId,
      },
    );
  }
}
