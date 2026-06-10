import { z } from "zod";
import type { InvestigationState, Severity, StepPriority } from "./stateTypes.js";

// Playbook tracking (issue #36, Phase 1). Turns the AI's "next steps" and the
// high-severity findings into a trackable checklist of remediation/investigation
// TASKS the analyst can move through (todo → in-progress → done/skipped), annotate
// with an assignee + due date, reorder, and add custom items to. Persisted per case
// in `state/playbook.json` (PlaybookStore) — NOT in InvestigationState, so synthesis
// never wipes analyst progress (like comments/tags/notebook). The derivation here is
// pure and deterministic so it can be re-run on every read/synthesis idempotently:
// an auto-task's id IS its source key, so re-deriving REFRESHES its text but PRESERVES
// the analyst's status/assignee/due-date/notes/order.

export const PLAYBOOK_STATUSES = ["todo", "in_progress", "done", "skipped"] as const;
export type PlaybookStatus = (typeof PLAYBOOK_STATUSES)[number];

export const PLAYBOOK_SOURCES = ["next_step", "finding", "custom"] as const;
export type PlaybookSource = (typeof PLAYBOOK_SOURCES)[number];

const STEP_PRIORITIES = ["critical", "high", "medium", "low"] as const;

export const playbookTaskSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string().catch(""),
  status: z.enum(PLAYBOOK_STATUSES).catch("todo" as PlaybookStatus),
  priority: z.enum(STEP_PRIORITIES).catch("medium" as StepPriority),
  source: z.enum(PLAYBOOK_SOURCES).catch("custom" as PlaybookSource),
  sourceKey: z.string().optional(),       // stable derive key (absent for custom tasks)
  relatedFindingId: z.string().optional(),
  assignee: z.string().optional(),
  dueDate: z.string().optional(),         // free-form date, e.g. "2026-06-15"
  notes: z.string().optional(),
  order: z.number().catch(0),
  createdAt: z.string(),
  updatedAt: z.string(),
});

export type PlaybookTask = z.infer<typeof playbookTaskSchema>;
export const playbookSchema = z.array(playbookTaskSchema).catch([]);

// A candidate task derived from case state (before it's merged into the stored list).
export interface DerivedTaskSeed {
  title: string;
  description: string;
  priority: StepPriority;
  source: "next_step" | "finding";
  sourceKey: string;
  relatedFindingId?: string;
}

const PRIORITY_FROM_SEVERITY: Record<Severity, StepPriority> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
  Info: "low",
};

function normalizePriority(p: string): StepPriority {
  const v = String(p).toLowerCase();
  return (STEP_PRIORITIES as readonly string[]).includes(v) ? (v as StepPriority) : "medium";
}

// Sort: by analyst-controlled `order`, then by creation time as a stable tiebreaker.
export function sortPlaybookTasks(tasks: PlaybookTask[]): PlaybookTask[] {
  return [...tasks].sort((a, b) => (a.order - b.order) || a.createdAt.localeCompare(b.createdAt));
}

// Derive the candidate task list from the synthesized case state:
//  - every AI next step → one task (priority carried through), and
//  - every NON-dismissed Critical/High finding → an "investigate & remediate" task
//    linked back to the finding (lower-severity findings stay out to avoid flooding).
// Each seed has a STABLE sourceKey so re-derivation is idempotent.
export function derivePlaybookTasks(state: InvestigationState): DerivedTaskSeed[] {
  const seeds: DerivedTaskSeed[] = [];
  for (const s of state.nextSteps ?? []) {
    const desc = [s.rationale, s.pointer ? `Where / what to collect: ${s.pointer}` : ""]
      .filter(Boolean)
      .join("\n\n");
    seeds.push({
      title: s.action,
      description: desc,
      priority: normalizePriority(s.priority),
      source: "next_step",
      sourceKey: `next_step:${s.id}`,
    });
  }
  for (const f of state.findings ?? []) {
    if (f.status === "dismissed") continue;
    const priority = PRIORITY_FROM_SEVERITY[f.severity] ?? "medium";
    if (priority !== "critical" && priority !== "high") continue;
    seeds.push({
      title: `Investigate & remediate: ${f.title}`,
      description: f.description,
      priority,
      source: "finding",
      sourceKey: `finding:${f.id}`,
      relatedFindingId: f.id,
    });
  }
  return seeds;
}

export interface MergeResult {
  tasks: PlaybookTask[];
  changed: boolean;
}

// Merge freshly-derived seeds into the existing stored tasks. An auto-task is keyed by
// its sourceKey (which is also its id). For a seed that already exists we REFRESH the
// title/description/priority/finding-link (synthesis may have reworded it) but PRESERVE
// the analyst's status/assignee/dueDate/notes/order. A seed with no existing task is
// appended as a fresh `todo`. Existing tasks whose seed disappeared are KEPT (never
// silently dropped — the analyst may have acted on them). Custom tasks are untouched.
// Pure + deterministic: pass `now` in so there's no clock dependency.
export function mergePlaybook(existing: PlaybookTask[], seeds: DerivedTaskSeed[], now: string): MergeResult {
  const result = existing.map((t) => ({ ...t }));
  const byId = new Map(result.map((t) => [t.id, t] as const));
  let changed = false;
  let maxOrder = result.reduce((m, t) => Math.max(m, t.order), -1);

  for (const seed of seeds) {
    const id = seed.sourceKey;
    const cur = byId.get(id);
    if (cur) {
      const findingChanged = (cur.relatedFindingId ?? "") !== (seed.relatedFindingId ?? "");
      if (cur.title !== seed.title || cur.description !== seed.description || cur.priority !== seed.priority || findingChanged) {
        const idx = result.findIndex((t) => t.id === id);
        result[idx] = {
          ...result[idx],
          title: seed.title,
          description: seed.description,
          priority: seed.priority,
          ...(seed.relatedFindingId ? { relatedFindingId: seed.relatedFindingId } : {}),
          updatedAt: now,
        };
        changed = true;
      }
    } else {
      maxOrder += 1;
      const task: PlaybookTask = {
        id,
        title: seed.title,
        description: seed.description,
        status: "todo",
        priority: seed.priority,
        source: seed.source,
        sourceKey: seed.sourceKey,
        ...(seed.relatedFindingId ? { relatedFindingId: seed.relatedFindingId } : {}),
        order: maxOrder,
        createdAt: now,
        updatedAt: now,
      };
      result.push(task);
      byId.set(id, task);
      changed = true;
    }
  }
  return { tasks: result, changed };
}

export interface PlaybookStats {
  total: number;
  done: number;
  skipped: number;
  open: number;            // todo + in_progress (still needs action)
  inProgress: number;
  completionPct: number;   // done / total, rounded
}

export function playbookStats(tasks: PlaybookTask[]): PlaybookStats {
  const total = tasks.length;
  const done = tasks.filter((t) => t.status === "done").length;
  const skipped = tasks.filter((t) => t.status === "skipped").length;
  const inProgress = tasks.filter((t) => t.status === "in_progress").length;
  const open = total - done - skipped;
  const completionPct = total ? Math.round((done / total) * 100) : 0;
  return { total, done, skipped, open, inProgress, completionPct };
}
