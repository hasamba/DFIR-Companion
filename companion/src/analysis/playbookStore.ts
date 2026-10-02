import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import type { InvestigationState, StepPriority } from "./stateTypes.js";
import {
  PLAYBOOK_STATUSES,
  type DeriveOptions,
  type PlaybookStatus,
  type PlaybookTask,
  playbookSchema,
  derivePlaybookTasks,
  mergePlaybook,
  nextShortId,
  sortPlaybookTasks,
  validateDependsOn,
  PlaybookValidationError,
} from "./playbook.js";
import type { ContainmentAttribution } from "./playbookContainment.js";

// Per-case playbook store: a trackable checklist auto-derived from the case's next
// steps + high-severity findings, plus analyst-added custom tasks. Kept in
// `state/playbook.json` (NOT in InvestigationState) so synthesis never wipes analyst
// progress — same side-file pattern as comments/tags/notebook. Writes go through
// atomicWrite (Dropbox-safe temp-rename). `sync` re-derives idempotently and only
// writes when something actually changed (no churn on a no-op read).

const STEP_PRIORITIES: readonly StepPriority[] = ["critical", "high", "medium", "low"];

// Serializes a case's load->modify->save section (#682). atomicWrite stops a TORN file, not a LOST
// one: two analysts ticking two tasks at the same moment both read the same snapshot and the second
// save discarded the first. MODULE-level, not per instance, because the app builds two
// PlaybookStores over the same case directory (composition/runtimeStores.ts for the routes and
// composition/aiProviders.ts for synthesis). A per-instance lock would leave those two free to
// clobber each other the moment the synthesis-side store starts writing. Keyed by case id, so a
// busy case never blocks another one, and private to playbook.json, so it can never deadlock
// against the pipeline's investigation-state lock.
const playbookLock = new StateLock();

export interface NewPlaybookTask {
  title: string;
  description?: string;
  status?: PlaybookStatus;
  priority?: StepPriority;
  assignee?: string;
  dueDate?: string;
  notes?: string;
  relatedFindingId?: string;
  // #1925: attribution for a task added from a Jev containment check. Set by the server from its
  // own check record; the generic POST /cases/:id/playbook route never reads it from a body.
  containmentCheck?: ContainmentAttribution;
}

export interface PlaybookTaskPatch {
  title?: string;
  description?: string;
  status?: PlaybookStatus;
  priority?: StepPriority;
  assignee?: string;
  dueDate?: string;
  notes?: string;
  dependsOn?: string[]; // task ids that must be "done" first (issue #81); [] clears all edges
}

function normalizeStatus(s: unknown): PlaybookStatus | undefined {
  return PLAYBOOK_STATUSES.includes(s as PlaybookStatus) ? (s as PlaybookStatus) : undefined;
}
function normalizePriority(p: unknown): StepPriority | undefined {
  return STEP_PRIORITIES.includes(p as StepPriority) ? (p as StepPriority) : undefined;
}

// Build one custom task from an analyst/server input: fresh id, the next shortId and order after
// `tasks`, trimmed text, empty optional fields omitted.
function buildCustomTask(tasks: readonly PlaybookTask[], input: NewPlaybookTask, now: string): PlaybookTask {
  const maxOrder = tasks.reduce((m, t) => Math.max(m, t.order), -1);
  return {
    id: `custom:${randomUUID()}`,
    shortId: nextShortId(tasks),
    title: String(input.title).trim(),
    description: String(input.description ?? "").trim(),
    status: normalizeStatus(input.status) ?? "todo",
    priority: normalizePriority(input.priority) ?? "medium",
    source: "custom",
    ...(input.relatedFindingId ? { relatedFindingId: input.relatedFindingId } : {}),
    ...(input.assignee?.trim() ? { assignee: input.assignee.trim() } : {}),
    ...(input.dueDate?.trim() ? { dueDate: input.dueDate.trim() } : {}),
    ...(input.notes?.trim() ? { notes: input.notes.trim() } : {}),
    ...(input.containmentCheck ? { containmentCheck: input.containmentCheck } : {}),
    order: maxOrder + 1,
    createdAt: now,
    updatedAt: now,
  };
}

export class PlaybookStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "playbook.json");
  }

  async load(caseId: string): Promise<PlaybookTask[]> {
    try {
      return sortPlaybookTasks(playbookSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8"))));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async save(caseId: string, tasks: PlaybookTask[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(tasks, null, 2));
  }

  // Add a custom (analyst-authored) task. Server assigns id/order/timestamps.
  add(caseId: string, input: NewPlaybookTask): Promise<PlaybookTask> {
    return playbookLock.runExclusive(caseId, async () => {
      const tasks = await this.load(caseId);
      const task = buildCustomTask(tasks, input, new Date().toISOString());
      await this.save(caseId, [...tasks, task]);
      return task;
    });
  }

  // Add several custom tasks in one locked load->save (#1925). An input that `isDuplicate`
  // matches against any stored task (any status) or against one added earlier in this batch is
  // skipped. Under the same lock as add(), so two concurrent calls cannot both add one step.
  addMany(
    caseId: string,
    inputs: NewPlaybookTask[],
    isDuplicate: (existing: PlaybookTask, input: NewPlaybookTask) => boolean,
  ): Promise<{ added: PlaybookTask[]; skipped: NewPlaybookTask[] }> {
    return playbookLock.runExclusive(caseId, async () => {
      const tasks = await this.load(caseId);
      const now = new Date().toISOString();
      const added: PlaybookTask[] = [];
      const skipped: NewPlaybookTask[] = [];
      for (const input of inputs) {
        const all = [...tasks, ...added];
        if (all.some((t) => isDuplicate(t, input))) {
          skipped.push(input);
          continue;
        }
        added.push(buildCustomTask(all, input, now));
      }
      if (added.length) await this.save(caseId, [...tasks, ...added]);
      return { added, skipped };
    });
  }

  // Patch a task's editable fields. Optional string fields (assignee/dueDate/notes) are
  // SET when a non-empty value is given and CLEARED when an explicit empty string is sent.
  // A `dependsOn` edit is validated (unknown ids / cycles) BEFORE anything is persisted —
  // throws PlaybookValidationError on a bad edge so the route can surface a 400.
  // Returns the updated task, or null if not found.
  update(caseId: string, taskId: string, patch: PlaybookTaskPatch): Promise<PlaybookTask | null> {
    return playbookLock.runExclusive(caseId, async () => {
      const tasks = await this.load(caseId);
      if (!tasks.some((t) => t.id === taskId)) return null;
      let dependsOn: string[] | undefined;
      if (patch.dependsOn !== undefined) {
        const validation = validateDependsOn(tasks, taskId, patch.dependsOn);
        if (!validation.ok) throw new PlaybookValidationError(validation.error);
        dependsOn = validation.dependsOn;
      }
      let updated: PlaybookTask | null = null;
      const next = tasks.map((t) => {
        if (t.id !== taskId) return t;
        const merged: PlaybookTask = {
          ...t,
          ...(patch.title !== undefined ? { title: String(patch.title).trim() } : {}),
          ...(patch.description !== undefined ? { description: String(patch.description).trim() } : {}),
          ...(normalizeStatus(patch.status) ? { status: normalizeStatus(patch.status)! } : {}),
          ...(normalizePriority(patch.priority) ? { priority: normalizePriority(patch.priority)! } : {}),
          updatedAt: new Date().toISOString(),
        };
        for (const field of ["assignee", "dueDate", "notes"] as const) {
          if (patch[field] === undefined) continue;
          const v = String(patch[field]).trim();
          if (v) merged[field] = v;
          else delete merged[field];
        }
        if (dependsOn !== undefined) {
          if (dependsOn.length) merged.dependsOn = dependsOn;
          else delete merged.dependsOn;
        }
        updated = merged;
        return merged;
      });
      if (!updated) return null;
      await this.save(caseId, next);
      return updated;
    });
  }

  remove(caseId: string, taskId: string): Promise<boolean> {
    return playbookLock.runExclusive(caseId, async () => {
      const tasks = await this.load(caseId);
      const task = tasks.find((t) => t.id === taskId);
      if (!task) return false;
      // Auto-derived tasks (next_step/finding) are re-added by syncPlaybook as long as their
      // source still exists. Mark them skipped instead so the analyst's intent persists across
      // re-syncs; the "Open only" filter hides them. Custom tasks are removed outright.
      if (task.source !== "custom") {
        const next: PlaybookTask[] = tasks.map((t) =>
          t.id === taskId ? { ...t, status: "skipped", updatedAt: new Date().toISOString() } : t,
        );
        await this.save(caseId, next);
      } else {
        await this.save(
          caseId,
          tasks.filter((t) => t.id !== taskId),
        );
      }
      return true;
    });
  }

  // Reassign `order` from a caller-supplied id sequence. Ids not in the list keep their
  // relative order and follow the listed ones. Returns the reordered list.
  reorder(caseId: string, orderedIds: string[]): Promise<PlaybookTask[]> {
    return playbookLock.runExclusive(caseId, async () => {
      const tasks = await this.load(caseId);
      const pos = new Map(orderedIds.map((id, i) => [id, i] as const));
      const next = [...tasks]
        .sort((a, b) => {
          const ai = pos.has(a.id) ? pos.get(a.id)! : Number.POSITIVE_INFINITY;
          const bi = pos.has(b.id) ? pos.get(b.id)! : Number.POSITIVE_INFINITY;
          return ai - bi || a.order - b.order;
        })
        .map((t, i) => ({ ...t, order: i }));
      await this.save(caseId, next);
      return next;
    });
  }

  // Re-derive auto-tasks from the current case state and merge them into the stored list
  // (idempotent — preserves analyst status/edits). `opts.useTemplates` expands Critical/High
  // findings into IR-phase templates. Writes only when something changed.
  sync(caseId: string, state: InvestigationState, opts: DeriveOptions = {}): Promise<PlaybookTask[]> {
    return playbookLock.runExclusive(caseId, async () => {
      const existing = await this.load(caseId);
      const { tasks, changed } = mergePlaybook(
        existing,
        derivePlaybookTasks(state, opts),
        new Date().toISOString(),
      );
      if (changed) await this.save(caseId, tasks);
      return sortPlaybookTasks(tasks);
    });
  }
}
