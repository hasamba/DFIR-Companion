import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { InvestigationState, StepPriority } from "./stateTypes.js";
import {
  PLAYBOOK_STATUSES,
  type DeriveOptions,
  type PlaybookStatus,
  type PlaybookTask,
  playbookSchema,
  derivePlaybookTasks,
  mergePlaybook,
  sortPlaybookTasks,
} from "./playbook.js";

// Per-case playbook store: a trackable checklist auto-derived from the case's next
// steps + high-severity findings, plus analyst-added custom tasks. Kept in
// `state/playbook.json` (NOT in InvestigationState) so synthesis never wipes analyst
// progress — same side-file pattern as comments/tags/notebook. Writes go through
// atomicWrite (Dropbox-safe temp-rename). `sync` re-derives idempotently and only
// writes when something actually changed (no churn on a no-op read).

const STEP_PRIORITIES: readonly StepPriority[] = ["critical", "high", "medium", "low"];

export interface NewPlaybookTask {
  title: string;
  description?: string;
  status?: PlaybookStatus;
  priority?: StepPriority;
  assignee?: string;
  dueDate?: string;
  notes?: string;
  relatedFindingId?: string;
}

export interface PlaybookTaskPatch {
  title?: string;
  description?: string;
  status?: PlaybookStatus;
  priority?: StepPriority;
  assignee?: string;
  dueDate?: string;
  notes?: string;
}

function normalizeStatus(s: unknown): PlaybookStatus | undefined {
  return PLAYBOOK_STATUSES.includes(s as PlaybookStatus) ? (s as PlaybookStatus) : undefined;
}
function normalizePriority(p: unknown): StepPriority | undefined {
  return STEP_PRIORITIES.includes(p as StepPriority) ? (p as StepPriority) : undefined;
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
  async add(caseId: string, input: NewPlaybookTask): Promise<PlaybookTask> {
    const tasks = await this.load(caseId);
    const maxOrder = tasks.reduce((m, t) => Math.max(m, t.order), -1);
    const now = new Date().toISOString();
    const task: PlaybookTask = {
      id: `custom:${randomUUID()}`,
      title: String(input.title).trim(),
      description: String(input.description ?? "").trim(),
      status: normalizeStatus(input.status) ?? "todo",
      priority: normalizePriority(input.priority) ?? "medium",
      source: "custom",
      ...(input.relatedFindingId ? { relatedFindingId: input.relatedFindingId } : {}),
      ...(input.assignee?.trim() ? { assignee: input.assignee.trim() } : {}),
      ...(input.dueDate?.trim() ? { dueDate: input.dueDate.trim() } : {}),
      ...(input.notes?.trim() ? { notes: input.notes.trim() } : {}),
      order: maxOrder + 1,
      createdAt: now,
      updatedAt: now,
    };
    await this.save(caseId, [...tasks, task]);
    return task;
  }

  // Patch a task's editable fields. Optional string fields (assignee/dueDate/notes) are
  // SET when a non-empty value is given and CLEARED when an explicit empty string is sent.
  // Returns the updated task, or null if not found.
  async update(caseId: string, taskId: string, patch: PlaybookTaskPatch): Promise<PlaybookTask | null> {
    const tasks = await this.load(caseId);
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
      updated = merged;
      return merged;
    });
    if (!updated) return null;
    await this.save(caseId, next);
    return updated;
  }

  async remove(caseId: string, taskId: string): Promise<boolean> {
    const tasks = await this.load(caseId);
    const next = tasks.filter((t) => t.id !== taskId);
    if (next.length === tasks.length) return false;
    await this.save(caseId, next);
    return true;
  }

  // Reassign `order` from a caller-supplied id sequence. Ids not in the list keep their
  // relative order and follow the listed ones. Returns the reordered list.
  async reorder(caseId: string, orderedIds: string[]): Promise<PlaybookTask[]> {
    const tasks = await this.load(caseId);
    const pos = new Map(orderedIds.map((id, i) => [id, i] as const));
    const next = [...tasks]
      .sort((a, b) => {
        const ai = pos.has(a.id) ? pos.get(a.id)! : Number.POSITIVE_INFINITY;
        const bi = pos.has(b.id) ? pos.get(b.id)! : Number.POSITIVE_INFINITY;
        return (ai - bi) || (a.order - b.order);
      })
      .map((t, i) => ({ ...t, order: i }));
    await this.save(caseId, next);
    return next;
  }

  // Re-derive auto-tasks from the current case state and merge them into the stored list
  // (idempotent — preserves analyst status/edits). `opts.useTemplates` expands Critical/High
  // findings into IR-phase templates. Writes only when something changed.
  async sync(caseId: string, state: InvestigationState, opts: DeriveOptions = {}): Promise<PlaybookTask[]> {
    const existing = await this.load(caseId);
    const { tasks, changed } = mergePlaybook(existing, derivePlaybookTasks(state, opts), new Date().toISOString());
    if (changed) await this.save(caseId, tasks);
    return sortPlaybookTasks(tasks);
  }
}
