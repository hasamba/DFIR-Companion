// Orchestrates a Companion playbook → ClickUp push (issue #36, Phase 3). For each playbook task:
// if we already created a ClickUp task for it (stored id) UPDATE it, else CREATE it and remember
// the id — so re-exporting never duplicates and status/edits sync. The client is injected as a
// structural interface so this is unit-testable with no network (the IRIS/Notion pattern).

import type { PlaybookTask } from "../../analysis/playbook.js";
import type { ClickUpTaskBody, ClickUpTaskRef } from "./clickupClient.js";
import type { ClickUpExportStore } from "./clickupExportStore.js";
import { mapPlaybookTaskToClickUp, resolveClickUpStatus } from "./clickupMap.js";

// Structural subset of ClickUpClient used here — lets tests pass a lightweight mock.
export interface ClickUpClientLike {
  me(): Promise<{ id?: string; username?: string }>;
  listStatuses(listId: string): Promise<string[]>;
  createTask(listId: string, body: ClickUpTaskBody): Promise<ClickUpTaskRef>;
  updateTask(taskId: string, body: ClickUpTaskBody): Promise<ClickUpTaskRef>;
}

export interface ClickUpPushInput {
  caseId: string;            // the Companion case id (key for the export pointer store)
  listId: string;           // target ClickUp list id
  tasks: PlaybookTask[];     // the playbook tasks to export
}

export interface ClickUpPushResult {
  listId: string;
  created: number;
  updated: number;
  skipped: number;
  taskUrl?: string;          // a sample task url for an "Open in ClickUp" link
  warnings: string[];
}

export async function pushPlaybookToClickUp(
  client: ClickUpClientLike,
  input: ClickUpPushInput,
  store: ClickUpExportStore,
  now: string,
): Promise<ClickUpPushResult> {
  const warnings: string[] = [];

  // 1. Auth check (fatal).
  await client.me();

  // 2. Read the list's real status names so we can map playbook statuses onto them (non-fatal —
  //    if we can't read them, tasks are created with the list's default status).
  let listStatuses: string[] = [];
  try { listStatuses = await client.listStatuses(input.listId); }
  catch (err) { warnings.push(`statuses: ${(err as Error).message} — tasks will use the list default status`); }

  const prev = await store.load(input.caseId);
  const taskIds: Record<string, string> = { ...prev.taskIds };
  let created = 0, updated = 0, skipped = 0;
  let taskUrl: string | undefined;

  for (const task of input.tasks) {
    const body = mapPlaybookTaskToClickUp(task, resolveClickUpStatus(listStatuses, task.status));
    const existingId = taskIds[task.id];
    try {
      if (existingId) {
        const ref = await client.updateTask(existingId, body);
        taskUrl ??= ref.url;
        updated += 1;
      } else {
        const ref = await client.createTask(input.listId, body);
        if (ref.id) taskIds[task.id] = ref.id;
        taskUrl ??= ref.url;
        created += 1;
      }
    } catch (err) {
      skipped += 1;
      warnings.push(`task "${task.title}": ${(err as Error).message}`);
    }
  }

  await store.record(input.caseId, { listId: input.listId, taskIds, lastExportedAt: now, ...(taskUrl ? { lastTaskUrl: taskUrl } : {}) });

  return { listId: input.listId, created, updated, skipped, taskUrl, warnings };
}
