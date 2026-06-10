// Pure mappers: a Response Playbook task → a ClickUp task body. No I/O — deterministic and
// unit-tested. The orchestrator (clickupPush.ts) resolves the list's actual status names and
// wires these to the live client.

import type { PlaybookStatus, PlaybookTask } from "../../analysis/playbook.js";
import type { StepPriority } from "../../analysis/stateTypes.js";
import type { ClickUpTaskBody } from "./clickupClient.js";

// ClickUp task priority is an integer: 1=urgent, 2=high, 3=normal, 4=low.
const PRIORITY_BY_STEP: Record<StepPriority, number> = { critical: 1, high: 2, medium: 3, low: 4 };

export function clickupPriority(priority: StepPriority): number {
  return PRIORITY_BY_STEP[priority] ?? 3;
}

// Candidate ClickUp status names (lowercased), best→fallback, for a playbook status. ClickUp lists
// have arbitrary custom statuses, so the push resolves these against the list's real status names.
export function clickupStatusCandidates(status: PlaybookStatus): string[] {
  switch (status) {
    case "done": return ["complete", "completed", "done", "closed"];
    case "in_progress": return ["in progress", "doing", "wip", "in review", "open"];
    case "skipped": return ["closed", "complete", "won't do", "wont do", "canceled", "cancelled", "done"];
    default: return ["to do", "todo", "open", "not started", "backlog", "new"];
  }
}

// Resolve a playbook status to a status name that actually exists on the list (case-insensitive),
// or undefined to let ClickUp use the list's default status.
export function resolveClickUpStatus(listStatuses: readonly string[], status: PlaybookStatus): string | undefined {
  const have = new Set(listStatuses.map((s) => s.toLowerCase()));
  for (const name of clickupStatusCandidates(status)) if (have.has(name)) return name;
  return undefined;
}

// Parse a free-form due date ("YYYY-MM-DD") into a Unix-ms timestamp, or undefined if unparseable.
function parseDueMs(due?: string): number | undefined {
  if (!due) return undefined;
  const ms = Date.parse(due);
  return Number.isFinite(ms) ? ms : undefined;
}

// Build a ClickUp task body from a playbook task. `statusName` is the already-resolved list status
// (omitted → ClickUp uses the list default). Assignee/notes/source ride along in the description
// (assignee-by-name can't be set without resolving ClickUp user ids, so it's recorded as text).
export function mapPlaybookTaskToClickUp(task: PlaybookTask, statusName?: string): ClickUpTaskBody {
  const description = [
    task.description,
    task.assignee ? `Assignee: ${task.assignee}` : "",
    task.notes ? `Notes: ${task.notes}` : "",
    `— DFIR Companion (${task.source}, ${task.priority})`,
  ].filter(Boolean).join("\n\n");

  const body: ClickUpTaskBody = {
    name: task.title,
    description,
    priority: clickupPriority(task.priority),
  };
  if (statusName) body.status = statusName;
  const due = parseDueMs(task.dueDate);
  if (due !== undefined) { body.due_date = due; body.due_date_time = false; }
  return body;
}
