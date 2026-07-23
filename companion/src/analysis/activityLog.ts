import { readFile, appendFile, mkdir } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";

// Per-case investigation activity log (#238, rescoped from #224 which is closed): a
// chronological record of security-relevant actions taken on a case — imports, mark/unmark
// false-positive, AI runs (synthesis/2nd-opinion/ask/…), enrichment/anonymization toggles,
// per-case settings changes, playbook edits, comments/tags, hunt runs, exports. Append-only
// JSONL (mirrors captures.jsonl/imports.jsonl in caseStore.ts) — NOT part of InvestigationState,
// so synthesis never wipes it. Per-case only: no global/admin view, no CSV/legal-export
// requirement (that was #224's dropped scope).

export const ACTIVITY_CATEGORIES = [
  "import", "triage", "ai", "enrichment", "anonymization",
  "settings", "playbook", "collaboration", "hunt", "export",
] as const;
export type ActivityCategory = (typeof ACTIVITY_CATEGORIES)[number];

export const activityLogEntrySchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  actor: z.string().catch("analyst"),
  category: z.enum(ACTIVITY_CATEGORIES).catch("settings"),
  action: z.string().catch(""),
  detail: z.string().catch(""),
  targetType: z.string().optional(),
  targetId: z.string().optional(),
  outcome: z.enum(["success", "error"]).catch("success"),
});
export type ActivityLogEntry = z.infer<typeof activityLogEntrySchema>;

export interface NewActivityEntry {
  actor?: string;
  category: ActivityCategory;
  action: string;
  detail: string;
  targetType?: string;
  targetId?: string;
  outcome?: "success" | "error";
}

export interface ActivityLogFilter {
  category?: ActivityCategory;
  limit?: number;
}

export class ActivityLogStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.metadataDir(caseId), "activity.jsonl");
  }

  // Append one entry (server-assigned id + timestamp; actor trimmed, blank -> "analyst").
  async add(caseId: string, input: NewActivityEntry): Promise<ActivityLogEntry> {
    const entry: ActivityLogEntry = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      actor: (input.actor ?? "").trim() || "analyst",
      category: input.category,
      action: input.action,
      detail: input.detail,
      ...(input.targetType ? { targetType: input.targetType } : {}),
      ...(input.targetId ? { targetId: input.targetId } : {}),
      outcome: input.outcome ?? "success",
    };
    await mkdir(this.cases.metadataDir(caseId), { recursive: true });
    await appendFile(this.path(caseId), JSON.stringify(entry) + "\n", "utf8");
    return entry;
  }

  // All entries, newest first. A malformed line (e.g. from a mid-write crash) is skipped, never
  // fatal — an append-only log must stay readable even when one line is corrupt.
  async load(caseId: string, filter: ActivityLogFilter = {}): Promise<ActivityLogEntry[]> {
    let text: string;
    try {
      text = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const entries: ActivityLogEntry[] = [];
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      try {
        entries.push(activityLogEntrySchema.parse(JSON.parse(line)));
      } catch { /* skip a malformed line */ }
    }
    entries.reverse();
    const filtered = filter.category ? entries.filter((e) => e.category === filter.category) : entries;
    return typeof filter.limit === "number" ? filtered.slice(0, filter.limit) : filtered;
  }
}

// Best-effort append used at every instrumented route. Never rejects — this is a side channel
// and must never break the primary action it records. Callers may ignore the returned promise
// for fire-and-forget logging, or await it when the response promises immediate read-after-write
// consistency (for example, tag mutations followed by an activity-log refresh). No-ops when the
// store isn't configured (createApp-only unit tests that don't wire one).
export function logActivity(
  store: ActivityLogStore | undefined,
  onActivity: ((caseId: string) => void) | undefined,
  caseId: string,
  input: NewActivityEntry,
): Promise<void> {
  if (!store) return Promise.resolve();
  return store.add(caseId, input)
    .then(() => { onActivity?.(caseId); })
    .catch(() => {});
}
