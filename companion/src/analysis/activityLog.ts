import { readFile, appendFile, mkdir } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { authenticatedActorFields } from "../auth/identityContext.js";

// Per-case investigation activity log (#238, rescoped from #224 which is closed): a
// chronological record of security-relevant actions taken on a case — imports, mark/unmark
// false-positive, AI runs (synthesis/2nd-opinion/ask/…), enrichment/anonymization toggles,
// per-case settings changes, playbook edits, comments/tags, hunt runs, exports. Append-only
// JSONL (mirrors captures.jsonl/imports.jsonl in caseStore.ts) — NOT part of InvestigationState,
// so synthesis never wipes it. Per-case only: no global/admin view, no CSV/legal-export
// requirement (that was #224's dropped scope).

export const ACTIVITY_CATEGORIES = [
  "import",
  "triage",
  "ai",
  "enrichment",
  "anonymization",
  "settings",
  "playbook",
  "collaboration",
  "hunt",
  "export",
] as const;
export type ActivityCategory = (typeof ACTIVITY_CATEGORIES)[number];

// How many raw log lines one forward read consumes (readFrom). Sized so a batch stays well inside
// a Splunk HEC or Elasticsearch bulk request without needing its own chunking, and so a case with
// years of history is walked in steps rather than loaded whole.
export const ACTIVITY_READ_BATCH = 500;

export const activityLogEntrySchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  actor: z.string().catch("analyst"),
  actorId: z.string().optional(),
  actorDisplayName: z.string().optional(),
  actorKind: z.enum(["local", "oidc", "service"]).optional(),
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
    const authenticated = authenticatedActorFields();
    const entry: ActivityLogEntry = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      actor: authenticated?.actorDisplayName ?? ((input.actor ?? "").trim() || "analyst"),
      ...(authenticated ?? {}),
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
      } catch {
        /* skip a malformed line */
      }
    }
    entries.reverse();
    const filtered = filter.category ? entries.filter((e) => e.category === filter.category) : entries;
    return typeof filter.limit === "number" ? filtered.slice(0, filter.limit) : filtered;
  }

  /**
   * Read forward from a position, oldest-first — the shape the SIEM audit export needs (#929).
   *
   * `load()` cannot serve that job: it returns newest-first, filters by category, and has no way to
   * say "what is new since last time". A feed must deliver actions in the order they happened and
   * must be able to resume, so this returns a slice plus the position after it.
   *
   * The position counts RAW LINES, including ones that failed to parse. Counting parsed entries
   * instead would shift the position by one for every corrupt line the reader skipped, and the
   * exporter would re-send a good entry after it forever.
   *
   * `limit` bounds one read so a long-lived case cannot pull its entire history into memory in one
   * go; the caller advances and calls again.
   */
  async readFrom(
    caseId: string,
    afterLines: number,
    limit = ACTIVITY_READ_BATCH,
  ): Promise<{ entries: ActivityLogEntry[]; lines: number }> {
    const from = Number.isFinite(afterLines) && afterLines > 0 ? Math.floor(afterLines) : 0;
    let text: string;
    try {
      text = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { entries: [], lines: from };
      throw err;
    }
    const raw = text.split("\n");
    // An append-only file always ends with a newline, which split() turns into a trailing empty
    // element. It is not a record and must not be counted as one.
    if (raw.length && raw[raw.length - 1] === "") raw.pop();
    const slice = raw.slice(from, from + Math.max(1, Math.floor(limit)));
    const entries: ActivityLogEntry[] = [];
    for (const line of slice) {
      if (!line.trim()) continue;
      try {
        entries.push(activityLogEntrySchema.parse(JSON.parse(line)));
      } catch {
        /* skip a malformed line — it is still counted, see above */
      }
    }
    return { entries, lines: from + slice.length };
  }
}

// Await an append when the response must disclose that the audit side channel failed. The warning
// is deliberately data, not a rejection: the primary action has already happened and still succeeds.
export async function logActivityWithWarning(
  store: ActivityLogStore | undefined,
  onActivity: ((caseId: string) => void) | undefined,
  caseId: string,
  input: NewActivityEntry,
): Promise<string | undefined> {
  if (!store) return undefined;
  try {
    await store.add(caseId, input);
  } catch (err) {
    return `activity log append failed for case ${caseId}: ${(err as Error).message}`;
  }
  try {
    onActivity?.(caseId);
  } catch {
    // A failed live-refresh notification does not mean the durable append failed.
  }
  return undefined;
}

// Best-effort append used at instrumented routes. Never rejects or breaks the primary action.
export async function logActivity(
  store: ActivityLogStore | undefined,
  onActivity: ((caseId: string) => void) | undefined,
  caseId: string,
  input: NewActivityEntry,
): Promise<void> {
  await logActivityWithWarning(store, onActivity, caseId, input);
}
