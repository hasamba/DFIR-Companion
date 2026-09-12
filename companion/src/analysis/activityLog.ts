import { readFile, appendFile, mkdir } from "node:fs/promises";
import { createReadStream, existsSync } from "node:fs";
import { createInterface } from "node:readline";
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
   * Walk forward from a position, oldest-first, one batch at a time — the shape the SIEM audit
   * export needs (#929).
   *
   * `load()` cannot serve that job: it returns newest-first, filters by category, and has no way to
   * say "what is new since last time". A feed must deliver actions in the order they happened and
   * must be able to resume.
   *
   * ONE PASS, STREAMED. The first version read the whole file with readFile() and sliced the
   * requested window out of it, so draining a long history in 500-line steps re-read every earlier
   * line on every step — quadratic I/O on a backfill, and every later live action re-reading years
   * of history to reach the tail. A line-by-line stream reads each line once per drain and holds
   * only one batch in memory, which is what the `limit` was supposed to guarantee.
   *
   * The position counts RAW LINES, including ones that failed to parse. Counting parsed entries
   * instead would shift the position by one for every corrupt line the reader skipped, and the
   * exporter would re-send a good entry after it forever.
   */
  async *readBatches(
    caseId: string,
    afterLines: number,
    limit = ACTIVITY_READ_BATCH,
  ): AsyncGenerator<{ entries: ActivityLogEntry[]; lines: number }> {
    const from = Number.isFinite(afterLines) && afterLines > 0 ? Math.floor(afterLines) : 0;
    const size = Math.max(1, Math.floor(limit));
    const lines = this.lineStream(caseId);
    if (!lines) return;
    let seen = 0;
    // Raw lines already yielded. Every window is measured from here, never from `from`, so the
    // second and later windows are full-sized rather than one line long.
    let windowStart = from;
    let entries: ActivityLogEntry[] = [];
    try {
      for await (const line of lines) {
        seen += 1;
        if (seen <= from) continue;
        if (line.trim()) {
          try {
            entries.push(activityLogEntrySchema.parse(JSON.parse(line)));
          } catch {
            /* skip a malformed line — it is still counted, see above */
          }
        }
        // The window closes on RAW lines, not on parsed entries, so the position it reports is the
        // position the caller must store.
        if (seen - windowStart >= size) {
          yield { entries, lines: seen };
          entries = [];
          windowStart = seen;
        }
      }
      // A final partial window. `seen > windowStart` is the only condition: it is false both for an
      // empty walk and for a history that divided exactly into full windows.
      if (seen > windowStart) yield { entries, lines: seen };
    } finally {
      lines.close();
    }
  }

  /**
   * The first batch from a position. Kept for callers that want one window rather than a walk;
   * built on the same stream, so it is not a whole-file read either.
   */
  async readFrom(
    caseId: string,
    afterLines: number,
    limit = ACTIVITY_READ_BATCH,
  ): Promise<{ entries: ActivityLogEntry[]; lines: number }> {
    const from = Number.isFinite(afterLines) && afterLines > 0 ? Math.floor(afterLines) : 0;
    for await (const batch of this.readBatches(caseId, from, limit)) {
      return batch;
    }
    return { entries: [], lines: from };
  }

  /**
   * How many raw lines the case's log holds. This is the value a destination's delivery position is
   * seeded with when it is switched on, so that enabling forwards what happens NEXT rather than
   * everything already recorded. Streamed — it never holds the file.
   */
  async countLines(caseId: string): Promise<number> {
    const lines = this.lineStream(caseId);
    if (!lines) return 0;
    let seen = 0;
    try {
      for await (const _line of lines) seen += 1;
    } finally {
      lines.close();
    }
    return seen;
  }

  /**
   * A line reader over the case's log, or undefined when there is no log yet. readline drops the
   * empty string a trailing newline would otherwise produce, which is the same correction the
   * whole-file version made by popping it.
   */
  private lineStream(caseId: string): ReturnType<typeof createInterface> | undefined {
    const path = this.path(caseId);
    if (!existsSync(path)) return undefined;
    return createInterface({
      input: createReadStream(path, { encoding: "utf8" }),
      crlfDelay: Infinity,
    });
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
