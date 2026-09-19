import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { storedFindingTaskSchema, type StoredFindingTask } from "./findingTasks.js";

// Per-case AI-written finding tasks (#1418), keyed by finding id. A side file
// (`state/finding-tasks.json`) rather than a field on the finding: synthesis rebuilds findings from
// scratch every run and the fold would have to learn to carry it, whereas a side file survives
// untouched and the playbook derivation reads it by id — the same pattern as playbook-control.json
// and the hypothesis store. Writes go through atomicWrite (Dropbox-safe temp-rename).

const FILE = "finding-tasks.json";

const fileSchema = z.object({
  version: z.literal(1),
  // A malformed entry is dropped, not fatal: one bad row must not blank every other finding's task.
  tasks: z.record(z.string(), z.unknown()),
});

export type FindingTaskMap = Readonly<Record<string, StoredFindingTask>>;

function parseTasks(raw: unknown): Record<string, StoredFindingTask> {
  const parsed = fileSchema.safeParse(raw);
  if (!parsed.success) return {};
  const out: Record<string, StoredFindingTask> = {};
  for (const [id, value] of Object.entries(parsed.data.tasks)) {
    const task = storedFindingTaskSchema.safeParse(value);
    if (task.success) out[id] = task.data;
  }
  return out;
}

export class FindingTaskStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), FILE);
  }

  async load(caseId: string): Promise<FindingTaskMap> {
    try {
      return parseTasks(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      // A torn or hand-edited file reads as empty; the next pass rewrites it.
      return {};
    }
  }

  // Merge `fresh` over what is stored, then drop every entry whose finding is not in
  // `liveFindingIds` (the case's current findings) so a renamed or removed finding leaves no orphan.
  async upsert(
    caseId: string,
    fresh: Readonly<Record<string, StoredFindingTask>>,
    liveFindingIds: readonly string[],
  ): Promise<FindingTaskMap> {
    const live = new Set(liveFindingIds);
    const merged: Record<string, StoredFindingTask> = {};
    for (const [id, task] of Object.entries({ ...(await this.load(caseId)), ...fresh })) {
      if (live.has(id)) merged[id] = task;
    }
    await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, tasks: merged }, null, 2));
    return merged;
  }
}
