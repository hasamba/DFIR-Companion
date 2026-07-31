import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import type { HuntDataset, HuntParameters } from "./huntQueryTypes.js";

const parameterValueSchema = z.union([z.string(), z.number().finite(), z.boolean(), z.null()]);
const parametersSchema = z.record(parameterValueSchema);
const executionStatusSchema = z.enum(["completed", "cancelled", "limited", "failed"]);

const savedHuntExecutionSchema = z.object({
  id: z.string(),
  executedAt: z.string(),
  executedBy: z.string(),
  status: executionStatusSchema,
  matched: z.number().int().nonnegative(),
  scanned: z.number().int().nonnegative(),
  durationMs: z.number().int().nonnegative(),
  parameters: parametersSchema,
  error: z.string().optional(),
});

const savedHuntSchema = z.object({
  id: z.string(),
  name: z.string(),
  query: z.string(),
  dataset: z.enum(["forensic", "super"]),
  author: z.string(),
  parameters: parametersSchema,
  createdAt: z.string(),
  updatedAt: z.string(),
  history: z.array(savedHuntExecutionSchema),
});

const savedHuntsSchema = z.array(savedHuntSchema).catch([]);

export type SavedHuntExecution = z.infer<typeof savedHuntExecutionSchema>;
export type SavedHunt = z.infer<typeof savedHuntSchema>;
export type SavedHuntExecutionStatus = z.infer<typeof executionStatusSchema>;

export interface SavedHuntInput {
  name: string;
  query: string;
  dataset: HuntDataset;
  author: string;
  parameters: HuntParameters;
}

export interface SavedHuntExecutionInput {
  executedBy: string;
  status: SavedHuntExecutionStatus;
  matched: number;
  scanned: number;
  durationMs: number;
  parameters: HuntParameters;
  error?: string;
}

export interface SavedHuntStoreOptions {
  maxHistory?: number;
  now?: () => Date;
}

const DEFAULT_MAX_HISTORY = 50;
const MAX_NAME_LENGTH = 200;
const MAX_QUERY_LENGTH = 20_000;
const MAX_AUTHOR_LENGTH = 200;
const MAX_ERROR_LENGTH = 1_000;

function cleanInput(input: SavedHuntInput): SavedHuntInput {
  const name = input.name.trim().slice(0, MAX_NAME_LENGTH);
  const query = input.query.trim().slice(0, MAX_QUERY_LENGTH);
  const author = input.author.trim().slice(0, MAX_AUTHOR_LENGTH) || "anonymous";
  if (!name) throw new Error("saved hunt name is required");
  if (!query) throw new Error("saved hunt query is required");
  return {
    name,
    query,
    dataset: input.dataset,
    author,
    parameters: parametersSchema.parse(input.parameters),
  };
}

export class SavedHuntStore {
  private readonly lock = new StateLock();
  private readonly maxHistory: number;
  private readonly now: () => Date;

  constructor(
    private readonly cases: CaseStore,
    options: SavedHuntStoreOptions = {},
  ) {
    this.maxHistory = Math.max(1, Math.floor(options.maxHistory ?? DEFAULT_MAX_HISTORY));
    this.now = options.now ?? (() => new Date());
  }

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "saved-hunts.json");
  }

  async list(caseId: string): Promise<SavedHunt[]> {
    try {
      return savedHuntsSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }

  private async save(caseId: string, hunts: readonly SavedHunt[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(hunts, null, 2));
  }

  async create(caseId: string, raw: SavedHuntInput): Promise<SavedHunt> {
    const input = cleanInput(raw);
    const timestamp = this.now().toISOString();
    const hunt: SavedHunt = {
      id: randomUUID(),
      ...input,
      createdAt: timestamp,
      updatedAt: timestamp,
      history: [],
    };
    return this.lock.runExclusive(caseId, async () => {
      const hunts = await this.list(caseId);
      await this.save(caseId, [hunt, ...hunts]);
      return hunt;
    });
  }

  async update(caseId: string, huntId: string, raw: SavedHuntInput): Promise<SavedHunt | null> {
    const input = cleanInput(raw);
    return this.lock.runExclusive(caseId, async () => {
      const hunts = await this.list(caseId);
      let updated: SavedHunt | null = null;
      const next = hunts.map((hunt) => {
        if (hunt.id !== huntId) return hunt;
        updated = {
          ...hunt,
          ...input,
          updatedAt: this.now().toISOString(),
        };
        return updated;
      });
      if (!updated) return null;
      await this.save(caseId, next);
      return updated;
    });
  }

  async remove(caseId: string, huntId: string): Promise<boolean> {
    return this.lock.runExclusive(caseId, async () => {
      const hunts = await this.list(caseId);
      const next = hunts.filter((hunt) => hunt.id !== huntId);
      if (next.length === hunts.length) return false;
      await this.save(caseId, next);
      return true;
    });
  }

  async recordExecution(
    caseId: string,
    huntId: string,
    raw: SavedHuntExecutionInput,
  ): Promise<SavedHunt | null> {
    const execution: SavedHuntExecution = {
      id: randomUUID(),
      executedAt: this.now().toISOString(),
      executedBy: raw.executedBy.trim().slice(0, MAX_AUTHOR_LENGTH) || "anonymous",
      status: raw.status,
      matched: Math.max(0, Math.floor(raw.matched)),
      scanned: Math.max(0, Math.floor(raw.scanned)),
      durationMs: Math.max(0, Math.floor(raw.durationMs)),
      parameters: parametersSchema.parse(raw.parameters),
      ...(raw.error ? { error: raw.error.slice(0, MAX_ERROR_LENGTH) } : {}),
    };
    return this.lock.runExclusive(caseId, async () => {
      const hunts = await this.list(caseId);
      let updated: SavedHunt | null = null;
      const next = hunts.map((hunt) => {
        if (hunt.id !== huntId) return hunt;
        updated = {
          ...hunt,
          updatedAt: execution.executedAt,
          history: [execution, ...hunt.history].slice(0, this.maxHistory),
        };
        return updated;
      });
      if (!updated) return null;
      await this.save(caseId, next);
      return updated;
    });
  }
}
