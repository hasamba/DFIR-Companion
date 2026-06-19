// companion/src/analysis/updateCheckStore.ts
import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { UpdateResult } from "./updateCheck.js";

// GLOBAL store for the update-check feature (issue #127). Shared across cases — the running
// version + "is a newer release out?" are environment-level, like NSRL / KEV / the IOC whitelist.
// File: updates/update-check.json in a SUBDIR beside cases/ (drive-root-safe). Atomic writes.
export interface UpdateCheckRecord {
  enabled?: boolean;       // the Settings toggle (undefined = analyst hasn't set it)
  result?: UpdateResult;   // the last cached check result
}

export class UpdateCheckStore {
  private cache: UpdateCheckRecord | null = null;
  constructor(private readonly file: string) {}

  async load(): Promise<UpdateCheckRecord> {
    if (this.cache) return this.cache;
    try {
      const raw = JSON.parse(await readFile(this.file, "utf8")) as unknown;
      this.cache = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as UpdateCheckRecord) : {};
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") this.cache = {};
      else throw err;
    }
    return this.cache;
  }

  private async persist(next: UpdateCheckRecord): Promise<void> {
    const dir = dirname(this.file);
    if (dir && !existsSync(dir)) await mkdir(dir, { recursive: true });
    await atomicWrite(this.file, JSON.stringify(next, null, 2));
    this.cache = next;
  }

  async setEnabled(enabled: boolean): Promise<void> {
    await this.persist({ ...(await this.load()), enabled });
  }

  async setResult(result: UpdateResult): Promise<void> {
    await this.persist({ ...(await this.load()), result });
  }
}
