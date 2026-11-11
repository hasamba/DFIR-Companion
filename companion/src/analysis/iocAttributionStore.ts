// Per-case analyst IOC attribution labels (#2543 part 1b), in state/ioc-attribution.json. A side
// file outside the investigation state, so neither a model delta nor a re-synthesis can set, clear
// or wipe a label. Read-modify-write under a per-file lock, like FalsePositiveStore.update (#1902):
// two quick label changes in the dashboard must not race to a lost write.

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import { StateLock } from "./stateLock.js";
import {
  attributionKey,
  sanitizeAttributionMap,
  type IocAttributionEntry,
  type IocAttributionLabel,
  type IocAttributionMap,
} from "./iocAttribution.js";

export const IOC_ATTRIBUTION_FILE = "ioc-attribution.json";

const fileLock = new StateLock();

export interface IocAttributionChange {
  value: string;
  before?: IocAttributionLabel;
  after?: IocAttributionLabel;
}

export class IocAttributionStore {
  constructor(private readonly cases: Pick<CaseStore, "stateDir">) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), IOC_ATTRIBUTION_FILE);
  }

  async load(caseId: string): Promise<IocAttributionMap> {
    try {
      return sanitizeAttributionMap(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
  }

  /** Set (label) or clear (null) one value's label. Returns the stored map and what changed. */
  async set(
    caseId: string,
    value: string,
    label: IocAttributionLabel | null,
    setBy: string,
  ): Promise<{ map: IocAttributionMap; change: IocAttributionChange }> {
    return fileLock.runExclusive(this.path(caseId), async () => {
      const current = await this.load(caseId);
      const key = attributionKey(value);
      const before = current[key]?.label;
      const { [key]: _old, ...rest } = current;
      const entry: IocAttributionEntry | null = label
        ? { value, label, setAt: new Date().toISOString(), setBy }
        : null;
      const next: IocAttributionMap = entry ? { ...rest, [key]: entry } : rest;
      if (before !== label) await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
      return {
        map: before !== label ? next : current,
        change: { value, ...(before ? { before } : {}), ...(label ? { after: label } : {}) },
      };
    });
  }
}
