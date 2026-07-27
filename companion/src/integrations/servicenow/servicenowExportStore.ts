import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../../storage/caseStore.js";
import { atomicWrite } from "../../storage/atomicWrite.js";
import type { ServiceNowIncidentRef } from "./servicenowClient.js";

// Per-case memory of finding → ServiceNow incident numbers. Stored in `state/servicenow-export.json`.

const servicenowExportSchema = z.object({
  incidentRefs: z.record(z.string(), z.object({ id: z.string(), number: z.string(), url: z.string().optional() })).catch({}),
  lastExportedAt: z.string().catch(""),
});

export type ServiceNowExport = z.infer<typeof servicenowExportSchema>;

const EMPTY: ServiceNowExport = { incidentRefs: {}, lastExportedAt: "" };

export class ServiceNowExportStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "servicenow-export.json");
  }

  async load(caseId: string): Promise<ServiceNowExport> {
    try {
      return servicenowExportSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  async record(caseId: string, refs: Record<string, ServiceNowIncidentRef>, now?: string): Promise<ServiceNowExport> {
    const prev = await this.load(caseId);
    const next: ServiceNowExport = {
      incidentRefs: { ...prev.incidentRefs, ...refs },
      lastExportedAt: now ?? new Date().toISOString(),
    };
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return next;
  }

  // Alias matching the structural store interface used by servicenowPush.ts.
  async save(caseId: string, refs: Record<string, ServiceNowIncidentRef>): Promise<void> {
    await this.record(caseId, refs);
  }
}
