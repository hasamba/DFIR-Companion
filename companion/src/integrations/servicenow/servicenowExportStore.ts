import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../../storage/caseStore.js";
import { atomicWrite } from "../../storage/atomicWrite.js";
import { StateLock } from "../../analysis/stateLock.js";
import type { ServiceNowIncidentRef } from "./servicenowClient.js";

// Per-case memory of finding → ServiceNow incident numbers. Stored in `state/servicenow-export.json`.

const servicenowExportSchema = z.object({
  incidentRefs: z
    .record(z.string(), z.object({ id: z.string(), number: z.string(), url: z.string().optional() }))
    .catch({}),
  lastExportedAt: z.string().catch(""),
});

export type ServiceNowExport = z.infer<typeof servicenowExportSchema>;

const EMPTY: ServiceNowExport = { incidentRefs: {}, lastExportedAt: "" };

// Serializes a case's load->merge->save section on the export pointer file (follow-up to #682). The
// ticket references live in one map, so two exports of the same case running together drop one
// side's refs — and because a missing ref is how this store says "no ticket exists yet", the NEXT
// export opens a DUPLICATE ticket in somebody else's queue. That is the rare one in this class with
// a consequence outside the tool.
const servicenowExportLock = new StateLock();

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

  record(
    caseId: string,
    refs: Record<string, ServiceNowIncidentRef>,
    now?: string,
  ): Promise<ServiceNowExport> {
    return servicenowExportLock.runExclusive(caseId, async () => {
      const prev = await this.load(caseId);
      const next: ServiceNowExport = {
        incidentRefs: { ...prev.incidentRefs, ...refs },
        lastExportedAt: now ?? new Date().toISOString(),
      };
      await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
      return next;
    });
  }

  // Alias matching the structural store interface used by servicenowPush.ts.
  async save(caseId: string, refs: Record<string, ServiceNowIncidentRef>): Promise<void> {
    await this.record(caseId, refs);
  }
}
