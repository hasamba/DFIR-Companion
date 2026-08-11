import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import { parseIncidentType, type IncidentType } from "./incidentTypes.js";
import { loadBuiltInIncidentTypes, getBuiltInIncidentType } from "./incidentTypesData.js";

// Per-case chosen incident-type store (#236), in state/incident-type.json. A stateless wrapper over
// CaseStore (mirrors SourceTrustStore / ClockSkewStore). Persists which incident type the analyst
// picked for this case, so the synthesis prompt, a re-apply, and the dashboard can read it back,
// plus the timestamp of the last apply.
//
// Custom (analyst-defined) incident types are loaded from a global data dir (mirroring
// TemplateStore's custom-templates dir): each *.json is one IncidentType definition, validated on
// read with the shared schema so a hand-edited file can't inject a malformed type into the apply
// path. Built-in types come from the bundled library (incidentTypesData.ts) and always win a
// name collision — a custom file cannot silently redefine "ransomware" out from under the analyst.

export interface IncidentTypeRecord {
  typeId: string; // the chosen incident type id (built-in or custom)
  appliedAt: string; // ISO timestamp of the last apply
}

export const EMPTY_INCIDENT_TYPE_RECORD: IncidentTypeRecord = { typeId: "", appliedAt: "" };

const incidentTypeRecordSchema = z.object({
  typeId: z.string().catch(""),
  appliedAt: z.string().catch(""),
});

export class IncidentTypeStore {
  constructor(
    private readonly cases: CaseStore,
    private readonly customDir: string,
  ) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "incident-type.json");
  }

  async loadRecord(caseId: string): Promise<IncidentTypeRecord> {
    try {
      return incidentTypeRecordSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY_INCIDENT_TYPE_RECORD };
      // A corrupt record must not block synthesis or the dashboard — the analyst can re-pick a type,
      // but they cannot recover a case whose every read throws.
      if (err instanceof SyntaxError) return { ...EMPTY_INCIDENT_TYPE_RECORD };
      throw err;
    }
  }

  async saveRecord(
    caseId: string,
    typeId: string,
    at: string = new Date().toISOString(),
  ): Promise<IncidentTypeRecord> {
    const record: IncidentTypeRecord = { typeId, appliedAt: at };
    await atomicWrite(this.path(caseId), JSON.stringify(record, null, 2));
    return record;
  }

  // The incident type currently chosen for a case, or null when none was picked (or the picked type
  // has since been deleted). Convenience for the synthesis path, which wants the definition and does
  // not care about the record.
  async loadType(caseId: string): Promise<IncidentType | null> {
    const record = await this.loadRecord(caseId);
    return record.typeId ? await this.get(record.typeId) : null;
  }

  // List every available incident type: built-ins first, then custom types from the data dir.
  async listAll(): Promise<IncidentType[]> {
    return [...loadBuiltInIncidentTypes(), ...(await this.listCustom())];
  }

  async listCustom(): Promise<IncidentType[]> {
    let entries: string[];
    try {
      entries = await readdir(this.customDir);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const out: IncidentType[] = [];
    for (const entry of entries) {
      if (!entry.endsWith(".json")) continue;
      try {
        const parsed = parseIncidentType(JSON.parse(await readFile(join(this.customDir, entry), "utf8")));
        // A custom file never gets to claim builtIn (the flag drives "can't delete this" in the UI),
        // and never gets to shadow a bundled id.
        if (parsed && !getBuiltInIncidentType(parsed.id)) out.push({ ...parsed, builtIn: false });
      } catch {
        // skip malformed files — never crash the type listing over a bad custom definition
      }
    }
    return out;
  }

  // Resolve a single incident type by id (built-in first, then custom).
  async get(id: string): Promise<IncidentType | null> {
    const builtin = getBuiltInIncidentType(id);
    if (builtin) return builtin;
    return (await this.listCustom()).find((t) => t.id === id) ?? null;
  }
}
