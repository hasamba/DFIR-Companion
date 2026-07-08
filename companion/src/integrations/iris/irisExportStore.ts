import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../../storage/caseStore.js";
import { atomicWrite } from "../../storage/atomicWrite.js";

// Per-case memory of the DFIR-IRIS case name used on the LAST push, so a re-push with no
// explicit override keeps targeting the SAME IRIS case (find-or-create is name-based) instead
// of falling back to the computed default and creating a duplicate. Kept in
// `state/iris-export.json`, like the other side-file stores (see clickupExportStore.ts).

export const irisExportSchema = z.object({
  caseName: z.string().catch(""),   // last IRIS case name used for this Companion case ("" = never pushed)
});

export type IrisExport = z.infer<typeof irisExportSchema>;

const EMPTY: IrisExport = { caseName: "" };

export class IrisExportStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "iris-export.json");
  }

  async load(caseId: string): Promise<IrisExport> {
    try {
      return irisExportSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  async record(caseId: string, caseName: string): Promise<IrisExport> {
    const next: IrisExport = { caseName };
    await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
    return next;
  }
}

// The IRIS case name to use when nothing has been pushed yet and no override is given:
// "<companion case id> — <friendly name>", or just the id when the case has no friendly name.
export function defaultIrisCaseName(caseId: string, name: string | null | undefined): string {
  const trimmed = (name ?? "").trim();
  return trimmed ? `${caseId} — ${trimmed}` : caseId;
}
