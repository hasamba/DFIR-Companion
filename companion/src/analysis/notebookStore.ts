import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";

// Per-case analyst notebook: free-form notes and open questions the investigator writes as they
// work through the case. Kept in `state/notebook.json` — NOT in InvestigationState, so synthesis
// never wipes it. Entries are optionally included in the holistic synthesis prompt when the
// analyst opts in via `ai-control.json` (includeNotebook: true), giving the AI context about
// current investigator thinking. Survives synthesis resets, like comments and tags.
//
// NOTE: the notebook is for observations + open questions. Testable, status-tracked HYPOTHESES
// have their own home — the Hypotheses panel (#140, `hypothesisStore`). The old "hypothesis"
// entry type was removed to avoid two competing "hypothesis" surfaces; any legacy `hypothesis`
// entry loads as a plain "note" (the enum `.catch("note")`), and a note can be promoted into a
// tracked hypothesis from the dashboard.

export const NOTEBOOK_ENTRY_TYPES = ["note", "question"] as const;
export type NotebookEntryType = (typeof NOTEBOOK_ENTRY_TYPES)[number];

export const notebookEntrySchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  text: z.string(),
  type: z.enum(NOTEBOOK_ENTRY_TYPES).catch("note" as NotebookEntryType),
  // Investigator who wrote the entry (display name from the browser). Optional so notebooks
  // written before authorship existed still load; new entries default to "anonymous".
  author: z.string().optional(),
  linkedEntityIds: z.array(z.string()).optional(),
});

export type NotebookEntry = z.infer<typeof notebookEntrySchema>;
const notebookSchema = z.array(notebookEntrySchema).catch([]);

export interface NewNotebookEntry {
  text: string;
  type: NotebookEntryType;
  author?: string;
  linkedEntityIds?: string[];
}

export class NotebookStore {
  // Serializes this case's load->modify->save section (#216). Guards notebook.json only — a
  // PRIVATE lock, like HypothesisStore's, so it can never contend with the state lock.
  private readonly lock = new StateLock();

  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "notebook.json");
  }

  async load(caseId: string): Promise<NotebookEntry[]> {
    try {
      return notebookSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async save(caseId: string, entries: NotebookEntry[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(entries, null, 2));
  }

  // Append an entry (server-assigned id + timestamp). Text is trimmed; type falls back
  // to "note" if unrecognized. Returns the stored entry.
  async add(caseId: string, input: NewNotebookEntry): Promise<NotebookEntry> {
    const type: NotebookEntryType = NOTEBOOK_ENTRY_TYPES.includes(input.type) ? input.type : "note";
    const entry: NotebookEntry = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      text: String(input.text).trim(),
      type,
      author: (input.author || "").trim() || "anonymous",
      ...(input.linkedEntityIds?.length ? { linkedEntityIds: input.linkedEntityIds } : {}),
    };
    return this.lock.runExclusive(caseId, async () => {
      await this.save(caseId, [...(await this.load(caseId)), entry]);
      return entry;
    });
  }

  // Update text, type, and/or linkedEntityIds of an existing entry. Returns the updated
  // entry, or null if not found.
  async update(
    caseId: string,
    entryId: string,
    patch: Partial<Pick<NotebookEntry, "text" | "type" | "linkedEntityIds">>,
  ): Promise<NotebookEntry | null> {
    return this.lock.runExclusive(caseId, async () => {
      const entries = await this.load(caseId);
      let updated: NotebookEntry | null = null;
      const next = entries.map((e) => {
        if (e.id !== entryId) return e;
        updated = {
          ...e,
          ...(patch.text !== undefined ? { text: String(patch.text).trim() } : {}),
          ...(patch.type !== undefined && NOTEBOOK_ENTRY_TYPES.includes(patch.type) ? { type: patch.type } : {}),
          ...(patch.linkedEntityIds !== undefined ? { linkedEntityIds: patch.linkedEntityIds } : {}),
        };
        return updated;
      });
      if (!updated) return null;
      await this.save(caseId, next);
      return updated;
    });
  }

  // Remove one entry by id; returns true if it existed.
  async remove(caseId: string, entryId: string): Promise<boolean> {
    return this.lock.runExclusive(caseId, async () => {
      const entries = await this.load(caseId);
      const next = entries.filter((e) => e.id !== entryId);
      if (next.length === entries.length) return false;
      await this.save(caseId, next);
      return true;
    });
  }
}
