import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Per-case analyst notebook: free-form hypotheses, notes, and open questions the
// investigator writes as they work through the case. Kept in `state/notebook.json`
// — NOT in InvestigationState, so synthesis never wipes it. Entries are optionally
// included in the holistic synthesis prompt when the analyst opts in via
// `ai-control.json` (includeNotebook: true), giving the AI context about current
// investigator thinking. Survives synthesis resets, like comments and tags.

export const NOTEBOOK_ENTRY_TYPES = ["hypothesis", "note", "question"] as const;
export type NotebookEntryType = (typeof NOTEBOOK_ENTRY_TYPES)[number];

export const notebookEntrySchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  text: z.string(),
  type: z.enum(NOTEBOOK_ENTRY_TYPES).catch("note" as NotebookEntryType),
  linkedEntityIds: z.array(z.string()).optional(),
});

export type NotebookEntry = z.infer<typeof notebookEntrySchema>;
const notebookSchema = z.array(notebookEntrySchema).catch([]);

export interface NewNotebookEntry {
  text: string;
  type: NotebookEntryType;
  linkedEntityIds?: string[];
}

export class NotebookStore {
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
      ...(input.linkedEntityIds?.length ? { linkedEntityIds: input.linkedEntityIds } : {}),
    };
    await this.save(caseId, [...(await this.load(caseId)), entry]);
    return entry;
  }

  // Update text, type, and/or linkedEntityIds of an existing entry. Returns the updated
  // entry, or null if not found.
  async update(
    caseId: string,
    entryId: string,
    patch: Partial<Pick<NotebookEntry, "text" | "type" | "linkedEntityIds">>,
  ): Promise<NotebookEntry | null> {
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
  }

  // Remove one entry by id; returns true if it existed.
  async remove(caseId: string, entryId: string): Promise<boolean> {
    const entries = await this.load(caseId);
    const next = entries.filter((e) => e.id !== entryId);
    if (next.length === entries.length) return false;
    await this.save(caseId, next);
    return true;
  }
}
