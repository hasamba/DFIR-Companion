import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Analyst assignment + workflow status for findings (#87). A finding carries an AI-set tri-state
// `status` (open/confirmed/dismissed, `stateTypes.ts`) but no HUMAN owner and no analyst-editable
// workflow state. This adds both — an `assignee` and a `workflowStatus` — kept in a per-case side
// file (`state/finding-workflow.json`), NOT in InvestigationState, so a re-synthesis never wipes an
// analyst's triage (the same guarantee comments/tags/pinned-findings rely on). Each record is keyed
// by findingId; the dashboard resolves it against the live findings and merges it onto the card.
//
// Modeled on pinnedFindings.ts, but a keyed UPSERT rather than an ordered list. The workflow status
// is deliberately separate from the AI `status`: the AI states an assessment, the analyst tracks the
// human triage lifecycle (new → in progress → in review → resolved).

// The analyst-editable workflow states. Distinct from the AI Finding.status enum.
export const FINDING_WORKFLOW_STATUSES = ["new", "in_progress", "in_review", "resolved"] as const;
export type FindingWorkflowStatus = (typeof FINDING_WORKFLOW_STATUSES)[number];

// Cap the free-text assignee so a paste can't bloat the side file (mirrors the spirit of the other
// bounded analyst-text inputs).
export const MAX_ASSIGNEE_LENGTH = 120;

export const findingWorkflowSchema = z.object({
  findingId: z.string(),
  assignee: z.string().default("").catch(""),
  // null = no workflow status set (the analyst may assign an owner without a status, or vice versa).
  status: z.enum(FINDING_WORKFLOW_STATUSES).nullable().default(null).catch(null),
  updatedAt: z.string(),
  updatedBy: z.string().default("").catch(""),
});
export type FindingWorkflow = z.infer<typeof findingWorkflowSchema>;
const findingWorkflowsSchema = z.array(findingWorkflowSchema).catch([]);

// Fields an analyst may PATCH. Each is optional: an absent field is left unchanged; a present field
// (including an empty assignee or a null status) is applied — so a field can be explicitly cleared.
export interface FindingWorkflowPatch {
  assignee?: string;
  status?: FindingWorkflowStatus | null;
  updatedBy?: string;
}

export class FindingWorkflowStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "finding-workflow.json");
  }

  async load(caseId: string): Promise<FindingWorkflow[]> {
    try {
      return findingWorkflowsSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async save(caseId: string, records: FindingWorkflow[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(records, null, 2));
  }

  // Upsert the assignee/status for one finding. Only the fields present in `patch` change; the rest
  // are preserved from any existing record. A record whose assignee AND status both end up empty is
  // DROPPED, so the file only ever holds actively-triaged findings. Returns the resulting record, or
  // null when it was cleared (or never existed). Throws on a blank findingId.
  async patch(caseId: string, findingId: string, patch: FindingWorkflowPatch): Promise<FindingWorkflow | null> {
    const id = String(findingId ?? "").trim();
    if (!id) throw new Error("findingId is required");

    const records = await this.load(caseId);
    const existing = records.find((r) => r.findingId === id);

    const assignee = patch.assignee !== undefined
      ? String(patch.assignee).trim().slice(0, MAX_ASSIGNEE_LENGTH)
      : (existing?.assignee ?? "");

    let status: FindingWorkflowStatus | null;
    if (patch.status !== undefined) {
      status = patch.status && (FINDING_WORKFLOW_STATUSES as readonly string[]).includes(patch.status)
        ? patch.status
        : null;
    } else {
      status = existing?.status ?? null;
    }

    const rest = records.filter((r) => r.findingId !== id);

    // Both cleared → drop the record entirely (only write when something actually changed).
    if (!assignee && !status) {
      if (existing) await this.save(caseId, rest);
      return null;
    }

    const record: FindingWorkflow = {
      findingId: id,
      assignee,
      status,
      updatedAt: new Date().toISOString(),
      updatedBy: String(patch.updatedBy ?? "").trim(),
    };
    await this.save(caseId, [...rest, record]);
    return record;
  }
}
