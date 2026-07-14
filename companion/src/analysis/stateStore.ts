import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { type InvestigationState, emptyState } from "./stateTypes.js";

export class StateStore {
  // onRetry (optional): invoked with (caseId, retries) when a save's atomic rename only succeeded
  // after retrying through a transient lock — lets the server warn that the state dir is contended
  // (antivirus / search-indexer / sync client) before it escalates to a hard EPERM failure.
  constructor(
    private readonly cases: CaseStore,
    private readonly onRetry?: (caseId: string, retries: number) => void,
  ) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "investigation.json");
  }

  async load(caseId: string): Promise<InvestigationState> {
    try {
      const raw = await readFile(this.path(caseId), "utf8");
      const parsed = JSON.parse(raw) as Partial<InvestigationState>;
      // Normalize over a fresh empty state so cases persisted before a field was
      // introduced (e.g. nextSteps, keyQuestions) still load with that field present.
      return { ...emptyState(caseId), ...parsed, caseId };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyState(caseId);
      throw err;
    }
  }

  async save(state: InvestigationState): Promise<void> {
    // Atomic write with retry — antivirus, the search indexer, or a Dropbox/OneDrive-synced cases/
    // dir can briefly lock investigation.json and make the rename throw EPERM. A large state file
    // (big imports) widens that window, so we also surface a warning when a save had to retry.
    await atomicWrite(this.path(state.caseId), JSON.stringify(state, null, 2), {
      onRetry: this.onRetry ? (retries) => this.onRetry?.(state.caseId, retries) : undefined,
    });
  }
}
