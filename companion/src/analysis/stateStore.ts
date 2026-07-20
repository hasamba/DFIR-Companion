import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { type InvestigationState, emptyState } from "./stateTypes.js";

export interface StateStoreDeps {
  readFile?: (path: string) => Promise<string>;
}

// True when `err` means "this file is bigger than a JS string can hold". Node's readFile throws
// ERR_STRING_TOO_LONG ("Cannot create a string longer than 0x1fffffe8 characters"); V8's string
// machinery can surface the same ceiling as a bare RangeError ("Invalid string length"). Both mean
// the state file crossed the ~512 MB max string length and cannot be decoded at all.
function isTooLargeToDecode(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException).code;
  if (code === "ERR_STRING_TOO_LONG") return true;
  const m = (err as Error)?.message ?? "";
  return /Invalid string length/i.test(m) || /string longer than/i.test(m);
}

export class StateStore {
  private readonly readFile: (path: string) => Promise<string>;

  // onRetry (optional): invoked with (caseId, retries) when a save's atomic rename only succeeded
  // after retrying through a transient lock — lets the server warn that the state dir is contended
  // (antivirus / search-indexer / sync client) before it escalates to a hard EPERM failure.
  // deps (optional): injection seam for tests — production uses fs readFile.
  constructor(
    private readonly cases: CaseStore,
    private readonly onRetry?: (caseId: string, retries: number) => void,
    deps: StateStoreDeps = {},
  ) {
    this.readFile = deps.readFile ?? ((p) => readFile(p, "utf8"));
  }

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "investigation.json");
  }

  async load(caseId: string): Promise<InvestigationState> {
    try {
      const raw = await this.readFile(this.path(caseId));
      const parsed = JSON.parse(raw) as Partial<InvestigationState>;
      // Normalize over a fresh empty state so cases persisted before a field was
      // introduced (e.g. nextSteps, keyQuestions) still load with that field present.
      return { ...emptyState(caseId), ...parsed, caseId };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyState(caseId);
      // A state file past the ~512 MB max string length can never be decoded again, so every
      // route that loads the case fails with an opaque RangeError and the case looks bricked.
      // Say so explicitly and name the recovery path (mirrors the 413 the import route returns
      // for an oversized input file, so the two limits read as the same limit).
      if (isTooLargeToDecode(err)) {
        throw new Error(
          `case "${caseId}" state file is too large to load: ${this.path(caseId)} exceeds the ~512 MB in-memory limit ` +
            `(roughly 900K events). Restore an earlier, smaller snapshot from the case's state/backups/ dir, ` +
            `or split the investigation across cases and re-import — no further imports into this case can be loaded.`,
        );
      }
      throw err;
    }
  }

  async save(state: InvestigationState): Promise<void> {
    // Atomic write with retry — antivirus, the search indexer, or a Dropbox/OneDrive-synced cases/
    // dir can briefly lock investigation.json and make the rename throw EPERM. A large state file
    // (big imports) widens that window, so we also surface a warning when a save had to retry.
    //
    // Serialized COMPACT, not pretty-printed: this file is machine-read (only StateStore.load
    // parses it), and at 250K events pretty costs 1210ms/112.5 MB vs 563ms/83.4 MB compact —
    // 2.1x faster to serialize and 26% smaller. Smaller also means a shorter rename window for
    // the retry budget above, and it pushes the unloadable ~512 MB ceiling in load() from
    // ~640K events out to ~900K.
    await atomicWrite(this.path(state.caseId), JSON.stringify(state), {
      onRetry: this.onRetry ? (retries) => this.onRetry?.(state.caseId, retries) : undefined,
    });
  }
}
