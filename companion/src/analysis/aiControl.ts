import { readFile } from "node:fs/promises";
import { atomicWrite } from "../storage/atomicWrite.js";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";

// Per-case AI analysis control. `enabled` gates the LIVE screenshot pipeline only —
// evidence is always captured, and explicit imports (CSV / log / THOR) always analyze.
// It defaults to OFF so a fresh app start or a brand-new case captures evidence without
// spending any AI until the analyst deliberately turns it on (the same OPSEC/cost-first
// default-off stance as threat-intel enrichment). `lastAnalyzedSeq` is the highest
// capture sequence the live pipeline has analyzed, so turning AI on backfills everything
// captured while it was off.
export interface AiControl {
  enabled: boolean;
  lastAnalyzedSeq: number;
  // When true, the analyst notebook entries are appended to the synthesis prompt so the
  // AI can incorporate investigator hypotheses and open questions. Off by default (opt-in).
  includeNotebook?: boolean;
}

const DEFAULT: AiControl = { enabled: false, lastAnalyzedSeq: 0 };

export class AiControlStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "ai-control.json");
  }

  async load(caseId: string): Promise<AiControl> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as Partial<AiControl>;
      return { ...DEFAULT, ...raw };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...DEFAULT };
      throw err;
    }
  }

  async save(caseId: string, control: AiControl): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(control, null, 2));
  }
}
