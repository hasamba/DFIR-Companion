import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";

// Per-case Findings-panel display preferences. `minConfidence` undefined = show all (0);
// each `hide…` undefined = show that origin. Machine/analyst display preferences, not
// investigation data — nothing here removes anything from case state.
// state/confidence-control.json via atomicWrite.
export interface ConfidenceControl {
  minConfidence?: number;
  hideAutoFindings?: boolean;
  hideGapFindings?: boolean;
}

const schema = z
  .object({
    minConfidence: z.number().min(0).max(100).optional().catch(undefined),
    hideAutoFindings: z.boolean().optional().catch(undefined),
    hideGapFindings: z.boolean().optional().catch(undefined),
  })
  .catch({});

export class ConfidenceControlStore {
  // Serializes this case's load->modify->save section in `set` (below). `atomicWrite` only makes
  // the WRITE atomic; it does nothing for the read-modify-write cycle around it. Before this store
  // grew a second lens, `set` had exactly one caller, so two `set`s in flight for the same case was
  // unreachable. It now has two independent dashboard callers — the debounced confidence-floor PUT
  // and the immediate lens-checkbox PUT — that can both be mid-flight at once: both `load()` calls
  // await file I/O before either write, so the second write's spread of the pre-write state
  // silently clobbers whatever the first write just saved. Same idiom, same hazard, as
  // PinnedFindingsStore's lock (see its comment) — a PRIVATE lock, scoped to this store only.
  private readonly lock = new StateLock();

  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "confidence-control.json");
  }

  async load(caseId: string): Promise<ConfidenceControl> {
    try {
      return schema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
  }

  async set(caseId: string, patch: ConfidenceControl): Promise<ConfidenceControl> {
    return this.lock.runExclusive(caseId, async () => {
      // Key by key, not a spread of `patch`: the dashboard saves the confidence floor and the two
      // origin lenses from separate code paths, so a patch naming one must leave the others alone.
      // An explicitly-undefined key still counts as present, which is how a value is cleared.
      const next: ConfidenceControl = {
        ...(await this.load(caseId)),
        ...("minConfidence" in patch ? { minConfidence: patch.minConfidence } : {}),
        ...("hideAutoFindings" in patch ? { hideAutoFindings: patch.hideAutoFindings } : {}),
        ...("hideGapFindings" in patch ? { hideGapFindings: patch.hideGapFindings } : {}),
      };
      await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
      return next;
    });
  }
}
