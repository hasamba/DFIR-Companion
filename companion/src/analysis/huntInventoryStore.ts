import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import { StateLock } from "./stateLock.js";
import { EMPTY_INVENTORY, type HuntInventory } from "./huntInventory.js";
import { canonicalizeInventory } from "./huntInventoryCanon.js";
import type { HuntGrade } from "./huntEntries.js";

/**
 * The per-case hunt inventory file (#2670), `state/hunt-inventory.json`, plus the bookkeeping the
 * grader needs: which grouped entries it last wrote and the signature of the inputs it graded, so an
 * empty settle with unchanged coverage costs one read. Written under a per-case lock.
 */
export interface HuntInventoryRecord {
  inventory: HuntInventory;
  /** Grouped entry ids the last grading wrote to the forensic timeline. */
  entryIds: string[];
  /** The last grading's grades, worst first, capped at GRADES_KEPT (panel + report). */
  grades: HuntGrade[];
  /** Labels of the items the baseline approves — the AI's hunt framing says "Approved by client". */
  approvedLabels: string[];
  /** What the last grading read (coverage, settings, baseline version) — skip when unchanged. */
  gradedSignature: string;
  /** The client baseline version the case was graded against (phase 5), pinned. */
  baselineVersion?: number;
}

export const GRADES_KEPT = 500;

export const EMPTY_RECORD: HuntInventoryRecord = {
  inventory: EMPTY_INVENTORY,
  entryIds: [],
  grades: [],
  approvedLabels: [],
  gradedSignature: "",
};

const lock = new StateLock();

function parse(raw: unknown): HuntInventoryRecord {
  const r = raw as Partial<HuntInventoryRecord> | null;
  if (!r || typeof r !== "object" || !r.inventory || typeof r.inventory !== "object")
    return { ...EMPTY_RECORD };
  // #2750: an inventory stored before known-folder GUID paths were normalised is re-keyed on load,
  // and its grading signature cleared so the next settle re-grades the merged items.
  const canon = canonicalizeInventory({ ...EMPTY_INVENTORY, ...r.inventory, items: r.inventory.items ?? {} });
  return {
    inventory: canon.inventory,
    entryIds: Array.isArray(r.entryIds) ? r.entryIds.filter((x): x is string => typeof x === "string") : [],
    // A re-key can merge hosts into an existing item, so every stored grade may now be wrong (a
    // "rare" item can stop being rare): drop them all and let the next settle or regrade rebuild them.
    grades: !canon.changed && Array.isArray(r.grades) ? r.grades.slice(0, GRADES_KEPT) : [],
    approvedLabels: Array.isArray(r.approvedLabels)
      ? r.approvedLabels.filter((x): x is string => typeof x === "string").slice(0, GRADES_KEPT)
      : [],
    gradedSignature: !canon.changed && typeof r.gradedSignature === "string" ? r.gradedSignature : "",
    ...(typeof r.baselineVersion === "number" ? { baselineVersion: r.baselineVersion } : {}),
  };
}

export class HuntInventoryStore {
  constructor(private readonly cases: Pick<CaseStore, "stateDir">) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "hunt-inventory.json");
  }

  async load(caseId: string): Promise<HuntInventoryRecord> {
    try {
      return parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || err instanceof SyntaxError) return { ...EMPTY_RECORD };
      throw err;
    }
  }

  /** Read-modify-write under the case's inventory lock. */
  update(
    caseId: string,
    fn: (cur: HuntInventoryRecord) => HuntInventoryRecord | Promise<HuntInventoryRecord>,
  ): Promise<HuntInventoryRecord> {
    return lock.runExclusive(caseId, async () => {
      const next = await fn(await this.load(caseId));
      await atomicWrite(this.path(caseId), JSON.stringify(next));
      return next;
    });
  }
}
