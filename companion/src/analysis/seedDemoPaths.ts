import { stat } from "node:fs/promises";
import { join } from "node:path";
import { isValidCaseId } from "../storage/caseStore.js";

/**
 * Where the demo case is written, and whether one is already there.
 *
 * Split out of seedDemoCase.ts so the id check cannot be skipped: every destructive operation in
 * the seeder (`rm -rf` under force, the mkdir loop, the case.json / investigation.json writes)
 * targets the directory this returns, and `join(casesRoot, "../../somewhere")` resolves outside
 * the cases root entirely. The HTTP route validates its body caseId too, but seedDemoCase is also
 * called by scripts/seed-demo-case.ts, so the guard belongs at the point the path is computed
 * rather than at one of the two callers (#427).
 */
export function demoCaseDir(casesRoot: string, caseId: string): string {
  if (!isValidCaseId(caseId)) {
    const err = new Error(
      `invalid caseId "${caseId}": use only letters, numbers, dots, dashes, or underscores, and no path traversal`,
    );
    (err as NodeJS.ErrnoException).code = "EINVAL";
    throw err;
  }
  return join(casesRoot, caseId);
}

/** True when caseDir already holds a case.json — the "exists, refuse unless force" precondition. */
export async function caseAlreadySeeded(caseDir: string): Promise<boolean> {
  try {
    await stat(join(caseDir, "case.json"));
    return true;
  } catch {
    return false;
  }
}
