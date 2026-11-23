import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { StateLock } from "../analysis/stateLock.js";
import { atomicWrite } from "./atomicWrite.js";

/**
 * Every case id this cases root has ever issued (#561, #2858).
 *
 * An incident number is not free again once it has been used: the reports, ZIP archives and
 * .dfircase exports written for that case still carry it, so reissuing it would file two unrelated
 * investigations under one number. Ids are recorded when a case is CREATED, not only when it is
 * deleted through the app — a folder removed outside the app (file manager, shell) never reaches
 * the delete route, and its number used to come straight back in the New Case wizard (#2858).
 *
 * Kept at the cases root (a dot-file, like the global job ledger) rather than inside any case,
 * because the whole point is to outlive every folder it names. The file name dates from when the
 * ledger held only deleted ids; it is kept so installs do not lose the ids already recorded.
 */
export const USED_IDS_FILENAME = ".dfir-companion-retired-cases.json";

export class UsedCaseIds {
  // Serializes the ledger read-modify-write — two creates landing together must not drop an id.
  private readonly lock = new StateLock();

  constructor(
    private readonly root: string,
    private readonly isValidCaseId: (caseId: string) => boolean,
  ) {}

  private path(): string {
    return join(this.root, USED_IDS_FILENAME);
  }

  // A missing or corrupt ledger reads as empty rather than throwing: not knowing which numbers are
  // used must never be able to block creating a case.
  async list(): Promise<string[]> {
    try {
      const parsed: unknown = JSON.parse(await readFile(this.path(), "utf8"));
      if (!Array.isArray(parsed)) return [];
      return parsed.filter((id): id is string => typeof id === "string" && this.isValidCaseId(id)).sort();
    } catch {
      return [];
    }
  }

  async remember(caseIds: readonly string[]): Promise<void> {
    const invalid = caseIds.find((id) => !this.isValidCaseId(id));
    if (invalid !== undefined) throw new Error(`refusing to record invalid caseId "${invalid}"`);
    await this.lock.runExclusive(USED_IDS_FILENAME, async () => {
      const known = new Set(await this.list());
      if (caseIds.every((id) => known.has(id))) return;
      const next = [...new Set([...known, ...caseIds])].sort();
      await atomicWrite(this.path(), JSON.stringify(next, null, 2));
    });
  }
}
