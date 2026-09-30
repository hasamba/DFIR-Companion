import { CaseKeyedMap } from "../storage/caseKeyedState.js";

// Results computed from a full super-timeline scan, kept until the rows change (#1881).
//
// A scan of a capped case is ~1.3 s at the default 100,000 rows and grows with the cap, and the
// host-scope ledger ran one on every page load and every report. The rows change only when an
// import, a rename, a rollback or the cap touches them, and each of those writes a new content
// version (caseSqliteWorkerSuper.ts, stampSuperContent). An entry is served only while the store
// still reports the version it was computed under.
//
// Entries are keyed by case incarnation (CaseKeyedMap), so a deleted case's result never reaches a
// new case with the same id, and a case delete drops them. The version is read before AND after the
// scan: a scan that raced a write is returned to its caller but never stored, because it may hold
// rows the version it started under does not name.

/** At most this many (case, name) results are held; the oldest case is dropped first. */
export const MAX_SCAN_MEMO_ENTRIES = 8;

interface MemoEntry {
  version: string;
  value: unknown;
}

export class SuperScanMemo {
  private readonly entries: CaseKeyedMap<MemoEntry>;

  constructor(casesRoot: () => string) {
    this.entries = new CaseKeyedMap<MemoEntry>(casesRoot);
  }

  async get<T>(
    caseId: string,
    name: string,
    version: () => Promise<string>,
    compute: () => Promise<T>,
  ): Promise<T> {
    const before = await version();
    // No stamp (a store that cannot report one): compute every time, as before #1881.
    if (!before) return compute();
    const hit = this.entries.get(caseId, name);
    if (hit && hit.version === before) return hit.value as T;
    const value = await compute();
    if ((await version()) === before) this.remember(caseId, name, { version: before, value });
    return value;
  }

  private remember(caseId: string, name: string, entry: MemoEntry): void {
    // Delete first so a refreshed entry moves to the end of the insertion order.
    this.entries.delete(caseId, name);
    this.entries.set(caseId, entry, name);
    while (this.entries.size > MAX_SCAN_MEMO_ENTRIES) {
      const oldest = this.entries.list()[0];
      if (!oldest) break;
      this.entries.forget(oldest.caseId);
    }
  }
}
