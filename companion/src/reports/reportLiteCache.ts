// #2057: keep the filtered slim state of the case being viewed, keyed on an exact revision.
//
// Timeline gaps, the swimlane, the IOC blocklist, STIX and the interactive report each answer with a
// few KB computed in milliseconds, but each request used to rebuild the whole case from SQLite first
// (3-5 s on 70k events). The coalescer (stateLoadGate.ts) only shares loads that are in flight
// together; this cache keeps the last result for sequential requests.
//
// A report must never be built from a state older than any write to the case. So:
//
//   - The revision covers EVERY input of reports/filteredState.ts: the database (the pool's write
//     sequence, bumped when a write is SUBMITTED, plus the identity of the file itself), the
//     case.json (a deleted and re-created case), and each side file it reads (FILTERED_STATE_SIDE_FILES).
//   - A hit needs the revision taken at the request to equal the stored one.
//   - A miss loads through the coalescer, takes the revision again afterwards, and stores the result
//     only when nothing changed in between. A write that raced the load is never cached.
//   - No revision (no database yet, a stat that failed) means no caching: today's path.
//
// Only the STATE is kept. Each route still computes its answer per request, so wall-clock output
// (intel retirement, the blocklist's Generated stamp) and env thresholds stay live.
//
// Bounded: one case per writer, dropped after REPORT_LITE_IDLE_MS idle. The state is shared by every
// caller and must not be modified (tests/reports/filteredStateImmutable.test.ts).

import { stat } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import { caseSqliteWorker } from "../analysis/caseSqliteWorker.js";
import { FILTERED_STATE_SIDE_FILES } from "./filteredState.js";
import { CaseLoadCoalescer } from "./stateLoadGate.js";

/** How long the viewed case's state is kept without a request. A constant, not a setting. */
export const REPORT_LITE_IDLE_MS = 5 * 60 * 1000;

/** `ino:size:mtime:ctime` of a file, "absent" when it does not exist; throws on any other error. */
async function fileIdentity(path: string): Promise<string> {
  try {
    const s = await stat(path, { bigint: true });
    return `${s.ino}:${s.size}:${s.mtimeNs}:${s.ctimeNs}`;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return "absent";
    throw err;
  }
}

/**
 * The exact read revision of a case for the report-lite projection, or null when it cannot be
 * known (no database yet: a legacy JSON case still to migrate). Any write to an input changes it.
 */
export async function caseReadRevision(
  cases: CaseStore,
  dbPath: string,
  caseId: string,
): Promise<string | null> {
  const seq = caseSqliteWorker.writeSequence(dbPath);
  const db = await fileIdentity(dbPath);
  if (db === "absent") return null;
  const stateDir = cases.stateDir(caseId);
  // Not the -wal file: a read-only reader opening the database may create it, which no write did.
  const parts = await Promise.all([
    fileIdentity(cases.caseMetaPath(caseId)),
    ...FILTERED_STATE_SIDE_FILES.map((name) => fileIdentity(join(stateDir, name))),
  ]);
  return [dbPath, seq, db, ...parts].join("|");
}

/** The report-lite cache of one ReportWriter; `src` is read per request, so it may be a late binding. */
export function liteStateCache(
  src: () => { cases: CaseStore; state: { databasePath(caseId: string): string } },
): ReportLiteCache<InvestigationState> {
  return new ReportLiteCache<InvestigationState>((caseId) => {
    const { cases, state } = src();
    return caseReadRevision(cases, state.databasePath(caseId), caseId);
  });
}

interface Entry<T> {
  caseId: string;
  revision: string;
  value: T;
}

export class ReportLiteCache<T> {
  private entry: Entry<T> | null = null;
  private timer: NodeJS.Timeout | null = null;
  private readonly misses = new Map<string, Promise<T>>();

  constructor(
    private readonly revisionOf: (caseId: string) => Promise<string | null>,
    private readonly loads: CaseLoadCoalescer<T> = new CaseLoadCoalescer<T>(),
  ) {}

  /** Cases held (0 or 1). */
  get size(): number {
    return this.entry ? 1 : 0;
  }

  async load(caseId: string, read: () => Promise<T>): Promise<T> {
    const revision = await this.safeRevision(caseId);
    if (revision === null) return this.loads.load(caseId, read);
    const held = this.entry;
    if (held && held.caseId === caseId && held.revision === revision) {
      this.touch();
      return held.value;
    }
    // Misses at the same revision share one load: the revision taking a stat first must not split a
    // dashboard fan-out into several cohorts. Equal revisions mean no write landed between the two
    // arrivals, so the shared result is as fresh for the later caller as a load of its own.
    const key = `${caseId}\0${revision}`;
    const running = this.misses.get(key);
    if (running) return running;
    const miss = this.miss(caseId, revision, read);
    this.misses.set(key, miss);
    const done = (): void => void this.misses.delete(key);
    miss.then(done, done);
    return miss;
  }

  private async miss(caseId: string, revision: string, read: () => Promise<T>): Promise<T> {
    const value = await this.loads.load(caseId, read);
    // Stored only when nothing changed during the load: a write that raced it is never cached.
    if ((await this.safeRevision(caseId)) === revision) {
      this.entry = { caseId, revision, value };
      this.touch();
    }
    return value;
  }

  clear(): void {
    this.entry = null;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private async safeRevision(caseId: string): Promise<string | null> {
    try {
      return await this.revisionOf(caseId);
    } catch {
      return null; // unknown revision: never serve or store a cached state
    }
  }

  private touch(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.clear(), REPORT_LITE_IDLE_MS);
    this.timer.unref();
  }
}
