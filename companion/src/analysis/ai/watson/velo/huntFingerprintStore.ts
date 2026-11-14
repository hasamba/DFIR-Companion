import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../../../../storage/caseStore.js";
import { atomicWrite } from "../../../../storage/atomicWrite.js";

// Per-case durable index of every VQL fingerprint ever deployed (state/hunt-fingerprints.json).
// Only release() removes entries: a launch that reserved its keys and then definitely did not run.
// The hunt-outcome ledger is capped (DFIR_HUNT_OUTCOME_MAX, default 50), so it cannot answer "did
// this hunt EVER run on the case?" — this set can. Append-only: never truncated, never pruned.
//
// NOT in SNAPSHOT_STATE_FILES (like Watson's history): a restore of an older backup would shrink the
// set and let a hunt run twice. It still travels with a case export, which walks the case folder.
//
// Fails closed: a missing file is an empty set, but a corrupt file THROWS — reading it as empty
// would mean "nothing ever ran" and reopen every re-run.

const FILE = "hunt-fingerprints.json";

/** What reserve() claimed: `added` is exactly what release() may later remove. */
export interface ReserveResult {
  ok: boolean;
  added: string[];
}

// Appends are read-modify-write; serialise them per file across every store instance so two
// concurrent deploys never lose an entry.
const queues = new Map<string, Promise<void>>();

export class HuntFingerprintStore {
  /**
   * @param legacy fingerprints to start from when the case has no index file yet (the outcome
   *   ledger, via fingerprintIndex.ts → fingerprintStoreFor); persisted with the first write.
   */
  constructor(
    private readonly cases: CaseStore,
    private readonly legacy?: (caseId: string) => Promise<readonly string[]>,
  ) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), FILE);
  }

  /** Every fingerprint deployed on the case. Throws on a corrupt file. */
  async load(caseId: string): Promise<Set<string>> {
    let raw: string;
    try {
      raw = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return new Set(this.legacy ? await this.legacy(caseId) : []);
      }
      throw err;
    }
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed) || !parsed.every((x) => typeof x === "string")) {
      throw new Error(`${FILE} is not a list of fingerprints`);
    }
    return new Set(parsed);
  }

  /** Run `task` after every earlier write to this case's index has settled. */
  private serialise<T>(caseId: string, task: () => Promise<T>): Promise<T> {
    const path = this.path(caseId);
    const prev = queues.get(path) ?? Promise.resolve();
    const next = prev.catch(() => {}).then(task);
    const tail = next.then(
      () => {},
      () => {},
    );
    queues.set(path, tail);
    void tail.then(() => {
      if (queues.get(path) === tail) queues.delete(path);
    });
    return next;
  }

  private async write(caseId: string, cur: ReadonlySet<string>, fresh: readonly string[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify([...new Set([...cur, ...fresh])], null, 2));
  }

  /** Add fingerprints (empty ones are skipped). Idempotent; serialised per case file. */
  add(caseId: string, fingerprints: readonly string[]): Promise<void> {
    const fresh = fingerprints.filter((f) => typeof f === "string" && f.length > 0);
    if (fresh.length === 0) return Promise.resolve();
    return this.serialise(caseId, async () => {
      const cur = await this.load(caseId);
      if (!fresh.every((f) => cur.has(f))) await this.write(caseId, cur, fresh);
    });
  }

  /**
   * Atomic add-if-absent, for a launch to claim its fingerprint(s) BEFORE it deploys. All or
   * nothing: `{ ok: true, added }` when none was present (all are now recorded and `added` lists
   * them); `{ ok: false, added: [] }` when any already ran or nothing was given — nothing written.
   * Throws on a corrupt index: the caller must refuse the launch.
   *
   * Task 4's call shape:
   *   const r = await store.reserve(caseId, check.fingerprints);
   *   if (!r.ok) refuse;                           // already ran (or racing launch won)
   *   try { deploy } catch { await store.release(caseId, r.added); throw; }  // only if it surely did not run
   * release() must be given exactly `r.added`, never other keys, so a key that existed before the
   * reservation is never removed.
   */
  reserve(
    caseId: string,
    fingerprint: string | readonly string[],
    /** Keys that must also be absent (checked atomically, never added): a collection's fleet keys. */
    mustBeAbsent: readonly string[] = [],
  ): Promise<ReserveResult> {
    const list = [...new Set(typeof fingerprint === "string" ? [fingerprint] : fingerprint)].filter(
      (f) => typeof f === "string" && f.length > 0,
    );
    if (list.length === 0) return Promise.resolve({ ok: false, added: [] });
    return this.serialise(caseId, async (): Promise<ReserveResult> => {
      const cur = await this.load(caseId);
      if (list.some((f) => cur.has(f)) || mustBeAbsent.some((f) => cur.has(f)))
        return { ok: false, added: [] };
      await this.write(caseId, cur, list);
      return { ok: true, added: list };
    });
  }

  /**
   * Drop the keys a reservation added, when its deploy definitely did not run. Pass exactly
   * `reserve(...).added`. Serialised like reserve.
   */
  release(caseId: string, fingerprints: readonly string[]): Promise<void> {
    const drop = new Set(fingerprints.filter((f) => typeof f === "string" && f.length > 0));
    if (drop.size === 0) return Promise.resolve();
    return this.serialise(caseId, async () => {
      const cur = await this.load(caseId);
      if (![...drop].some((f) => cur.has(f))) return;
      const kept = [...cur].filter((f) => !drop.has(f));
      await atomicWrite(this.path(caseId), JSON.stringify(kept, null, 2));
    });
  }
}
