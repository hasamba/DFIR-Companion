import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../../../../storage/caseStore.js";
import { atomicWrite } from "../../../../storage/atomicWrite.js";

// Per-case durable index of every VQL fingerprint ever deployed (state/hunt-fingerprints.json).
// The hunt-outcome ledger is capped (DFIR_HUNT_OUTCOME_MAX, default 50), so it cannot answer "did
// this hunt EVER run on the case?" — this set can. Append-only: never truncated, never pruned.
//
// NOT in SNAPSHOT_STATE_FILES (like Watson's history): a restore of an older backup would shrink the
// set and let a hunt run twice. It still travels with a case export, which walks the case folder.
//
// Fails closed: a missing file is an empty set, but a corrupt file THROWS — reading it as empty
// would mean "nothing ever ran" and reopen every re-run.

const FILE = "hunt-fingerprints.json";

// Appends are read-modify-write; serialise them per file across every store instance so two
// concurrent deploys never lose an entry.
const queues = new Map<string, Promise<void>>();

export class HuntFingerprintStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), FILE);
  }

  /** Every fingerprint deployed on the case. Throws on a corrupt file. */
  async load(caseId: string): Promise<Set<string>> {
    let raw: string;
    try {
      raw = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return new Set();
      throw err;
    }
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed) || !parsed.every((x) => typeof x === "string")) {
      throw new Error(`${FILE} is not a list of fingerprints`);
    }
    return new Set(parsed);
  }

  /** Add fingerprints (empty ones are skipped). Serialised per case file. */
  add(caseId: string, fingerprints: readonly string[]): Promise<void> {
    const fresh = fingerprints.filter((f) => typeof f === "string" && f.length > 0);
    if (fresh.length === 0) return Promise.resolve();
    const path = this.path(caseId);
    const prev = queues.get(path) ?? Promise.resolve();
    const next = prev
      .catch(() => {})
      .then(async () => {
        const cur = await this.load(caseId);
        if (fresh.every((f) => cur.has(f))) return;
        await atomicWrite(path, JSON.stringify([...new Set([...cur, ...fresh])], null, 2));
      });
    queues.set(path, next);
    void next
      .finally(() => {
        if (queues.get(path) === next) queues.delete(path);
      })
      .catch(() => {});
    return next;
  }
}
