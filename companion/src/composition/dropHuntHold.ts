import type { DropFileStat } from "../analysis/dropScan.js";
import type { DropLogEntry } from "../analysis/dropLog.js";
import type { HuntPlan } from "../analysis/veloHuntLayout.js";
import { huntArtifactLimitsFromEnv, planHolds } from "../analysis/huntArtifactLimits.js";
import type { ZipMember } from "../storage/zipMembers.js";
import type { HuntZipLedger } from "./dropHuntZipLedger.js";
import type { HeldArchive, HuntHeldStore } from "../analysis/huntHeldStore.js";

/**
 * One hunt zip's size holds for one run (#2746). The holds come from the archive's frozen record,
 * worked out the first time the archive is seen. A member already in the ledger is never held, and a
 * decided entry is consumed once its outcome is recorded.
 */
export interface ZipHolds {
  /** Members held without a decision: not imported this run. */
  undecided: ReadonlySet<string>;
  /** Members the analyst skipped this run (recorded in the ledger, logged SKIPPED). */
  skipped: ReadonlySet<string>;
  /** After the run: store what is still held; returns how many members still wait for a decision. */
  finish(completed: boolean): Promise<number>;
}

export const NO_HOLDS: ZipHolds = {
  undecided: new Set(),
  skipped: new Set(),
  finish: async () => 0,
};

export const SKIP_REASON = "over the hunt artifact size limit — skipped by the analyst";

interface HoldArgs {
  store: HuntHeldStore;
  caseId: string;
  archiveId: string;
  zipRel: string;
  file: DropFileStat;
  plans: readonly HuntPlan[];
  byName: ReadonlyMap<string, ZipMember>;
  ledger: HuntZipLedger;
  log: DropLogEntry[];
}

function firstRecord(a: HoldArgs): HeldArchive | undefined {
  const limits = huntArtifactLimitsFromEnv();
  const held = a.plans.flatMap((p) =>
    planHolds(
      p.imports
        .filter((i) => !a.ledger.done.has(i.path))
        .map((i) => ({ ...i, bytes: a.byName.get(i.path)?.entry.uncompressedSize ?? 0 })),
      limits,
    ),
  );
  if (!held.length) return undefined;
  return {
    ...{
      archiveId: a.archiveId,
      relpath: a.zipRel,
      size: a.file.size,
      mtimeMs: a.file.mtimeMs,
      waiting: false,
    },
    entries: held.map((h) => ({
      ...{ member: h.path, artifact: h.artifact, host: h.host, bytes: h.bytes },
      ...{ groupBytes: h.groupBytes, reason: h.reason, limitMb: h.limitMb },
    })),
  };
}

/** Resolve this run's holds and record the analyst's skips in the ledger. */
export async function resolveZipHolds(a: HoldArgs): Promise<ZipHolds> {
  let record = await a.store.get(a.caseId, a.archiveId);
  if (!record) {
    record = firstRecord(a);
    if (!record) return NO_HOLDS;
    await a.store.put(a.caseId, record);
  }
  const live = record.entries.filter((e) => !a.ledger.done.has(e.member));
  const skipped = new Set<string>();
  for (const e of live.filter((x) => x.decision === "skip")) {
    await a.ledger.record(e.member, { ok: false, skipped: true, reason: SKIP_REASON });
    a.log.push({ status: "SKIPPED", relpath: `${a.zipRel}!${e.member}`, reason: SKIP_REASON });
    skipped.add(e.member);
  }
  const undecided = new Set(live.filter((e) => !e.decision).map((e) => e.member));
  return {
    undecided,
    skipped,
    async finish(completed) {
      // Re-read: a decision the analyst made during this run must not be overwritten.
      const rec = await a.store.update(a.caseId, a.archiveId, (cur) => {
        const entries = cur.entries.filter((e) => !a.ledger.done.has(e.member));
        const waiting = entries.filter((e) => !e.decision).length;
        return {
          ...cur,
          entries,
          size: a.file.size,
          mtimeMs: a.file.mtimeMs,
          // Idle only when nothing but undecided holds is left; an interrupted run must run again.
          waiting: completed && waiting > 0 && waiting === entries.length,
        };
      });
      return rec ? rec.entries.filter((e) => !e.decision).length : 0;
    },
  };
}
