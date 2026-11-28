import type { AppOptions } from "./appOptions.js";
import type { TagOutcome } from "../analysis/gradeMark.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { ImportBaseline } from "../analysis/importBaseline.js";
import type { SuperEvictionTally } from "../analysis/superTimelineStore.js";
import type { SettleDeps } from "../routes/importSettle.js";
import type { ImportDemote } from "./importDemote.js";
import { settleImportOrRecover } from "../routes/importRowRecovery.js";
import { countsFromSettled, type ImportCounts } from "../analysis/importNotification.js";

/**
 * The settle + import-meta tail the two streamed-ingest entry points share (ingestStreamed and its
 * byte-native macOS twin, composition/importIngest.ts). Lifted out of that file so both run one
 * copy, and so it could take the section's baseline instead of a full snapshot (#1874).
 *
 * import-meta is recorded ONLY on a non-empty diff, so a quiet poll cannot reset the dashboard's
 * "NEW since last import" highlighting every 30 seconds. One more case writes it (#2831): a BATCHED
 * run of this import reported rows its cap passes pushed out of the super-timeline. Those rows have
 * left the case, the settle cannot see them, and the record is the only place the analyst is told —
 * so it is written also when the import kept nothing forensic. The settle's OWN dropped rows do not
 * open the record: on a monitored case with a full super-timeline every quiet poll would take over
 * the import card. Non-fatal: the import is already merged.
 *
 * A missing snapshot or a failed settle is no longer silent (#2890): it logs a WARN and settles this
 * import's rows by stored name (routes/importRowRecovery.ts), from inside the held section, before
 * the next import's case-wide demote could move them out untagged. Only the settle call is guarded,
 * so a failed import-meta write after a complete settle re-stamps nothing.
 */
export interface StreamedSettleDeps {
  options: AppOptions;
  runStateExclusive: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
  /** The held tagger for rows marked "held" (#2918): absent, a held row the settle meets stays marked. */
  tagHeld?: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
  demote: ImportDemote;
}

/** What the tail settled. `counts` only when the settle itself ran — a recovered one is unknown (#2982). */
export interface StreamedSettled {
  addedEvents: number;
  addedIocs: number;
  counts?: ImportCounts;
}

/** The deps every import seam hands settleForensicImport, from the app's wiring. */
export function importSettleDeps(deps: StreamedSettleDeps): SettleDeps | null {
  const { options } = deps;
  if (!options.stateStore) return null;
  return {
    stateStore: options.stateStore,
    runStateExclusive: deps.runStateExclusive,
    superTimelineStore: options.superTimelineStore,
    onSuperTimeline: options.onSuperTimeline,
    onStateChanged: options.onStateChanged,
    onState: options.onState,
    autoTagImported: deps.autoTagImported,
    ...(deps.tagHeld ? { tagHeld: deps.tagHeld } : {}),
    demoteForensic: deps.demote.demoteForensic,
  };
}

export async function settleStreamedImport(
  deps: StreamedSettleDeps,
  args: {
    caseId: string;
    kind: string;
    storedName: string;
    baseline: ImportBaseline | null;
    /** A streamed import's record count and disclosure, for the import-meta record (#2336). */
    streamMeta?: { linesIn?: number; streamDisclosure?: string[] };
    /** What this import's batched runs said the cap dropped (#2816) — the same tally its base carried. */
    superEvictions?: SuperEvictionTally;
  },
): Promise<StreamedSettled> {
  const { options } = deps;
  const settleDeps = importSettleDeps(deps);
  const counts: StreamedSettled = { addedEvents: 0, addedIocs: 0 };
  const target = { caseId: args.caseId, storedNames: [args.storedName], tag: "import" };
  const settled = await settleImportOrRecover(settleDeps, target, args.baseline, args.storedName);
  if (!settled) return counts;
  counts.counts = countsFromSettled(settled); // the post-tagger, post-demote diff (#2982)
  try {
    const { timelineDiff: tDiff, iocsDiff: iDiff } = settled;
    counts.addedEvents = tDiff.added.length;
    counts.addedIocs = iDiff.added.length;
    const changed = tDiff.added.length || iDiff.added.length || tDiff.removed.length || iDiff.removed.length;
    const batchedDropped = args.superEvictions?.plus(undefined)?.count; // the runs' own, not the settle's
    if ((changed || batchedDropped) && options.importMetaStore) {
      await options.importMetaStore.record(args.caseId, {
        kind: args.kind,
        file: args.storedName,
        diff: tDiff,
        superTimelineAddedCount: settled.superTimelineAddedCount,
        superTimelineAvailable: settled.superTimelineAvailable, // #3045
        superTimelineEvicted: args.superEvictions
          ? args.superEvictions.plus(settled.superTimelineEvicted)
          : settled.superTimelineEvicted,
        iocsDiff: iDiff,
        ...args.streamMeta,
      });
      options.onImportMeta?.(args.caseId);
    }
  } catch {
    /* non-fatal: the rows are settled; only the record is lost */
  }
  return counts;
}
