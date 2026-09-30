import type { AppOptions } from "./appOptions.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { ImportBaseline } from "../analysis/importBaseline.js";
import { settleForensicImport, type SettleDeps } from "../routes/importSettle.js";
import type { ImportDemote } from "./importDemote.js";

/**
 * The settle + import-meta tail the two streamed-ingest entry points share (ingestStreamed and its
 * byte-native macOS twin, composition/importIngest.ts). Lifted out of that file so both run one
 * copy, and so it could take the section's baseline instead of a full snapshot (#1874).
 *
 * import-meta is recorded ONLY on a non-empty diff, so a quiet poll cannot reset the dashboard's
 * "NEW since last import" highlighting every 30 seconds. Non-fatal: the import is already merged.
 */
export interface StreamedSettleDeps {
  options: AppOptions;
  runStateExclusive: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<void>;
  demote: ImportDemote;
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
    demoteForensic: deps.demote.demoteForensic,
  };
}

export async function settleStreamedImport(
  deps: StreamedSettleDeps,
  args: { caseId: string; kind: string; storedName: string; baseline: ImportBaseline | null },
): Promise<{ addedEvents: number; addedIocs: number }> {
  const { options } = deps;
  const settleDeps = importSettleDeps(deps);
  if (!settleDeps || !args.baseline) return { addedEvents: 0, addedIocs: 0 };
  const counts = { addedEvents: 0, addedIocs: 0 };
  try {
    const settled = await settleForensicImport(settleDeps, args.caseId, args.baseline, args.storedName);
    const { timelineDiff: tDiff, iocsDiff: iDiff } = settled;
    counts.addedEvents = tDiff.added.length;
    counts.addedIocs = iDiff.added.length;
    const changed = tDiff.added.length || iDiff.added.length || tDiff.removed.length || iDiff.removed.length;
    if (changed && options.importMetaStore) {
      await options.importMetaStore.record(args.caseId, {
        kind: args.kind,
        file: args.storedName,
        diff: tDiff,
        superTimelineAddedCount: settled.superTimelineAddedCount,
        superTimelineEvicted: settled.superTimelineEvicted,
        iocsDiff: iDiff,
      });
      options.onImportMeta?.(args.caseId);
    }
  } catch {
    /* non-fatal */
  }
  return counts;
}
