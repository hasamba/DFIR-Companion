import type { ForensicEvent, Severity } from "../analysis/stateTypes.js";
import type { StateStore } from "../analysis/stateStore.js";
import type { SuperTimelineStore } from "../analysis/superTimelineStore.js";
import type { TaggerStore } from "../analysis/taggerStore.js";
import type { TagsStore } from "../analysis/tags.js";
import type { ForensicGateControlStore } from "../analysis/forensicGateControl.js";
import type { AnalysisRunStore } from "../analysis/analysisRunStore.js";
import { resolveForensicMinSeverity } from "../analysis/forensicGate.js";
import { readTaggerSettings, runAndApplyTagger } from "../analysis/taggerRun.js";
import { hashManifestValue } from "../analysis/analysisRunHash.js";
import { isAnalystWorkLog } from "../analysis/workLogFilter.js";
import {
  readBulkBatchRows,
  readBulkMinBytes,
  type BatchTagger,
  type BulkImportSink,
  type BulkRunSummary,
} from "../analysis/ingest/velociraptorBulk.js";

/**
 * Binds the batched Velociraptor driver (analysis/ingest/velociraptorBulk.ts, #1439) to the live
 * stores. Everything here is the same collaborator the whole-file seam uses, reached through its
 * indexed method instead of a whole-state load: the forensic table's append, the super store's
 * append, the tagger's ruleset + tag writer, and the case gate as demote resolves it.
 *
 * Absent stores degrade the way they do elsewhere: no super store → the driver is not wired at all
 * (a bulk import with nowhere to put Info telemetry would drop it, and the whole-file path at least
 * keeps it in memory until demote); no tagger/tags store → the tagger step is skipped, as
 * autoTagNewEvents skips it.
 */
export interface BulkImportSinkDeps {
  stateStore: StateStore;
  superTimelineStore?: SuperTimelineStore;
  taggerStore?: TaggerStore;
  tagsStore?: TagsStore;
  forensicGateControlStore?: ForensicGateControlStore;
  analysisRunStore?: AnalysisRunStore;
  log: (msg: string, caseId?: string) => void;
  onSuperTimeline?: (caseId: string) => void;
  onTags?: (caseId: string) => void;
  env?: NodeJS.ProcessEnv;
}

export function buildBulkImportSink(deps: BulkImportSinkDeps): BulkImportSink | undefined {
  const { superTimelineStore } = deps;
  if (!superTimelineStore) return undefined;
  const env = deps.env ?? process.env;

  const openTagger = async (caseId: string, mode: "forensic" | "super-only"): Promise<BatchTagger | null> => {
    const { taggerStore, tagsStore } = deps;
    if (!taggerStore || !tagsStore) return null;
    const settings = readTaggerSettings(env);
    if (!settings.auto) return null;
    let ruleset: Awaited<ReturnType<TaggerStore["load"]>>;
    let rulesHash: string;
    try {
      const active = await taggerStore.readActive();
      ruleset = await taggerStore.load(); // throws on an invalid hand-edited file → skip, as autoTagNewEvents does
      rulesHash = hashManifestValue(active.text);
    } catch (err) {
      deps.log(`[tagger] ${caseId} bulk auto-tag skipped: ${(err as Error).message}`, caseId);
      return null;
    }
    if (!ruleset.rules.length) return null;
    // Severity/MITRE are raised on the batch itself (it IS the forensic candidate set), never on the
    // raw record: super-only mode and TAGGER_SCOPE=super write tags only.
    const mutateForensic = mode === "forensic" && settings.scope !== "super";
    return {
      rulesHash,
      async apply(id, events) {
        const applied = await runAndApplyTagger({
          caseId: id,
          events,
          ruleset,
          forensicTimeline: events,
          tagsStore,
          mutateForensic,
        });
        return { events: applied.forensicTimeline, matched: applied.result.totalMatched };
      },
    };
  };

  const forensicMinSeverity = async (caseId: string): Promise<Severity> => {
    const perCase = deps.forensicGateControlStore
      ? (await deps.forensicGateControlStore.load(caseId)).minSeverity
      : undefined;
    return resolveForensicMinSeverity(perCase, env.DFIR_FORENSIC_MIN_SEVERITY);
  };

  const recordRun = async (caseId: string, s: BulkRunSummary): Promise<void> => {
    if (!deps.analysisRunStore) return;
    try {
      await deps.analysisRunStore.record(caseId, {
        kind: "deterministic",
        startedAt: s.startedAt,
        finishedAt: s.finishedAt,
        versions: { schema: "import-bulk/v1", ...(s.rulesHash ? { rules: s.rulesHash } : {}) },
        input: {
          artifacts: [],
          eventIds: [],
          entityIds: [],
          selectionHash: hashManifestValue([s.label, s.rows, s.events]), // the stored file is named in parameters.label
        },
        configuration: {
          parameters: {
            analyzer: "velociraptor-import",
            label: s.label,
            path: s.path,
            mode: s.mode,
            batches: s.batches,
            rows: s.rows,
            events: s.events,
            forensicKept: s.forensicKept,
            superAppended: s.superAppended,
            taggerMatched: s.tagged,
          },
          filteringPolicy: { scope: s.mode },
        },
        output: { entityIds: [], hashes: [], claims: [] },
      });
    } catch (err) {
      deps.log(`[import] ${caseId} bulk run record skipped: ${(err as Error).message}`, caseId);
    }
  };

  return {
    minBytes: readBulkMinBytes(env),
    batchRows: readBulkBatchRows(env),
    // The same door guard mergeDelta applies: tool-usage narration never enters the forensic timeline.
    appendForensic: (caseId: string, events: ForensicEvent[]) =>
      deps.stateStore.appendForensicEvents(
        caseId,
        events.filter((e) => !isAnalystWorkLog(e)),
      ),
    appendSuper: (caseId: string, events: ForensicEvent[]) => superTimelineStore.append(caseId, events),
    openTagger,
    forensicMinSeverity,
    log: deps.log,
    onSuperTimeline: deps.onSuperTimeline,
    onTags: deps.onTags,
    recordRun,
  };
}
