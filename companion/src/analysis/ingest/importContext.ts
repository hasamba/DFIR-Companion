import type { WindowContext, mergeDelta } from "../stateMerge.js";
import type { InvestigationState, Severity } from "../stateTypes.js";
import type { PlasoParseResult } from "../plasoImport.js";
import type { StateStore } from "../stateStore.js";

/**
 * What an importer needs from the pipeline, and nothing else (#384).
 *
 * The 36 import methods on AnalysisPipeline were 1,779 of its lines, and between them they reached
 * for exactly FIVE members of `this`. That is what makes them extractable: they are not entangled
 * with the class, they are long. Each one parses its own format, builds a delta, and hands it to
 * the same three collaborators.
 *
 * So this is the seam. An importer takes an ImportContext instead of being a method, and
 * AnalysisPipeline satisfies the interface structurally — it keeps its public import methods as
 * one-line delegations, so every route and test calling `pipeline.importThor(...)` is untouched.
 *
 * WHY AN INTERFACE RATHER THAN PASSING THE PIPELINE. The type says what an importer is allowed to
 * do. An importer cannot reach for the AI providers, the hypothesis store or the synthesis path,
 * because they are not on this type — which is the boundary that keeps deterministic import
 * deterministic. `analysis/ingest` sits at tier 3 and `analysis/ai` at tier 5 for the same reason;
 * this interface is that rule expressed where the compiler can enforce it.
 */
export interface ImportContext {
  /**
   * The only two pipeline options an importer touches, out of the ~40 on PipelineOptions.
   *
   * Enumerated rather than widened to PipelineOptions for two reasons. It states the real
   * dependency -- load state, save state, announce the new state -- and it keeps the AI providers,
   * hypothesis store and synthesis knobs out of reach of deterministic import. It also avoids
   * importing PipelineOptions from pipeline.ts, which would be an ingest -> ai edge: upward, and
   * rejected by check:boundaries.
   */
  readonly opts: {
    stateStore: StateStore;
    onState?: (state: InvestigationState) => void;
  };

  /**
   * Serialise a read-modify-write against one case's state.
   *
   * CAUTION, carried over from the pipeline: never call this from inside another withStateLock
   * callback for the SAME caseId — it nests onto the outer call's unresolved promise and deadlocks.
   */
  withStateLock<T>(caseId: string, fn: () => Promise<T>): Promise<T>;

  /** mergeDelta plus the case's analyst IOC-merge aliases (#82), so merged duplicates stay folded. */
  mergeWithAliases(
    state: InvestigationState,
    delta: Parameters<typeof mergeDelta>[1],
    ctx: WindowContext,
  ): Promise<InvestigationState>;

  /**
   * Record that an import produced nothing, with the importer's own record count so the note says
   * how much was READ. "0 events from 0 records" (wrong format) and "0 events from 75,951 records"
   * (understood but uninteresting) are very different problems.
   */
  noteEmptyImport(
    caseId: string,
    opts: { label: string; importedAt: string; onProgress?: (done: number, total: number) => void },
    kind: string,
    total: number,
  ): Promise<InvestigationState>;

  /** Shared tail for the two Plaso entry points (text and file), which differ only in how they parse. */
  persistPlasoParsed(
    caseId: string,
    parsed: PlasoParseResult,
    opts: {
      label: string;
      idPrefix: string;
      importedAt: string;
      minSeverity?: Severity;
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState>;
}
