import type { PipelineOptions } from "./pipelineOptions.js";
import { analystDecisionOpts } from "./analystQueries.js";

/**
 * The option view the AI-backed families read through `AnalysisPipeline.aiCtx.opts`. Live getters,
 * not a snapshot, for the reason `importCtx` gives there: a copy made at construction would go stale
 * the first settings save. Moved out of pipeline.ts (#1734) when the synthesis fallback option took
 * that file over its size budget; the shape is exactly what the constructor built inline.
 */
export function buildAiCallOpts(opts: PipelineOptions) {
  return {
    get synthesisProvider() {
      return opts.synthesisProvider;
    },
    get stateStore() {
      return opts.stateStore;
    },
    get falsePositiveStore() {
      return opts.falsePositiveStore;
    },
    get scopeStore() {
      return opts.scopeStore;
    },
    get superTimelineStore() {
      return opts.superTimelineStore;
    },
    get hypothesisStore() {
      return opts.hypothesisStore;
    },
    get velociraptorProvider() {
      return opts.velociraptorProvider;
    },
    get huntOutcomeStore() {
      return opts.huntOutcomeStore;
    },
    get importMetaStore() {
      return opts.importMetaStore;
    },
    get cloudCoverageStore() {
      return opts.cloudCoverageStore;
    },
    get provider() {
      return opts.provider;
    },
    get imageLoader() {
      return opts.imageLoader;
    },
    get onState() {
      return opts.onState;
    },
    get anonStore() {
      return opts.anonStore;
    },
    get customEntitiesStore() {
      return opts.customEntitiesStore;
    },
    get discoveredStore() {
      return opts.discoveredStore;
    },
    get ocrRunner() {
      return opts.ocrRunner;
    },
    get presidio() {
      return opts.presidio;
    },
    get presidioPendingStore() {
      return opts.presidioPendingStore;
    },
    get presidioScanCapsOverride() {
      return opts.presidioScanCapsOverride;
    },
    get aiCostStore() {
      return opts.aiCostStore;
    },
    get operationalMetrics() {
      return opts.operationalMetrics;
    },
    get correlationProfileStore() {
      return opts.correlationProfileStore;
    },
    get sourceTrustStore() {
      return opts.sourceTrustStore;
    },
    get clockSkewStore() {
      return opts.clockSkewStore;
    },
    get notebookStore() {
      return opts.notebookStore;
    },
    get aiControlStore() {
      return opts.aiControlStore;
    },
    get playbookStore() {
      return opts.playbookStore;
    },
    get incidentTypeStore() {
      return opts.incidentTypeStore;
    },
    get learnedPatternStore() {
      return opts.learnedPatternStore;
    },
    get secondOpinionStore() {
      return opts.secondOpinionStore;
    },
    get findingSeverityRestoreStore() {
      return opts.findingSeverityRestoreStore;
    },
    get secondOpinionProvider() {
      return opts.secondOpinionProvider;
    },
    get secondOpinionModelLabel() {
      return opts.secondOpinionModelLabel;
    },
    get referee() {
      return opts.referee;
    },
    get synthesisModelLabel() {
      return opts.synthesisModelLabel;
    },
    get synthesisFallback() {
      return opts.synthesisFallback;
    },
    get synthesisSafetyRetries() {
      return opts.synthesisSafetyRetries;
    },
    get synthMetaStore() {
      return opts.synthMetaStore;
    },
    get veloHuntStore() {
      return opts.veloHuntStore;
    },
    get analysisRunStore() {
      return opts.analysisRunStore;
    },
    get stateLock() {
      return opts.stateLock;
    },
    get onSynth() {
      return opts.onSynth;
    },
    get assetOverridesStore() {
      return opts.assetOverridesStore;
    },
    get velociraptorClientStore() {
      return opts.velociraptorClientStore;
    },
    get hostDuplicateDismissalStore() {
      return opts.hostDuplicateDismissalStore;
    },
    get evidenceAttestationStore() {
      return opts.evidenceAttestationStore;
    },
    ...analystDecisionOpts(opts),
    get retries() {
      return opts.retries;
    },
    get backoffMs() {
      return opts.backoffMs;
    },
  };
}
