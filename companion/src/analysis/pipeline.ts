import { ProviderError, type AIProvider } from "../providers/provider.js";
import { createConsoleLogger, normalizeLogLevel, type Logger } from "../logging/logger.js";
import type { CaptureMetadata } from "../types.js";
import type { InvestigationState } from "./stateTypes.js";
import {
  type AskAnswer,
  type ExecSummary,
  type ExplainEventResult,
  type RemediationPlan,
} from "./responseSchema.js";
import { mergeDelta, type WindowContext } from "./stateMerge.js";

import { checkConfiguredPromptDrift } from "./promptCapabilities.js";
import { type SuggestOutcome } from "./taggerRuleSuggest.js";
import { type SynthThinkingInput } from "./synthThinking.js";
import { type GapHypothesesResult } from "./gapHypothesis.js";
import { type KnownUnknownItem } from "./knownUnknowns.js";
import * as ingest from "./ingest/index.js";
// The options bag and the retry policy moved out with the families that read them (#418).
import type { PipelineOptions } from "./ai/pipelineOptions.js";
export type { PipelineOptions } from "./ai/pipelineOptions.js";
import { withRetry } from "./ai/retry.js";
import type { ImportContext } from "./ingest/importContext.js";

/**
 * The argument list of an importer, minus the ImportContext it takes first (#384).
 *
 * Every import method below is a one-line delegation to src/analysis/ingest/. Deriving the
 * parameters rather than restating them means the two cannot drift: change an importer's signature
 * and the delegation stops compiling, which is the property a hand-copied signature would not have.
 */
type ImporterArgs<F> = F extends (ctx: ImportContext, ...args: infer R) => unknown ? R : never;
/** The same trick for the AI extraction calls, which take an ExtractionContext first (#418). */
type AiExtractionArgs<F> = F extends (ctx: ExtractionContext, ...args: infer R) => unknown ? R : never;
/** Ditto for the calls that take the widest context of all — synthesis and its two consumers. */
type AiArgs<F> = F extends (ctx: SynthesisContext, ...args: infer R) => unknown ? R : never;
// The prompt registry moved to ai/prompts/ (#384). Imported for the pipeline's own use and
// re-exported below, because 23 modules and the eval harness import these names from here.
export * from "./ai/prompts/index.js";
// The AI-backed families extracted in #418. Each method below is a one-line delegation; the result
// types moved with them and are re-exported here, because routes/reports/tests import them from
// this module and the extraction is not supposed to be visible to callers.
import type { CaseReportContext } from "./ai/caseReports.js";
import * as caseReports from "./ai/caseReports.js";
import type { AnalystQueryContext } from "./ai/analystQueries.js";
import * as analystQueries from "./ai/analystQueries.js";
import type { SessionSummaryResult, StarredSummaryResult, ViewReportContext } from "./ai/viewReports.js";
import * as viewReports from "./ai/viewReports.js";
export {
  VIEW_SUMMARY_MAX_ROWS,
  type StarredSummaryResult,
  type SessionSummaryResult,
} from "./ai/viewReports.js";
import type { ExtractionContext } from "./ai/extraction.js";
import * as extraction from "./ai/extraction.js";
import { analyzeRestored } from "./ai/providerCall.js";
import type { HuntContext } from "./ai/hunts.js";
import * as synthesis from "./ai/synthesis.js";
import type { SynthesisContext } from "./ai/synthesis.js";
import * as deepPassRun from "./ai/deepPassRun.js";
import type { SecondOpinionContext } from "./ai/secondOpinionRun.js";
import * as secondOpinionRun from "./ai/secondOpinionRun.js";
import type { DeepPassResult } from "./ai/deepPassRun.js";
export type { DeepPassResult } from "./ai/deepPassRun.js";
import * as hunts from "./ai/hunts.js";
import * as nextSteps from "./ai/nextSteps.js";
import { type PromptBlockContext } from "./ai/promptBlocks.js";
import * as promptBlocks from "./ai/promptBlocks.js";
import { safeAiErrorKind, safeAiPhase } from "./operationalMetrics.js";
import { type SecondOpinion } from "./secondOpinion.js";
import { type AggregateStats } from "./logAggregate.js";
import { type FloorOption } from "./deepPass.js";
import { type KevCatalog } from "./kev.js";
import { type HuntSuggestion } from "./huntSuggest.js";
import { type PlaybookHuntSuggestion } from "./playbookHunt.js";
import type { SuperQuery, SuperLabelMap } from "./superTimeline.js";
import { type MemoryNextStep } from "./memoryNextStep.js";
import { type QueryTranslationResult } from "./queryTranslate.js";
import { type HuntPlatform } from "./huntPlatforms.js";
import type { PlaybookTask } from "./playbook.js";
import { uniqueProviderModels } from "./analysisRunRecorders.js";
import { type HypothesisReviewItem } from "./hypothesis.js";

export class AnalysisPipeline {
  private readonly log: Logger;
  // Lazily loaded from opts.kevStore so we don't block the constructor on disk I/O.
  private kevCatalogCache: KevCatalog | undefined;

  /**
   * The ONLY thing src/analysis/ingest/ ever receives (#384).
   *
   * The first cut of the ingest extraction passed `this` and let AnalysisPipeline satisfy
   * ImportContext structurally, which meant `opts` and four methods had to become public. That
   * bought the importers a narrow interface at the cost of handing every OTHER consumer of the
   * pipeline the entire options bag -- the AI providers, every store, every tuning knob. A boundary
   * that has to widen the class to exist is not much of a boundary.
   *
   * This adapter closes over the permitted operations instead, so the class members stay private
   * and the importers still see nothing beyond what ImportContext declares. `opts` is exposed
   * through getters rather than a snapshot because the settings-reload path rebuilds live options
   * in place; a copy taken at construction would go stale the first time an operator saved a
   * setting.
   *
   * Down to three operations since #418 moved the two shared import tails — `noteEmptyImport` and
   * `persistPlasoParsed` — into `ingest/importState.ts`, where their only callers already live.
   */
  private readonly importCtx: ImportContext;

  /**
   * The same adapter idea, for the AI-backed families extracted in #418.
   *
   * One object, several narrower views of it: `ai/caseReports.ts` takes a CaseReportContext,
   * `ai/analystQueries.ts` an AnalystQueryContext, and so on. Each interface declares only the
   * members that family may touch, so a report cannot reach the hypothesis store simply because
   * hypothesisReview needs it. Live getters rather than a snapshot for the reason importCtx gives:
   * the settings-reload path rebuilds these options in place.
   */
  private readonly aiCtx: CaseReportContext &
    AnalystQueryContext &
    ViewReportContext &
    HuntContext &
    PromptBlockContext &
    ExtractionContext &
    SynthesisContext &
    SecondOpinionContext;

  constructor(private readonly opts: PipelineOptions) {
    this.log = opts.logger ?? createConsoleLogger(normalizeLogLevel(process.env.DFIR_LOG_LEVEL));
    this.importCtx = {
      opts: {
        get stateStore() {
          return opts.stateStore;
        },
        get onState() {
          return opts.onState;
        },
      },
      withStateLock: (caseId, fn) => this.withStateLock(caseId, fn),
      mergeWithAliases: (state, delta, ctx) => this.mergeWithAliases(state, delta, ctx),
    };
    this.aiCtx = {
      opts: {
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
        get secondOpinionProvider() {
          return opts.secondOpinionProvider;
        },
        get secondOpinionModelLabel() {
          return opts.secondOpinionModelLabel;
        },
        get synthesisModelLabel() {
          return opts.synthesisModelLabel;
        },
        get synthMetaStore() {
          return opts.synthMetaStore;
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
        get retries() {
          return opts.retries;
        },
        get backoffMs() {
          return opts.backoffMs;
        },
      },
      log: this.log,
      requireProvider: (purpose) => this.requireProvider(purpose),
      withStateLock: (caseId, fn) => this.withStateLock(caseId, fn),
      mergeWithAliases: (state, delta, c) => this.mergeWithAliases(state, delta, c),
      warnOnPromptDrift: () => this.warnOnPromptDrift(),
      lastSynthHash: this.lastSynthHash,
      recordImportTruncation: (caseId, stats) => {
        if (stats) this.importTruncation.set(caseId, stats);
        else this.importTruncation.delete(caseId);
      },
      getKevCatalog: () => this.getKevCatalog(),
      withRetry: (caseId, label, fn, retries, backoffMs) =>
        this.withRetry(caseId, label, fn, retries, backoffMs),
      analyzeRestored: (caseId, state, provider, req, label, skipPresidioGate) =>
        analyzeRestored(this.aiCtx, caseId, state, provider, req, label, skipPresidioGate),
      promoteSuperTimeline: (caseId, events, o) => this.promoteSuperTimeline(caseId, events, o),
    };
  }

  // Wraps mergeDelta with the case's analyst IOC-merge aliases (#82), if any store is configured.
  // Every import/synthesis call site uses this instead of calling mergeDelta directly, so a merged
  // duplicate value stays folded onto its canonical IOC across every future window/re-synthesis.
  private async mergeWithAliases(
    state: InvestigationState,
    delta: Parameters<typeof mergeDelta>[1],
    ctx: WindowContext,
  ): Promise<InvestigationState> {
    if (!this.opts.iocAliasStore) return mergeDelta(state, delta, ctx);
    const { aliases } = await this.opts.iocAliasStore.load(state.caseId);
    return mergeDelta(state, delta, { ...ctx, iocAliases: aliases });
  }

  // Serializes the load->merge->save critical section of every import/analyze method per
  // caseId, so two concurrent imports for the same case can't race (second save clobbering
  // the first's merged delta). See src/analysis/stateLock.ts. Falls back to running fn
  // immediately when no lock is configured (e.g. some script/test call sites).
  // CAUTION: never call this from inside another withStateLock/runExclusive callback for the
  // SAME caseId — that nests onto the outer call's own unresolved promise and deadlocks.
  private withStateLock<T>(caseId: string, fn: () => Promise<T>): Promise<T> {
    return this.opts.stateLock ? this.opts.stateLock.runExclusive(caseId, fn) : fn();
  }

  // Wraps the module-level withRetry() with server-log visibility: every AI call site in this class
  // routes through here instead of calling withRetry() directly. Previously a failed/retried AI call
  // was silent everywhere except the dashboard's error badge and the case Activity Log — the server
  // console/session log showed only the DEBUG "AI call [label] ..." line for each attempt's START,
  // never why an attempt failed. Each failed attempt now logs a WARN with the case id, call label,
  // provider error kind (when available), and whether it's retrying or giving up.
  private withRetry<T>(
    caseId: string,
    label: string,
    fn: () => Promise<T>,
    retries: number,
    backoffMs: number,
  ): Promise<T> {
    return withRetry(fn, retries, backoffMs, (err, attempt, willRetry) => {
      const msg = err instanceof Error ? err.message : String(err);
      const kind = err instanceof ProviderError ? ` kind=${err.kind}` : "";
      this.log.warn(
        `AI call [${label}] attempt ${attempt + 1} failed${kind}: ${msg}${willRetry ? " — retrying" : " — giving up"}`,
        { caseId },
      );
      if (willRetry)
        void this.opts.operationalMetrics?.record({
          type: "ai_retry",
          phase: safeAiPhase(label),
          errorKind: safeAiErrorKind(err instanceof ProviderError ? err.kind : "other"),
        });
    });
  }

  /**
   * Measure per-host clock skew (#228) from the PRE-merge timeline and persist it, then return the
   * time function correlation should compare at — skew-corrected when the analyst has alignment on,
   * `undefined` (recorded times) otherwise.
   *
   * Detection is best-effort: a case with no clock-skew store, or one whose evidence yields no
   * anchors, simply correlates on recorded times exactly as before.
   */

  private async getKevCatalog(): Promise<KevCatalog | undefined> {
    if (!this.opts.kevStore) return undefined;
    if (!this.kevCatalogCache) this.kevCatalogCache = await this.opts.kevStore.loadCatalog();
    return this.kevCatalogCache;
  }

  // Called by the /kev routes after a catalog update so the next synthesis picks it up.
  invalidateKevCache(): void {
    this.kevCatalogCache = undefined;
  }

  hasAiProvider(): boolean {
    return Boolean(this.opts.provider);
  }

  // Text features resolve `synthesisProvider ?? provider`, so this preserves OCR-less installs.
  // Do not gate them on hasAiProvider(), which reflects only screenshot/vision capability.
  hasSynthesisProvider(): boolean {
    return Boolean(this.opts.synthesisProvider ?? this.opts.provider);
  }

  analysisProviderModels(): Array<{ provider: string; model: string }> {
    return uniqueProviderModels([
      this.opts.provider,
      this.opts.synthesisProvider,
      this.opts.secondOpinionProvider,
    ]);
  }

  analysisTextProviderModel(): { provider: string; model: string } | null {
    const provider = this.opts.synthesisProvider ?? this.opts.provider;
    return provider ? { provider: provider.name, model: provider.model } : null;
  }
  analysisProvider(providerName: string, model: string): AIProvider | undefined {
    return [this.opts.provider, this.opts.synthesisProvider, this.opts.secondOpinionProvider].find(
      (provider) => provider?.name === providerName && provider.model === model,
    );
  }

  private requireProvider(purpose: string): AIProvider {
    if (!this.opts.provider)
      throw new Error(`AI provider not configured; ${purpose} requires an AI provider`);
    return this.opts.provider;
  }

  /** Scan already-masked text with Presidio; fail closed on a scan error or unapproved value. */

  /** Scan one complete masked import up front so batched CSV/log analysis needs one approval round. */

  /**
   * Build the same (known entities, anonymizer) pair analyzeRestored derives per call, so an
   * import's pre-scan sees exactly the masked text the chunk loop would later produce. Returns
   * null when anonymization is off case-wide (mirrors analyzeRestored's own early return for
   * `!policy.enabled`) — with anonymization off there is no masked text for Presidio to see.
   */

  // Hash of the last successfully-synthesized inputs per case. The live, debounced
  // synthesis fires after every capture window; this lets us skip the (expensive) AI call
  // when nothing that affects the output has changed since the last run. In-memory: a
  // fresh process (or an explicit `force`) always synthesizes.
  private readonly lastSynthHash = new Map<string, string>();
  // Per-case log-aggregation truncation (investigation-guidance #10, trigger b): set by analyzeLog when
  // the distinct-template cap dropped patterns the AI never saw; consumed once by the import route to
  // stamp a cap-hit coverage warning onto import-meta. A side channel because import methods return only
  // the state, not metadata.
  private readonly importTruncation = new Map<string, AggregateStats>();
  consumeImportTruncation(caseId: string): AggregateStats | undefined {
    const v = this.importTruncation.get(caseId);
    this.importTruncation.delete(caseId);
    return v;
  }
  // Warn ONCE per process when a configured synthesis-prompt override is missing shipped capabilities
  // (investigation-guidance #1). Preflight surfaces the same drift in the UI; this covers a post-boot
  // edit to the override file, and keeps the warning from spamming every synthesis run.
  private warnedPromptDrift = false;

  private warnOnPromptDrift(): void {
    if (this.warnedPromptDrift) return;
    this.warnedPromptDrift = true;
    for (const d of checkConfiguredPromptDrift()) {
      this.log.warn(
        `[DFIR] prompt override ${d.file} is missing capabilities: ${d.missing.join(", ")} — ` +
          `model output will silently lack them; re-run 'npm run prompts:eject' to refresh it`,
      );
    }
  }

  analyzeWindow(caseId: string, captures: CaptureMetadata[]): Promise<InvestigationState> {
    return extraction.analyzeWindow(this.aiCtx, caseId, captures);
  }

  analyzeCsv(...args: AiExtractionArgs<typeof extraction.analyzeCsv>): Promise<InvestigationState> {
    return extraction.analyzeCsv(this.aiCtx, ...args);
  }

  analyzeLog(...args: AiExtractionArgs<typeof extraction.analyzeLog>): Promise<InvestigationState> {
    return extraction.analyzeLog(this.aiCtx, ...args);
  }

  importThor(...args: ImporterArgs<typeof ingest.importThor>): Promise<InvestigationState> {
    return ingest.importThor(this.importCtx, ...args);
  }

  importSiem(...args: ImporterArgs<typeof ingest.importSiem>): Promise<InvestigationState> {
    return ingest.importSiem(this.importCtx, ...args);
  }

  importEvtxXml(...args: ImporterArgs<typeof ingest.importEvtxXml>): Promise<InvestigationState> {
    return ingest.importEvtxXml(this.importCtx, ...args);
  }

  importBashHistory(...args: ImporterArgs<typeof ingest.importBashHistory>): Promise<InvestigationState> {
    return ingest.importBashHistory(this.importCtx, ...args);
  }

  importDeclarative(...args: ImporterArgs<typeof ingest.importDeclarative>): Promise<InvestigationState> {
    return ingest.importDeclarative(this.importCtx, ...args);
  }

  promoteSuperTimeline(
    ...args: ImporterArgs<typeof ingest.promoteSuperTimeline>
  ): Promise<InvestigationState> {
    return ingest.promoteSuperTimeline(this.importCtx, ...args);
  }

  importChainsaw(...args: ImporterArgs<typeof ingest.importChainsaw>): Promise<InvestigationState> {
    return ingest.importChainsaw(this.importCtx, ...args);
  }

  importHayabusa(...args: ImporterArgs<typeof ingest.importHayabusa>): Promise<InvestigationState> {
    return ingest.importHayabusa(this.importCtx, ...args);
  }

  importVelociraptor(...args: ImporterArgs<typeof ingest.importVelociraptor>): Promise<InvestigationState> {
    return ingest.importVelociraptor(this.importCtx, ...args);
  }

  importEcar(...args: ImporterArgs<typeof ingest.importEcar>): Promise<InvestigationState> {
    return ingest.importEcar(this.importCtx, ...args);
  }

  importCombinedLog(...args: ImporterArgs<typeof ingest.importCombinedLog>): Promise<InvestigationState> {
    return ingest.importCombinedLog(this.importCtx, ...args);
  }

  importCiscoAsa(...args: ImporterArgs<typeof ingest.importCiscoAsa>): Promise<InvestigationState> {
    return ingest.importCiscoAsa(this.importCtx, ...args);
  }

  importSnort(...args: ImporterArgs<typeof ingest.importSnort>): Promise<InvestigationState> {
    return ingest.importSnort(this.importCtx, ...args);
  }

  importYara(...args: ImporterArgs<typeof ingest.importYara>): Promise<InvestigationState> {
    return ingest.importYara(this.importCtx, ...args);
  }

  importSyslog(...args: ImporterArgs<typeof ingest.importSyslog>): Promise<InvestigationState> {
    return ingest.importSyslog(this.importCtx, ...args);
  }

  importNetwork(...args: ImporterArgs<typeof ingest.importNetwork>): Promise<InvestigationState> {
    return ingest.importNetwork(this.importCtx, ...args);
  }

  importSocrates(...args: ImporterArgs<typeof ingest.importSocrates>): Promise<InvestigationState> {
    return ingest.importSocrates(this.importCtx, ...args);
  }

  importSecurityOnion(...args: ImporterArgs<typeof ingest.importSecurityOnion>): Promise<InvestigationState> {
    return ingest.importSecurityOnion(this.importCtx, ...args);
  }

  importKape(...args: ImporterArgs<typeof ingest.importKape>): Promise<InvestigationState> {
    return ingest.importKape(this.importCtx, ...args);
  }

  importCybertriage(...args: ImporterArgs<typeof ingest.importCybertriage>): Promise<InvestigationState> {
    return ingest.importCybertriage(this.importCtx, ...args);
  }

  importM365(...args: ImporterArgs<typeof ingest.importM365>): Promise<InvestigationState> {
    return ingest.importM365(this.importCtx, ...args);
  }

  importOkta(...args: ImporterArgs<typeof ingest.importOkta>): Promise<InvestigationState> {
    return ingest.importOkta(this.importCtx, ...args);
  }

  importAws(...args: ImporterArgs<typeof ingest.importAws>): Promise<InvestigationState> {
    return ingest.importAws(this.importCtx, ...args);
  }

  importCloudActivity(...args: ImporterArgs<typeof ingest.importCloudActivity>): Promise<InvestigationState> {
    return ingest.importCloudActivity(this.importCtx, ...args);
  }

  importK8sAudit(...args: ImporterArgs<typeof ingest.importK8sAudit>): Promise<InvestigationState> {
    return ingest.importK8sAudit(this.importCtx, ...args);
  }

  importOsquery(...args: ImporterArgs<typeof ingest.importOsquery>): Promise<InvestigationState> {
    return ingest.importOsquery(this.importCtx, ...args);
  }

  importPlaso(...args: ImporterArgs<typeof ingest.importPlaso>): Promise<InvestigationState> {
    return ingest.importPlaso(this.importCtx, ...args);
  }

  importPlasoFile(...args: ImporterArgs<typeof ingest.importPlasoFile>): Promise<InvestigationState> {
    return ingest.importPlasoFile(this.importCtx, ...args);
  }

  importAuditd(...args: ImporterArgs<typeof ingest.importAuditd>): Promise<InvestigationState> {
    return ingest.importAuditd(this.importCtx, ...args);
  }

  importJournald(...args: ImporterArgs<typeof ingest.importJournald>): Promise<InvestigationState> {
    return ingest.importJournald(this.importCtx, ...args);
  }

  importSysdig(...args: ImporterArgs<typeof ingest.importSysdig>): Promise<InvestigationState> {
    return ingest.importSysdig(this.importCtx, ...args);
  }

  importWazuh(...args: ImporterArgs<typeof ingest.importWazuh>): Promise<InvestigationState> {
    return ingest.importWazuh(this.importCtx, ...args);
  }

  importSandbox(...args: ImporterArgs<typeof ingest.importSandbox>): Promise<InvestigationState> {
    return ingest.importSandbox(this.importCtx, ...args);
  }

  importMemory(...args: ImporterArgs<typeof ingest.importMemory>): Promise<InvestigationState> {
    return ingest.importMemory(this.importCtx, ...args);
  }

  importEmail(...args: ImporterArgs<typeof ingest.importEmail>): Promise<InvestigationState> {
    return ingest.importEmail(this.importCtx, ...args);
  }

  importTheHive(...args: ImporterArgs<typeof ingest.importTheHive>): Promise<InvestigationState> {
    return ingest.importTheHive(this.importCtx, ...args);
  }

  importIris(...args: ImporterArgs<typeof ingest.importIris>): Promise<InvestigationState> {
    return ingest.importIris(this.importCtx, ...args);
  }

  // Everything below is a one-line delegation into src/analysis/ai/ (#418). Each method's
  // documentation lives with its implementation there, so there is only ever one copy to keep true.
  ask(caseId: string, question: string): Promise<AskAnswer> {
    return analystQueries.ask(this.aiCtx, caseId, question);
  }

  explainEvent(caseId: string, eventId: string): Promise<ExplainEventResult> {
    return analystQueries.explainEvent(this.aiCtx, caseId, eventId);
  }

  knownUnknownsForCase(caseId: string): Promise<KnownUnknownItem[]> {
    return promptBlocks.knownUnknownsForCase(this.aiCtx, caseId);
  }

  suggestHunts(caseId: string, opts?: { excludeVql?: string }): Promise<HuntSuggestion[]> {
    return hunts.suggestHunts(this.aiCtx, caseId, opts);
  }

  suggestTechniqueHunts(
    caseId: string,
    techniqueId: string,
    techniqueName?: string,
  ): Promise<HuntSuggestion[]> {
    return hunts.suggestTechniqueHunts(this.aiCtx, caseId, techniqueId, techniqueName);
  }

  suggestMemoryNextSteps(caseId: string): Promise<MemoryNextStep[]> {
    return nextSteps.suggestMemoryNextSteps(this.aiCtx, caseId);
  }

  translateQuery(
    caseId: string,
    request: string,
    platforms?: readonly HuntPlatform[],
  ): Promise<QueryTranslationResult> {
    return hunts.translateQuery(this.aiCtx, caseId, request, platforms);
  }

  suggestTaggerRule(caseId: string, description: string): Promise<SuggestOutcome> {
    return nextSteps.suggestTaggerRule(this.aiCtx, caseId, description);
  }

  hypothesizeGaps(caseId: string): Promise<GapHypothesesResult> {
    return nextSteps.hypothesizeGaps(this.aiCtx, caseId);
  }

  suggestPlaybookHunts(
    caseId: string,
    tasks: PlaybookTask[],
    availableArtifacts: string[] = [],
    opts?: { excludeVql?: string },
  ): Promise<PlaybookHuntSuggestion[]> {
    return hunts.suggestPlaybookHunts(this.aiCtx, caseId, tasks, availableArtifacts, opts);
  }

  generateNarrative(caseId: string): Promise<{ narrativeTimeline: string }> {
    return caseReports.generateNarrative(this.aiCtx, caseId);
  }

  executiveSummary(caseId: string): Promise<ExecSummary> {
    return caseReports.executiveSummary(this.aiCtx, caseId);
  }

  starredReport(caseId: string, starredIds: string[]): Promise<StarredSummaryResult> {
    return viewReports.starredReport(this.aiCtx, caseId, starredIds);
  }

  sessionSummary(caseId: string, sessionId: string): Promise<SessionSummaryResult> {
    return viewReports.sessionSummary(this.aiCtx, caseId, sessionId);
  }

  viewSummary(caseId: string, filters: SuperQuery, labelMap?: SuperLabelMap): Promise<StarredSummaryResult> {
    return viewReports.viewSummary(this.aiCtx, caseId, filters, labelMap);
  }

  remediationPlan(caseId: string): Promise<RemediationPlan> {
    return caseReports.remediationPlan(this.aiCtx, caseId);
  }

  hypothesisReview(caseId: string): Promise<{ reviews: HypothesisReviewItem[] }> {
    return caseReports.hypothesisReview(this.aiCtx, caseId);
  }

  suggestFalsePositiveSimilarAi(
    caseId: string,
    anchorId: string,
    anchorLabel: string,
    candidateIds: string[],
    candidateLabels: string[],
  ): Promise<string[]> {
    return analystQueries.suggestFalsePositiveSimilarAi(
      this.aiCtx,
      caseId,
      anchorId,
      anchorLabel,
      candidateIds,
      candidateLabels,
    );
  }

  deepPassPreview(caseId: string): Promise<{ cap: number; floors: FloorOption[] }> {
    return deepPassRun.deepPassPreview(this.aiCtx, caseId);
  }

  /** Read every graded event at the chosen floor in batches, then fold observations into one
   * synthesis. Preview uses the same ordering; cancellation records a failed run but changes no case data. */
  deepPass(...args: AiArgs<typeof deepPassRun.deepPass>): Promise<DeepPassResult> {
    return deepPassRun.deepPass(this.aiCtx, ...args);
  }

  synthesize(...args: AiArgs<typeof synthesis.synthesize>): Promise<InvestigationState> {
    return synthesis.synthesize(this.aiCtx, ...args);
  }

  secondOpinion(caseId: string, opts: SynthThinkingInput = {}): Promise<SecondOpinion> {
    return secondOpinionRun.secondOpinion(this.aiCtx, caseId, opts);
  }

  // Accept or reject ONE second-opinion delta. The analyst's decision is recorded on the delta, and
  // ALL currently-accepted deltas are (re-)applied onto the live case state (idempotent) — so an
  // accept adds/edits the finding/severity/technique now and survives the next synthesis (the same
  // re-apply runs in synthesize()). A reject just records the decision; state is unchanged.
  applySecondOpinion(
    caseId: string,
    deltaId: string,
    accept: boolean,
  ): Promise<{ record: SecondOpinion; state: InvestigationState }> {
    return secondOpinionRun.applySecondOpinion(this.aiCtx, caseId, deltaId, accept);
  }

  // Bulk accept-all / reject-all: decide every still-PENDING delta at once (already-decided deltas
  // are left as the analyst set them), persist, and apply the accepted set to the case in ONE pass.
  applyAllSecondOpinion(
    caseId: string,
    accept: boolean,
  ): Promise<{ record: SecondOpinion; state: InvestigationState }> {
    return secondOpinionRun.applyAllSecondOpinion(this.aiCtx, caseId, accept);
  }

  // Save the (re)decided record, then re-apply ALL accepted deltas onto the live state (idempotent).
  // Shared by the single + bulk apply methods so both persist and broadcast identically.
}
