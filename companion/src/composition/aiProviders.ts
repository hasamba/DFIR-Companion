/**
 * AI model factories and the runtime pipeline wiring — the "build X from env" half of what
 * server.ts used to hold (#416, following #409's integration factories into this directory).
 *
 * Everything here is a CONSTRUCTOR CALL over `process.env`: no network, no I/O, no domain logic.
 * That is why it could move ahead of the stateful blocks — there is no lifecycle to get wrong.
 * `buildProvider()` in particular is deliberately re-read per call (Settings → Diagnostics rebuilds
 * a provider from the CURRENT env to test connectivity), so these must stay functions, not consts.
 *
 * Re-exported from server.ts, because scripts/{reanalyze,synthesize,deep-pass,verify-ai}.ts and the
 * provider wiring tests import them from `src/server.js`.
 */
import type { CaseStore } from "../storage/caseStore.js";
import { StateStore as StateStoreImpl } from "../analysis/stateStore.js";
import { AnalysisPipeline as AnalysisPipelineImpl } from "../analysis/pipeline.js";
import { makeImageLoader } from "../analysis/imageLoader.js";
import { ProviderRegistry } from "../providers/provider.js";
import type { AIProvider as AnalyzeProvider } from "../providers/provider.js";
import { visionEnv } from "../config/aiEnv.js";
import { OpenAIProvider } from "../providers/openai.js";
import { OpenRouterProvider } from "../providers/openrouter.js";
import { OllamaCloudProvider } from "../providers/ollama.js";
import { LiteLlmProvider } from "../providers/litellm.js";
import { GeminiProvider } from "../providers/gemini.js";
import { AnthropicProvider } from "../providers/anthropic.js";
import { ClaudeCodeProvider } from "../providers/claudeCode.js";
import { CodexProvider } from "../providers/codex.js";
import { contextTokens as resolveContextTokens } from "../analysis/promptBudget.js";
import { FalsePositiveStore } from "../analysis/falsePositive.js";
import { ScopeStore } from "../analysis/scope.js";
import { AnonControlStore } from "../analysis/anonControl.js";
import { CustomEntitiesStore } from "../analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../analysis/anonDiscovered.js";
import { PresidioPendingStore } from "../analysis/presidioPending.js";
import { SynthMetaStore } from "../analysis/synthMeta.js";
import { AiCostStore } from "../analysis/aiCost.js";
import { CorrelationProfileStore } from "../analysis/correlationProfile.js";
import { NotebookStore } from "../analysis/notebookStore.js";
import { HypothesisStore } from "../analysis/hypothesisStore.js";
import { LearnedPatternStore } from "../analysis/learnedPatternStore.js";
import { SourceTrustStore } from "../analysis/sourceTrustStore.js";
import { PlaybookStore } from "../analysis/playbookStore.js";
import { ImportMetaStore } from "../analysis/importMeta.js";
import { AiControlStore } from "../analysis/aiControl.js";
import { HuntOutcomeStore } from "../analysis/huntOutcomeStore.js";
import { SuperTimelineStore } from "../analysis/superTimelineStore.js";
import { IocAliasStore } from "../analysis/iocAlias.js";
import type { KevStore } from "../analysis/kevStore.js";
import type { ClockSkewStore } from "../analysis/clockSkewStore.js";
import type { IncidentTypeStore } from "../analysis/incidentTypeStore.js";
import type { SecondOpinionStore } from "../analysis/secondOpinionStore.js";
import type { StateLock } from "../analysis/stateLock.js";
import type { AnalysisRunStore } from "../analysis/analysisRunStore.js";
import type { OperationalMetricsStore } from "../analysis/operationalMetrics.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import type { Logger } from "../logging/logger.js";

export interface ProviderParams {
  provider?: string;
  model?: string;
  apiKey?: string;
  imageDetail?: "high" | "low" | "auto";
  timeoutMs?: number;
  maxTokens?: number;
  // The model's context window (tokens) for the provider's pre-flight guard. Defaults from
  // DFIR_AI_CONTEXT_TOKENS (or 128000) so an oversized prompt is trimmed/clearly-errored.
  contextTokens?: number;
  // Override the provider's API base URL. Required for a self-hosted LiteLLM proxy
  // (and any OpenAI-compatible local endpoint); each provider keeps its own default
  // when this is unset. Empty string is treated as unset.
  baseUrl?: string;
}

// Build a provider from explicit params (so callers can build more than one,
// e.g. a cheap extraction model + a stronger synthesis model).
export function buildProviderFrom(params: ProviderParams): AnalyzeProvider | undefined {
  const name = params.provider;
  if (!name) return undefined;
  const model = params.model ?? "";
  const apiKey = params.apiKey ?? "";
  const imageDetail = params.imageDetail ?? "high";
  // Empty string → undefined so each provider falls back to its built-in default.
  const baseUrl = params.baseUrl?.trim() || undefined;
  // Strong models over a large timeline can take >60s — make the request timeout tunable.
  const timeoutMs = params.timeoutMs ?? (Number(process.env.DFIR_AI_TIMEOUT_MS) || 180_000);
  // Bound completion tokens. Without this, OpenRouter reserves the model's full max
  // output for its per-request credit check and can 402 a large request (e.g. THOR
  // synthesis) even when the account has credits. Tunable via DFIR_AI_MAX_TOKENS.
  const maxTokens = params.maxTokens ?? (Number(process.env.DFIR_AI_MAX_TOKENS) || 16000);
  // Context window for the pre-flight guard — same default the pipeline budgets against, so
  // a too-big prompt is trimmed by the pipeline and, as a backstop, caught here before the API.
  const contextTokens = params.contextTokens ?? resolveContextTokens();
  const registry = new ProviderRegistry();
  registry.register(
    new OpenAIProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens, contextTokens }),
  );
  registry.register(
    new OpenRouterProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens, contextTokens }),
  );
  registry.register(
    new OllamaCloudProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens, contextTokens }),
  );
  registry.register(
    new LiteLlmProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens, contextTokens }),
  );
  registry.register(new GeminiProvider({ apiKey, model, baseUrl, timeoutMs, maxTokens }));
  registry.register(new AnthropicProvider({ apiKey, model, baseUrl, timeoutMs, maxTokens }));
  registry.register(new ClaudeCodeProvider({ model, timeoutMs, bin: process.env.DFIR_AI_CLAUDE_CODE_BIN }));
  registry.register(new CodexProvider({ model, timeoutMs, bin: process.env.DFIR_AI_CODEX_BIN }));
  return registry.get(name);
}

export function buildProvider(): AnalyzeProvider | undefined {
  // Vision/screenshot model — DFIR_VISION_* (legacy DFIR_AI_* still honored via visionEnv).
  return buildProviderFrom({
    provider: visionEnv(process.env, "PROVIDER"),
    model: visionEnv(process.env, "MODEL"),
    apiKey: visionEnv(process.env, "KEY"),
    baseUrl: visionEnv(process.env, "BASE_URL"),
    imageDetail: visionEnv(process.env, "IMAGE_DETAIL") as "high" | "low" | "auto" | undefined,
  });
}

// Synthesis model: dedicated DFIR_AI_SYNTH_* vars, falling back to the main model.
export function buildSynthesisProvider(): AnalyzeProvider | undefined {
  // Text model — DFIR_AI_SYNTH_*, falling back to the vision model's config (DFIR_VISION_*, legacy
  // DFIR_AI_* via visionEnv) when a dedicated synth var is unset.
  return buildProviderFrom({
    provider: process.env.DFIR_AI_SYNTH_PROVIDER ?? visionEnv(process.env, "PROVIDER"),
    model: process.env.DFIR_AI_SYNTH_MODEL ?? visionEnv(process.env, "MODEL"),
    apiKey: process.env.DFIR_AI_SYNTH_KEY ?? visionEnv(process.env, "KEY"),
    baseUrl: process.env.DFIR_AI_SYNTH_BASE_URL ?? visionEnv(process.env, "BASE_URL"),
    imageDetail: visionEnv(process.env, "IMAGE_DETAIL") as "high" | "low" | "auto" | undefined,
  });
}

// Second-opinion model (issue #116): a DEDICATED, DIFFERENT model for the on-demand QA cross-check.
// Returns undefined UNLESS DFIR_AI_SECOND_OPINION_MODEL is set — that env var IS the opt-in, and its
// absence disables the feature (route 501, dashboard button hidden). Recommend a model from a
// DIFFERENT provider than the primary synthesis model so the opinion is genuinely independent; the
// key/provider/baseUrl fall back to the main AI config so it works out of the box on one account.
export function buildSecondOpinionProvider(): AnalyzeProvider | undefined {
  const model = process.env.DFIR_AI_SECOND_OPINION_MODEL?.trim();
  if (!model) return undefined;
  return buildProviderFrom({
    provider: process.env.DFIR_AI_SECOND_OPINION_PROVIDER ?? visionEnv(process.env, "PROVIDER"),
    model,
    apiKey: process.env.DFIR_AI_SECOND_OPINION_KEY ?? visionEnv(process.env, "KEY"),
    baseUrl: process.env.DFIR_AI_SECOND_OPINION_BASE_URL ?? visionEnv(process.env, "BASE_URL"),
  });
}

// Velociraptor-hunt model (issue #70): a DEDICATED model just for generating Velociraptor VQL hunts
// (suggestPlaybookHunts + suggestHunts), since many models botch VQL. Defaults to openrouter /
// anthropic/claude-haiku-latest regardless of the main/synth provider; the key falls back to the main
// AI key (so it works out of the box when the main provider is openrouter). The pipeline uses this
// over the synthesis/main provider for hunt generation only.
export const DEFAULT_VELO_PROVIDER = "openrouter";
export const DEFAULT_VELO_MODEL = "anthropic/claude-haiku-4.5"; // latest Haiku; a VALID OpenRouter id (claude-haiku-latest 400s there)
export function buildVelociraptorProvider(): AnalyzeProvider | undefined {
  return buildProviderFrom({
    provider: process.env.DFIR_AI_VELO_PROVIDER?.trim() || DEFAULT_VELO_PROVIDER,
    model: process.env.DFIR_AI_VELO_MODEL?.trim() || DEFAULT_VELO_MODEL,
    apiKey: process.env.DFIR_AI_VELO_KEY ?? visionEnv(process.env, "KEY"),
    baseUrl: process.env.DFIR_AI_VELO_BASE_URL ?? visionEnv(process.env, "BASE_URL"),
  });
}

export interface RuntimePipelineParams {
  provider?: AnalyzeProvider;
  synthesisProvider?: AnalyzeProvider;
  // Dedicated model for Velociraptor VQL hunt generation (#70); falls back to synthesis/main.
  velociraptorProvider?: AnalyzeProvider;
  stateStore: StateStoreImpl;
  store: CaseStore;
  imageLoader?: ConstructorParameters<typeof AnalysisPipelineImpl>[0]["imageLoader"];
  onState?: (state: InvestigationState) => void;
  // Fired after a real synthesis run with the findings diff + new state (issue #58 notifications).
  onSynth?: ConstructorParameters<typeof AnalysisPipelineImpl>[0]["onSynth"];
  // Provided only when the AI vision provider is external (not local). See ocrRedact.ts.
  ocrRunner?: ConstructorParameters<typeof AnalysisPipelineImpl>[0]["ocrRunner"];
  // Optional Presidio layer (Task 7). Absent → the option stays undefined and the gate is a no-op
  // for every one of the 27 AI call sites that funnel through analyzeRestored.
  presidio?: ConstructorParameters<typeof AnalysisPipelineImpl>[0]["presidio"];
  presidioPendingStore?: ConstructorParameters<typeof AnalysisPipelineImpl>[0]["presidioPendingStore"];
  // Shared logger so AI/OCR/anonymization debug traces land in the same session + per-case logs.
  logger?: Logger;
  // CISA KEV catalog (issue #99): passed to the pipeline so synthesis context includes KEV hits.
  kevStore?: KevStore;
  // Clock-skew store (#228): synthesis measures per-host offsets from the PRE-merge timeline (the
  // correlation that follows collapses the anchors) and stores them here.
  clockSkewStore?: ClockSkewStore;
  // Incident-type store (#236): synthesis reads the case's chosen type for its one-line hint.
  // Passed in rather than built here — it needs the custom-types dir, not just the case store.
  incidentTypeStore?: IncidentTypeStore;
  // Second LLM opinion (issue #116): a different model + its persistence store, plus the model
  // labels for the comparison header. Absent → the feature is disabled (route 501).
  secondOpinionProvider?: AnalyzeProvider;
  secondOpinionStore?: SecondOpinionStore;
  synthesisModelLabel?: string;
  secondOpinionModelLabel?: string;
  stateLock?: StateLock;
  analysisRunStore?: AnalysisRunStore;
  operationalMetrics?: OperationalMetricsStore;
}

export function buildRuntimePipeline(params: RuntimePipelineParams): AnalysisPipelineImpl {
  return new AnalysisPipelineImpl({
    provider: params.provider,
    synthesisProvider: params.synthesisProvider,
    velociraptorProvider: params.velociraptorProvider,
    secondOpinionProvider: params.secondOpinionProvider,
    secondOpinionStore: params.secondOpinionStore,
    synthesisModelLabel: params.synthesisModelLabel,
    secondOpinionModelLabel: params.secondOpinionModelLabel,
    stateLock: params.stateLock,
    stateStore: params.stateStore,
    falsePositiveStore: new FalsePositiveStore(params.store),
    scopeStore: new ScopeStore(params.store),
    imageLoader: params.imageLoader ?? makeImageLoader(params.store),
    onState: params.onState,
    onSynth: params.onSynth,
    anonStore: new AnonControlStore(params.store),
    customEntitiesStore: new CustomEntitiesStore(params.store),
    discoveredStore: new DiscoveredEntitiesStore(params.store),
    synthMetaStore: new SynthMetaStore(params.store),
    analysisRunStore: params.analysisRunStore,
    operationalMetrics: params.operationalMetrics,
    aiCostStore: new AiCostStore(params.store),
    correlationProfileStore: new CorrelationProfileStore(params.store),
    notebookStore: new NotebookStore(params.store),
    hypothesisStore: new HypothesisStore(params.store), // #140 auto-generate hypotheses on synthesis
    learnedPatternStore: new LearnedPatternStore(params.store), // #65 feed learned dismissal patterns into synthesis
    sourceTrustStore: new SourceTrustStore(params.store), // #66 per-source trust weights for merge + confidence
    clockSkewStore: params.clockSkewStore, // #228 measure clock skew on the PRE-merge timeline
    incidentTypeStore: params.incidentTypeStore, // #236 frame synthesis with the case's incident type
    playbookStore: new PlaybookStore(params.store), // #2 feed DONE/SKIPPED task status into synthesis
    importMetaStore: new ImportMetaStore(params.store), // #10 flag a zero-yield AI import as a coverage gap
    aiControlStore: new AiControlStore(params.store),
    huntOutcomeStore: new HuntOutcomeStore(params.store), // #157 hunting feedback loop
    superTimelineStore: new SuperTimelineStore(
      params.store,
      Number(process.env.DFIR_SUPERTIMELINE_MAX) || undefined,
      params.operationalMetrics,
    ), // explainEvent falls back here for raw super-only events
    ocrRunner: params.ocrRunner,
    presidio: params.presidio,
    presidioPendingStore: params.presidioPendingStore ?? new PresidioPendingStore(params.store),
    logger: params.logger,
    kevStore: params.kevStore,
    iocAliasStore: new IocAliasStore(params.store), // #82: keep analyst IOC merges applied across re-synthesis
  });
}
