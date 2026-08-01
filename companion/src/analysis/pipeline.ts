import { createReadStream } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { join as joinPath } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import { ProviderError, type AIProvider, type AnalyzeImage, type AnalyzeRequest, type AnalyzeResult, type ProviderErrorKind } from "../providers/provider.js";
import { createConsoleLogger, normalizeLogLevel, type Logger } from "../logging/logger.js";
import { createAnonymizer, deriveKnownEntities, isMaskableIpv4, isInternalIp, type Anonymizer, type CustomEntity, type KnownEntities } from "./anonymize.js";
import { mapFindings, PresidioApprovalRequired, type PresidioClient, type PresidioFinding } from "./presidio.js";
import type { PresidioPendingStore } from "./presidioPending.js";
import { toAnonPolicy, type AnonControlStore } from "./anonControl.js";
import type { CustomEntitiesStore } from "./anonEntities.js";
import type { DiscoveredEntitiesStore } from "./anonDiscovered.js";
import type { CaptureMetadata } from "../types.js";
import type { StateStore } from "./stateStore.js";
import type { InvestigationState, InvestigationQuestion, ForensicEvent, Severity, TimelineEntry } from "./stateTypes.js";
import { deltaSchema, askSchema, execSummarySchema, explainEventSchema, remediationPlanSchema, fpSimilaritySchema, hypothesisReviewSchema, stripAiExtractedFrom, type AskAnswer, type ExecSummary, type ExplainEventResult, type RemediationPlan } from "./responseSchema.js";
import { buildMitigationsResult } from "./attackMitigations.js";
import { loadMitigationsDataset } from "./attackMitigationsData.js";
import { buildD3fendResult } from "./d3fendMap.js";
import { loadD3fendDataset, d3fendEnvOptions } from "./d3fendData.js";
import { buildStateSummary } from "./summary.js";
import { mergeDelta, type WindowContext } from "./stateMerge.js";
import type { IocAliasStore } from "./iocAlias.js";
import type { StateLock } from "./stateLock.js";
import { sortByEventTime } from "./forensicSort.js";
import { segmentSessions, sessionEnvOptions } from "./sessionSegmentation.js";
import { applySeverityFloor } from "./severityFloor.js";
import type { ExternalImporter } from "./declarativeImporter.js";
import { parseJsonLoose } from "./extractJson.js";
import { applyFalsePositive, buildFalsePositiveContext, buildAuthorizedContextBlock, filterFalsePositiveEvents, type FalsePositiveStore } from "./falsePositive.js";
import { buildLearnedPatternsBlock } from "./learnedPatterns.js";
import type { LearnedPatternStore } from "./learnedPatternStore.js";
import { backfillHighSeverityFindings } from "./highSeverityFindings.js";
import { checkConfiguredPromptDrift } from "./promptCapabilities.js";
import { MATCHABLE_FIELDS } from "./taggerRules.js";
import { suggestedRuleResponseSchema, sanitizeSuggestedRule, type SuggestOutcome } from "./taggerRuleSuggest.js";
import { resolveSynthThinkingBudget, type SynthThinkingInput } from "./synthThinking.js";
import { detectTimelineGaps, backfillSilenceGapFindings, gapEnvOptions } from "./gapDetect.js";
import {
  gapHypothesesResponseSchema,
  sanitizeGapHypotheses,
  buildGapHypotheses,
  surroundingEvents,
  renderGapsForPrompt,
  hasGapMaterial,
  GAP_HYPOTHESIS_MAX_DEFAULT,
  SURROUNDING_EVENTS_DEFAULT,
  GAP_HYPOTHESIS_CAVEAT,
  type GapHypothesesResult,
} from "./gapHypothesis.js";
import { SHADOW_ARTIFACTS } from "./shadowArtifacts.js";
import { diffFindings, type FindingsDiff } from "./findingsDiff.js";
import { buildKnownUnknownItems, renderKnownUnknowns, type KnownUnknownItem } from "./knownUnknowns.js";
import { classifyImportYield, type ImportMetaStore, type ImportYieldWarning } from "./importMeta.js";
import { buildAdversaryHintsResult } from "./adversaryHints.js";
import { loadAdversaryGroupsDataset, adversaryHintEnvOptions } from "./adversaryGroupsData.js";
import { loadKnownPlaybooks } from "./knownPlaybooksData.js";
import { buildPlaybookMatchResult, playbookMatchEnvOptions } from "./playbookMatch.js";
import { buildSynthesisCoverage, type SynthMetaStore, type SynthesisCoverage } from "./synthMeta.js";
import { AiCostStore, bucketForLabel } from "./aiCost.js";
// The prompt registry moved to ai/prompts/ (#384). Imported for the pipeline's own use and
// re-exported below, because 23 modules and the eval harness import these names from here.
import {
  getAskPrompt, getCsvPrompt, getExecSummaryPrompt, getExplainEventPrompt, getFpSimilarityPrompt,
  getGapHypothesisPrompt, getHuntSuggestPrompt, getHypothesisReviewPrompt,
  getLogPrompt, getMemoryNextStepPrompt, getNarrativePrompt, getObservePrompt, getPlaybookHuntPrompt,
  getQueryTranslatePrompt, getReconcilePrompt, getRemediationPrompt, getSessionSummaryPrompt,
  getStarredReportPrompt, getSynthesisPrompt, getSystemPrompt, getTaggerRulePrompt,
  getViewSummaryPrompt,
} from "./ai/prompts/index.js";
export * from "./ai/prompts/index.js";
import { CorrelationProfileStore } from "./correlationProfile.js";
import type { SecondOpinionStore } from "./secondOpinionStore.js";
import {
  buildSecondOpinion,
  buildReconcilePrompt,
  reconcileResponseSchema,
  mergeReconcileVerdicts,
  applyAcceptedSecondOpinion,
  setDeltaStatus,
  setAllPendingStatus,
  type SecondOpinion,
} from "./secondOpinion.js";
import { correlateEvents, correlationGroups, type CorrelateOptions } from "./correlate.js";
import { detectClockSkew, effectiveOffsets, alignedEpoch } from "./clockSkew.js";
import { effectiveTrustMap } from "./sourceTrust.js";
import type { SourceTrustStore } from "./sourceTrustStore.js";
import type { ClockSkewStore } from "./clockSkewStore.js";
import { detectTool } from "./toolDetect.js";
import { filterEventsByScope, hasScope, NO_SCOPE, type ScopeStore, type ScopeWindow } from "./scope.js";
import { parseCsv, chunkToCsvText } from "./csvImport.js";
import { parseLogLines } from "./logImport.js";
import { aggregateLogLines, type AggregateStats } from "./logAggregate.js";
import { parseThorReport, type ThorImportOptions } from "./thorImport.js";
import { parseSiemExport, resolveExtractedFrom, type SiemImportOptions, type SiemParseResult } from "./siemImport.js";
import { parseEvtxXmlProgress } from "./evtxXmlImport.js";
import { parseShellHistoryFile, userFromHistoryFilename } from "./bashHistoryImport.js";
import { parseChainsawReport, type ChainsawImportOptions } from "./chainsawImport.js";
import { parseHayabusaTimeline, type HayabusaImportOptions } from "./hayabusaImport.js";
import { parseVelociraptorJsonProgress, type VelociraptorImportOptions } from "./velociraptorImport.js";
import { parseEcarJson, ECAR_SOURCE, type EcarImportOptions } from "./ecarImport.js";
import { parseSnortLog, SNORT_SOURCE, type SnortImportOptions } from "./snortImport.js";
import { parseYaraOutput, YARA_SOURCE, type YaraImportOptions } from "./yaraImport.js";
import { parseCombinedLog, COMBINED_LOG_SOURCE, type CombinedLogImportOptions } from "./combinedLogImport.js";
import { parseCiscoAsaLog, CISCO_ASA_SOURCE, type CiscoAsaImportOptions } from "./ciscoAsaImport.js";
import { parseSyslog, SYSLOG_SOURCE, type SyslogImportOptions } from "./syslogImport.js";
import { pickImportYear } from "./timeYearClamp.js";
import { parseNetworkLogs, type NetworkImportOptions } from "./networkImport.js";
import { parseSocrates, type SocratesImportOptions } from "./socratesImport.js";
import { parseSecurityOnion, type SecurityOnionImportOptions } from "./securityOnionImport.js";
import { parseKapeCsv, type KapeImportOptions } from "./kapeImport.js";
import { parseCybertriage, type CybertriageImportOptions } from "./cybertriageImport.js";
import { parseM365Audit, type M365ImportOptions } from "./m365Import.js";
import { parseCloudTrail, type AwsImportOptions } from "./awsImport.js";
import { parseCloudActivity, type CloudActivityImportOptions } from "./cloudActivityImport.js";
import { parseK8sAudit, type K8sAuditImportOptions } from "./k8sAuditImport.js";
import { parseOsqueryLog, type OsqueryImportOptions } from "./osqueryImport.js";
import { parsePlasoCsv, parsePlasoFromLines, type PlasoImportOptions, type PlasoParseResult } from "./plasoImport.js";
import { parseSandboxReport, type SandboxImportOptions } from "./sandboxImport.js";
import { parseMemory, type MemoryImportOptions } from "./memoryImport.js";
import { parseEmail, type EmailImportOptions } from "./emailImport.js";
import { parseTheHive, type TheHiveImportOptions } from "./theHiveImport.js";
import { parseIrisCase, type IrisCaseData, type IrisImportOptions } from "./irisImport.js";
import { parseAuditdLog, type AuditdImportOptions } from "./auditdImport.js";
import { parseJournald, type JournaldImportOptions } from "./journaldImport.js";
import { parseSysdig, type SysdigImportOptions } from "./sysdigImport.js";
import { parseWazuhAlerts, type WazuhImportOptions } from "./wazuhImport.js";
import { selectSynthesisEvents, selectSynthesisEventsAnnotated, buildSynthesisContext, type SelectionClass } from "./synthSelect.js";
import { collapseForPrompt, renderGroupSuffix, groupEnvOptions, groupingEnabled, maxPromptEvents, promptCandidates, type CollapsedPrompt } from "./synthGroup.js";
import {
  previewFloors, planBatches, floorsWithinBudget, renderObservationDigest,
  DEFAULT_MAX_BATCHES, type DeepPassCheckpoint, type FloorOption,
} from "./deepPass.js";
import { executeDeepPassBatches } from "./deepPassExecution.js";
import { lastImportEventSequence } from "./importResume.js";
import { unionEventTechniques } from "./reconTechniques.js";
import { buildGraphContext, DEFAULT_MAX_GRAPH_EDGES } from "./graphContext.js";
import type { KevStore } from "./kevStore.js";
import { extractCveIds, matchKevEntries, type KevCatalog } from "./kev.js";
import {
  huntSuggestionsResponseSchema,
  sanitizeHuntSuggestions,
  renderHuntFindings,
  renderHuntIocs,
  hasHuntMaterial,
  HUNT_SUGGEST_MAX_DEFAULT,
  type HuntSuggestion,
} from "./huntSuggest.js";
import {
  playbookHuntResponseSchema,
  sanitizePlaybookHuntSuggestions,
  buildTaskEndpointsMap,
  knownEndpoints,
  renderPlaybookHuntTasks,
  renderKnownEndpoints,
  renderAvailableArtifacts,
  hasPlaybookHuntMaterial,
  PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT,
  type PlaybookHuntSuggestion,
} from "./playbookHunt.js";
import {
  deployedFingerprints,
  renderPriorHuntsBlock,
  renderHuntProductivityBlock,
  vqlFingerprint,
  type HuntOutcome,
} from "./huntOutcomes.js";
import type { HuntOutcomeStore } from "./huntOutcomeStore.js";
import type { SuperTimelineStore } from "./superTimelineStore.js";
import type { SuperQuery, SuperLabelMap } from "./superTimeline.js";
import {
  memoryNextStepResponseSchema,
  sanitizeMemoryNextSteps,
  renderMemoryEvidence,
  memoryPluginsPresent,
  isMemoryEvent,
  hasMemoryMaterial,
  MEMORY_NEXTSTEP_MAX_DEFAULT,
  type MemoryNextStep,
} from "./memoryNextStep.js";
import {
  queryTranslationResponseSchema,
  sanitizeQueryTranslations,
  sanitizeInterpretation,
  renderPlatformGuide,
  renderCaseDataSources,
  type QueryTranslationResult,
} from "./queryTranslate.js";
import { HUNT_PLATFORMS, type HuntPlatform } from "./huntPlatforms.js";
import type { PlaybookTask } from "./playbook.js";
import type { PlaybookStore } from "./playbookStore.js";
import type { IncidentTypeStore } from "./incidentTypeStore.js";
import type { AnalysisRunStore } from "./analysisRunStore.js";
import { recordDeepPassRun, recordSynthesisRun, uniqueProviderModels } from "./analysisRunRecorders.js";
import { renderIncidentTypeBlock } from "./incidentTypes.js";
import { renderPlaybookProgressBlock, renderRefutedHypothesesBlock, demoteCompletedNextSteps } from "./priorWork.js";
import { flagContradictedAnswers } from "./answerContradiction.js";
import { detectSatisfiedCollections, buildSatisfiedCollectionsBlock } from "./collectSatisfaction.js";
import { renderStructuredTags, buildBeaconDigest, buildAttackPhaseDigest } from "./synthEvidence.js";
import { detectBeacons, beaconEnvOptions } from "./beaconDetect.js";
import { buildAttackPhases } from "./burstDetect.js";
import { buildEvidenceGraph } from "./evidenceGraph.js";
import { buildAssetGraph } from "./assetGraph.js";
import { shortHost, rankConnectiveIocs } from "./iocAnchors.js";
import {
  buildSecondLookRequests, resolveSecondLookRequests, buildSecondLookPlan, summarizeSecondLook,
  deriveWindow, type ModelEvidenceRequest,
} from "./secondLook.js";
import { groundAndScoreFindings, capIntelOnlyFindings, buildIntelCorroborationSteps, corroborationLabel } from "./findingGrounding.js";
import { scoreFindingsRelevance } from "./findingRelevance.js";
import { buildPrevalenceIndex, eventPrevalence, prevalenceTag, rarityScore } from "./prevalence.js";
import { reconsiderKeyQuestions, textMentionsFindingId } from "./fpCascade.js";
import { estimateTokens, inputTokenBudget, batchByBudget, fitItemsToBudget } from "./promptBudget.js";
import type { AiControlStore } from "./aiControl.js";
import type { NotebookStore } from "./notebookStore.js";
import type { HypothesisStore } from "./hypothesisStore.js";
import { sanitizeHypotheses, sanitizeHypothesisReviews, type HypothesisReviewItem } from "./hypothesis.js";
import { ocrRedactImage, type OcrRunner } from "./ocrRedact.js";

// Write a redacted screenshot copy to DFIR_OCR_DEBUG_DIR for visual inspection. The redacted
// buffer keeps the source image format (sharp infers it from the input), so the extension is
// derived from the source mime type. Best-effort: a dump failure must never break analysis, and
// caseId is sanitized so it can't escape the debug dir. This never touches the evidence files.
async function dumpRedactedImage(
  dir: string,
  caseId: string,
  index: number,
  mimeType: string,
  buffer: Buffer,
): Promise<void> {
  try {
    const ext = (mimeType.split("/")[1] ?? "png").replace(/[^a-z0-9]/gi, "") || "png";
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const safeCase = caseId.replace(/[^a-z0-9_-]/gi, "_");
    const outDir = joinPath(dir, safeCase);
    await mkdir(outDir, { recursive: true });
    await writeFile(joinPath(outDir, `${stamp}-img${index + 1}.${ext}`), buffer);
  } catch (err) {
    console.warn(`[OCR dump] ${(err as Error).message}`);
  }
}






/** What one deep-pass run did, for the analyst and the route response. */
export interface DeepPassResult {
  aborted: boolean;
  floor: Severity;        // the minimum severity that was read
  events: number;         // graded events at or above the floor
  rows: number;           // prompt rows after detection-burst grouping
  batches: number;        // observation calls made
  batchesFailed: number;  // batches whose response never parsed — that slice went unread
  observations: number;   // observations that survived sanitising
}

// Result of the two view-scoped AI summaries (starred report / view summary). `eventCount` is the
// full deduplicated match; `usedEvents` what actually fit the AI input budget.
export interface StarredSummaryResult {
  markdown: string;
  eventCount: number;
  usedEvents: number;
  truncated: boolean;
}

/** One session's AI account (#342). Carries the session identity so a stale card can't mislabel it. */
export interface SessionSummaryResult extends StarredSummaryResult {
  sessionId: string;
  label: string;
}

export interface PipelineOptions {
  // The VISION model: screenshot analysis only (analyzeWindow). Screenshots need an image-capable
  // model and are the one path a cheap/fast model is genuinely suited to.
  provider?: AIProvider;
  // The TEXT model: every text-only reasoning call — synthesis, ask/explain, memory next-steps, and
  // (since #66-era model routing) CSV + log extraction. Falls back to `provider` when unset, so a
  // single-model install is unaffected.
  //
  // CSV/log extraction moved here because it is a text-reasoning task, not an OCR one: measured on
  // the eval harness (`npm run eval:real`), gpt-4o-mini returned ZERO events for a proxy log holding
  // six large CONNECT-to-mega.nz transfers on every run, while gemini-2.5-pro found it every time on
  // the identical input through the identical code path. The same silent-miss shows up in the
  // northpeak benchmark, where a 27k-line proxy log and both web logs yielded zero forensic events.
  synthesisProvider?: AIProvider;
  // Optional DEDICATED model for Velociraptor VQL hunt generation (#70) — many models botch VQL,
  // so the analyst can pin a known-good one just for suggestHunts/suggestPlaybookHunts. Falls back
  // to synthesisProvider, then the main provider.
  velociraptorProvider?: AIProvider;
  // Per-case hunt outcomes (#157) — the hunting feedback loop. When set, suggestHunts /
  // suggestTechniqueHunts / suggestPlaybookHunts read prior-hunt outcomes to (a) drop a suggestion
  // whose VQL already ran and (b) feed a "PRIOR HUNTS" context block so the model pivots on what hit.
  // Server-only (absent in scripts/* like the other Velociraptor features) → loop simply off.
  huntOutcomeStore?: HuntOutcomeStore;
  // Per-case super-timeline store (the raw imported host-triage events not in InvestigationState).
  // When set, explainEvent falls back to it so an event that was only imported into the super-timeline
  // (never promoted into the forensic timeline) can still be explained. Server-only (absent in scripts/*).
  superTimelineStore?: SuperTimelineStore;
  // Client-confirmed false-positive findings/IOCs to exclude from synthesis.
  falsePositiveStore?: FalsePositiveStore;
  // Learned dismissal patterns (issue #65): recurring reasoned dismissals distilled into a per-case
  // ledger. When set, synthesis feeds a "PREVIOUSLY DISMISSED PATTERNS" block so NEW activity resembling
  // one is surfaced with LOWER confidence unless corroborated (complements falsePositiveStore's EXCLUDE).
  learnedPatternStore?: LearnedPatternStore;
  // Per-source trust overrides (issue #66): steers cross-source merge description choice + caps confidence
  // for low-trust-only findings. Absent → built-in DEFAULT_SOURCE_TRUST only (no per-case override).
  sourceTrustStore?: SourceTrustStore;
  // Per-host clock offsets + the alignment toggle (#228). Synthesis measures skew from the pre-merge
  // timeline and stores it here; when alignment is on the corrected times steer correlation windows.
  // Absent → no skew detection, correlation compares recorded times (pre-#228 behavior).
  clockSkewStore?: ClockSkewStore;
  // Analyst IOC merges (#82): duplicate value -> canonical IOC id. When set, every mergeDelta call
  // resolves it first, so a later import/synthesis re-extracting the merged-away duplicate routes
  // onto the canonical IOC instead of recreating it. Absent → no alias resolution (pre-#82 behavior).
  iocAliasStore?: IocAliasStore;
  // Optional investigation time-window — events outside it are excluded.
  scopeStore?: ScopeStore;
  // Per-case anonymization control. When a case has it enabled, the userPrompt is tokenized
  // before the provider call and the response is restored before parsing. Optional: absent →
  // no anonymization (used by older tests).
  anonStore?: AnonControlStore;
  // Per-case analyst-added entities to anonymize (exact-match), merged with the auto-derived ones.
  customEntitiesStore?: CustomEntitiesStore;
  // Per-case OCR-discovered entities + the analyst's suppression list. When set, the OCR pass feeds
  // every entity it tokenizes out of a screenshot back here (so the auto-discovery list grows), and
  // suppressed values are excluded from anonymization. Absent → no screenshot auto-discovery.
  discoveredStore?: DiscoveredEntitiesStore;
  stateStore: StateStore;
  imageLoader: (caseId: string, screenshotFile: string) => Promise<AnalyzeImage>;
  retries?: number;
  backoffMs?: number;
  onState?: (state: InvestigationState) => void;
  // Optional: fired after a REAL synthesis run (not a skip) with the findings diff + the new state,
  // so the server can dispatch notifications (issue #58 — new/escalated findings). Best-effort; the
  // pipeline never awaits it. Absent → no notifications (used by CLI scripts/tests).
  onSynth?: (caseId: string, diff: FindingsDiff, state: InvestigationState) => void;
  // Optional: record when synthesis actually ran + what changed in the findings, so the
  // dashboard can show "last synthesized N ago" and a what-changed diff. Absent → not recorded.
  synthMetaStore?: SynthMetaStore;
  analysisRunStore?: AnalysisRunStore; // append-only reproducibility ledger (#377)
  // Per-case AI cost/token accounting (vision / synthesis / other buckets), read by the
  // Diagnostics "AI cost — this case" card. Absent → cost tracking is skipped (CLI scripts).
  aiCostStore?: AiCostStore;
  correlationProfileStore?: CorrelationProfileStore;
  // When both notebookStore and aiControlStore are set, synthesis checks aiControl.includeNotebook
  // and — when true — appends the analyst's notebook entries to the synthesis prompt.
  notebookStore?: NotebookStore;
  aiControlStore?: AiControlStore;
  // When set (external AI provider only), each screenshot is OCR-redacted before the vision
  // call: words the anonymizer would tokenize are covered with opaque rectangles. The original
  // evidence file is never touched — only the in-memory buffer sent to the model is redacted.
  ocrRunner?: OcrRunner;
  // Optional Presidio layer. Runs AFTER the local anonymizer on already-masked text, so it only
  // ever sees scrubbed data and reports only what the regex layer missed. Absent → skipped
  // entirely. `url` is carried for the error message only.
  presidio?: { client: PresidioClient; url: string; minScore: number };
  // Holds findings awaiting analyst approval across the 409 round trip.
  presidioPendingStore?: PresidioPendingStore;
  // TEST-ONLY override for the import pre-scan's character-count caps (see
  // AnalysisPipeline.presidioPreScan). Production code never sets this — the real caps are the
  // PRESIDIO_SCAN_CHUNK_CHARS / PRESIDIO_SCAN_MAX_CHARS constants. Exists so a test can force the
  // truncation-warning path (masked text exceeding the cap) without generating megabytes of
  // synthetic text.
  presidioScanCapsOverride?: { chunkChars: number; maxChars: number };
  // Shared leveled logger. Absent → a console-only logger at DFIR_LOG_LEVEL (used by CLI scripts
  // and tests). The server passes its file-backed logger so AI/OCR/anon traces land in the case log.
  logger?: Logger;
  // CISA KEV catalog (issue #99): when set, CVEs found in forensic events + IOCs are matched
  // against the catalog and the hits are prepended to the synthesis context so the AI can flag
  // actively-exploited CVEs as probable initial-access vectors. Opt-in (store starts empty).
  kevStore?: KevStore;
  // Second LLM opinion (issue #116): a DIFFERENT model that independently re-synthesizes the case
  // for a QA cross-check. When set, secondOpinion() runs Pass 1 (independent synthesis through this
  // provider) + Pass 2 (reconcile). Absent → the feature is disabled (route returns 501).
  secondOpinionProvider?: AIProvider;
  // Persists the last second-opinion run (deltas + analyst accept/reject). Also read by synthesize()
  // so analyst-accepted deltas are re-applied after the wholesale findings rewrite (durability).
  secondOpinionStore?: SecondOpinionStore;
  // Human-readable model labels for the second-opinion comparison header (e.g. "claude-opus-4-8"
  // vs "gpt-4o"). Fall back to the provider name when absent.
  synthesisModelLabel?: string;
  secondOpinionModelLabel?: string;
  // Per-case mutex serializing load->save critical sections (manual adds, background
  // enrichment, synthesis) so concurrent state writes cannot clobber each other (lost update).
  // Absent -> no locking (CLI scripts/tests).
  stateLock?: StateLock;
  // Per-case hypothesis store (issue #140). When set, synthesis merges the model's auto-generated
  // hypotheses into it (refresh-pristine / freeze-touched). Absent → no auto-generation (CLI/tests).
  hypothesisStore?: HypothesisStore;
  // Per-case playbook store. When set, synthesis reads DONE/SKIPPED task status so it can build on
  // completed work instead of re-recommending it (investigation-guidance #2). Absent → no digest.
  playbookStore?: PlaybookStore;
  // Per-case import-meta store. When set, synthesis + the evidence-gap panel flag a zero-yield AI
  // import (a source read as "clean" that actually dropped everything — investigation-guidance #10).
  importMetaStore?: ImportMetaStore;
  // Per-case incident-type store (#236). When set, synthesis prepends the chosen type's one-line
  // hint so the model prioritizes the techniques that matter for a ransomware / BEC / exfil case.
  // Absent → no hint (CLI/tests).
  incidentTypeStore?: IncidentTypeStore;
}

// Keep analyst-pinned questions across a synthesis. The model is told about them and may
// answer one (same id) — keep that, flagged pinned; if it dropped one, re-add the original.
function mergePinnedQuestions(pinned: InvestigationQuestion[], current: InvestigationQuestion[]): InvestigationQuestion[] {
  if (pinned.length === 0) return current;
  const byId = new Map(current.map((q) => [q.id, q]));
  for (const p of pinned) {
    const cur = byId.get(p.id);
    byId.set(p.id, cur ? { ...cur, pinned: true } : p);
  }
  return [...byId.values()];
}

// Error kinds where the failure is inherent to the call (bad/expired creds, exhausted quota, a hung
// process) rather than a transient blip — retrying just re-runs into the same wall, tripling the wait
// before the analyst sees the same error.
const NON_RETRYABLE_KINDS = new Set<ProviderErrorKind>(["auth", "rate_limit", "timeout"]);

function isRetryableError(err: unknown): boolean {
  // An approval gate is not a transient failure. Retrying it re-runs the Presidio scan and delays
  // the 409 the analyst is waiting on, so surface it on the first throw.
  if (err instanceof PresidioApprovalRequired) return false;
  return !(err instanceof ProviderError && NON_RETRYABLE_KINDS.has(err.kind));
}

async function withRetry<T>(
  fn: () => Promise<T>,
  retries: number,
  backoffMs: number,
  onError?: (err: unknown, attempt: number, willRetry: boolean) => void,
): Promise<T> {
  let attempt = 0;
  for (;;) {
    try {
      return await fn();
    } catch (err) {
      const willRetry = attempt < retries && isRetryableError(err);
      onError?.(err, attempt, willRetry);
      if (!willRetry) throw err;
      await new Promise((r) => setTimeout(r, backoffMs * 2 ** attempt));
      attempt++;
    }
  }
}

export class AnalysisPipeline {
  private readonly log: Logger;
  // Lazily loaded from opts.kevStore so we don't block the constructor on disk I/O.
  private kevCatalogCache: KevCatalog | undefined;

  constructor(private readonly opts: PipelineOptions) {
    this.log = opts.logger ?? createConsoleLogger(normalizeLogLevel(process.env.DFIR_LOG_LEVEL));
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
  private withRetry<T>(caseId: string, label: string, fn: () => Promise<T>, retries: number, backoffMs: number): Promise<T> {
    return withRetry(fn, retries, backoffMs, (err, attempt, willRetry) => {
      const msg = err instanceof Error ? err.message : String(err);
      const kind = err instanceof ProviderError ? ` kind=${err.kind}` : "";
      this.log.warn(
        `AI call [${label}] attempt ${attempt + 1} failed${kind}: ${msg}${willRetry ? " — retrying" : " — giving up"}`,
        { caseId },
      );
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
  private async detectSkew(
    caseId: string,
    preMerge: ForensicEvent[],
    opts: CorrelateOptions,
  ): Promise<((e: ForensicEvent) => number | undefined) | undefined> {
    const store = this.opts.clockSkewStore;
    if (!store) return undefined;
    let record;
    try {
      const report = detectClockSkew(correlationGroups(preMerge, { ...opts, crossHostArtifacts: true }), opts);
      record = await store.recordDetection(caseId, report);
    } catch {
      try { record = await store.load(caseId); } catch { return undefined; }
    }
    if (!record.alignEnabled) return undefined;
    const offsets = effectiveOffsets(record.results, record.overrides);
    if (offsets.size === 0) return undefined;
    return (e: ForensicEvent) => alignedEpoch(e, offsets);
  }

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
    return uniqueProviderModels([this.opts.provider, this.opts.synthesisProvider, this.opts.secondOpinionProvider]);
  }

  analysisTextProviderModel(): { provider: string; model: string } | null {
    const provider = this.opts.synthesisProvider ?? this.opts.provider;
    return provider ? { provider: provider.name, model: provider.model } : null;
  }
  analysisProvider(providerName: string, model: string): AIProvider | undefined {
    return [this.opts.provider, this.opts.synthesisProvider, this.opts.secondOpinionProvider]
      .find((provider) => provider?.name === providerName && provider.model === model);
  }

  private requireProvider(purpose: string): AIProvider {
    if (!this.opts.provider) throw new Error(`AI provider not configured; ${purpose} requires an AI provider`);
    return this.opts.provider;
  }

  // Apply per-case prompt/image anonymization in memory, then restore parsed JSON before schema
  // validation so real values containing JSON metacharacters cannot corrupt parsing.
  private async analyzeRestored(
    caseId: string,
    state: InvestigationState,
    provider: AIProvider,
    req: AnalyzeRequest,
    label = "ai",
    skipPresidioGate = false,
  ): Promise<unknown> {
    const control = this.opts.anonStore ? await this.opts.anonStore.load(caseId) : null;
    const policy = toAnonPolicy(control);
    this.log.debug(
      `AI call [${label}] provider=${provider.name} images=${req.images.length} ` +
        `promptChars=${req.userPrompt.length} anonymize=${policy.enabled ? "on" : "off"}`,
      { caseId },
    );
    if (!policy.enabled) {
      const result = await provider.analyze(req);
      this.logAiUsage(caseId, label, provider, result);
      await this.recordAiCost(caseId, label, provider, result);
      return parseJsonLoose(result.rawText);
    }
    const known = deriveKnownEntities(state);
    const custom = this.opts.customEntitiesStore ? await this.opts.customEntitiesStore.load(caseId) : [];
    // Auto-discovered screenshot entities are tokenized too; suppressed ones are never tokenized.
    const disc = this.opts.discoveredStore ? await this.opts.discoveredStore.load(caseId) : { discovered: [], suppressed: [] };
    known.custom = [...custom, ...disc.discovered];
    known.suppressed = disc.suppressed;
    const anon = createAnonymizer(policy, known);
    this.log.debug(`anonymized prompt before [${label}] AI call`, { caseId });

    // OCR-discovered entities to persist into the case's auto-discovery list after this pass.
    const discoveredFromOcr: CustomEntity[] = [];

    // OCR-redact image buffers when an external-provider runner is configured.
    let images = req.images;
    if (this.opts.ocrRunner && images.length > 0) {
      const runner = this.opts.ocrRunner;
      // DFIR_OCR_DEBUG forces the per-image detail to INFO (always shown); otherwise it is a
      // DEBUG line, surfaced when DFIR_LOG_LEVEL=debug or the dashboard's Logging toggle is on.
      const forceInfo = !!process.env.DFIR_OCR_DEBUG;
      const dumpDir = process.env.DFIR_OCR_DEBUG_DIR;      // write the redacted copy for inspection
      const count = images.length;
      let totalRedactions = 0;
      let redactedImages = 0;
      let publicIpsBoxed = 0;
      images = await Promise.all(
        images.map(async (img, i) => {
          try {
            const buf = Buffer.from(img.base64, "base64");
            const res = await ocrRedactImage(buf, policy, known, runner);
            if (res.discovered.length) discoveredFromOcr.push(...res.discovered);
            if (res.changed) {
              redactedImages++;
              totalRedactions += res.redactions.length;
              publicIpsBoxed += res.redactions.filter(
                (w) => isMaskableIpv4(w.text.trim()) && !isInternalIp(w.text.trim()),
              ).length;
              if (dumpDir) await dumpRedactedImage(dumpDir, caseId, i, img.mimeType, res.buffer);
            }
            const matched = res.redactions.map((w) => w.text).join(", ");
            const line =
              `[OCR] image ${i + 1}/${count}: read ${res.wordCount} word(s), ` +
              `redacted ${res.redactions.length}${matched ? ` [${matched}]` : ""}`;
            if (forceInfo) this.log.info(line, { caseId });
            else this.log.debug(line, { caseId });
            return res.changed ? { ...img, base64: res.buffer.toString("base64") } : img;
          } catch (err) {
            // OCR failure is non-fatal — log and forward the original image.
            this.log.warn(`[OCR redact] ${(err as Error).message}`, { caseId });
            return img;
          }
        }),
      );
      // Always-on confirmation that the OCR pre-pass ran (vs. images going to the model
      // unredacted because anon is off or the provider is local). One line per analyze call.
      this.log.info(
        `[OCR] redaction ran on ${count} screenshot(s) — scrubbed ` +
          `${totalRedactions} word(s) across ${redactedImages} image(s) before sending to the model`,
        { caseId },
      );
      if (publicIpsBoxed > 0) {
        this.log.warn(
          `[OCR] ${publicIpsBoxed} public IP(s) were blacked out of the screenshot(s). Image ` +
            `redaction is one-way, so these will NOT be extracted as IOCs from this capture.`,
          { caseId },
        );
      }
      // Feed what OCR tokenized back into the case's auto-discovery list (dedupe/suppress handled
      // by the store). Best-effort — a write failure must not fail the analysis.
      if (this.opts.discoveredStore && discoveredFromOcr.length > 0) {
        try {
          const added = await this.opts.discoveredStore.addDiscovered(caseId, discoveredFromOcr);
          this.log.debug(`[OCR] auto-discovery now holds ${added.discovered.length} entit(y/ies)`, { caseId });
        } catch (err) {
          this.log.warn(`[OCR] could not persist discovered entities: ${(err as Error).message}`, { caseId });
        }
      }
    }

    // Mask FIRST, then let Presidio look at the result. It never sees a real hostname, IP,
    // username, email, SID or secret — only what our own detectors could not find.
    const maskedPrompt = anon.apply(req.userPrompt);
    // Import call sites (analyzeCsv/analyzeLog) pre-scan the WHOLE payload once, up front, and
    // pass skipPresidioGate=true so the loop that calls this per-chunk doesn't re-gate (and
    // re-approve) the same import one chunk at a time.
    if (!skipPresidioGate) await this.presidioGate(caseId, maskedPrompt, known);

    const result = await provider.analyze({ ...req, userPrompt: maskedPrompt, images });
    this.logAiUsage(caseId, label, provider, result);
    await this.recordAiCost(caseId, label, provider, result);
    return anon.restoreDeep(parseJsonLoose(result.rawText));
  }

  /**
   * Scan already-masked text with Presidio and stop the call if it surfaces a value this case has
   * not seen before. Approved values live in the discovered list, so on the retry they are already
   * in `known.custom` and anon.apply() masks them — no second pass is needed here.
   *
   * Fails CLOSED. An analyst who enabled Presidio believes names are being masked; silently
   * proceeding when the container is down or answers with garbage would leave that belief wrong
   * and unfalsifiable.
   */
  private async presidioGate(caseId: string, maskedText: string, known: KnownEntities): Promise<void> {
    const presidio = this.opts.presidio;
    if (!presidio) return;

    let raw;
    try {
      raw = await presidio.client.analyze(maskedText);
    } catch (err) {
      throw new Error(
        `Presidio is enabled but the scan at ${presidio.url} failed (not reachable, or returned an ` +
          `unusable response): ${(err as Error).message}. Start the container or clear ` +
          `DFIR_PRESIDIO_URL to disable the layer.`,
      );
    }

    const found = mapFindings(raw, presidio.minScore);
    if (found.length === 0) return;

    // known.suppressed is DOCUMENTED as pre-lowercased (anonDiscovered.ts) and both writers
    // enforce it today, but that invariant is easy to violate at a distance and this is the
    // load-bearing case: a suppressed value is deliberately left UNMASKED, so Presidio sees it
    // raw on every single call. A case-fold mismatch here would re-trigger the approval gate
    // forever on a value the analyst already vetoed. Lower-case defensively rather than trust it.
    const alreadyKnown = new Set<string>([
      ...(known.custom ?? []).map((e) => e.value.toLowerCase()),
      ...(known.suppressed ?? []).map((s) => s.toLowerCase()),
    ]);
    const fresh = found.filter((e) => !alreadyKnown.has(e.value.toLowerCase()));
    if (fresh.length === 0) return;

    this.log.warn(
      `[presidio] ${fresh.length} new PII value(s) need approval before this case can call the AI`,
      { caseId },
    );
    await this.opts.presidioPendingStore?.save(caseId, fresh);
    throw new PresidioApprovalRequired(fresh);
  }

  // Presidio's /analyze cannot take an arbitrarily large body, and a big CSV would be many
  // requests. These bound it. They are module constants rather than env vars to keep the
  // settings surface small — the truncation is logged, so hitting the cap is visible.
  //
  // NAMED "_CHARS", NOT "_BYTES": both are compared against JS string .length, which counts
  // UTF-16 code units, not UTF-8 bytes. For non-ASCII PII (Hebrew, Cyrillic, accented names —
  // all plausible in a DFIR case) that undercounts real UTF-8 size by up to ~3-4x, so the
  // effective request-size cap is larger than a "_BYTES" name would imply. Left as a rough
  // request-size bound rather than switched to a real byte measure (e.g. Buffer.byteLength)
  // because the cap only needs to keep /analyze requests reasonably sized, not hit an exact
  // number — and the split/truncate arithmetic below is unit-tested against character counts.
  private static readonly PRESIDIO_SCAN_CHUNK_CHARS = 50_000;
  private static readonly PRESIDIO_SCAN_MAX_CHARS = 5_000_000;

  /**
   * Scan an entire import prompt once, up front, instead of letting the chunk loop hit
   * presidioGate repeatedly. analyzeCsv/analyzeLog call this before their batch loop starts, then
   * pass skipPresidioGate=true into every analyzeRestored() call in that loop — so an import
   * produces exactly ONE approval round trip, no matter how many chunks it is batched into.
   *
   * Callers pass BOTH halves of what a batch prompt carries — the state summary and the payload —
   * not just the payload. Scanning the payload alone was a fail-open: the summary (finding titles
   * and descriptions, open threads, recent forensic events and known IOC values, all RESTORED to
   * real values) is prepended to every batch prompt and every batch skips the gate, so it went to
   * the provider unscanned.
   *
   * KNOWN, DELIBERATE RESIDUAL GAP: `state` mutates as batches merge, so batch N's prompt carries
   * a summary REVISED by batches 1..N-1 — text that did not exist when this ran. One up-front
   * scan cannot cover those revisions, and re-gating per batch is exactly the stall-approve-restart
   * loop this method exists to avoid. The revisions are model output derived from payload text
   * that WAS scanned, and the next non-import AI call (ask/synthesis/explain/screenshot) gates on
   * its own prompt, which includes the then-current summary — so anything genuinely new surfaces
   * there instead. Widening this would mean gating per batch; that is a product decision, not an
   * oversight here.
   *
   * Fails CLOSED, same as presidioGate: an unreachable container throws rather than letting the
   * import proceed unscanned.
   */
  private async presidioPreScan(caseId: string, text: string, known: KnownEntities, anon: Anonymizer): Promise<void> {
    const presidio = this.opts.presidio;
    if (!presidio) return;

    // TEST-ONLY seam (see PipelineOptions.presidioScanCapsOverride) so a test can force the
    // truncation path with a tiny budget instead of generating megabytes of synthetic text.
    // Production never sets this; the caps default to the real, class-wide constants.
    const chunkChars = this.opts.presidioScanCapsOverride?.chunkChars ?? AnalysisPipeline.PRESIDIO_SCAN_CHUNK_CHARS;
    const maxChars = this.opts.presidioScanCapsOverride?.maxChars ?? AnalysisPipeline.PRESIDIO_SCAN_MAX_CHARS;

    // Mask FIRST, same as analyzeRestored — Presidio only ever sees already-scrubbed text.
    const masked = anon.apply(text);
    const scanned = masked.length > maxChars ? masked.slice(0, maxChars) : masked;
    if (masked.length > maxChars) {
      // A silent partial scan is worse than no scan: an analyst who sees "import scanned, no PII
      // found" must be able to trust that claim. Name the unscanned character count so a
      // truncated scan is never mistaken for a complete one.
      this.log.warn(
        `[presidio] import pre-scan truncated — ${masked.length - maxChars} character(s) of this ` +
          `import were NOT scanned for PII (cap is ${maxChars} characters)`,
        { caseId },
      );
    }

    // Split on line boundaries so an entity is never cut in half across two /analyze requests.
    const chunks: string[] = [];
    let start = 0;
    while (start < scanned.length) {
      let end = Math.min(start + chunkChars, scanned.length);
      if (end < scanned.length) {
        const nl = scanned.lastIndexOf("\n", end);
        if (nl > start) end = nl + 1;
      }
      chunks.push(scanned.slice(start, end));
      start = end;
    }

    const all: PresidioFinding[] = [];
    for (const chunk of chunks) {
      try {
        all.push(...(await presidio.client.analyze(chunk)));
      } catch (err) {
        throw new Error(
          `Presidio is enabled but the scan at ${presidio.url} failed (not reachable, or returned ` +
            `an unusable response): ${(err as Error).message}. Start the container or clear ` +
            `DFIR_PRESIDIO_URL to disable the layer.`,
        );
      }
    }

    const found = mapFindings(all, presidio.minScore);
    if (found.length === 0) return;

    // Defensive lower-case on BOTH sides, same reasoning as presidioGate: known.suppressed is
    // documented as pre-lowercased, but trusting that at a distance risks re-triggering approval
    // forever on a value the analyst already vetoed.
    const alreadyKnown = new Set<string>([
      ...(known.custom ?? []).map((e) => e.value.toLowerCase()),
      ...(known.suppressed ?? []).map((s) => s.toLowerCase()),
    ]);
    const fresh = found.filter((e) => !alreadyKnown.has(e.value.toLowerCase()));
    if (fresh.length === 0) return;

    this.log.warn(`[presidio] import pre-scan found ${fresh.length} new PII value(s) needing approval`, { caseId });
    await this.opts.presidioPendingStore?.save(caseId, fresh);
    throw new PresidioApprovalRequired(fresh);
  }

  /**
   * Build the same (known entities, anonymizer) pair analyzeRestored derives per call, so an
   * import's pre-scan sees exactly the masked text the chunk loop would later produce. Returns
   * null when anonymization is off case-wide (mirrors analyzeRestored's own early return for
   * `!policy.enabled`) — with anonymization off there is no masked text for Presidio to see.
   */
  private async buildImportAnonContext(caseId: string, state: InvestigationState): Promise<{ known: KnownEntities; anon: Anonymizer } | null> {
    const control = this.opts.anonStore ? await this.opts.anonStore.load(caseId) : null;
    const policy = toAnonPolicy(control);
    if (!policy.enabled) return null;
    const known = deriveKnownEntities(state);
    const custom = this.opts.customEntitiesStore ? await this.opts.customEntitiesStore.load(caseId) : [];
    const disc = this.opts.discoveredStore ? await this.opts.discoveredStore.load(caseId) : { discovered: [], suppressed: [] };
    known.custom = [...custom, ...disc.discovered];
    known.suppressed = disc.suppressed;
    const anon = createAnonymizer(policy, known);
    return { known, anon };
  }

  // Accumulate this call's tokens/cost into the case's running AI-cost totals (Settings →
  // Diagnostics). Best-effort: a write failure here must never fail the underlying AI call.
  private async recordAiCost(caseId: string, label: string, provider: AIProvider, result: AnalyzeResult): Promise<void> {
    if (!this.opts.aiCostStore) return;
    try {
      await this.opts.aiCostStore.record(caseId, bucketForLabel(label), provider.name, provider.model, result.usage);
    } catch (err) {
      this.log.warn(`[ai-cost] could not record: ${(err as Error).message}`, { caseId });
    }
  }

  // Log token usage at DEBUG after a provider call (surfaced with DFIR_LOG_LEVEL=debug).
  private logAiUsage(caseId: string, label: string, provider: AIProvider, result: AnalyzeResult): void {
    const u = result.usage;
    if (!u) {
      this.log.debug(`AI call [${label}] done provider=${provider.name} (no usage reported)`, { caseId });
      return;
    }
    const cache =
      (u.cacheReadTokens ? ` cacheRead=${u.cacheReadTokens}` : "") +
      (u.cacheCreationTokens ? ` cacheWrite=${u.cacheCreationTokens}` : "");
    // resolvedModel: the concrete model id actually served, when the provider reports one — e.g.
    // claude-code's --model alias ("sonnet") resolves to "claude-sonnet-4-6" server-side; surfacing
    // it here means DFIR_AI_SYNTH_MODEL=sonnet doesn't leave the exact version silently ambiguous.
    const resolved = u.resolvedModel && u.resolvedModel !== provider.model ? ` resolvedModel=${u.resolvedModel}` : "";
    this.log.debug(
      `AI call [${label}] done provider=${provider.name} model=${provider.model}${resolved} in=${u.inputTokens ?? "?"} out=${u.outputTokens ?? "?"}${cache}`,
      { caseId },
    );
  }

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

  async analyzeWindow(caseId: string, captures: CaptureMetadata[]): Promise<InvestigationState> {
    const provider = this.requireProvider("screenshot analysis");
    const analyzable = captures.filter((c) => !c.isDuplicate);
    if (analyzable.length === 0) return this.opts.stateStore.load(caseId);

    return this.withStateLock(caseId, async () => {
      const state = await this.opts.stateStore.load(caseId);
      const images = await Promise.all(
        analyzable.map((c) => this.opts.imageLoader(caseId, c.screenshotFile)),
      );
      // Note: we deliberately do NOT put the capture time on these lines — the model
      // would otherwise copy it into forensicEvents instead of reading the artifact's
      // own timestamp column shown in the image.
      const contextLines = analyzable
        .map((c) => `Screenshot ${c.screenshotFile} — ${c.tabTitle} (${c.url})`)
        .join("\n");
      const userPrompt =
        `${buildStateSummary(state)}\n\nNEW SCREENSHOTS (read each artifact's OWN timestamp column ` +
        `for event times — do not use any capture/current time):\n${contextLines}\n\nReturn the JSON delta.`;

      const retries = this.opts.retries ?? 3;
      const backoffMs = this.opts.backoffMs ?? 500;

      const delta = await this.withRetry(caseId, "extract", async () => {
        const parsed = await this.analyzeRestored(caseId, state, provider, { systemPrompt: getSystemPrompt(), userPrompt, images }, "extract");
        return stripAiExtractedFrom(deltaSchema.parse(parsed));
      }, retries, backoffMs);

      const windowSequence = analyzable[analyzable.length - 1].sequenceNumber;
      // Tag each event's source for correlation/corroboration: detect the real tool from the
      // captured tab titles (e.g. "Velociraptor", "CrowdStrike Falcon"), else generic "screenshot".
      const winSource = detectTool(analyzable.map((c) => c.tabTitle).join(" ")) ?? "screenshot";
      const tagged = { ...delta, forensicEvents: (delta.forensicEvents ?? []).map((e) => ({ ...e, sources: e.sources?.length ? e.sources : [winSource] })) };
      const next = await this.mergeWithAliases(state, tagged, {
        windowSequence,
        timestamp: analyzable[analyzable.length - 1].timestamp,
        sourceScreenshots: analyzable.map((c) => c.screenshotFile),
      });
      await this.opts.stateStore.save(next);
      this.opts.onState?.(next);
      return next;
    });
  }

  // Import an uploaded CSV (e.g. a Velociraptor result export) as evidence: extract
  // dated forensic events + IOCs from the rows, batch by batch, into the timeline —
  // the same delta the screenshot path produces. Findings/TTPs/attacker-path come
  // afterwards from synthesize() (call it after this resolves), exactly like capture.
  async analyzeCsv(
    caseId: string,
    csvText: string,
    opts: {
      label: string;             // evidence label shown as the event source (stored filename)
      idPrefix: string;          // unique per import (e.g. "m3") so event ids never collide
      importedAt: string;        // ISO time used for timeline/firstSeen context
      rowsPerBatch?: number;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void | Promise<void>;
      signal?: AbortSignal;      // #225: analyst cancel — aborts the in-flight AI call + stops between batches
      startBatch?: number;
    },
  ): Promise<InvestigationState> {
    // Text model (same idiom as ask/explain/synthesis): CSV extraction is text reasoning, not OCR.
    const provider = this.opts.synthesisProvider ?? this.requireProvider("CSV analysis");
    const { headers, rows } = parseCsv(csvText);
    if (rows.length === 0) return this.opts.stateStore.load(caseId);

    const retries = this.opts.retries ?? 3;
    const backoffMs = this.opts.backoffMs ?? 500;

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      let evSeq = lastImportEventSequence(state.forensicTimeline, opts.idPrefix);

      // Scan the WHOLE import once, up front, instead of letting the per-chunk batches below hit
      // presidioGate repeatedly (which would stall-approve-restart on a large CSV with names
      // scattered through it). One approval round trip per import, not one per chunk.
      //
      // The scan covers the STATE SUMMARY as well as the payload, because every batch prompt
      // below is `buildStateSummary(state) + csvChunk`, and every batch passes
      // skipPresidioGate=true. Scanning csvText alone left the summary — finding titles and
      // descriptions, open threads, the last 12 forensic events and every known IOC value, all
      // RESTORED to real values — reaching the provider having never been seen by Presidio: a
      // fail-OPEN in a layer whose contract is fail-closed.
      if (this.opts.presidio) {
        const importAnonCtx = await this.buildImportAnonContext(caseId, state);
        if (importAnonCtx) await this.presidioPreScan(caseId, `${buildStateSummary(state)}\n${csvText}`, importAnonCtx.known, importAnonCtx.anon);
      }

      // Batch by BOTH the row cap and a token budget: wide rows (long EDR/SIEM command-lines)
      // could otherwise pack 50 rows into a prompt that overflows the model context. Reserve
      // room for the system prompt + the state-summary that's prepended to every batch.
      const csvOverhead = estimateTokens(getCsvPrompt()) + estimateTokens(buildStateSummary(state))
        + estimateTokens(chunkToCsvText(headers, [])) + 64;
      const rowBudget = Math.max(0, inputTokenBudget() - csvOverhead);
      const batches = batchByBudget(rows, opts.rowsPerBatch ?? 50, (r) => r.join(","), rowBudget);

      for (let b = opts.startBatch ?? 0; b < batches.length; b++) {
        if (opts.signal?.aborted) break;   // #225: cancelled — stop before the next batch, keep prior batches
        const csvChunk = chunkToCsvText(headers, batches[b]);
        const userPrompt =
          `${buildStateSummary(state)}\n\nCSV ARTIFACT ROWS (source: ${opts.label}; batch ${b + 1}/${batches.length}). ` +
          `Read each row's OWN time column for event times — do not use the current time:\n\n${csvChunk}\n\n` +
          `Return the JSON delta.`;

        const delta = await this.withRetry(caseId, "csv", async () => {
          // skipPresidioGate=true: the pre-scan above already covered this whole import.
          const parsed = await this.analyzeRestored(caseId, state, provider, { systemPrompt: getCsvPrompt(), userPrompt, images: [], ...(opts.signal ? { signal: opts.signal } : {}) }, "csv", true);
          return stripAiExtractedFrom(deltaSchema.parse(parsed));
        }, retries, backoffMs);

        // Renumber event ids so chunked imports don't overwrite each other (merge
        // dedupes forensic events by id, and each batch independently emits e1, e2…).
        const renumbered = {
          ...delta,
          forensicEvents: applySeverityFloor(delta.forensicEvents ?? [], opts.minSeverity).map((e) => ({ ...e, id: `${opts.idPrefix}e${++evSeq}`, sources: e.sources?.length ? e.sources : [detectTool(opts.label) ?? "CSV import"] })),
        };

        state = await this.mergeWithAliases(state, renumbered, {
          windowSequence: -(b + 1), // negative: distinguishes import batches from capture windows
          timestamp: opts.importedAt,
          sourceScreenshots: [opts.label], // evidence traceability: the CSV file
        });
        await this.opts.stateStore.save(state);
        this.opts.onState?.(state);
        await opts.onProgress?.(b + 1, batches.length);
      }
      return state;
    });
  }

  // Import an uploaded generic log file (firewall logs, syslog, sshd, IIS, etc.)
  // as evidence. Logs are mostly repetition, so we DEDUPLICATE deterministically
  // first (aggregateLogLines collapses near-identical lines into counted patterns),
  // then ask the model to triage the PATTERNS — emitting one aggregated forensic
  // event only for the security-relevant ones and skipping routine noise. This
  // keeps the timeline signal-rich and cuts the analysis to ~one AI call.
  // Findings/TTPs/attacker-path come afterwards from synthesize().
  async analyzeLog(
    caseId: string,
    logText: string,
    opts: {
      label: string;             // evidence label shown as the event source (stored filename)
      idPrefix: string;          // unique per import (e.g. "l3") so event ids never collide
      importedAt: string;        // ISO time used for timeline/firstSeen context
      patternsPerBatch?: number; // how many distinct patterns to triage per AI call
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void | Promise<void>;
      signal?: AbortSignal;      // #225: analyst cancel — aborts the in-flight AI call + stops between batches
      startBatch?: number;
    },
  ): Promise<InvestigationState> {
    // Text model (same idiom as ask/explain/synthesis): log triage is text reasoning, not OCR.
    const provider = this.opts.synthesisProvider ?? this.requireProvider("log analysis");
    const { lines } = parseLogLines(logText);
    if (lines.length === 0) return this.opts.stateStore.load(caseId);

    // Collapse the raw lines into distinct, counted patterns (most frequent first). Capture the
    // aggregation stats so a cap-hit (more distinct patterns than the AI could be shown) is flagged
    // as a coverage blind spot by the import route (#10 trigger b).
    const aggStats: AggregateStats = { distinctTemplates: 0, keptTemplates: 0 };
    const maxTemplates = Number(process.env.DFIR_LOG_MAX_TEMPLATES) || undefined;   // else the built-in default
    const templates = aggregateLogLines(lines, { maxTemplates }, aggStats);
    if (aggStats.distinctTemplates > aggStats.keptTemplates) this.importTruncation.set(caseId, aggStats);
    else this.importTruncation.delete(caseId);
    const retries = this.opts.retries ?? 3;
    const backoffMs = this.opts.backoffMs ?? 500;

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      let evSeq = lastImportEventSequence(state.forensicTimeline, opts.idPrefix);

      // Scan the WHOLE import once, up front — see analyzeCsv for why this must precede the
      // per-pattern batch loop below rather than living inside it, and why the state summary is
      // scanned alongside the payload (every batch prompt below prepends it and skips the gate).
      if (this.opts.presidio) {
        const importAnonCtx = await this.buildImportAnonContext(caseId, state);
        if (importAnonCtx) await this.presidioPreScan(caseId, `${buildStateSummary(state)}\n${logText}`, importAnonCtx.known, importAnonCtx.anon);
      }

      // Batch by BOTH the pattern cap and a token budget — a few patterns with very long
      // examples shouldn't form a prompt that overflows the model context.
      const renderPattern = (t: typeof templates[number]) =>
        `×${t.count} ${t.firstTimestamp ?? ""} ${t.lastTimestamp ?? ""} ${t.example}`;
      const logOverhead = estimateTokens(getLogPrompt()) + estimateTokens(buildStateSummary(state)) + 96;
      const patternBudget = Math.max(0, inputTokenBudget() - logOverhead);
      const batches = batchByBudget(templates, opts.patternsPerBatch ?? 120, renderPattern, patternBudget);

      for (let b = opts.startBatch ?? 0; b < batches.length; b++) {
        if (opts.signal?.aborted) break;   // #225: cancelled — stop before the next batch, keep prior batches
        // Present each pattern with its occurrence count, time span, and an example.
        const patternText = batches[b]
          .map((t, i) =>
            `[p${i + 1}] ×${t.count}` +
            (t.firstTimestamp ? ` first=${t.firstTimestamp}` : "") +
            (t.lastTimestamp && t.lastTimestamp !== t.firstTimestamp ? ` last=${t.lastTimestamp}` : "") +
            `\n     e.g. ${t.example}`,
          )
          .join("\n");
        const userPrompt =
          `${buildStateSummary(state)}\n\nDEDUPLICATED LOG PATTERNS (source: ${opts.label}; ` +
          `batch ${b + 1}/${batches.length}; ${lines.length} raw line(s) → ${templates.length} pattern(s)). ` +
          `Emit an aggregated event ONLY for security-relevant patterns; skip routine noise:\n\n${patternText}\n\n` +
          `Return the JSON delta.`;

        const delta = await this.withRetry(caseId, "log", async () => {
          // skipPresidioGate=true: the pre-scan above already covered this whole import.
          const parsed = await this.analyzeRestored(caseId, state, provider, { systemPrompt: getLogPrompt(), userPrompt, images: [], ...(opts.signal ? { signal: opts.signal } : {}) }, "log", true);
          return stripAiExtractedFrom(deltaSchema.parse(parsed));
        }, retries, backoffMs);

        const renumbered = {
          ...delta,
          forensicEvents: applySeverityFloor(delta.forensicEvents ?? [], opts.minSeverity).map((e) => ({ ...e, id: `${opts.idPrefix}e${++evSeq}`, sources: e.sources?.length ? e.sources : [detectTool(opts.label) ?? "Log import"] })),
        };

        state = await this.mergeWithAliases(state, renumbered, {
          windowSequence: -(b + 1),
          timestamp: opts.importedAt,
          sourceScreenshots: [opts.label],
        });
        await this.opts.stateStore.save(state);
        this.opts.onState?.(state);
        await opts.onProgress?.(b + 1, batches.length);
      }
      return state;
    });
  }

  // Record an import that parsed cleanly but contributed nothing.
  //
  // Every deterministic importer guards on "no events (and no IOCs) → return the state unchanged".
  // That guard is correct — an empty delta must not be merged — but returning silently meant the
  // file was 202-accepted, stored under `imports/`, and left NO trace in the case: the analyst had
  // no way to tell "ingested and understood" from "silently dropped". On the northpeak benchmark
  // that hid Zeek conn.json contributing zero events out of 75,951 records, the largest artifact in
  // the case. A note costs one small timeline row and makes the outcome legible.
  //
  // `total` is the importer's own parsed-record count, so the note says how much was READ, not just
  // that nothing came out — "0 events from 0 records" (wrong format) and "0 events from 75,951
  // records" (understood but uninteresting) are very different problems.
  private async noteEmptyImport(
    caseId: string,
    opts: { label: string; importedAt: string; onProgress?: (done: number, total: number) => void },
    kind: string,
    total: number,
  ): Promise<InvestigationState> {
    const delta = deltaSchema.parse({
      findings: [], iocs: [], mitreTechniques: [], forensicEvents: [],
      threadsOpened: [], threadsClosed: [],
      timelineNote: `${kind} import: no events from ${total} record(s) — nothing added to the case`,
      summary: "",
    });
    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a THOR (Nextron) scanner report in JSON-Lines format. Unlike the CSV/log
  // paths this is DETERMINISTIC — THOR's JSON is structured and stable, so each
  // finding maps straight to a forensic event + IOCs with NO AI extraction call.
  // Scan-lifecycle/info noise (module init, "Info" level) is dropped by default.
  // Findings/attacker-path still come from a later synthesize().
  async importThor(
    caseId: string,
    jsonText: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import (e.g. "t3") so ids never collide
      importedAt: string;
      thor?: ThorImportOptions;  // filtering overrides (dropInfo, dropLifecycleModules…)
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseThorReport(jsonText, opts.thor);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "THOR", parsed.total);

    // Assign stable, collision-free ids and validate the delta against the schema
    // (fills defaults like relatedFindingIds). No model call — purely structural.
    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({ ...e, id: `${opts.idPrefix}e${i + 1}` })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `THOR import: ${parsed.kept} finding(s) kept, ${parsed.dropped} info/lifecycle row(s) dropped` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a SIEM / EDR JSON export (Elastic/Kibana, Splunk, an EDR console, a raw
  // winlogbeat dump…). Like THOR, the mapping is DETERMINISTIC (no AI call): the
  // container is unwrapped, Windows/Sysmon events get a per-EID mapping, other records
  // fall back to field auto-detection, and repetitive events are aggregated. The
  // detected tool name (from the filename / source) tags each event's `sources`.
  async importSiem(
    caseId: string,
    jsonText: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import (e.g. "s3") so ids never collide
      importedAt: string;
      siem?: SiemImportOptions;  // filtering overrides (aggregate, minSeverity, maxEvents…)
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseSiemExport(jsonText, opts.siem);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "SIEM", parsed.total);

    const source = detectTool(opts.label) ?? detectTool(parsed.format) ?? "SIEM import";
    const eventIdByAggKey = new Map<string, string>();
    const forensicEvents = parsed.events.map((e, i) => {
      const { aggKey, ...rest } = e;
      const id = `${opts.idPrefix}e${i + 1}`;
      if (aggKey) eventIdByAggKey.set(aggKey, id);
      return { ...rest, id, sources: rest.sources?.length ? rest.sources : [source] };
    });
    const raw = {
      findings: [],
      iocs: resolveExtractedFrom(parsed.iocs, eventIdByAggKey).map((c, i) => ({
        id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value,
        ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
      })),
      mitreTechniques: [],
      forensicEvents,
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `SIEM import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import Windows Event XML through the shared deterministic SIEM/EVTX mapping.
  async importEvtxXml(
    caseId: string,
    xmlText: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import (e.g. "s3") so ids never collide
      importedAt: string;
      siem?: SiemImportOptions;  // filtering overrides (aggregate, minSeverity, maxEvents…)
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void | Promise<void>; onParseProgress?: (done: number, total: number, detail?: string) => void | Promise<void>; signal?: AbortSignal; startBatch?: number;
    },
  ): Promise<InvestigationState> {
    if ((opts.startBatch ?? 0) >= 1) { await opts.onProgress?.(1, 1); return this.opts.stateStore.load(caseId); }
    let parseTotal = 0;
    const parsedRaw = await parseEvtxXmlProgress(xmlText, opts.siem, (done, total) => { parseTotal = total; return opts.onParseProgress?.(done, total * 2, "reading Windows events"); }, (done, total) => opts.onParseProgress?.(parseTotal + done, parseTotal + total, "processing Windows events"), opts.signal);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Windows Event Log (XML)", parsed.total);

    const source = detectTool(opts.label) ?? "Windows Event Log";
    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [source],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Windows Event Log (XML) import: ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      if (opts.signal?.aborted) throw Object.assign(new Error("import processing cancelled; stored evidence retained"), { name: "AbortError" });
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      await opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a Linux/Unix shell history file (.bash_history / .zsh_history / …). Deterministic
  // host-triage: one forensic event per command at the artifact's own time (bash HISTTIMEFORMAT
  // `#<epoch>` / zsh extended history), Info by default with a conservative tradecraft bump. The
  // account is derived from the filename and shown in each event.
  async importBashHistory(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import (e.g. "b3") so ids never collide
      importedAt: string;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const user = userFromHistoryFilename(opts.label);
    const parsedRaw = parseShellHistoryFile(text, { user });
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Shell history", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Shell history"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Shell history import${user ? ` (${user})` : ""}: ${parsed.kept} command(s) from ${parsed.total} line(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Run a USER-authored declarative importer (the external plugin path). Mirrors the built-in
  // deterministic wrappers exactly: parse -> severity floor -> standard delta (findings/MITRE empty,
  // MITRE rides inside each event) -> mergeDelta -> save -> notify. Does NOT depend on any shared-runner
  // refactor of the built-ins.
  async importDeclarative(
    caseId: string,
    text: string,
    opts: {
      importer: ExternalImporter;
      label: string;
      idPrefix: string;
      importedAt: string;
      minSeverity?: Severity;
      onProgress?: (done: number, total: number) => void;
      // Per-importer health (#84): fired with the raw parse stats (total/kept/dropped/format) right
      // after parsing, BEFORE the zero-events early return, so a run that legitimately produced
      // nothing still counts as a completed (not failed) run in the diagnostics table.
      onParsed?: (result: SiemParseResult) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = opts.importer.parse(text, { minSeverity: opts.minSeverity });
    opts.onParsed?.(parsedRaw);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, opts.importer.label, parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [opts.importer.label],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `${opts.importer.label} import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, { windowSequence: -1, timestamp: opts.importedAt, sourceScreenshots: [opts.label] });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // "Promote" copies already-imported super-timeline events UP into the forensic timeline so AI
  // synthesis runs over them. The raw super-timeline is a complete record (incl. host-triage artifacts
  // routed there exclusively) that is never synthesized; this is how the analyst pulls the events that
  // matter into the analyzed timeline. Reuses mergeDelta (dedups forensic events by id) — a stored super
  // event keeps its id, so a double-promote is a no-op. No AI here; the caller re-synthesizes.
  async promoteSuperTimeline(
    caseId: string,
    events: ForensicEvent[],
    opts: { importedAt: string; tagById?: Record<string, string[]>; note?: string },
  ): Promise<InvestigationState> {
    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      if (!events.length) return state;
      const delta = deltaSchema.parse({
        findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        timelineNote: opts.note ?? `Promoted ${events.length} event(s) from the super-timeline`, summary: "",
        forensicEvents: events.map((e) => ({ ...e })),
      });
      state = await this.mergeWithAliases(state, delta, { windowSequence: -1, timestamp: opts.importedAt, sourceScreenshots: [] });
      // Stamp provenance markers on the promoted rows (second-look #11) — mergeDelta carries no
      // provenance through the delta schema, so apply them here by id (union with any existing). Lets the
      // forensic timeline show WHY a raw row was pulled up ("[second-look: h2]").
      if (opts.tagById) {
        const tagged = new Set(Object.keys(opts.tagById));
        state = {
          ...state,
          forensicTimeline: state.forensicTimeline.map((e) =>
            tagged.has(e.id)
              ? { ...e, provenance: [...new Set([...(e.provenance ?? []), ...opts.tagById![e.id]])] }
              : e,
          ),
        };
      }
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      return state;
    });
  }

  // Import Chainsaw (WithSecure) hunt output or a raw EVTX-as-JSON dump. Like THOR/SIEM
  // the mapping is DETERMINISTIC (no AI call): the embedded EVTX events get the same
  // per-EID Windows mapping as the SIEM import, and — for Chainsaw — the matched Sigma
  // rule's level drives severity while its `attack.tXXXX` tags become MITRE techniques.
  // Each event is tagged Chainsaw / EVTX as its source for cross-source correlation.
  async importChainsaw(
    caseId: string,
    jsonText: string,
    opts: {
      label: string;
      idPrefix: string;               // unique per import (e.g. "c3") so ids never collide
      importedAt: string;
      chainsaw?: ChainsawImportOptions; // filtering overrides (aggregate, minSeverity, maxEvents…)
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseChainsawReport(jsonText, opts.chainsaw);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Chainsaw", parsed.total);

    const fallback = parsed.detections > 0 ? "Chainsaw" : "EVTX";
    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [fallback],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `${parsed.detections > 0 ? "Chainsaw" : "EVTX"} import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.detections > 0 ? `, ${parsed.detections} rule detection(s)` : "") +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a Hayabusa (Yamato Security) detection timeline — JSON/JSONL or CSV. Like the
  // other deterministic paths there is no AI call: the matched Sigma rule's level drives
  // severity, its title leads the description, its tactics/tags become MITRE, and IOCs /
  // asset / process-chain come from the rendered detail fields. Tagged Hayabusa as source.
  async importHayabusa(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;                  // unique per import (e.g. "h3") so ids never collide
      importedAt: string;
      hayabusa?: HayabusaImportOptions;  // filtering overrides (aggregate, minSeverity, maxEvents…)
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseHayabusaTimeline(text, opts.hayabusa);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Hayabusa", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Hayabusa"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Hayabusa import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import Velociraptor native JSON output (collection results / hunt export). Like the
  // other deterministic paths there is no AI call: each row is classified (Sigma / YARA /
  // EventLog / generic) and mapped — detection rows are verdict-driven, the rest auto-detect
  // the artifact's own time + IOCs. Every event is tagged Velociraptor as its source.
  async importVelociraptor(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;                       // unique per import (e.g. "v3") so ids never collide
      importedAt: string;
      velociraptor?: VelociraptorImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      veloUrl?: string;          // the originating hunt/flow's GUI URL (only known for a live hunt/flow import) — stamped onto every event so the forensic timeline's "↗ Velociraptor" link resolves, mirroring the super-only path
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    // Rows often carry no _Source; use the (Velociraptor-named) filename as the fallback artifact
    // label so generic/detection events show their source — e.g. "DetectRaptor.Windows.Detection.NamedPipes".
    const rawArtifact = opts.label.replace(/^\d+_/, "").replace(/\.(json|jsonl|ndjson|csv)$/i, "");
    let artifact = rawArtifact;
    try { artifact = decodeURIComponent(rawArtifact); } catch { /* malformed %xx — keep the raw label */ }
    // Chunked async parse: reports (rowsDone, rowsTotal) as it goes (→ the import job's progress bar
    // and the "importing X/Y" status) and yields to the event loop between chunks, so a huge MFT/USN
    // import streams live progress instead of freezing the server on one synchronous pass.
    const parsedRaw = await parseVelociraptorJsonProgress(text, { artifact, ...opts.velociraptor }, opts.onProgress);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Velociraptor", parsed.total);

    const eventIdByAggKey = new Map<string, string>();
    const forensicEvents = parsed.events.map((e, i) => {
      const { aggKey, ...rest } = e;
      const id = `${opts.idPrefix}e${i + 1}`;
      if (aggKey) eventIdByAggKey.set(aggKey, id);
      return {
        ...rest, id, sources: rest.sources?.length ? rest.sources : ["Velociraptor"],
        ...(opts.veloUrl ? { veloUrl: opts.veloUrl } : {}),
      };
    });

    const raw = {
      findings: [],
      iocs: resolveExtractedFrom(parsed.iocs, eventIdByAggKey).map((c, i) => ({
        id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value,
        ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
      })),
      mitreTechniques: [],
      forensicEvents,
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Velociraptor import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s)` +
        (parsed.detections > 0 ? `, ${parsed.detections} detection(s)` : "") +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import ECAR — EDR Common Activity Record telemetry (NDJSON of (object, action) endpoint events).
  // Deterministic (no AI call): maps each record's object/action/properties into a forensic event,
  // reads `timestamp_ms`, scrapes PUBLIC IPs as IOCs, and keeps severity conservative (Info evidence,
  // bumped only on real tradecraft) so high-volume raw telemetry doesn't flood the timeline. See
  // ecarImport.ts for the mapping (and the lsass-access false-positive rationale).
  async importEcar(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import so ids never collide
      importedAt: string;
      ecar?: EcarImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseEcarJson(text, { ...opts.ecar });
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "ECAR", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [ECAR_SOURCE],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `ECAR import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import an Apache/Nginx/Squid combined access log (web server or forward-proxy). Deterministic
  // (no AI): raw web/proxy telemetry, Info by default with a conservative bump only for an
  // access-denied response; git smart-HTTP clone/push tagged T1213. See combinedLogImport.ts.
  async importCombinedLog(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;
      importedAt: string;
      combinedLog?: CombinedLogImportOptions;
      minSeverity?: Severity;
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseCombinedLog(text, { ...opts.combinedLog });
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Web/proxy access-log", parsed.total);

    const eventIdByAggKey = new Map<string, string>();
    const forensicEvents = parsed.events.map((e, i) => {
      const { aggKey, ...rest } = e;
      const id = `${opts.idPrefix}e${i + 1}`;
      if (aggKey) eventIdByAggKey.set(aggKey, id);
      return { ...rest, id, sources: rest.sources?.length ? rest.sources : [COMBINED_LOG_SOURCE] };
    });
    const raw = {
      findings: [],
      iocs: resolveExtractedFrom(parsed.iocs, eventIdByAggKey).map((c, i) => ({
        id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value,
        ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
      })),
      mitreTechniques: [],
      forensicEvents,
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Web/proxy access-log import (${parsed.format}): ${parsed.kept} request(s) from ${parsed.total} line(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a Cisco ASA firewall syslog export. Deterministic (no AI): Built/Teardown telemetry
  // stays Info, an explicit Deny bumps to Low, dynamic-NAT-translation noise is dropped,
  // year-less timestamps are re-anchored by the mergeDelta year-clamp. See ciscoAsaImport.ts.
  async importCiscoAsa(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;
      importedAt: string;
      ciscoAsa?: CiscoAsaImportOptions;
      minSeverity?: Severity;
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    // Year-less BSD-style timestamps default to the CURRENT calendar year unless the case already has
    // an established dominant year to anchor onto — see pickImportYear (a big year-less import can
    // outweigh clampOutlierYears' post-hoc ≥90% minority-outlier guard).
    const priorState = await this.opts.stateStore.load(caseId).catch(() => null);
    const assumeYear = opts.ciscoAsa?.assumeYear ?? pickImportYear(priorState?.forensicTimeline ?? []);
    const parsedRaw = parseCiscoAsaLog(text, { ...opts.ciscoAsa, ...(assumeYear !== undefined ? { assumeYear } : {}) });
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Cisco ASA", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [CISCO_ASA_SOURCE],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Cisco ASA import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} line(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a Snort / Suricata "fast" alert log — a real IDS verdict feed. Deterministic (no AI):
  // severity is the rule's Priority verdict, public src/dst IPs become IOCs, year-less timestamps are
  // re-anchored by the mergeDelta year-clamp. See snortImport.ts.
  async importSnort(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;
      importedAt: string;
      snort?: SnortImportOptions;
      minSeverity?: Severity;
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    // Year-less BSD-style timestamps default to the CURRENT calendar year unless the case already has
    // an established dominant year to anchor onto — see pickImportYear (a big year-less import can
    // outweigh clampOutlierYears' post-hoc ≥90% minority-outlier guard).
    const priorState = await this.opts.stateStore.load(caseId).catch(() => null);
    const assumeYear = opts.snort?.assumeYear ?? pickImportYear(priorState?.forensicTimeline ?? []);
    const parsedRaw = parseSnortLog(text, { ...opts.snort, ...(assumeYear !== undefined ? { assumeYear } : {}) });
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Snort", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [SNORT_SOURCE],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Snort import (${parsed.format}): ${parsed.kept} alert(s) from ${parsed.total} line(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import YARA CLI scan output (`yara -s -m <rules> <target>`). Deterministic (no AI): each rule
  // match becomes a file-match event (default Medium, bumped only on an explicit rule-meta signal),
  // matched file + hash meta become IOCs. YARA output is undated, so mergeDelta stamps events at import
  // time. Used by the external-tools run path (#211). See yaraImport.ts.
  async importYara(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;
      importedAt: string;
      yara?: YaraImportOptions;
      minSeverity?: Severity;
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseYaraOutput(text, { ...opts.yara });
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, "YARA", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [YARA_SOURCE],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `YARA import: ${parsed.kept} match event(s) from ${parsed.total} match(es)` +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a plain Linux/Unix syslog export (RFC 5424 / RFC 3164). Deterministic (no AI): host
  // telemetry stays Info, an auth-failure or crit/alert/emerg PRI bumps to Low, the host is carried
  // as the event's asset, RFC-3164 year-less timestamps are re-anchored by the mergeDelta year-clamp.
  // See syslogImport.ts.
  async importSyslog(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;
      importedAt: string;
      syslog?: SyslogImportOptions;
      minSeverity?: Severity;
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    // Year-less BSD-style timestamps default to the CURRENT calendar year unless the case already has
    // an established dominant year to anchor onto — see pickImportYear (a big year-less import can
    // outweigh clampOutlierYears' post-hoc ≥90% minority-outlier guard).
    const priorState = await this.opts.stateStore.load(caseId).catch(() => null);
    const assumeYear = opts.syslog?.assumeYear ?? pickImportYear(priorState?.forensicTimeline ?? []);
    const parsedRaw = parseSyslog(text, { ...opts.syslog, ...(assumeYear !== undefined ? { assumeYear } : {}) });
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Syslog", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [SYSLOG_SOURCE],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Syslog import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} line(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import network-monitor logs — Suricata `eve.json` and Zeek JSON (Security Onion's
  // network side). Deterministic (no AI call): the timeline is built from the detections
  // (Suricata alerts + Zeek notices); surrounding telemetry (dns/http/tls/files/conn)
  // contributes IOCs only. Events are tagged Suricata / Zeek.
  async importNetwork(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;                // unique per import (e.g. "n3") so ids never collide
      importedAt: string;
      network?: NetworkImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    // Pass the import filename so per-stream Zeek JSON (conn.json / dns.json / … with no `_path`)
    // routes to the right stream (#197).
    const parsedRaw = parseNetworkLogs(text, { ...opts.network, filename: opts.network?.filename ?? opts.label });
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, "Network", parsed.total);

    const eventIdByAggKey = new Map<string, string>();
    const forensicEvents = parsed.events.map((e, i) => {
      const { aggKey, ...rest } = e;
      const id = `${opts.idPrefix}e${i + 1}`;
      if (aggKey) eventIdByAggKey.set(aggKey, id);
      return { ...rest, id, sources: rest.sources?.length ? rest.sources : ["Suricata"] };
    });
    const raw = {
      findings: [],
      iocs: resolveExtractedFrom(parsed.iocs, eventIdByAggKey).map((c, i) => ({
        id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value,
        ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
      })),
      mitreTechniques: [],
      forensicEvents,
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Network import (${parsed.format}): ${parsed.kept} detection event(s) from ${parsed.total} record(s)` +
        (parsed.alerts > 0 ? `, ${parsed.alerts} alert/notice(s)` : "") +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import SO-CRATES (dougburks/so-crates) verdicts — Suricata IDS alerts, YARA file matches, and
  // Sigma log detections — as the browser extension pushes them (or a raw export). Deterministic
  // (no AI). Events are tagged "SO-CRATES" (+ the underlying engine) for cross-source correlation.
  async importSocrates(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;                // unique per import (e.g. "s4") so ids never collide
      importedAt: string;
      socrates?: SocratesImportOptions;
      minSeverity?: Severity;          // gate-aware import floor (unified Import button)
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseSocrates(text, opts.socrates);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, "SO-CRATES", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["SO-CRATES"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `SO-CRATES import (${parsed.format}): ${parsed.kept} detection event(s) from ${parsed.total} record(s)` +
        ` — ${parsed.alerts} Suricata alert(s), ${parsed.yara} YARA, ${parsed.sigma} Sigma, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import Security Onion Console (SOC) events — the Alerts / Hunt views the browser extension
  // pushes. Deterministic (no AI call), verdict-first per the post-detection principle: the
  // event's own `event.severity_label` drives severity, `rule.name` leads the description, ECS
  // threat fields become MITRE, and source/destination IPs + app-layer fields become IOCs.
  // Events are tagged "Security Onion".
  async importSecurityOnion(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;                // unique per import (e.g. "so3") so ids never collide
      importedAt: string;
      securityOnion?: SecurityOnionImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseSecurityOnion(text, opts.securityOnion);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, "Security Onion", parsed.total);

    const eventIdByAggKey = new Map<string, string>();
    const forensicEvents = parsed.events.map((e, i) => {
      const { aggKey, ...rest } = e;
      const id = `${opts.idPrefix}e${i + 1}`;
      if (aggKey) eventIdByAggKey.set(aggKey, id);
      return { ...rest, id, sources: rest.sources?.length ? rest.sources : ["Security Onion"] };
    });
    const raw = {
      findings: [],
      iocs: resolveExtractedFrom(parsed.iocs, eventIdByAggKey).map((c, i) => ({
        id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value,
        ...(c.extractedFrom ? { extractedFrom: c.extractedFrom } : {}),
      })),
      mitreTechniques: [],
      forensicEvents,
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Security Onion import: ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a KAPE / Eric Zimmerman Tools CSV (Prefetch, Amcache, ShimCache, LNK, JumpLists,
  // UsnJrnl, MFT, SRUM, Recycle Bin, Shellbags). Deterministic (no AI call): the EZ tool is
  // detected from the CSV header, then each row maps to a forensic event reading the
  // artifact's own time + file/hash/process IOCs. Events are tagged by artifact name.
  async importKape(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;             // unique per import (e.g. "k3") so ids never collide
      importedAt: string;
      kape?: KapeImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseKapeCsv(text, opts.kape);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, `KAPE/${parsed.artifact}`, parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [parsed.artifact],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `KAPE/${parsed.artifact} import: ${parsed.kept} event(s) from ${parsed.total} row(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a Cyber Triage timeline export (JSONL / JSON array / CSV). Deterministic (no AI call):
  // scored rows map verdict-first (severity from the Bad/Suspicious verdict + reason keywords),
  // unscored process/task rows become Info evidence, the bulk File super-timeline is dropped
  // (unless `fileTelemetry`), and Active-Connection remote IPs become IOCs. Events tagged
  // "Cyber Triage".
  async importCybertriage(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;                  // unique per import (e.g. "ct3") so ids never collide
      importedAt: string;
      cybertriage?: CybertriageImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseCybertriage(text, opts.cybertriage);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, "Cyber Triage", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Cyber Triage"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Cyber Triage import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s)` +
        (parsed.notable > 0 ? `, ${parsed.notable} scored item(s)` : "") +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import Microsoft 365 Unified Audit Log + Entra ID (sign-in / directory audit) data.
  // Deterministic (no AI call): each record is classified (UAL / sign-in / audit) and mapped,
  // severity derived from the operation (BEC tradecraft) or Entra's own risk verdict; the
  // source IP becomes an IOC and the UPN is surfaced for the asset graph.
  async importM365(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "m3") so ids never collide
      importedAt: string;
      m365?: M365ImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseM365Audit(text, opts.m365);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Microsoft 365", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Microsoft 365"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Microsoft 365 import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import AWS CloudTrail logs. Deterministic (no AI call): each API-call record is mapped,
  // severity derived from the action (IAM persistence, logging/detection tampering, S3
  // exposure, secrets access) + denied/root/console-failure bumps; the caller IP → IOC.
  async importAws(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import (e.g. "a3") so ids never collide
      importedAt: string;
      aws?: AwsImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseCloudTrail(text, opts.aws);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "AWS CloudTrail", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["AWS CloudTrail"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `AWS CloudTrail import: ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import GCP Cloud Audit Logs + Azure Activity Log. Deterministic (no AI call): each record
  // is routed (GCP / Azure) and mapped, severity derived from the action (+ denied bump); the
  // caller IP → IOC and the principal email is surfaced for the asset graph.
  async importCloudActivity(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import (e.g. "g3") so ids never collide
      importedAt: string;
      cloud?: CloudActivityImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseCloudActivity(text, opts.cloud);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Cloud activity", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Cloud Audit"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Cloud activity import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import Kubernetes API-server audit logs (audit.k8s.io). Deterministic (no AI call): each audit
  // Event → a forensic event whose severity is derived from the (verb, resource, subresource) tuple
  // (pod exec/attach, secret access, RBAC change, privileged-pod create, anonymous access), Info by
  // default. Source IP → IOC. Tagged Kubernetes Audit.
  async importK8sAudit(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import (e.g. "k3") so ids never collide
      importedAt: string;
      k8s?: K8sAuditImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseK8sAudit(text, opts.k8s);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Kubernetes audit", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Kubernetes Audit"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Kubernetes audit import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import osquery scheduled-query result logs (differential `columns` rows + `snapshot` sets).
  // Deterministic (no AI call): Info-by-default endpoint telemetry, with a conservative tradecraft
  // bump on a command-line column; columns → IOCs (path/hash/ip/process). Tagged osquery.
  async importOsquery(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import (e.g. "o3") so ids never collide
      importedAt: string;
      osquery?: OsqueryImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseOsqueryLog(text, opts.osquery);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "osquery", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["osquery"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `osquery import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a Plaso / log2timeline super-timeline (psort CSV — dynamic or l2tcsv). Deterministic
  // (no AI call): each row is an Info evidence event read at its own time, with IOCs scraped
  // from the message (hashes/URLs/IPs) and the source file path. Tagged Plaso.
  async importPlaso(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "p3") so ids never collide
      importedAt: string;
      plaso?: PlasoImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parsePlasoCsv(text, opts.plaso);
    return this.persistPlasoParsed(caseId, parsedRaw, opts);
  }

  // Streaming-from-disk Plaso import: for super-timelines too large to hold as one JS string (a
  // 555 MB export EXCEEDS V8's ~512 MB max string length, so readFile(utf8) throws "Invalid string
  // length"). Reads the file line-by-line via node:readline and feeds parsePlasoFromLines, which
  // keeps memory bounded by the distinct-key set, not the row count. Same downstream merge as
  // importPlaso. The route persists the evidence file separately (by copy, not as a string).
  async importPlasoFile(
    caseId: string,
    filePath: string,
    opts: {
      label: string;
      idPrefix: string;
      importedAt: string;
      plaso?: PlasoImportOptions;
      minSeverity?: Severity;
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const rl = createInterface({
      input: createReadStream(filePath, { encoding: "utf8", highWaterMark: 1 << 20 }),
      crlfDelay: Infinity,
    });
    let parsedRaw: PlasoParseResult;
    try {
      parsedRaw = await parsePlasoFromLines(rl, opts.plaso);
    } finally {
      rl.close();
    }
    return this.persistPlasoParsed(caseId, parsedRaw, opts);
  }

  // Shared tail of both Plaso entry points: apply the severity floor, build the delta and merge it
  // into the case state. (Keeping this in one place means the in-memory and streaming importers
  // produce identical timeline rows / IOCs / notes.)
  private async persistPlasoParsed(
    caseId: string,
    parsedRaw: PlasoParseResult,
    opts: { label: string; idPrefix: string; importedAt: string; minSeverity?: Severity; onProgress?: (done: number, total: number) => void },
  ): Promise<InvestigationState> {
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Plaso", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Plaso"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Plaso import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a Linux auditd log (raw audit.log / `ausearch` record format, or an `aureport` table).
  // Deterministic (no AI call): records sharing a serial collapse into one logical event, mapped
  // to severity/MITRE by record type (logins, account/group mgmt, sudo, SELinux denials, audit-config
  // tampering), bumped on a failed auth or a suspicious command. Read at the audit() epoch. Tagged auditd.
  async importAuditd(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "ad3") so ids never collide
      importedAt: string;
      auditd?: AuditdImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseAuditdLog(text, opts.auditd);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, "auditd", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["auditd"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `auditd import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a systemd-journald structured log (`journalctl -o json` / `-o json-pretty`). Deterministic
  // (no AI call): each entry is read at its own time (_SOURCE/__REALTIME µs epoch), severity derived
  // from PRIORITY then bumped from the message (sshd auth, sudo, useradd, kernel), with IOCs scraped
  // from _EXE/_COMM and the MESSAGE. Tagged journald.
  async importJournald(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "jd3") so ids never collide
      importedAt: string;
      journald?: JournaldImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseJournald(text, opts.journald);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, "journald", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["journald"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `journald import: ${parsed.kept} event(s) from ${parsed.total} entr(y/ies)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a sysdig / Falco export (Falco alert JSON and/or sysdig `-j` event JSON). Deterministic
  // (no AI call): Falco rule hits are the DETECTIONS (verdict-first: priority → severity, tags →
  // MITRE) and surface on the timeline; raw sysdig syscall events are telemetry → Info evidence;
  // both contribute proc/file/network IOCs. Tagged Falco / sysdig.
  async importSysdig(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "sd3") so ids never collide
      importedAt: string;
      sysdig?: SysdigImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseSysdig(text, opts.sysdig);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, "sysdig/Falco", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["sysdig"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `sysdig/Falco import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.alerts > 0 ? `, ${parsed.alerts} Falco alert(s)` : "") +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import Wazuh SIEM/EDR alert exports (alerts.json / NDJSON / API export). Deterministic
  // (no AI call): rule.level drives severity (≥13 Critical, ≥10 High, ≥7 Medium, else Info),
  // rule.mitre.technique → MITRE, agent.name → asset, data.srcip/dstip/md5/sha256/url → IOCs.
  async importWazuh(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "w3") so ids never collide
      importedAt: string;
      wazuh?: WazuhImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseWazuhAlerts(text, opts.wazuh);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Wazuh", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Wazuh"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Wazuh import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a malware-sandbox detonation report (CAPEv2 or CrowdStrike Falcon Sandbox).
  // Deterministic (no AI call): the sample verdict + each behavioural signature map to events
  // (severity from the report's own score/verdict, MITRE from its ATT&CK), and every
  // dropped/extracted file hash + network host/domain/URL is harvested as an IOC.
  async importSandbox(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "sb3") so ids never collide
      importedAt: string;
      sandbox?: SandboxImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseSandboxReport(text, opts.sandbox);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.noteEmptyImport(caseId, opts, "Sandbox", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Sandbox"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Sandbox import (${parsed.format}): ${parsed.kept} event(s)` +
        (parsed.signatures > 0 ? `, ${parsed.signatures} signature(s)` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import memory-forensics tool output (Volatility 3 or Rekall). Deterministic (no AI call): each
  // plugin table is identified by its columns and mapped — pslist/psscan/pstree → process-tree
  // events (with parent→child links), netscan/netstat → network-connection events (+ foreign IP/
  // port IOCs), malfind → High injected-code events (ATT&CK T1055), cmdline → command-line events
  // (bumped on LOLBin/encoded tradecraft), svcscan/modules → service/driver evidence. Tagged
  // "Volatility" / "Rekall" for cross-source correlation; reads the artifact's own time.
  async importMemory(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "mem3") so ids never collide
      importedAt: string;
      memory?: MemoryImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseMemory(text, { ...opts.memory, filename: opts.label });
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, "Memory", parsed.total);

    const tool = parsed.tool || "Volatility";
    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [tool],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Memory import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s) across ${parsed.tables} plugin(s)` +
        (parsed.injected > 0 ? `, ${parsed.injected} injected-code hit(s)` : "") +
        (parsed.connections > 0 ? `, ${parsed.connections} connection(s)` : "") +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import an email artifact (.eml RFC 2822, or best-effort .msg). Deterministic (no AI call):
  // ONE forensic event dated at the message's own Date: header, severity DERIVED from the email's
  // SPF/DKIM/DMARC verdict + sender heuristics; URLs, sender/reply-to domains, originating IP and
  // attachment names/hashes become IOCs. Covers ATT&CK T1566 (Phishing). Tagged "Email".
  async importEmail(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "em3") so ids never collide
      importedAt: string;
      email?: EmailImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseEmail(text, opts.email);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, "Email", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Email"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Email import (${parsed.format}): ${parsed.kept} event(s)` +
        (parsed.subject ? ` — "${parsed.subject.slice(0, 80)}"` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import a TheHive 5 case, alert, or observable export. Deterministic (no AI call):
  // case/alert records → forensic events (severity from TheHive's own 1–4 scale, MITRE from
  // ATT&CK-tagged tags, TLP/PAP labels prepended); observable records → IOCs by dataType.
  async importTheHive(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "th3") so ids never collide
      importedAt: string;
      thehive?: TheHiveImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseTheHive(text, opts.thehive);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, "TheHive", parsed.total);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["TheHive"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `TheHive import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.observables > 0 ? `, ${parsed.observables} observable(s)` : "") +
        `, ${parsed.iocCount} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Import an existing DFIR-IRIS case (issue #88) — the reverse of the IRIS push. Takes the raw
  // case rows already fetched from the IRIS API (analysis/irisImport.ts parses them deterministically,
  // NO AI call): timeline → forensic events, IOCs → IOCs, assets → evidence events. All feed the
  // same forensic timeline via mergeDelta, exactly like the other importers.
  async importIris(
    caseId: string,
    data: IrisCaseData,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "iris3") so ids never collide
      importedAt: string;
      iris?: IrisImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseIrisCase(data, opts.iris);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.noteEmptyImport(caseId, opts, "DFIR-IRIS", parsed.timelineCount);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["DFIR-IRIS"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `DFIR-IRIS import (${parsed.caseName ?? `case #${parsed.irisCaseId ?? "?"}`}): ` +
        `${parsed.kept} event(s) from ${parsed.timelineCount} timeline + ${parsed.assetCount} asset(s)` +
        `, ${parsed.iocCount} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    return this.withStateLock(caseId, async () => {
      let state = await this.opts.stateStore.load(caseId);
      state = await this.mergeWithAliases(state, delta, {
        windowSequence: -1,
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(1, 1);
      return state;
    });
  }

  // Holistic pass: read the whole forensic timeline and produce findings, MITRE
  // mapping, and the attacker-path narrative. Text-only (no images), one call.
  // Answer a free-form analyst question about the case from its evidence (single-shot, no
  // state change). Returns a grounded answer + status + collection guidance (`pointer`).
  async ask(caseId: string, question: string): Promise<AskAnswer> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("case questions");
    const loaded = await this.opts.stateStore.load(caseId);
    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);

    const max = maxPromptEvents();
    let events = selectSynthesisEvents(scopedEvents, max);
    const renderEvent = (e: ForensicEvent) =>
      `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${e.description.slice(0, 240)}`;
    const findingsText = loaded.findings.slice(0, 150).map((f) => `[${f.id}] [${f.severity}] ${f.title}`).join("\n") || "(none)";
    const questionsText = loaded.keyQuestions.map((q) => `- ${q.question}${q.answer ? ` → ${q.answer}` : " (open)"}`).join("\n") || "(none)";
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(loaded, scopedEvents, kevCatalog);
    // GraphRAG (#98): serialize the deterministic evidence-chain graph (causal edges) so the model
    // can trace multi-hop attack paths via the graph's relationships, not just the flat timeline.
    const graphMaxEdges = Number(process.env.DFIR_ASK_GRAPH_MAX_EDGES) || DEFAULT_MAX_GRAPH_EDGES;
    const graphBlock = buildGraphContext({ ...loaded, forensicTimeline: scopedEvents }, { maxEdges: graphMaxEdges });

    // Trim the timeline so the whole prompt fits the model context (the rest is fixed overhead).
    const askOverhead = estimateTokens(getAskPrompt())
      + estimateTokens(contextBlock + graphBlock + (loaded.attackerPath || "") + findingsText + questionsText + question) + 300;
    const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - askOverhead));
    if (fit < events.length) events = selectSynthesisEvents(scopedEvents, fit);
    const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

    const userPrompt =
      contextBlock +
      graphBlock +
      `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
      `FINDINGS:\n${findingsText}\n\n` +
      `FORENSIC TIMELINE (${scopedEvents.length} in-scope events):\n${timelineText}\n\n` +
      `CURRENT QUESTIONS:\n${questionsText}\n\n` +
      `ANALYST QUESTION: ${question.trim()}\n\nAnswer it as JSON.`;

    return this.withRetry(caseId, "ask", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getAskPrompt(), userPrompt, images: [] }, "ask");
      return askSchema.parse(parsed);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // Explain a single forensic event in context (issue #141). Single text-only AI call; EPHEMERAL —
  // no state change. Returns structured analysis: what happened, why it matters, ATT&CK mapping,
  // normal vs suspicious context, pivot queries, and evidence for/against maliciousness.
  async explainEvent(caseId: string, eventId: string): Promise<ExplainEventResult> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("event explanation");
    const loaded = await this.opts.stateStore.load(caseId);

    // Resolve the focal event + the universe of events to build context from. Normally the forensic
    // timeline, but a raw super-timeline event (imported into the super-timeline and never promoted) is
    // NOT in InvestigationState — fall back to the super-timeline store so it can still be explained.
    let event = loaded.forensicTimeline.find((e) => e.id === eventId);
    let universe = loaded.forensicTimeline;
    if (!event && this.opts.superTimelineStore) {
      const superEvents = (await this.opts.superTimelineStore.query(caseId, {})).events;
      event = superEvents.find((e) => e.id === eventId);
      if (event) universe = superEvents;
    }
    if (!event) throw new Error(`event not found: ${eventId}`);

    // Context: events adjacent in time + events on the same asset (up to 15 total).
    const sorted = [...universe].sort((a, b) =>
      (a.timestamp || "").localeCompare(b.timestamp || ""),
    );
    const focalIdx = sorted.findIndex((e) => e.id === eventId);
    const nearby = [
      ...sorted.slice(Math.max(0, focalIdx - 7), focalIdx),
      ...sorted.slice(focalIdx + 1, focalIdx + 8),
    ];
    const sameAsset = event.asset
      ? universe.filter((e) => e.id !== eventId && e.asset === event.asset).slice(0, 10)
      : [];
    const contextIds = new Set([...nearby.map((e) => e.id), ...sameAsset.map((e) => e.id)]);
    const contextEvents = [...contextIds]
      .map((id) => universe.find((e) => e.id === id)!)
      .filter(Boolean)
      .slice(0, 15);

    const renderEv = (e: ForensicEvent, focal = false): string =>
      `[${e.id}]${focal ? " *** FOCAL EVENT ***" : ""} ${e.timestamp || "(undated)"} [${e.severity}]`
      + ` ${e.description.slice(0, 300)}`
      + (e.asset ? ` | asset: ${e.asset}` : "")
      + (e.processName ? ` | process: ${e.processName}` : "")
      + (e.parentName ? ` | parent: ${e.parentName}` : "")
      + (e.sha256 ? ` | sha256: ${e.sha256.slice(0, 16)}…` : "")
      + (e.path ? ` | path: ${e.path}` : "")
      + (e.mitreTechniques.length ? ` | MITRE: ${e.mitreTechniques.join(", ")}` : "");

    const findingsText = loaded.findings.slice(0, 50)
      .map((f) => `[${f.severity}] ${f.title}`).join("\n") || "(none)";
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(loaded, [event, ...contextEvents], kevCatalog);

    const userPrompt =
      contextBlock
      + `CASE FINDINGS (summary):\n${findingsText}\n\n`
      + `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n`
      + `FOCAL EVENT TO EXPLAIN:\n${renderEv(event, true)}\n\n`
      + `CONTEXT EVENTS (nearby / same asset):\n`
      + (contextEvents.map((e) => renderEv(e)).join("\n") || "(no context events)")
      + `\n\nExplain the focal event as JSON.`;

    return this.withRetry(caseId, "explain-event", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getExplainEventPrompt(), userPrompt, images: [] }, "explain-event");
      return explainEventSchema.parse(parsed);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // The hunting feedback loop's prior-hunt outcomes for a case (#157) — [] when no store is wired
  // (scripts/*) or the file is absent/corrupt, so the loop simply stays off without ever throwing.
  private async loadHuntOutcomes(caseId: string): Promise<HuntOutcome[]> {
    if (!this.opts.huntOutcomeStore) return [];
    try {
      return await this.opts.huntOutcomeStore.load(caseId);
    } catch {
      return [];
    }
  }

  // Known-unknowns preamble (#165): the gaps in the story (silent windows, uncovered ATT&CK phases,
  // the matched actors' likely-next techniques) so synthesis + hunts treat what's MISSING as open
  // questions, not just what the evidence shows. Pure block; the offline adversary dataset is cached.
  // Wrapped defensively — a known-unknowns failure must never break synthesis or hunt suggestions.
  // The STRUCTURED known-unknowns for a case (investigation-guidance #9) — the SINGLE source the
  // synthesis prompt block AND the GET /cases/:id/known-unknowns panel both consume, so the model and
  // the analyst provably see the same gap list. Defensive: a failure here must never break synthesis.
  private knownUnknownItems(state: InvestigationState, scopedEvents: ForensicEvent[], yieldWarning?: ImportYieldWarning | null): KnownUnknownItem[] {
    try {
      const hints = buildAdversaryHintsResult(state, loadAdversaryGroupsDataset(), adversaryHintEnvOptions());
      // #230: the top playbook match, so an unobserved step of a chain the case otherwise follows
      // becomes a named gap. Scored over the SCOPED events, exactly as the panel and report see them.
      const playbook = buildPlaybookMatchResult(scopedEvents, loadKnownPlaybooks(), playbookMatchEnvOptions());
      return buildKnownUnknownItems(state, scopedEvents, {
        gapOptions: gapEnvOptions(),
        nextTechniques: hints.nextTechniques,
        playbookMatch: playbook.matches[0] ?? null,
        yieldWarning,
      });
    } catch {
      return [];
    }
  }

  // The classified source-yield warning for the LAST import (investigation-guidance #10) — a large file
  // that yielded ZERO events via AI triage (the northpeak blind spot). Defensive: null when no store,
  // no import-meta, or nothing anomalous.
  private async loadYieldWarning(caseId: string): Promise<ImportYieldWarning | null> {
    if (!this.opts.importMetaStore) return null;
    try {
      return classifyImportYield(await this.opts.importMetaStore.load(caseId));
    } catch {
      return null;
    }
  }

  private async knownUnknownsBlock(state: InvestigationState, scopedEvents: ForensicEvent[], caseId: string): Promise<string> {
    const max = Math.max(0, Number(process.env.DFIR_SYNTH_KNOWN_UNKNOWNS_MAX) || 10);
    return renderKnownUnknowns(this.knownUnknownItems(state, scopedEvents, await this.loadYieldWarning(caseId)), max);
  }

  // Read-only: the structured evidence-gap items for a case (scope + false-positive filtered, exactly
  // as synthesis sees them). Powers the "Evidence gaps" dashboard panel and the report section.
  async knownUnknownsForCase(caseId: string): Promise<KnownUnknownItem[]> {
    const loaded = await this.opts.stateStore.load(caseId);
    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);
    return this.knownUnknownItems(loaded, scopedEvents, await this.loadYieldWarning(caseId));
  }

  // Candidate-threat-actor preamble (#165), OFF by default (DFIR_SYNTH_ADVERSARY_HINTS). Feeds the
  // technique-overlap hints (already shown in the report) into synthesis as LOW-CONFIDENCE candidates.
  // Gated because feeding model-derived attribution back into the model is a confirmation-bias loop;
  // labelled "NOT attribution". Pure + cached dataset; defensive — never breaks synthesis.
  private adversaryHintBlock(state: InvestigationState): string {
    if (!/^(1|true|on|yes)$/i.test(process.env.DFIR_SYNTH_ADVERSARY_HINTS ?? "")) return "";
    try {
      const r = buildAdversaryHintsResult(state, loadAdversaryGroupsDataset(), adversaryHintEnvOptions());
      if (!r.hints.length) return "";
      const top = r.hints.slice(0, 5).map((h) => `${h.name} (${h.overlapCount}/${h.groupTechniqueCount} techniques)`).join(", ");
      return `CANDIDATE THREAT ACTORS (technique-overlap hypothesis, NOT attribution — ${r.caveat}): ${top}\n\n`;
    } catch {
      return "";
    }
  }

  // Drop any suggestion whose VQL was already deployed in this case (#157) — the deterministic guarantee
  // that a hunt the analyst already ran is never re-proposed (the "PRIOR HUNTS" prompt block is the soft
  // signal; this is the hard one). Bundles contribute no fingerprint, so they never exclude a suggestion.
  private excludeDeployedHunts<T extends { vql: string }>(suggestions: T[], outcomes: readonly HuntOutcome[]): T[] {
    const fps = deployedFingerprints(outcomes);
    if (!fps.size) return suggestions;
    return suggestions.filter((s) => !fps.has(vqlFingerprint(s.vql)));
  }

  // Propose proactive Velociraptor VQL fleet-hunts from the synthesized findings (issue #57).
  // Single text-only AI call; EPHEMERAL like ask()/executiveSummary() — it does NOT mutate state.
  // The analyst reviews each hunt's VQL + rationale, then one-click deploys it through the existing
  // launchHunt flow (POST /velociraptor/hunt). Returns [] without an AI call on an empty case.
  async suggestHunts(caseId: string, opts?: { excludeVql?: string }): Promise<HuntSuggestion[]> {
    const provider = this.opts.velociraptorProvider ?? this.opts.synthesisProvider ?? this.requireProvider("hunt suggestions");
    const loaded = await this.opts.stateStore.load(caseId);
    if (!hasHuntMaterial(loaded)) return [];   // nothing to pivot on — don't spend a call

    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);

    const max = maxPromptEvents();
    let events = selectSynthesisEvents(scopedEvents, max);
    const renderEvent = (e: ForensicEvent) =>
      `[${e.timestamp || "(undated)"}] [${e.severity}] ${e.description.slice(0, 240)}`;
    const findingsText = renderHuntFindings(loaded.findings);
    const iocText = renderHuntIocs(loaded.iocs);
    const techText = loaded.mitreTechniques.map((t) => `${t.id} ${t.name}`).join(", ") || "(none)";
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(loaded, scopedEvents, kevCatalog);
    // Causal grounding (#124): serialize the deterministic evidence-chain graph — process spawn
    // chains, file lineage, lateral-movement edges — so the model hunts the RELATIONSHIP (the
    // parent→child chain, the binary/account that moved between hosts) fleet-wide, not just the leaf
    // indicator. The flat timeline drops processName/parentName; the graph carries them. Built from
    // the SAME scoped+legitimate-filtered events as the rest of the prompt; "" when there are no edges.
    // Capped at the shared default (the timeline trim below absorbs the block into the prompt budget).
    const graphBlock = buildGraphContext({ ...loaded, forensicTimeline: scopedEvents }, { maxEdges: DEFAULT_MAX_GRAPH_EDGES });

    // Feedback loop (#157): the prior hunts already run in this case (what hit / what missed), so the
    // model proposes follow-ups that pivot on productive hunts and avoids repeating dead ones. "" when
    // there are no recorded outcomes (or no store wired). Also drives the deterministic exclusion below.
    const outcomes = await this.loadHuntOutcomes(caseId);
    const priorHuntsBlock = renderPriorHuntsBlock(outcomes);
    // Productivity tuning (#72): the aggregate hit-rate by pivot class (hash/process/path/network/
    // registry) across this case's hunt history, so the model biases toward classes that have found
    // evidence rather than only avoiding exact repeats (priorHuntsBlock is the per-hunt signal; this
    // is the aggregate one). "" until there's collected history to bias on.
    const productivityBlock = renderHuntProductivityBlock(outcomes);
    // Known unknowns (#165): the gaps in the story (silent windows, uncovered ATT&CK phases, likely-
    // next techniques) so suggested hunts target what's MISSING, not just re-confirm what's known.
    const knownUnknownsBlock = await this.knownUnknownsBlock(loaded, scopedEvents, caseId);

    // Trim the timeline so the whole prompt fits the model context (the rest is fixed overhead).
    const overhead = estimateTokens(getHuntSuggestPrompt())
      + estimateTokens(priorHuntsBlock + productivityBlock + contextBlock + knownUnknownsBlock + graphBlock + findingsText + iocText + techText + (loaded.attackerPath || "")) + 300;
    const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - overhead));
    if (fit < events.length) events = selectSynthesisEvents(scopedEvents, fit);
    const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

    // Regenerate hook (mirrors suggestPlaybookHunts): when the analyst asks for a DIFFERENT take on a
    // hunt whose VQL was bad/unwanted, the excluded query is shown so the model varies the approach.
    const excludeNote = opts?.excludeVql
      ? `ALREADY SUGGESTED (this VQL was already shown to the analyst — generate something DIFFERENT that investigates from a different angle or uses different VQL plugins):\n${opts.excludeVql}\n\n`
      : "";
    const userPrompt =
      priorHuntsBlock +
      productivityBlock +
      contextBlock +
      knownUnknownsBlock +
      graphBlock +
      `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
      `ATT&CK TECHNIQUES: ${techText}\n\n` +
      `FINDINGS:\n${findingsText}\n\n` +
      `PIVOTABLE INDICATORS:\n${iocText}\n\n` +
      `FORENSIC TIMELINE (${scopedEvents.length} in-scope events):\n${timelineText}\n\n` +
      excludeNote +
      `Propose the fleet-hunts as JSON.`;

    const limit = Number(process.env.DFIR_HUNT_SUGGEST_MAX) || HUNT_SUGGEST_MAX_DEFAULT;
    return this.withRetry(caseId, "suggest-hunts", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getHuntSuggestPrompt(), userPrompt, images: [] }, "suggest-hunts");
      const { suggestions } = huntSuggestionsResponseSchema.parse(parsed);
      return this.excludeDeployedHunts(sanitizeHuntSuggestions(suggestions, limit), outcomes);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // Targeted hunt for ONE ATT&CK technique the adversary-emulation panel flagged as a likely next
  // move (issue #121). Unlike suggestHunts (findings-driven), this is technique-DRIVEN: the technique
  // has NOT been observed yet — the analyst wants VQL to detect it proactively if a lookalike actor
  // brings it here. Reuses the fleet-hunt system prompt + schema + sanitizer + deploy flow, with a
  // technique-focused user prompt grounded in the case's pivotable IOCs. EPHEMERAL like suggestHunts()
  // — no state change. Works on ANY case (the technique is by definition not in the timeline).
  async suggestTechniqueHunts(caseId: string, techniqueId: string, techniqueName?: string): Promise<HuntSuggestion[]> {
    const provider = this.opts.velociraptorProvider ?? this.opts.synthesisProvider ?? this.requireProvider("technique hunt");
    const id = String(techniqueId || "").trim().toUpperCase();
    if (!/^T\d{4}(?:\.\d{3})?$/.test(id)) return []; // not a technique id — nothing to hunt
    const loaded = await this.opts.stateStore.load(caseId);
    const iocText = renderHuntIocs(loaded.iocs);
    const label = techniqueName ? `${id} (${techniqueName})` : id;
    const outcomes = await this.loadHuntOutcomes(caseId);   // #157 feedback loop (exclude + prior-hunts context)
    const priorHuntsBlock = renderPriorHuntsBlock(outcomes);
    const productivityBlock = renderHuntProductivityBlock(outcomes);   // #72: aggregate hit-rate by pivot class
    const userPrompt =
      priorHuntsBlock +
      productivityBlock +
      `Focus EXCLUSIVELY on ONE ATT&CK technique the analyst wants to hunt for proactively across the fleet:\n` +
      `  ${label}\n\n` +
      `This technique has NOT yet been observed in this case. A group whose tradecraft resembles this case is known ` +
      `to use it, so the goal is to DETECT it on any enrolled endpoint if it is being used here but missed.\n\n` +
      `Propose 1–3 CLIENT-side Velociraptor VQL hunts that surface this technique's tradecraft generally (not tied to ` +
      `one host). Where relevant, pivot on these case indicators, but do not depend on them:\n` +
      `PIVOTABLE INDICATORS:\n${iocText}\n\n` +
      `Set every suggestion's mitreTechniques to ["${id}"]. Propose the hunt(s) as JSON.`;
    const limit = Number(process.env.DFIR_HUNT_SUGGEST_MAX) || HUNT_SUGGEST_MAX_DEFAULT;
    return this.withRetry(caseId, "hunt-technique", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getHuntSuggestPrompt(), userPrompt, images: [] }, "hunt-technique");
      const { suggestions } = huntSuggestionsResponseSchema.parse(parsed);
      return this.excludeDeployedHunts(sanitizeHuntSuggestions(suggestions, limit), outcomes);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // Memory-forensics "Next-Step" agent (issue #101). The case already has Volatility 3 / Rekall output
  // imported as forensic events; read that memory evidence (the process tree, connections, malfind,
  // command lines, services), identify the anomalies, and propose the EXACT next Volatility 3 command
  // the analyst should run to dig deeper. Single text-only AI call; EPHEMERAL like ask()/suggestHunts()
  // — it does NOT mutate state. Returns [] without an AI call when the case has no memory evidence.
  async suggestMemoryNextSteps(caseId: string): Promise<MemoryNextStep[]> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("memory next-step suggestions");
    const loaded = await this.opts.stateStore.load(caseId);
    if (!hasMemoryMaterial(loaded)) return [];   // no Volatility/Rekall evidence — don't spend a call

    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);
    const memEvents = scopedEvents.filter(isMemoryEvent);
    if (!memEvents.length) return [];            // all memory evidence is out-of-scope / legitimate

    const pluginsText = memoryPluginsPresent(memEvents).join(", ") || "(unknown)";

    // Trim the memory evidence so the whole prompt fits the model context (the rest is fixed overhead).
    const renderEvent = (e: ForensicEvent) =>
      `[${e.severity}] ${(e.description ?? "").replace(/\s+/g, " ").trim().slice(0, 300)}`;
    const overhead = estimateTokens(getMemoryNextStepPrompt()) + estimateTokens(pluginsText) + 300;
    const fit = fitItemsToBudget(memEvents, renderEvent, Math.max(0, inputTokenBudget() - overhead));
    const evidenceText = renderMemoryEvidence(memEvents, Math.max(1, fit));

    const userPrompt =
      `ALREADY-IMPORTED MEMORY PLUGINS (prefer suggesting plugins NOT in this list where they advance the case): ${pluginsText}\n\n` +
      `MEMORY EVIDENCE (${memEvents.length} Volatility/Rekall events, worst-severity first):\n${evidenceText}\n\n` +
      `Propose the next Volatility 3 commands as JSON.`;

    const limit = Number(process.env.DFIR_MEMORY_NEXTSTEP_MAX) || MEMORY_NEXTSTEP_MAX_DEFAULT;
    return this.withRetry(caseId, "memory-next-steps", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getMemoryNextStepPrompt(), userPrompt, images: [] }, "memory-next-steps");
      const { suggestions } = memoryNextStepResponseSchema.parse(parsed);
      return sanitizeMemoryNextSteps(suggestions, limit);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // Translate a free-text analyst request into a runnable hunting query per platform (issue #100).
  // Unlike suggestHunts (findings-driven proposals), this is analyst-DRIVEN: the request is plain
  // English ("PowerShell downloading a file and executing it") and the model maps that intent onto
  // each requested platform's real schema. EPHEMERAL like ask()/suggestHunts() — no state change.
  // Works on an empty case (the analyst may translate before any evidence is imported); the case's
  // known data sources + pivotable IOCs are passed only as light grounding. Uses the strong
  // synthesisProvider like ask()/executiveSummary() — this spans MANY query languages (KQL/SPL/ES|QL/
  // Sigma/…) in one call, so the broad general model follows the multi-platform instruction far better
  // than the narrow VQL-tuned velociraptorProvider (which biases toward VQL and ignores the rest).
  async translateQuery(caseId: string, request: string, platforms?: readonly HuntPlatform[]): Promise<QueryTranslationResult> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("query translation");
    const loaded = await this.opts.stateStore.load(caseId);

    // The caller's requested subset, intersected with the canonical platform set; empty → all.
    const requested = (platforms ?? []).filter((p): p is HuntPlatform => (HUNT_PLATFORMS as readonly string[]).includes(p));
    const targets: HuntPlatform[] = requested.length ? [...new Set(requested)] : [...HUNT_PLATFORMS];

    const sourcesText = renderCaseDataSources(loaded);
    const iocText = renderHuntIocs(loaded.iocs);
    const guide = renderPlatformGuide(targets);

    const userPrompt =
      `KNOWN CASE DATA SOURCES (the tools/log sources this investigation already has data from):\n${sourcesText}\n\n` +
      `PIVOTABLE INDICATORS observed in this case (use these exact values when the request refers to "this" host/IP/hash/etc.):\n${iocText}\n\n` +
      `TARGET PLATFORMS (emit one query per key, grounded in the schema shown):\n${guide}\n\n` +
      `ANALYST REQUEST: ${request.trim()}\n\nTranslate it as JSON.`;

    return this.withRetry(caseId, "translate-query", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getQueryTranslatePrompt(), userPrompt, images: [] }, "translate-query");
      const { interpretation, queries } = queryTranslationResponseSchema.parse(parsed);
      return { interpretation: sanitizeInterpretation(interpretation), queries: sanitizeQueryTranslations(queries, targets) };
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // Convert a plain-English description into ONE content-tagger rule (PR #112 follow-up), or a
  // decline reason when it can't be expressed as a single-event field-match rule. EPHEMERAL — this
  // returns a candidate for review; nothing is persisted here (the route's add step saves it). Uses
  // the strong synthesisProvider like translateQuery — authoring a schema-constrained rule benefits
  // from the general model over the VQL-tuned velociraptorProvider.
  async suggestTaggerRule(caseId: string, description: string): Promise<SuggestOutcome> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("tagger rule suggestion");
    const loaded = await this.opts.stateStore.load(caseId);
    const userPrompt =
      `MATCHABLE FIELDS (use ONLY these): ${MATCHABLE_FIELDS.join(", ")}\n\n` +
      `ANALYST REQUEST: ${description.trim()}\n\n` +
      `Return the rule as JSON (or a decline).`;
    return this.withRetry(caseId, "suggest-tagger-rule", async () => {
      const parsed = await this.analyzeRestored(
        caseId, loaded, provider,
        { systemPrompt: getTaggerRulePrompt(), userPrompt, images: [] },
        "suggest-tagger-rule",
      );
      return sanitizeSuggestedRule(suggestedRuleResponseSchema.parse(parsed));
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // Hypothesise what an attacker did during the timeline's SILENT periods (issue #96). Builds on the
  // deterministic gap detector: detect the suspicious gaps, then make ONE text-only AI call that reads
  // each gap's bounding events (before/after the silence) and infers the attacker activity that fits.
  // Each gap is also paired with the DETERMINISTIC shadow-artifact collections (USN journal, SRUM,
  // Prefetch, Amcache, …) that reconstruct the missing window — so even a gap the model skips still
  // carries deployable Velociraptor collections. EPHEMERAL like ask()/suggestHunts(): no state change.
  // Returns an empty result (no AI spend) when the timeline has no flagged gaps.
  async hypothesizeGaps(caseId: string): Promise<GapHypothesesResult> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("gap hypothesis");
    const loaded = await this.opts.stateStore.load(caseId);
    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);

    // Use the SAME gap detection (and thresholds) the panel/report use, so the analyst hypothesises
    // about exactly the gaps they see flagged.
    const gaps = detectTimelineGaps(scopedEvents, gapEnvOptions());
    if (!hasGapMaterial(gaps)) return { hypotheses: [], caveat: GAP_HYPOTHESIS_CAVEAT };

    const cap = Number(process.env.DFIR_GAP_HYPOTHESIS_MAX) || GAP_HYPOTHESIS_MAX_DEFAULT;
    const focusGaps = gaps.slice(0, Math.max(1, Math.floor(cap)));   // worst-first → keep the most suspicious
    const around = Number(process.env.DFIR_GAP_HYPOTHESIS_CONTEXT) || SURROUNDING_EVENTS_DEFAULT;
    const surroundByGapId = new Map(focusGaps.map((g) => [g.id, surroundingEvents(g, scopedEvents, around)]));
    const validGapIds = new Set(focusGaps.map((g) => g.id));

    const gapsText = renderGapsForPrompt(focusGaps, surroundByGapId);
    // The shadow-artifact catalog the model ranks against (id → what it reconstructs). The catalog
    // supplies the actual collection VQL deterministically; the model only picks the relevant ids.
    const artifactsText = SHADOW_ARTIFACTS.map((a) => `- ${a.id}: ${a.name} — ${a.reconstructs}`).join("\n");
    const userPrompt =
      `SHADOW ARTIFACTS (reference recommendedArtifactIds ONLY from these ids):\n${artifactsText}\n\n` +
      `TIMELINE GAPS (${focusGaps.length} of ${gaps.length} flagged; worst-first) with their surrounding events:\n\n` +
      `${gapsText}\n\n` +
      `Hypothesise the attacker activity for each gap as JSON.`;

    const aiHypotheses = await this.withRetry(caseId, "hypothesize-gaps", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getGapHypothesisPrompt(), userPrompt, images: [] }, "hypothesize-gaps");
      const { hypotheses } = gapHypothesesResponseSchema.parse(parsed);
      return sanitizeGapHypotheses(hypotheses, validGapIds, focusGaps.length);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);

    return buildGapHypotheses(aiHypotheses, focusGaps, surroundByGapId);
  }

  // Propose a Velociraptor hunt for each ENDPOINT-related PLAYBOOK task (issue #70). Single text-only
  // AI call; EPHEMERAL like suggestHunts() — it does NOT mutate state. The deploy MODE is decided here
  // deterministically from the case's observed endpoints: a task tied to exactly one host → a single
  // client COLLECTION on it; otherwise → a fleet HUNT. The playbook `tasks` are passed in by the route
  // (the pipeline has no PlaybookStore). Returns [] without an AI call when there's no endpoint task.
  async suggestPlaybookHunts(caseId: string, tasks: PlaybookTask[], availableArtifacts: string[] = [], opts?: { excludeVql?: string }): Promise<PlaybookHuntSuggestion[]> {
    const provider = this.opts.velociraptorProvider ?? this.opts.synthesisProvider ?? this.requireProvider("playbook hunt suggestions");
    const loaded = await this.opts.stateStore.load(caseId);
    if (!hasPlaybookHuntMaterial(loaded, tasks)) return [];   // empty/closed playbook → don't spend a call

    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);

    const endpointsByTaskId = buildTaskEndpointsMap(loaded, tasks);
    const endpoints = knownEndpoints(loaded);
    const tasksText = renderPlaybookHuntTasks(tasks, endpointsByTaskId);
    const endpointsText = renderKnownEndpoints(endpoints);
    // The server's REAL CLIENT artifacts (passed in by the route) — the model may reference an
    // Artifact.<Name> only from this list (otherwise it hallucinates a name that won't compile).
    const artifactsText = renderAvailableArtifacts(availableArtifacts, Number(process.env.DFIR_PBHUNT_MAX_ARTIFACTS) || 150);

    // This call hunts PER TASK (grounded by the tasks + findings + IOCs + endpoints), so it does NOT
    // need the full synthesis timeline — a smaller stratified event sample keeps the signal while
    // cutting the prompt (the timeline dominates it). A leaner prompt is faster + cheaper and shrinks
    // the window for a transient provider transport failure on a long generation. Tune via
    // DFIR_PBHUNT_MAX_EVENTS (default 120, well below synthesis's 300).
    const max = Number(process.env.DFIR_PBHUNT_MAX_EVENTS) || 120;
    let events = selectSynthesisEvents(scopedEvents, max);
    const renderEvent = (e: ForensicEvent) =>
      `[${e.timestamp || "(undated)"}] [${e.severity}]${e.asset ? ` <${e.asset}>` : ""} ${e.description.slice(0, 240)}`;
    const findingsText = renderHuntFindings(loaded.findings);
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(loaded, scopedEvents, kevCatalog);
    const outcomes = await this.loadHuntOutcomes(caseId);   // #157 feedback loop (exclude + prior-hunts context)
    const priorHuntsBlock = renderPriorHuntsBlock(outcomes);
    const productivityBlock = renderHuntProductivityBlock(outcomes);   // #72: aggregate hit-rate by pivot class

    // Trim the timeline so the whole prompt fits the model context (the rest is fixed overhead).
    const overhead = estimateTokens(getPlaybookHuntPrompt())
      + estimateTokens(priorHuntsBlock + productivityBlock + contextBlock + tasksText + endpointsText + artifactsText + findingsText + (loaded.attackerPath || "")) + 300;
    const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - overhead));
    if (fit < events.length) events = selectSynthesisEvents(scopedEvents, fit);
    const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

    const excludeNote = opts?.excludeVql
      ? `ALREADY SUGGESTED (this VQL was already shown to the analyst — generate something DIFFERENT that investigates from a different angle or uses different VQL plugins):\n${opts.excludeVql}\n\n`
      : "";
    const userPrompt =
      priorHuntsBlock +
      productivityBlock +
      contextBlock +
      `KNOWN ENDPOINTS (hosts — pick a targetHost ONLY from these): ${endpointsText}\n\n` +
      `AVAILABLE VELOCIRAPTOR ARTIFACTS (reference Artifact.<Name> ONLY if <Name> is in this list — else use a raw plugin):\n${artifactsText}\n\n` +
      `PLAYBOOK TASKS:\n${tasksText}\n\n` +
      `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
      `FINDINGS:\n${findingsText}\n\n` +
      `FORENSIC TIMELINE (${scopedEvents.length} in-scope events):\n${timelineText}\n\n` +
      excludeNote +
      `Propose the per-task hunts as JSON.`;

    const limit = Number(process.env.DFIR_PBHUNT_SUGGEST_MAX) || PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT;
    return this.withRetry(caseId, "suggest-playbook-hunts", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getPlaybookHuntPrompt(), userPrompt, images: [] }, "suggest-playbook-hunts");
      const { suggestions } = playbookHuntResponseSchema.parse(parsed);
      return this.excludeDeployedHunts(sanitizePlaybookHuntSuggestions(suggestions, endpointsByTaskId, endpoints, limit), outcomes);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // Generate a chronological prose narrative of the incident for management/stakeholders
  // (single AI call). The result is saved to state.narrativeTimeline so it persists and
  // appears in the report and dashboard immediately without a manual copy step.
  async generateNarrative(caseId: string): Promise<{ narrativeTimeline: string }> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("narrative generation");
    const loaded = await this.opts.stateStore.load(caseId);
    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);

    const max = maxPromptEvents();
    let events = selectSynthesisEvents(scopedEvents, max);
    const renderEvent = (e: ForensicEvent) =>
      `[${e.timestamp || "(undated)"}] [${e.severity}] ${e.description.slice(0, 240)}`;
    const findingsText = loaded.findings.slice(0, 150).map((f) => `[${f.severity}] ${f.title}`).join("\n") || "(none)";
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(loaded, scopedEvents, kevCatalog);

    const narrativePrompt = getNarrativePrompt();
    const overhead = estimateTokens(narrativePrompt)
      + estimateTokens(contextBlock + (loaded.attackerPath || "") + findingsText) + 300;
    const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - overhead));
    if (fit < events.length) events = selectSynthesisEvents(scopedEvents, fit);
    const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

    const userPrompt =
      contextBlock +
      `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
      `FINDINGS:\n${findingsText}\n\n` +
      `FORENSIC TIMELINE (${scopedEvents.length} in-scope events):\n${timelineText}\n\n` +
      `Write the narrative timeline as JSON.`;

    const narrativeSchema = z.object({ narrativeTimeline: z.string().catch("") });
    const result = await this.withRetry(caseId, "narrative", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: narrativePrompt, userPrompt, images: [] }, "narrative");
      return narrativeSchema.parse(parsed);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);

    // Re-read state before saving so imports/edits that arrived during the AI call aren't clobbered.
    const fresh = await this.opts.stateStore.load(caseId);
    await this.opts.stateStore.save({ ...fresh, narrativeTimeline: result.narrativeTimeline });
    return result;
  }

  // Generate a management-facing executive summary of the case (single-shot, no state change).
  // Text-only over the synthesized digest, like ask(); returns plain prose for the analyst to
  // review and save into the report's executive-summary section.
  async executiveSummary(caseId: string): Promise<ExecSummary> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("executive summary");
    const loaded = await this.opts.stateStore.load(caseId);
    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);

    const max = maxPromptEvents();
    let events = selectSynthesisEvents(scopedEvents, max);
    const renderEvent = (e: ForensicEvent) =>
      `[${e.timestamp || "(undated)"}] [${e.severity}] ${e.description.slice(0, 240)}`;
    const findingsText = loaded.findings.slice(0, 150).map((f) => `[${f.severity}] ${f.title}`).join("\n") || "(none)";
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(loaded, scopedEvents, kevCatalog);

    const overhead = estimateTokens(getExecSummaryPrompt())
      + estimateTokens(contextBlock + (loaded.attackerPath || "") + findingsText) + 300;
    const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - overhead));
    if (fit < events.length) events = selectSynthesisEvents(scopedEvents, fit);
    const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

    const userPrompt =
      contextBlock +
      `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
      `FINDINGS:\n${findingsText}\n\n` +
      `FORENSIC TIMELINE (${scopedEvents.length} in-scope events):\n${timelineText}\n\n` +
      `Write the executive summary as JSON.`;

    return this.withRetry(caseId, "exec-summary", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getExecSummaryPrompt(), userPrompt, images: [] }, "exec-summary");
      return execSummarySchema.parse(parsed);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // TimeSketch-style Starred Events Report: ONE text-only AI call over ONLY the analyst-starred
  // events (ids resolved by the route from the reserved "starred" tags — the pipeline has no tags
  // store). Events resolve from the super-timeline store UNIONed with the forensic timeline
  // (manual/pushed events may exist only there), deduped by id. Deliberately NO scope / false-
  // positive filtering: the analyst hand-picked these events. EPHEMERAL — no state change.
  async starredReport(caseId: string, starredIds: string[]): Promise<StarredSummaryResult> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("starred report");
    const loaded = await this.opts.stateStore.load(caseId);
    const wanted = new Set(starredIds);
    // FORENSIC copies win the union: imports dual-write the same event ids to both stores, but all
    // later severity/MITRE re-grades (content tagger, synthesis mergeDelta) land on the forensic copy
    // only — the super copy is frozen at import time, so it must not shadow the re-graded one.
    // Super-only events (raw host triage never promoted) still resolve via the fill-the-gaps pass.
    const byId = new Map<string, ForensicEvent>();
    for (const e of loaded.forensicTimeline) if (wanted.has(e.id)) byId.set(e.id, e);
    if (this.opts.superTimelineStore) {
      for (const e of await this.opts.superTimelineStore.all(caseId)) if (wanted.has(e.id) && !byId.has(e.id)) byId.set(e.id, e);
    }
    const all = sortByEventTime([...byId.values()]);
    if (!all.length) throw new Error("no starred events");

    // The provenance line is computed HERE (the model copies it verbatim, it never counts events
    // itself) so the report's stated coverage is always accurate — including when the budget cap
    // reduced the set.
    const provenance = (used: number): string => used < all.length
      ? `[*This report was generated based on the ${used} most significant of ${all.length} (deduplicated) starred events.*]`
      : `[*This report was generated based on ${all.length} (deduplicated) starred events.*]`;

    const prompt = getStarredReportPrompt();
    const { events, render } = this.fitViewEvents(all, estimateTokens(prompt) + estimateTokens(provenance(all.length)) + 300);

    const userPrompt =
      `PROVENANCE LINE (copy verbatim directly under the title): ${provenance(events.length)}\n\n` +
      `STARRED EVENTS (${events.length} of ${all.length}, chronological):\n` +
      events.map(render).join("\n") +
      `\n\nWrite the starred events report as JSON.`;

    const mdSchema = z.object({ markdown: z.string().min(1) });
    const result = await this.withRetry(caseId, "starred-report", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: prompt, userPrompt, images: [] }, "starred-report");
      return mdSchema.parse(parsed);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);

    return { markdown: result.markdown, eventCount: all.length, usedEvents: events.length, truncated: events.length < all.length };
  }

  // Per-session summary (#342): ONE text-only AI call over just the events of a single attacker
  // session. Cheaper and more coherent than full synthesis — the events already share a host and a
  // tight window, so the model gets a focused slice instead of a 600-event wall.
  //
  // The session is re-derived HERE from the case's own timeline rather than trusting a caller-passed
  // event list: a session id is only meaningful relative to a segmentation run, and re-segmenting
  // with sessionEnvOptions() guarantees the summary covers exactly the session the dashboard and the
  // report call by that id. EPHEMERAL — no state change.
  async sessionSummary(caseId: string, sessionId: string): Promise<SessionSummaryResult> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("session summary");
    const loaded = await this.opts.stateStore.load(caseId);
    const sessions = segmentSessions(loaded.forensicTimeline, sessionEnvOptions());
    const session = sessions.find((s) => s.id === sessionId);
    if (!session) throw new Error(`session not found: ${sessionId}`);

    const wanted = new Set(session.eventIds);
    const all = sortByEventTime(loaded.forensicTimeline.filter((e) => wanted.has(e.id)));
    if (!all.length) throw new Error(`session not found: ${sessionId}`);

    const prompt = getSessionSummaryPrompt();
    const { events, render } = this.fitViewEvents(all, estimateTokens(prompt) + 300);

    const userPrompt =
      `SESSION: ${session.label}\n` +
      `HOST: ${session.host}\n` +
      (session.account ? `ACCOUNT: ${session.account}\n` : "") +
      `WINDOW: ${session.startTime} → ${session.endTime}\n\n` +
      `EVENTS (${events.length} of ${all.length}, chronological):\n` +
      events.map(render).join("\n") +
      `\n\nWrite the session account as JSON.`;

    const mdSchema = z.object({ markdown: z.string().min(1) });
    const result = await this.withRetry(caseId, "session-summary", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: prompt, userPrompt, images: [] }, "session-summary");
      return mdSchema.parse(parsed);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);

    return {
      markdown: result.markdown,
      sessionId: session.id,
      label: session.label,
      eventCount: all.length,
      usedEvents: events.length,
      truncated: events.length < all.length,
    };
  }

  // Summarize the analyst's CURRENT super-timeline view: the route passes the exact filter set the
  // dashboard has applied plus the tag label map (tags live outside the pipeline). EPHEMERAL.
  async viewSummary(caseId: string, filters: SuperQuery, labelMap?: SuperLabelMap): Promise<StarredSummaryResult> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("view summary");
    if (!this.opts.superTimelineStore) throw new Error("super-timeline not configured");
    const loaded = await this.opts.stateStore.load(caseId);
    const { events: matched } = await this.opts.superTimelineStore.query(
      caseId, { ...filters, offset: 0, limit: 10_000 }, labelMap);
    if (!matched.length) throw new Error("no events match the current filters");

    const prompt = getViewSummaryPrompt();
    const { events, render } = this.fitViewEvents(matched, estimateTokens(prompt) + 300);

    const userPrompt =
      `EVENTS (${events.length} of ${matched.length} matching the analyst's current filters, chronological):\n` +
      events.map(render).join("\n") +
      `\n\nWrite the overview as JSON.`;

    const mdSchema = z.object({ markdown: z.string().min(1) });
    const result = await this.withRetry(caseId, "view-summary", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: prompt, userPrompt, images: [] }, "view-summary");
      return mdSchema.parse(parsed);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);

    return { markdown: result.markdown, eventCount: matched.length, usedEvents: events.length, truncated: events.length < matched.length };
  }

  // Shared event-selection for the two view-scoped summaries: cap to the synthesis event budget
  // (DFIR_AI_SYNTH_MAX_EVENTS, default 600), token-fit against the prompt overhead, keep the most
  // signal-bearing subset (selectSynthesisEvents) and re-sort it chronologically for the report.
  private fitViewEvents(all: ForensicEvent[], overheadTokens: number): { events: ForensicEvent[]; render: (e: ForensicEvent) => string } {
    const render = (e: ForensicEvent): string =>
      `[${e.timestamp || "(undated)"}] [${e.severity}]` +
      (e.asset ? ` [${e.asset}]` : "") +
      ` ${e.description.slice(0, 240)}` +
      (e.processName ? ` | process: ${e.processName}` : "") +
      (e.srcIp || e.dstIp ? ` | net: ${[e.srcIp, e.dstIp].filter(Boolean).join(" → ")}` : "");
    const max = maxPromptEvents();
    let events = selectSynthesisEvents(all, max);
    const fit = fitItemsToBudget(events, render, Math.max(0, inputTokenBudget() - overheadTokens));
    if (fit < events.length) events = selectSynthesisEvents(all, fit);
    return { events: sortByEventTime(events), render };
  }

  // Incident-specific remediation plan (#178): a concrete, prioritized action list for the IR team,
  // GROUNDED in the deterministic ATT&CK Mitigations for the case's techniques so the model turns
  // generic guidance into specific steps instead of hallucinating. Single-shot, no state change.
  async remediationPlan(caseId: string): Promise<RemediationPlan> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("remediation plan");
    const loaded = await this.opts.stateStore.load(caseId);
    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);
    const filtered: InvestigationState = { ...loaded, forensicTimeline: scopedEvents };

    const findingsText =
      loaded.findings.slice(0, 100).map((f) => `[${f.severity}] ${f.title}${f.mitreTechniques?.length ? ` (${f.mitreTechniques.join(", ")})` : ""}`).join("\n") || "(none)";

    // The deterministic ATT&CK mitigations for this case's techniques — the grounding facts.
    const mit = buildMitigationsResult(filtered, loadMitigationsDataset());
    const mitigationsText =
      mit.byMitigation
        .slice(0, 30)
        .map((m) => `- ${m.id} ${m.name} (covers ${m.techniques.join(", ")}): ${m.description}`)
        .join("\n") || "(no mapped ATT&CK mitigations)";

    // The deterministic D3FEND countermeasures (defensive techniques/sensors) for the same
    // techniques — so the plan can also cite the relevant D3FEND control alongside the M-code.
    const d3f = buildD3fendResult(filtered, loadD3fendDataset(), d3fendEnvOptions());
    const d3fendText =
      d3f.byTactic
        .flatMap((g) => g.countermeasures.map((c) => `- ${c.name} [${c.tactic}] (covers ${c.techniques.join(", ")})`))
        .slice(0, 40)
        .join("\n") || "(no mapped D3FEND countermeasures)";

    const contextBlock = buildSynthesisContext(loaded, scopedEvents, await this.getKevCatalog());

    const userPrompt =
      contextBlock +
      `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
      `FINDINGS:\n${findingsText}\n\n` +
      `RECOMMENDED ATT&CK MITIGATIONS (use these as the basis for concrete steps):\n${mitigationsText}\n\n` +
      `RELEVANT D3FEND COUNTERMEASURES (the defensive technique/sensor for each — cite alongside the ATT&CK mitigation where it fits):\n${d3fendText}\n\n` +
      `Write the incident-specific remediation plan as JSON.`;

    return this.withRetry(caseId, "remediation", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getRemediationPrompt(), userPrompt, images: [] }, "remediation");
      return remediationPlanSchema.parse(parsed);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // On-demand hypothesis falsification review (issue #71). A focused, human-readable devil's-advocate
  // pass over the OPEN hypotheses: for each, the plain-English evidence FOR and AGAINST it plus an
  // ADVISORY recommended status. One text-only AI call; EPHEMERAL — no state change, and crucially it
  // NEVER mutates a hypothesis's status (the analyst-freeze contract); the recommendation is surfaced for
  // the analyst to apply. Returns { reviews: [] } with no AI call when there are no open hypotheses.
  async hypothesisReview(caseId: string): Promise<{ reviews: HypothesisReviewItem[] }> {
    if (!this.opts.hypothesisStore) throw new Error("hypotheses not configured");
    const provider = this.opts.synthesisProvider ?? this.requireProvider("hypothesis review");
    const loaded = await this.opts.stateStore.load(caseId);

    const allHypotheses = await this.opts.hypothesisStore.load(caseId);
    // Review OPEN, non-exhausted hypotheses (analyst- or synthesis-authored). Resolved/exhausted ones
    // are already settled, so re-litigating them wastes tokens and invites status churn.
    const open = allHypotheses.filter((h) => h.status === "open" && !h.exhausted);
    if (!open.length) return { reviews: [] };

    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);
    const validEventIds = new Set(scopedEvents.map((e) => e.id));

    const max = maxPromptEvents();
    let events = selectSynthesisEvents(scopedEvents, max);
    const renderEvent = (e: ForensicEvent) =>
      `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${e.description.slice(0, 240)}`;
    const findingsText = loaded.findings.slice(0, 150).map((f) => `[${f.id}] [${f.severity}] ${f.title}`).join("\n") || "(none)";
    const contextBlock = buildSynthesisContext(loaded, scopedEvents, await this.getKevCatalog());

    // Render the open hypotheses with the evidence already linked to them, so the model reviews the
    // analyst's/synthesis's current picture rather than starting cold.
    const hypothesesText = open.map((h) => {
      const parts = [`[${h.id}] ${h.title}`];
      if (h.expectedOutcome) parts.push(`    decided by: ${h.expectedOutcome}`);
      if (h.relatedEventIds.length) parts.push(`    currently-supporting events: ${h.relatedEventIds.join(", ")}`);
      if (h.contradictingEventIds.length) parts.push(`    known contradicting events: ${h.contradictingEventIds.join(", ")}`);
      return parts.join("\n");
    }).join("\n");

    // Trim the timeline so the whole prompt fits the model context.
    const overhead = estimateTokens(getHypothesisReviewPrompt())
      + estimateTokens(contextBlock + (loaded.attackerPath || "") + findingsText + hypothesesText) + 300;
    const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - overhead));
    if (fit < events.length) events = selectSynthesisEvents(scopedEvents, fit);
    const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

    const userPrompt =
      contextBlock +
      `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
      `FINDINGS:\n${findingsText}\n\n` +
      `FORENSIC TIMELINE (${scopedEvents.length} in-scope events):\n${timelineText}\n\n` +
      `OPEN HYPOTHESES TO REVIEW:\n${hypothesesText}\n\n` +
      `Review each open hypothesis for supporting AND refuting evidence, and return the JSON.`;

    const knownHypotheses = new Map(open.map((h) => [h.id, h.title] as const));
    return this.withRetry(caseId, "hypothesis-review", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getHypothesisReviewPrompt(), userPrompt, images: [] }, "hypothesis-review");
      const result = hypothesisReviewSchema.parse(parsed);
      return { reviews: sanitizeHypothesisReviews(result.reviews, knownHypotheses, validEventIds) };
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // Optional AI-assisted extension of deterministic FP suggestions (#227). The caller narrows the
  // candidates and returned ids are validated against them, so hallucinated ids cannot be applied.
  async suggestFalsePositiveSimilarAi(
    caseId: string,
    anchorId: string,
    anchorLabel: string,
    candidateIds: string[],
    candidateLabels: string[],
  ): Promise<string[]> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("false positive suggestions");
    const loaded = await this.opts.stateStore.load(caseId);
    const list = candidateIds.map((id, i) => `[${id}] ${candidateLabels[i] ?? ""}`).join("\n") || "(none)";
    const userPrompt =
      `ANCHOR ITEM (just marked false positive): [${anchorId}] ${anchorLabel}\n\n` +
      `OTHER ITEMS IN THIS CASE:\n${list}\n\n` +
      "Which of the other items are likely the same false-positive pattern?";
    return this.withRetry(caseId, "fp-similarity", async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getFpSimilarityPrompt(), userPrompt, images: [] }, "fp-similarity");
      const result = fpSimilaritySchema.parse(parsed);
      const valid = new Set(candidateIds);
      return result.candidateIds.filter((id) => valid.has(id));
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // `dryRun` returns conclusions without persistence or side effects; second opinion uses it for
  // model B (#116). `provider` overrides the synthesis model. Both default off for a normal run.
  /** Estimate each Deep Pass severity floor against this case before the analyst spends credits. */
  async deepPassPreview(caseId: string): Promise<{ cap: number; floors: FloorOption[] }> {
    const state = await this.opts.stateStore.load(caseId);
    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(state.forensicTimeline, scope), markers);
    const cap = maxPromptEvents();
    return { cap, floors: previewFloors(scopedEvents, { cap }) };
  }

  /** Read every graded event at the chosen floor in batches, then fold observations into one
   * synthesis. Preview uses the same ordering; cancellation records a failed run but changes no case data. */
  async deepPass(caseId: string, opts: {
    minSeverity: Severity;
    provider?: AIProvider;
    signal?: AbortSignal;
    maxBatches?: number;
    onProgress?: (done: number, total: number, detail: string) => void;
    onCheckpoint?: (checkpoint: DeepPassCheckpoint) => Promise<void>;
    resumeFrom?: DeepPassCheckpoint;
    analysisParentRunId?: string;
  }): Promise<DeepPassResult> {
    const runStartedAt = new Date().toISOString();
    const runId = `${runStartedAt.replace(/[:.]/g, "-")}-${randomUUID().slice(0, 8)}`;
    const state = await this.opts.stateStore.load(caseId);
    const provider = opts.provider ?? this.opts.synthesisProvider ?? this.opts.provider;
    if (!provider) throw new Error("no synthesis provider configured");

    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(state.forensicTimeline, scope), markers);

    const cap = maxPromptEvents();
    const floored = applySeverityFloor([...promptCandidates(scopedEvents)], opts.minSeverity);
    const { events: rows } = collapseForPrompt(floored, groupEnvOptions());
    const batches = planBatches(rows, cap);
    const selectionHash = createHash("sha256")
      .update(JSON.stringify(rows.map((event) => event.id)))
      .digest("hex");

    // Refuse rather than quietly starting a very expensive job — and name a floor that would fit.
    const ceiling = opts.maxBatches ?? (Number(process.env.DFIR_DEEP_PASS_MAX_BATCHES) || DEFAULT_MAX_BATCHES);
    if (batches.length > ceiling) {
      const fits = floorsWithinBudget(previewFloors(scopedEvents, { cap }), ceiling);
      throw new Error(
        `deep pass needs ${batches.length} batches, above the ${ceiling} limit. ` +
        (fits.length ? `Raise the floor to ${fits[fits.length - 1]} or above.` : "Raise DFIR_DEEP_PASS_MAX_BATCHES."),
      );
    }

    const retries = this.opts.retries ?? 3;
    const backoffMs = this.opts.backoffMs ?? 500;
    const execution = await executeDeepPassBatches({
      batches, floor: opts.minSeverity, selectionHash,
      validEventIds: new Set(state.forensicTimeline.map((event) => event.id)),
      digestBudget: Math.max(0, Math.floor(inputTokenBudget() * 0.25)),
      ...(opts.resumeFrom ? { resumeFrom: opts.resumeFrom } : {}),
      ...(opts.signal ? { signal: opts.signal } : {}),
      ...(opts.onProgress ? { onProgress: opts.onProgress } : {}),
      ...(opts.onCheckpoint ? { onCheckpoint: opts.onCheckpoint } : {}),
      renderBatch: (batch) => this.renderBatchRows(batch),
      observe: (userPrompt) => this.withRetry(
        caseId, "deep-pass-observe", () => this.analyzeRestored(
          caseId, state, provider,
          { systemPrompt: getObservePrompt(), userPrompt, images: [], ...(opts.signal ? { signal: opts.signal } : {}) },
          "deep-pass-observe",
        ), retries, backoffMs,
      ),
      onFailure: (message) => this.log.warn(`deep pass: ${message}`, { caseId }),
    });
    const { observations, batchesFailed, aborted } = execution;

    const summary: DeepPassResult = {
      aborted,
      floor: opts.minSeverity,
      events: floored.length,
      rows: rows.length,
      batches: batches.length,
      batchesFailed,
      observations: observations.length,
    };
    const runRecord = {
      id: runId, parentRunId: opts.analysisParentRunId, startedAt: runStartedAt,
      provider: provider.name, model: provider.model, eventIds: floored.map((event) => event.id),
      minSeverity: opts.minSeverity, maxBatches: ceiling, rowsPerBatch: cap, scope, batchesFailed,
      falsePositiveMarkers: markers.length,
      observePrompt: getObservePrompt(), synthesisPrompt: getSynthesisPrompt(),
    };
    if (aborted) {
      await recordDeepPassRun(this.opts.analysisRunStore, caseId, { ...runRecord, status: "failed", error: "cancelled before final synthesis", output: state });
      return summary;
    }

    opts.onProgress?.(batches.length, batches.length, "synthesizing");
    await this.synthesize(caseId, {
      force: true,
      ...(opts.signal ? { signal: opts.signal } : {}),
      ...(opts.provider ? { provider: opts.provider } : {}),
      observationsBlock: renderObservationDigest(observations),
      analysisParentRunId: runId,
    });
    const finalState = await this.opts.stateStore.load(caseId);
    await recordDeepPassRun(this.opts.analysisRunStore, caseId, { ...runRecord, output: finalState });
    return summary;
  }

  // Observation rows match synthesis timeline rows, minus the selection-class prefix.
  private renderBatchRows(rows: readonly ForensicEvent[]): string {
    return rows
      .map((e) => `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${e.description.slice(0, 240)}${renderStructuredTags(e)}`)
      .join("\n");
  }

  async synthesize(caseId: string, opts: { force?: boolean; dryRun?: boolean; provider?: AIProvider; signal?: AbortSignal; skipSecondLook?: boolean; observationsBlock?: string; analysisParentRunId?: string } & SynthThinkingInput = {}): Promise<InvestigationState> {
    // Deep Pass supplies observations for events this prompt will not show row by row.
    const observationsBlock = opts.observationsBlock ?? "";
    const synthProvider = opts.provider ?? this.opts.synthesisProvider ?? this.requireProvider("synthesis");
    this.warnOnPromptDrift();   // once per process: a stale synthesis-prompt override silently drops shipped capabilities
    const loaded = await this.opts.stateStore.load(caseId);
    if (loaded.forensicTimeline.length === 0) return loaded;

    // Correlate the same artifact across tools first: deduplicate into one corroborated event and
    // one finding with both sources. This is idempotent and the correlated timeline is persisted.
    const envWindow = Number(process.env.DFIR_CORRELATE_WINDOW_S);
    const corrProfile = await this.opts.correlationProfileStore?.load(caseId);
    const windowSeconds = Number.isFinite(envWindow) ? envWindow : (corrProfile?.windowSeconds ?? 2);
    // Source trust (#66) selects merge wording and caps low-trust-only findings.
    const trustOverrides = this.opts.sourceTrustStore ? await this.opts.sourceTrustStore.load(caseId) : undefined;
    const sourceTrust = effectiveTrustMap(trustOverrides);
    // Measure clock skew pre-merge (#228), before correlation erases the disagreeing anchors.
    // Aligned times guide windows; persisted events retain recorded timestamps.
    const skew = await this.detectSkew(caseId, loaded.forensicTimeline, { windowSeconds, sourceTrust });
    const state: InvestigationState = {
      ...loaded,
      forensicTimeline: correlateEvents(loaded.forensicTimeline, { windowSeconds, sourceTrust, epochOf: skew }),
    };

    const markers = this.opts.falsePositiveStore ? await this.opts.falsePositiveStore.load(caseId) : [];

    // Scope: only events inside the investigation window feed synthesis, so
    // findings/IOCs/attacker-path/questions reflect only in-scope activity.
    // Then drop events the client confirmed legitimate so the model never derives
    // conclusions from benign activity (the raw events stay in state — reversible).
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    // Split the two filter stages so the coverage audit (#62) can attribute omissions: `inWindowEvents`
    // is after the scope filter (out-of-window events dropped); `scopedEvents` is after the additional
    // false-positive/legitimate filter. The budget cap below drops the rest from the prompt.
    const inWindowEvents = filterEventsByScope(state.forensicTimeline, scope);
    const scopedEvents = filterFalsePositiveEvents(inWindowEvents, markers);

    // Detection-burst grouping (spec 2026-07-21): the same Sigma/YARA detection firing hundreds of
    // times used to consume hundreds of prompt seats. Collapse each burst to ONE representative row so
    // every DISTINCT detection reaches the model. Prompt-only and derived on read — `scopedEvents` (and
    // therefore the case, the coverage denominators and the high-severity backfill) is untouched.
    // The explicit CollapsedPrompt annotation matters: without it the disabled branch's bare `new Map()`
    // infers Map<unknown, unknown> and every later `grouping.groupById.get(...)` fails to typecheck.
    // Info-severity events don't get prompt seats (DFIR_SYNTH_INCLUDE_INFO=1 restores them): on a real
    // case 213 Info rows pushed the prompt from 546 to 759 entries, past the cap, costing 26 GRADED
    // detections their place. They remain in the case, the timeline and the coverage denominators —
    // this only decides who gets budget.
    const eligibleForPrompt = promptCandidates(scopedEvents);
    const omittedInfo = scopedEvents.length - eligibleForPrompt.length;
    const grouping: CollapsedPrompt = groupingEnabled()
      ? collapseForPrompt(eligibleForPrompt, groupEnvOptions())
      : { events: [...eligibleForPrompt], groupById: new Map(), memberIdsByRepresentative: new Map() };
    const collapsedEvents = grouping.events;

    // Bound the prompt for large imports (e.g. THOR: hundreds of events + auto-findings).
    // Send the MOST SEVERE events (then most recent) up to a cap, and truncate each
    // description — this keeps the request affordable (avoids OpenRouter 402 on a giant
    // request) and inside the model's context. The deterministic high-severity backfill
    // still creates findings for any Critical/High event NOT shown here (eligibleIds below
    // is the full scoped set), so capping the prompt never loses a severe detection.
    const SYNTH_MAX_EVENTS = maxPromptEvents();
    // Per-case prevalence/baseline (investigation-guidance #15): how common each activity PATTERN is
    // across the WHOLE case timeline (not just the scoped subset — the baseline is a property of the
    // corpus). Feeds a rarity bias into the selection fill (a 1-off wins a seat over 500× noise) and a
    // common/rare tag into each rendered event so the model gets explicit baseline context.
    const prevalenceIndex = buildPrevalenceIndex(state.forensicTimeline);
    const rarityOf = (e: ForensicEvent): number => rarityScore(e, prevalenceIndex);
    // Stratified selection: all Critical/High + the earliest (initial-access) + an even
    // time-spread sample, chronologically — better kill-chain coverage than severity-only. The ANNOTATED
    // form (investigation-guidance #4) exposes which CLASS claimed each event, so renderEvent can prefix
    // context-only rows with "~" (the model reads anchors vs supporting context) and the synth-meta card
    // can show the analyst what evidence classes the model actually saw.
    let selection = selectSynthesisEventsAnnotated(collapsedEvents, SYNTH_MAX_EVENTS, rarityOf);
    let promptEvents = selection.events;
    // Context classes: everything that is NOT a primary verdict-bearing anchor / initial-access event —
    // these are the supporting rows the model should read as context, marked "~" in the timeline.
    const CONTEXT_CLASSES = new Set<SelectionClass>(["anchor_context", "corroborated", "technique", "rare", "spread"]);
    const isContext = (id: string): boolean => CONTEXT_CLASSES.has(selection.classOf.get(id) as SelectionClass);

    // Analyst notebook context: when both notebookStore and aiControlStore are wired and the
    // analyst has opted in (includeNotebook: true in ai-control.json), append the notebook
    // entries to the synthesis prompt so the AI incorporates investigator hypotheses.
    // Loaded here (before the hash) so notebook changes also trigger a fresh synthesis.
    let notebookBlock = "";
    if (this.opts.notebookStore && this.opts.aiControlStore) {
      const aiCtrl = await this.opts.aiControlStore.load(caseId);
      if (aiCtrl.includeNotebook) {
        const notebookEntries = await this.opts.notebookStore.load(caseId);
        if (notebookEntries.length) {
          notebookBlock =
            "ANALYST NOTEBOOK (investigator notes and open questions — take these into account when synthesizing findings and the attacker path):\n" +
            notebookEntries.map((e) => `[${e.type.toUpperCase()}] ${e.text}`).join("\n") +
            "\n\n";
        }
      }
    }

    // Analyst hypotheses as steering (issue #140): feed the investigator's OPEN, analyst-owned
    // hypotheses into the prompt so the model actively hunts evidence to support/refute them and
    // reflects it in findings/events + its own hypotheses output. We do NOT ask it to flip the
    // analyst's hypothesis status — those are frozen by mergeHypotheses (the analyst stays in
    // control); the steering shows up as findings/events the analyst then uses to judge. Only
    // analyst-authored or analyst-touched OPEN ones (pure inputs, never rewritten by synthesis),
    // so including them in the hash below can't cause a re-synthesis loop. Bounded for prompt size.
    let analystHypothesesBlock = "";
    // Refuted hypotheses fed back as NEGATIVE KNOWLEDGE (investigation-guidance #2): a theory the
    // analyst ruled out must not be re-asserted or re-opened. Loaded from the same store, once.
    let refutedHypothesesBlock = "";
    if (this.opts.hypothesisStore) {
      // ACH exhaustion (investigation-guidance #14): before reading, flag hypotheses whose linked or
      // technique-matched hunts have come back empty — so the negative-knowledge block below and the
      // "to test" list reflect them. Derived from collected hunt outcomes; persisted; idempotent.
      const exhaustionOutcomes = await this.loadHuntOutcomes(caseId);
      const huntSignals = exhaustionOutcomes
        .filter((o) => o.status === "collected")
        .map((o) => ({
          ...(o.relatedHypothesisId ? { relatedHypothesisId: o.relatedHypothesisId } : {}),
          techniques: o.mitreTechniques ?? [],
          missed: o.foundEvidence === false,
          title: o.title,
        }));
      if (huntSignals.some((s) => s.missed)) await this.opts.hypothesisStore.applyExhaustion(caseId, huntSignals);

      const allHypotheses = await this.opts.hypothesisStore.load(caseId);
      const open = allHypotheses
        .filter((h) => h.status === "open" && !h.exhausted && (h.source === "analyst" || h.analystTouched))
        .slice(0, 15);
      if (open.length) {
        analystHypothesesBlock =
          "ANALYST HYPOTHESES TO TEST (the investigator proposed these — actively look for evidence that " +
          "SUPPORTS or REFUTES each and surface it in findings/events; you may add a corroborating hypothesis, " +
          "but do NOT mark the analyst's own hypothesis resolved):\n" +
          open.map((h) => `- ${h.title}${h.expectedOutcome ? ` (decided by: ${h.expectedOutcome})` : ""}`).join("\n") +
          "\n\n";
      }
      refutedHypothesesBlock = renderRefutedHypothesesBlock(allHypotheses);
    }

    // Prior-work feedback (investigation-guidance #2): the hunt hit/miss ledger (#157, previously fed
    // only to the hunt prompts) and the playbook DONE/SKIPPED digest, so synthesis builds on completed
    // work and dead hunts instead of re-recommending them. Loaded before the hash so completing a task
    // or collecting a hunt triggers a fresh synthesis (a hit is a pivot; a miss is negative evidence).
    const priorHuntsBlock = renderPriorHuntsBlock(await this.loadHuntOutcomes(caseId));
    const playbookTasks = this.opts.playbookStore ? await this.opts.playbookStore.load(caseId) : [];
    const playbookProgressBlock = renderPlaybookProgressBlock(playbookTasks);

    // Incident-type framing (#236): the one-line hint for the type the analyst picked at case
    // creation, so the model prioritizes ransomware / BEC / exfil techniques. A pure INPUT synthesis
    // never rewrites, and cheap (one short line) — but changing the type must re-synthesize, so it
    // joins the skip-if-unchanged hash below.
    const incidentTypeBlock = renderIncidentTypeBlock(
      this.opts.incidentTypeStore ? await this.opts.incidentTypeStore.loadType(caseId) : null,
    );

    // Skip-if-unchanged: hash only the STABLE INPUTS to synthesis — the in-scope timeline,
    // the IOCs (value + intel verdicts), the scope, the legitimate markers, and (when opted
    // in) the notebook entries. NOT the findings / MITRE / threads / summary, which synthesis
    // itself rewrites (including those would make two consecutive runs hash differently and
    // never skip). If the inputs are identical to the last successful run, return the saved
    // state — no AI call.
    const synthHash = createHash("sha1").update(JSON.stringify({
      ev: scopedEvents.map((e) => [e.id, e.severity, e.timestamp, e.description]),
      io: state.iocs.map((i) => [i.id, i.value, (i.enrichments ?? []).map((e) => e.verdict).join(",")]),
      sc: scope, lg: markers.map((m) => m.id),
      nb: notebookBlock,
      hy: analystHypothesesBlock,
      // Prior-work feedback (#2): completing a task, collecting a hunt, or refuting a hypothesis
      // changes these strings, so an otherwise-identical timeline re-synthesizes to fold in the
      // new negative knowledge instead of skipping. Pure inputs — synthesis never rewrites them.
      pw: priorHuntsBlock + playbookProgressBlock + refutedHypothesesBlock,
      // Re-picking the incident type reframes what the model should prioritize — an otherwise
      // identical timeline must re-synthesize rather than skip.
      it: incidentTypeBlock,
      // Deep-pass observations are a pure INPUT synthesis never rewrites, but they change what the
      // model can see — so a run carrying fresh ones must never be skipped as "inputs unchanged".
      ob: observationsBlock,
    })).digest("hex");
    if (!opts.force && !opts.dryRun && this.lastSynthHash.get(caseId) === synthHash) return loaded;

    const scopeNote = hasScope(scope)
      ? `INVESTIGATION SCOPE: only consider activity from ${scope.start ?? "the beginning"} to ${scope.end ?? "now"}. ` +
        `Events outside this window have already been removed below.\n\n`
      : "";
    // Cap the existing-findings echo too (a big import can produce 100s of auto-findings). Append the
    // prior run's corroboration label (investigation-guidance #6) so the model sees which of its own
    // earlier claims were weak/uncorroborated and can strengthen or drop them this run.
    const existingFindings = state.findings.slice(0, 150).map((f) => {
      const corr = corroborationLabel(f);
      return `[${f.id}] ${f.title}${corr ? ` — ${corr}` : ""}`;
    }).join("\n") || "(none yet)";
    const openThreads = state.openThreads
      .filter((t) => t.status === "open")
      .map((t) => `[${t.id}] ${t.description}`)
      .join("\n") || "(none open)";
    const falsePositiveBlock = buildFalsePositiveContext(markers);
    // Rabbit-hole detection (#13): authorized-test / known-good-tool markers are RETAINED as shaping
    // context (a sanctioned pentest during the window is signal, not just noise), not merely erased.
    const authorizedContextBlock = buildAuthorizedContextBlock(markers);
    // Learn from dismissals (#65): recurring reasoned dismissals → a "PREVIOUSLY DISMISSED PATTERNS" block
    // that DOWN-WEIGHTS (not excludes) new look-alike activity. Distinct from the two blocks above: those
    // act on EXACT current markers; this generalizes. Env-tunable recurrence floor. Best-effort/optional.
    let learnedPatternsBlock = "";
    if (this.opts.learnedPatternStore) {
      const minCount = Number(process.env.DFIR_LEARNED_PATTERN_MIN_COUNT) || undefined;
      learnedPatternsBlock = buildLearnedPatternsBlock(await this.opts.learnedPatternStore.load(caseId), minCount);
    }
    // Compact, corroborated context (compromised assets + threat-intel verdicts + KEV hits)
    // so the model grounds findings/attacker-path in structure instead of inferring blind.
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(state, scopedEvents, kevCatalog);
    // Known unknowns (#165): the gaps in the story (silent windows, uncovered ATT&CK phases, likely-
    // next techniques) so the model builds on what's MISSING instead of glossing over it. Plus the
    // (env-gated, default OFF) candidate-actor block. Both DERIVED — computed AFTER the skip-hash
    // above, so they never affect skip-if-unchanged.
    const knownUnknownsBlock = await this.knownUnknownsBlock(state, scopedEvents, caseId);
    const adversaryBlock = this.adversaryHintBlock(state);
    // Structured causal evidence (investigation-guidance #5), all DERIVED after the skip-hash so they
    // never affect skip-if-unchanged: the deterministic ATTACK GRAPH (spawn/file-lineage/lateral/network
    // edges with confidence+rule — previously fed only to ask()/suggestHunts(), never the call that
    // writes findings), the statistically-confirmed periodic-beacon candidates, and the activity-phase
    // digest. These give synthesis the cross-host structure it was inferring blind from truncated prose.
    const graphBlock = buildGraphContext({ ...state, forensicTimeline: scopedEvents }, { maxEdges: DEFAULT_MAX_GRAPH_EDGES });
    const beaconBlock = buildBeaconDigest(detectBeacons(scopedEvents, beaconEnvOptions()));
    const attackPhaseBlock = buildAttackPhaseDigest(buildAttackPhases(scopedEvents));
    // Import-satisfaction (investigation-guidance #8, phase 2): a collection this case previously
    // recommended (prior nextSteps / unknown questions carrying a structured collect target) whose host
    // now HAS matching events was fulfilled — stop re-recommending it and re-evaluate the question it
    // served. Derived from the PRIOR run's guidance vs the current events; the served questions are
    // added to the re-answer set below so the model reconsiders them with the new evidence.
    const satisfiedCollections = detectSatisfiedCollections(state, scopedEvents);
    const satisfiedBlock = buildSatisfiedCollectionsBlock(satisfiedCollections);
    const satisfiedQuestionIds = new Set(
      satisfiedCollections.filter((s) => s.target.from === "question").map((s) => s.target.refId),
    );
    // Analyst-pinned open questions: tell the model to address each (answer when the evidence
    // now supports it) and keep them. They're re-merged into the output below so they persist.
    const pinnedQuestions = state.keyQuestions.filter((q) => q.pinned);
    const pinnedBlock = pinnedQuestions.length
      ? `OPEN QUESTIONS TO ADDRESS (include EACH in keyQuestions with the SAME id; answer with ` +
        `status/answer + supporting relatedEventIds if the evidence now supports it, else status ` +
        `"unknown" with a 'pointer' to the artifact to collect):\n` +
        pinnedQuestions.map((q) => `[${q.id}] ${q.question}`).join("\n") + "\n\n"
      : "";
    // A finding just confirmed false-positive forces a re-answer of any key question that cited it
    // as support — otherwise a question "answered" from a finding the analyst just rejected would
    // keep looking answered until the model happens to reconsider it unprompted. The sanitize pass
    // after the AI call (below, near applyFalsePositive) is the deterministic backstop for when the
    // model ignores this and echoes the stale answer back.
    const droppedFindingIds = new Set(
      state.findings
        .filter((f) => !applyFalsePositive(state, markers).findings.some((k) => k.id === f.id))
        .map((f) => f.id),
    );
    const questionsToReanswer = state.keyQuestions.filter((q) => {
      if (q.pinned) return false;
      // A question whose recommended collection was just satisfied (#8 phase 2) must be re-evaluated
      // with the evidence now present, not left showing its old "unknown".
      if (satisfiedQuestionIds.has(q.id)) return true;
      if ((q.relatedFindingIds ?? []).some((id) => droppedFindingIds.has(id))) return true;
      // Fallback for a question that predates relatedFindingIds (or whose answer only ever named
      // the finding in prose): its free-text pointer/answer still cites the now-rejected finding.
      return [...droppedFindingIds].some(
        (id) => textMentionsFindingId(q.pointer, id) || textMentionsFindingId(q.answer, id),
      );
    });
    const reanswerBlock = questionsToReanswer.length
      ? `QUESTIONS TO RE-ANSWER (a finding backing this answer was just confirmed a FALSE POSITIVE — ` +
        `re-evaluate using ONLY the CURRENT findings/evidence, ignoring the rejected finding entirely; ` +
        `if nothing else supports it, set status "unknown", clear the answer, and set relatedFindingIds ` +
        `to []):\n` +
        questionsToReanswer.map((q) => `[${q.id}] ${q.question} (previously: "${q.answer}")`).join("\n") + "\n\n"
      : "";

    // Token budget: trim the timeline so the WHOLE prompt fits the model context — the rest
    // (context block, findings echo, system prompt) is the fixed overhead. Re-select for the
    // smaller count so the kept events stay the most important; the high-severity backfill
    // still creates findings for any Critical/High event dropped here.
    // Each event carries its structured tags (host / process lineage / src→dst / corroborating-source
    // count) after the prose (investigation-guidance #5) — only when set, so a bare event costs no extra
    // tokens. This is what lets the model connect cross-host activity instead of guessing from prose.
    const renderEvent = (e: ForensicEvent) => {
      // Grouped rows carry their own count/host-spread/span suffix, which supersedes the prevalence
      // tag — showing both would state the same repetition twice in different words.
      const group = grouping.groupById.get(e.id);
      const groupTag = group ? renderGroupSuffix(group) : "";
      // Prevalence baseline tag (#15): only the informative extremes (clearly common / clearly rare) are
      // tagged, so the model knows a 500× pattern is routine and a 1-off is anomalous.
      const p = group ? null : eventPrevalence(e, prevalenceIndex);
      const prevTag = p ? prevalenceTag(p) : "";
      // "~" prefix (investigation-guidance #4): this row is supporting CONTEXT (pulled in to explain an
      // anchor), not itself a primary verdict-bearing event — so the model weights it as background.
      const ctx = isContext(e.id) ? "~" : "";
      return `${ctx}[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${e.description.slice(0, 240)}${renderStructuredTags(e)}${groupTag}${prevTag ? ` ⟨${prevTag}⟩` : ""}`;
    };
    const synthOverhead = estimateTokens(getSynthesisPrompt())
      + estimateTokens(incidentTypeBlock + scopeNote + contextBlock + graphBlock + beaconBlock + attackPhaseBlock + knownUnknownsBlock + adversaryBlock + notebookBlock + analystHypothesesBlock + refutedHypothesesBlock + priorHuntsBlock + playbookProgressBlock + satisfiedBlock + pinnedBlock + reanswerBlock + observationsBlock + existingFindings + openThreads + falsePositiveBlock + authorizedContextBlock + learnedPatternsBlock + (state.lastSummary || "")) + 400;
    const fit = fitItemsToBudget(promptEvents, renderEvent, Math.max(0, inputTokenBudget() - synthOverhead));
    if (fit < promptEvents.length) { selection = selectSynthesisEventsAnnotated(collapsedEvents, fit, rarityOf); promptEvents = selection.events; }

    const timelineText = promptEvents.map(renderEvent).join("\n");
    // Coverage audit (#62): what the model actually saw this run vs what was left out and why. Computed
    // here where promptEvents + the token overhead are final. Of the budget-omitted events, the safety-net
    // backfill (below) still guarantees a finding for any Critical/High, so surface that count too.
    // A grouped row stands for every member of its burst, so all of those events were SEEN by the model —
    // counting only the representative would report the rest as "omitted for the size limit", the
    // opposite of the truth.
    const shownIds = new Set<string>();
    let groupEntries = 0;
    let groupedEvents = 0;
    for (const e of promptEvents) {
      shownIds.add(e.id);
      const members = grouping.memberIdsByRepresentative.get(e.id);
      if (!members) continue;
      groupEntries += 1;
      groupedEvents += members.length;
      for (const id of members) shownIds.add(id);
    }
    const representedEvents = scopedEvents.filter((e) => shownIds.has(e.id));
    const omittedHighSeverity = scopedEvents.filter(
      (e) => !shownIds.has(e.id) && (e.severity === "Critical" || e.severity === "High"),
    ).length;
    const synthCoverage: SynthesisCoverage = buildSynthesisCoverage({
      totalEvents: state.forensicTimeline.length,
      inWindow: inWindowEvents.length,
      scoped: scopedEvents.length,
      considered: shownIds.size,
      groupEntries,
      groupedEvents,
      omittedInfo,
      omittedHighSeverity,
      promptTokensEstimate: synthOverhead + estimateTokens(timelineText),
    });
    const truncatedNote = scopedEvents.length > shownIds.size
      ? ` — showing ${shownIds.size} of ${scopedEvents.length}; ${scopedEvents.length - shownIds.size} event(s) omitted from this prompt but still in the case`
      : "";
    // Legend for the "~" context prefix (investigation-guidance #4) — only when at least one context row
    // is present, so it costs nothing on a small case.
    const contextLegend = promptEvents.some((e) => isContext(e.id))
      ? " Rows prefixed \"~\" are SUPPORTING CONTEXT (pulled in to explain a nearby anchor), not primary findings — weight them as background."
      : "";
    const userPrompt =
      incidentTypeBlock +
      scopeNote +
      contextBlock +
      graphBlock +
      beaconBlock +
      attackPhaseBlock +
      knownUnknownsBlock +
      adversaryBlock +
      notebookBlock +
      analystHypothesesBlock +
      refutedHypothesesBlock +
      priorHuntsBlock +
      playbookProgressBlock +
      satisfiedBlock +
      pinnedBlock +
      reanswerBlock +
      observationsBlock +
      `FORENSIC TIMELINE (${scopedEvents.length} dated events${truncatedNote}).${contextLegend}\n${timelineText}\n\n` +
      `EXISTING FINDINGS (update by id, do not duplicate):\n${existingFindings}\n\n` +
      `CURRENTLY OPEN THREADS (close by id in threadsClosed when the evidence resolves them):\n${openThreads}\n\n` +
      (falsePositiveBlock ? `${falsePositiveBlock}\n\n` : "") +
      (authorizedContextBlock ? `${authorizedContextBlock}\n\n` : "") +
      (learnedPatternsBlock ? `${learnedPatternsBlock}\n\n` : "") +
      `Running notes: ${state.lastSummary || "(none)"}\n\nReturn the JSON conclusions.`;

    const synthStart = Date.now();
    const retries = this.opts.retries ?? 3;
    const backoffMs = this.opts.backoffMs ?? 500;
    // Chain-of-Thought / extended thinking for the complex synthesis call (issue #121, feature 1).
    // Budget resolved per-run: an explicit value or the dashboard "deep reasoning" toggle wins, else
    // the global DFIR_AI_SYNTH_THINKING_TOKENS default (off when unset). The Anthropic provider maps
    // it to extended thinking; OpenRouter to its unified `reasoning`; other providers ignore it. Only
    // synthesis reasons step-by-step — extraction stays cheap.
    const synthThinkingTokens = resolveSynthThinkingBudget(opts, Number(process.env.DFIR_AI_SYNTH_THINKING_TOKENS) || 0);
    // Per-model quality telemetry (#74): count retries the synthesis call actually needed (a failed
    // parse/schema-mismatch attempt increments this). Counted on catch INSIDE the retried closure
    // rather than via this.withRetry's onRetry hook, because that hook is the shared server-logging
    // callback — routing through this.withRetry keeps master's per-attempt WARN logging intact while
    // the local catch keeps the count. Surfaced on synth-meta so a flaky model shows up empirically.
    let synthParseRetries = 0;
    const delta = await this.withRetry(caseId, "synthesis", async () => {
      try {
        const parsed = await this.analyzeRestored(
          caseId,
          state,
          synthProvider,
          { systemPrompt: getSynthesisPrompt(), userPrompt, images: [], ...(synthThinkingTokens > 0 ? { thinkingTokens: synthThinkingTokens } : {}), ...(opts.signal ? { signal: opts.signal } : {}) },
          "synthesis",
        );
        return stripAiExtractedFrom(deltaSchema.parse(parsed));
      } catch (err) {
        synthParseRetries++;
        throw err;
      }
    }, retries, backoffMs);

    // Anchor finding timestamps to the last real event time (fallback: existing state time).
    const ts = state.forensicTimeline[state.forensicTimeline.length - 1]?.timestamp || state.updatedAt;
    // Synthesis is an authoritative holistic reassessment: replace the CONCLUSIONS
    // (findings, MITRE techniques) rather than accumulate, so anything no longer
    // supported by the in-scope timeline (e.g. out-of-scope or removed events) is
    // dropped. IOCs are OBSERVED INDICATORS (often from deterministic imports like THOR
    // — 100s of hashes the text-only synthesis can't re-derive), so they are PRESERVED
    // and merged (deduped by value); scope/legitimate still filter them at projection.
    // Threads and the forensic timeline are also preserved.
    const base = { ...state, findings: [], mitreTechniques: [] };
    const merged = await this.mergeWithAliases(base, delta, { windowSequence: 0, timestamp: ts, sourceScreenshots: [] });
    // Safety net: drop anything confirmed false-positive even if the model re-introduced it.
    const filtered = applyFalsePositive(merged, markers);

    // Back-link forensic events to the CORRECT findings using the synthesis output
    // (each finding lists the event ids it's based on). Replaces extraction guesses.
    const surviving = new Set(filtered.findings.map((f) => f.id));
    const eventToFindings = new Map<string, string[]>();
    for (const f of delta.findings) {
      if (!surviving.has(f.id)) continue;
      for (const eid of f.relatedEventIds ?? []) {
        const arr = eventToFindings.get(eid) ?? [];
        if (!arr.includes(f.id)) arr.push(f.id);
        eventToFindings.set(eid, arr);
      }
    }
    const linked = {
      ...filtered,
      forensicTimeline: filtered.forensicTimeline.map((e) => ({ ...e, relatedFindingIds: eventToFindings.get(e.id) ?? [] })),
    };

    // Heuristic safety net: a Critical/High artifact row is almost always a finding.
    // Any in-scope, non-legitimate high-severity event that synthesis left WITHOUT a
    // finding gets one auto-created, so a severe detection can never be silently
    // missed. Restricted to the events synthesis actually considered (scopedEvents).
    const eligibleIds = new Set(scopedEvents.map((e) => e.id));
    const backfilled = backfillHighSeverityFindings(linked, eligibleIds, ts);
    // #74: how many findings the safety net had to add — a proxy for detections synthModel itself missed.
    const highSeverityBackfillCount = backfilled.findings.length - linked.findings.length;
    // Log gap analysis (#83): a COMPLETE-silence gap — a window where every source went dark — is the
    // classic signature of cleared logs / a stopped collector, so escalate it to a finding here too.
    // Gaps are derived on read (not persisted); only the complete ones earn a persisted finding, and
    // the finding id is derived from the bounding events so re-synthesis over the same gap is idempotent.
    const gapOpts = gapEnvOptions();
    const gaps = detectTimelineGaps(scopedEvents, gapOpts);
    const gapFilled = backfillSilenceGapFindings(backfilled, gaps, ts, gapOpts.maxFindings);
    // Preserve analyst-pinned questions (synthesis replaces keyQuestions wholesale). Re-read
    // the LATEST state here, not the pre-AI snapshot, so a question added DURING the
    // seconds-long AI call isn't clobbered by this write (read-modify-write race).
    const pinnedNow = (await this.opts.stateStore.load(caseId)).keyQuestions.filter((q) => q.pinned);
    let next = pinnedNow.length
      ? { ...gapFilled, keyQuestions: mergePinnedQuestions(pinnedNow, gapFilled.keyQuestions) }
      : gapFilled;

    // Deterministic backstop for the reanswerBlock instruction above: if the model still cited a
    // now-dead finding (ignored the instruction) — whether via a structured relatedFindingIds link
    // or only in the free-text pointer/answer prose (the only signal available for a question that
    // predates relatedFindingIds) — force the question back to "unknown" (clearing the stale
    // answer). ANY dependency on a rejected finding forces the reset, not just total loss of
    // support: a partial answer that still names a finding the analyst just confirmed is NOT a
    // threat is misleading even when another finding also backs it, and we can't safely guess what
    // the finding-minus-the-FP'd-one answer should say without asking the model again. Guarantees a
    // key question can never keep citing a finding that's already gone.
    // Shared with the FP-mark route's synchronous cascade (investigation-guidance #12). Here it runs as
    // the AUTHORITATIVE recompute (staleReSynth off → clears any interim stale badge), guaranteeing a key
    // question can never keep citing a finding that's gone.
    next = {
      ...next,
      keyQuestions: reconsiderKeyQuestions(next.keyQuestions, {
        survivingFindingIds: new Set(next.findings.map((f) => f.id)),
        priorFindingIds: state.findings.map((f) => f.id), // ids that existed going into this run
      }).questions,
    };

    // Answer-contradiction validator (investigation-guidance #3): a key question whose answer asserts
    // an ABSENCE ("no data exfiltration confirmed") while in-scope events carry the matching ATT&CK
    // techniques is a dangerous false negative. Force such answers to "partial" and cite the
    // contradicting events. Runs AFTER the FP reset (so a reset-to-unknown answer isn't re-flagged) over
    // the same scoped, non-FP events the model saw. Pure + idempotent.
    next = { ...next, keyQuestions: flagContradictedAnswers(next.keyQuestions, scopedEvents) };

    // Union the deterministically-identified ATT&CK techniques carried by the (in-scope) timeline
    // into the synthesized MITRE table, so techniques the model didn't echo — especially the Info/Low
    // discovery phase (whoami/net group/findstr password/cat .env) tagged by the importers — still
    // appear in the case's MITRE table and report. Same scoped events synthesis saw; pure + idempotent.
    next = { ...next, mitreTechniques: unionEventTechniques(next.mitreTechniques, scopedEvents) };

    // Prior-work safety net (investigation-guidance #2): even with the PLAYBOOK PROGRESS prompt block,
    // the model may still echo a nextStep that repeats a COMPLETED task. Deterministically DEMOTE (not
    // drop) any such step to priority "low" with an annotation, requiring a shared host/artifact token
    // so a same-verb different-target step survives. Keeps the top of the next-steps list actionable.
    if (playbookTasks.length) {
      const doneTitles = playbookTasks.filter((t) => t.status === "done").map((t) => t.title);
      if (doneTitles.length) {
        const { steps, demotedIds } = demoteCompletedNextSteps(next.nextSteps, doneTitles);
        if (demotedIds.length) next = { ...next, nextSteps: steps };
      }
    }

    // Dry run (second-opinion Pass 1): return model B's conclusions WITHOUT persisting or any side
    // effect — and WITHOUT folding in accepted deltas, so B stays an independent opinion.
    if (opts.dryRun) return next;

    // Durability (issue #116): re-apply any analyst-ACCEPTED second-opinion deltas after the
    // wholesale findings rewrite, so a confirmed model-B finding/severity/technique is never lost
    // on re-synthesis. Pure + idempotent; a no-op when the store or record is absent/empty.
    if (this.opts.secondOpinionStore) {
      next = applyAcceptedSecondOpinion(next, await this.opts.secondOpinionStore.load(caseId));
    }

    // Per-finding grounding + corroboration (investigation-guidance #6): resolve each finding's
    // supporting in-scope events (forward relatedEventIds AND reverse forensicTimeline links, so the
    // deterministic backfill findings ground correctly), roll up { tools, hosts, intel, graph-linked },
    // flag an uncited finding as `ungrounded`, and CAP an ungrounded/single-source finding's confidence.
    // Also catches the subtler case where cited ids resolve but the finding's own claimed IP never
    // appears in their text (`contentMismatch`) — floors High/Critical to Medium (veridia-deep-pass
    // 2026-07-22). Deterministic + idempotent; only ever lowers confidence/severity. Runs last, so it
    // grades the FINAL finding set (incl. backfills + accepted second-opinion deltas).
    {
      const evidenceGraph = buildEvidenceGraph(next);
      const graphLinkedEventIds = new Set(evidenceGraph.edges.flatMap((e) => e.eventIds));
      const inScope = next.forensicTimeline.filter((e) => eligibleIds.has(e.id));
      // KEV-linked confidence signal (issue #61): the CVEs mentioned in-scope (events + IOCs) that match
      // the CISA KEV catalog. Empty when no catalog is loaded, so the signal is simply never set then.
      const kevCatalog = await this.getKevCatalog();
      let kevCveIds: Set<string> | undefined;
      if (kevCatalog && kevCatalog.size > 0) {
        const cveIds = new Set<string>();
        for (const e of inScope) { extractCveIds(e.description).forEach((id) => cveIds.add(id)); if (e.message) extractCveIds(e.message).forEach((id) => cveIds.add(id)); }
        for (const i of next.iocs) extractCveIds(i.value).forEach((id) => cveIds.add(id));
        kevCveIds = new Set(matchKevEntries([...cveIds], kevCatalog).map((m) => m.cveID));
      }
      const grounded = groundAndScoreFindings({ findings: next.findings, scopedEvents: inScope, iocs: next.iocs, graphLinkedEventIds, kevCveIds, sourceTrust });
      // Intel-verdict gate (investigation-guidance #7): floor an intel-ONLY High/Critical finding (no
      // behavioral corroboration, all its verdict IOCs lone-intel/conflicted) to Medium/≤60 — the
      // northpeak stale-CTI-on-own-server class. Runs after grounding so it sees the corroboration rollup.
      const hostNames = new Set(buildAssetGraph(next).assets.filter((a) => a.type === "host").map((a) => shortHost(a.name)));
      const capped = capIntelOnlyFindings({ findings: grounded, iocs: next.iocs, scopedEvents: inScope, hostNames });
      // Rabbit-hole detection (investigation-guidance #13): place each finding relative to the corroborated
      // main attack component. A finding whose graph-modeled evidence sits in a SEPARATE component is a
      // rabbit-hole candidate ('disconnected'); the model's per-finding relevance verdict refines a
      // disconnected one into 'unrelated-but-real' (a genuine separate issue) vs undetermined noise. The
      // deterministic linkage is authoritative; the AI never upgrades a rabbit hole into a lead.
      const aiRelevanceById = new Map(
        (delta.findings ?? [])
          .filter((f): f is typeof f & { relevance: "connected" | "unrelated-but-real" | "undetermined" } => !!f.relevance && surviving.has(f.id))
          .map((f) => [f.id, f.relevance] as const),
      );
      next = { ...next, findings: scoreFindingsRelevance({ findings: capped, scopedEvents: inScope, graph: evidenceGraph, aiRelevanceById }) };

      // Auto "corroborate <ioc>" next-steps (investigation-guidance #7, deferred): for every finding the
      // intel gate just floored to intel-only, add a concrete "go get the behavioral evidence" step so the
      // capped lead becomes a directed action, not a dead end. Idempotent ids; prepend so the verification
      // steps sit near the top, and don't duplicate a step the model already emitted with the same id.
      const corroborateSteps = buildIntelCorroborationSteps({ findings: next.findings, iocs: next.iocs, scopedEvents: inScope, hostNames });
      if (corroborateSteps.length) {
        const existing = new Set((next.nextSteps ?? []).map((s) => s.id));
        const fresh = corroborateSteps.filter((s) => !existing.has(s.id));
        if (fresh.length) next = { ...next, nextSteps: [...fresh, ...(next.nextSteps ?? [])] };
      }
    }

    // What this run changed vs the pre-AI findings. Findings are FINAL here — neither persistLatest
    // nor the hypothesis auto-gen below touch them — so it's computed once and reused for the
    // Investigation-Log entry (#165), the synth-meta record, and the notify hook.
    const findingsDiff = diffFindings(loaded.findings, next.findings);

    // Lost-update guard (mirrors the pinned-questions re-load above): a manual event/IOC/thread
    // added DURING the seconds-long AI call would otherwise be clobbered by this write, because
    // `next` was derived from the snapshot taken before the call. Re-read the LATEST state and
    // carry forward only items NEW since that snapshot (by id/value), so synthesis's conclusions
    // and its correlation/legitimate work on the snapshot timeline are preserved while concurrent
    // analyst additions survive. Reference the RAW snapshot (`loaded`), not the in-memory
    // correlated `state`, so events deduped by correlateEvents aren't re-added.
    const persistLatest = async () => {
      const latest = await this.opts.stateStore.load(caseId);
      const snapEventIds = new Set(loaded.forensicTimeline.map((e) => e.id));
      const nextEventIds = new Set(next.forensicTimeline.map((e) => e.id));
      const addedEvents = latest.forensicTimeline.filter((e) => !snapEventIds.has(e.id) && !nextEventIds.has(e.id));
      const snapIocVals = new Set(loaded.iocs.map((i) => i.value.toLowerCase()));
      const nextIocVals = new Set(next.iocs.map((i) => i.value.toLowerCase()));
      const latestIocByVal = new Map(latest.iocs.map((i) => [i.value.toLowerCase(), i]));
      const mergedIocs = [
        ...next.iocs.map((i) => latestIocByVal.get(i.value.toLowerCase()) ?? i),
        ...latest.iocs.filter((i) => !snapIocVals.has(i.value.toLowerCase()) && !nextIocVals.has(i.value.toLowerCase())),
      ];
      const snapThreadIds = new Set(loaded.openThreads.map((t) => t.id));
      const nextThreadIds = new Set(next.openThreads.map((t) => t.id));
      const addedThreads = latest.openThreads.filter((t) => !snapThreadIds.has(t.id) && !nextThreadIds.has(t.id));
      // Investigation Log (#165): carry forward any timeline line a CONCURRENT import appended during
      // the AI call (dedupe by timestamp+sequence+text), so the synthesis write doesn't clobber it.
      const tlKey = (t: TimelineEntry) => `${t.timestamp}|${t.windowSequence}|${t.description}`;
      const snapTimeline = new Set(loaded.timeline.map(tlKey));
      const nextTimeline = new Set(next.timeline.map(tlKey));
      const addedTimeline = latest.timeline.filter((t) => !snapTimeline.has(tlKey(t)) && !nextTimeline.has(tlKey(t)));
      next = {
        ...next,
        forensicTimeline: addedEvents.length ? sortByEventTime([...next.forensicTimeline, ...addedEvents]) : next.forensicTimeline,
        iocs: mergedIocs,
        openThreads: addedThreads.length ? [...next.openThreads, ...addedThreads] : next.openThreads,
        timeline: addedTimeline.length ? [...next.timeline, ...addedTimeline] : next.timeline,
      };
      // Record THIS synthesis run as a durable, cross-session Investigation-Log line (#165) — imports
      // already log via timelineNote; synthesis didn't. Final merged counts; one entry per real run.
      const synthLogEntry: TimelineEntry = {
        timestamp: new Date().toISOString(),
        windowSequence: 0,
        description:
          `Synthesis: ${next.findings.length} finding(s) (${findingsDiff.added.length} new, ` +
          `${findingsDiff.severityChanged.length} reclassified), ${next.forensicTimeline.length} event(s), ` +
          `${next.iocs.length} IOC(s)`,
        sourceScreenshots: [],
      };
      next = { ...next, timeline: [...next.timeline, synthLogEntry] };
      await this.opts.stateStore.save(next);
    };
    if (this.opts.stateLock) await this.opts.stateLock.runExclusive(caseId, persistLatest);
    else await persistLatest();

    // Auto-generate hypotheses (issue #140). Merge the model's hypotheses into the per-case store,
    // refreshing pristine auto ones and FREEZING any the analyst touched (see mergeHypotheses). Only
    // when the model actually returned some — an omitted field must never prune the analyst's set.
    // Sanitized against the FINAL event/IOC ids so evidence links can't dangle. Side store, not
    // InvestigationState; runs after the state is persisted so a failure here can't lose the synthesis.
    if (this.opts.hypothesisStore && delta.hypotheses && delta.hypotheses.length) {
      const validEventIds = new Set(next.forensicTimeline.map((e) => e.id));
      const validIocIds = new Set(next.iocs.map((i) => i.id));
      const seeds = sanitizeHypotheses(delta.hypotheses, validEventIds, validIocIds);
      await this.opts.hypothesisStore.applyAutoGenerated(caseId, seeds, new Date().toISOString());
    }

    this.lastSynthHash.set(caseId, synthHash);   // remember these inputs so an identical re-run skips the AI call
    // Record what this run changed (findingsDiff computed above) and when it ran — surfaced on the
    // dashboard. Only reached on a real run; skips return early above.
    await this.opts.synthMetaStore?.record(caseId, findingsDiff, new Date().toISOString(), {
      durationMs: Date.now() - synthStart,
      eventCount: next.forensicTimeline.length,
      iocCount: next.iocs.length,
      selectionCounts: { ...selection.counts },   // #4: the evidence mix the model saw
      coverage: synthCoverage,                     // #62: included/omitted coverage audit
      synthModel: this.opts.synthesisModelLabel ?? `${synthProvider.name}/${synthProvider.model}`, // #74
      findingsCount: next.findings.length,          // #74
      highSeverityBackfillCount,                    // #74
      parseRetries: synthParseRetries,              // #74
    });
    const anonPolicy = toAnonPolicy(this.opts.anonStore ? await this.opts.anonStore.load(caseId) : null);
    await recordSynthesisRun(this.opts.analysisRunStore, caseId, {
      parentRunId: opts.analysisParentRunId, startedAt: new Date(synthStart).toISOString(),
      provider: synthProvider.name, model: synthProvider.model, eventIds: [...shownIds],
      inputState: state, outputState: next, prompt: getSynthesisPrompt(), maxEvents: SYNTH_MAX_EVENTS,
      thinkingTokens: synthThinkingTokens, correlationWindowSeconds: windowSeconds, anonymizationPolicy: anonPolicy,
      scope, falsePositiveMarkers: markers.length, infoEventsExcluded: omittedInfo > 0,
      observationsIncluded: observationsBlock.length > 0, parseRetries: synthParseRetries, coverage: synthCoverage,
    });
    // Notify on new/escalated findings (issue #58). Best-effort, fire-and-forget — never blocks or
    // fails synthesis. Only on a real run, so a skipped (unchanged) re-synthesis sends nothing.
    this.opts.onSynth?.(caseId, findingsDiff, next);
    this.opts.onState?.(next);

    // Second-look loop (investigation-guidance #11): now that this run has conclusions + (open)
    // hypotheses + key questions, re-query the COMPLETE raw record (the super-timeline + the scoped
    // events the sampler omitted) for the terms those open questions imply, promote the matches, and
    // trigger EXACTLY ONE bounded re-synthesis so the conclusions fold them in. `skipSecondLook` on that
    // re-synthesis (and on the second-opinion dryRun path, already returned above) is the one-iteration
    // guard that makes this terminate. Best-effort: a sweep failure must never fail the synthesis.
    if (!opts.skipSecondLook && this.opts.superTimelineStore) {
      try {
        const outcome = await this.runSecondLook(caseId, {
          // The sweep treats anything not in `promptEvents` as a candidate to re-discover; events
          // already covered by a grouped row HAVE been seen, so hand it the expanded set.
          next, scopedEvents, promptEvents: representedEvents, scope, evidenceRequests: delta.evidenceRequests,
        });
        if (outcome) {
          if (outcome.meta.promoted > 0) {
            // Promotion changed the in-scope timeline → the synthHash differs → this re-synthesis runs
            // (not skipped) and, with skipSecondLook, does NOT sweep again. Bounded to one extra AI call.
            const resynth = await this.synthesize(caseId, {
              force: true, skipSecondLook: true, ...(opts.signal ? { signal: opts.signal } : {}),
            });
            await this.opts.synthMetaStore?.recordSecondLook(caseId, outcome.meta);
            return resynth;
          }
          // Nothing new to promote, but empty requests are still surfaced as collection leads.
          await this.opts.synthMetaStore?.recordSecondLook(caseId, outcome.meta);
        }
      } catch (err) {
        console.warn(`[DFIR] second-look sweep failed for case ${caseId}: ${(err as Error).message}`);
      }
    }
    return next;
  }

  // Second-look sweep (investigation-guidance #11) — the impure orchestration around the pure secondLook
  // module. Mines the case's OPEN questions (open hypotheses, unknown/partial key questions with a
  // collect target, top connective IOCs) plus the model's own evidenceRequests into concrete searches,
  // resolves them against the omitted scoped events AND the super-timeline within the active window,
  // promotes the not-yet-analyzed matches (capped, tagged with provenance), and returns a meta summary.
  // Returns null when there was nothing to search for. Never re-synthesizes itself — the caller does.
  private async runSecondLook(
    caseId: string,
    ctx: {
      next: InvestigationState;
      scopedEvents: ForensicEvent[];
      promptEvents: ForensicEvent[];
      scope: ScopeWindow;
      evidenceRequests?: ModelEvidenceRequest[];
    },
  ): Promise<{ meta: import("./synthMeta.js").SecondLookMeta } | null> {
    const superStore = this.opts.superTimelineStore;
    if (!superStore) return null;

    // Active window: the explicit scope when set, else the span of the dated in-scope events. Bounds the
    // raw re-query so a huge super-timeline is searched only over the incident window.
    const window = hasScope(ctx.scope)
      ? { from: ctx.scope.start ?? undefined, to: ctx.scope.end ?? undefined }
      : deriveWindow(ctx.scopedEvents);

    const hypotheses = this.opts.hypothesisStore ? await this.opts.hypothesisStore.load(caseId) : [];
    const iocValueById = new Map(ctx.next.iocs.map((i) => [i.id, i.value] as const));
    const connectiveIocs = rankConnectiveIocs(ctx.next, ctx.scopedEvents, { max: 5 });

    const requests = buildSecondLookRequests({
      hypotheses,
      iocValueById,
      keyQuestions: ctx.next.keyQuestions,
      connectiveIocs,
      modelRequests: ctx.evidenceRequests,
      window,
    });
    if (!requests.length) return null;

    // Candidate pool: the scoped events the sampler OMITTED from the prompt + the super-timeline rows in
    // the window (deduped by id). A super row that is a copy of a forensic event shares its id, so
    // `forensicEventIds` (below) correctly marks it non-promotable — only genuinely-new raw rows promote.
    const shownIds = new Set(ctx.promptEvents.map((e) => e.id));
    const omitted = ctx.scopedEvents.filter((e) => !shownIds.has(e.id));
    const superRows = (await superStore.query(caseId, { from: window.from, to: window.to })).events;
    const byId = new Map<string, ForensicEvent>();
    for (const e of [...omitted, ...superRows]) if (!byId.has(e.id)) byId.set(e.id, e);
    const candidates = [...byId.values()];

    const forensicEventIds = new Set(ctx.next.forensicTimeline.map((e) => e.id));
    const resolutions = resolveSecondLookRequests(requests, candidates, forensicEventIds);
    const plan = buildSecondLookPlan(resolutions);

    if (plan.promotions.length) {
      await this.promoteSuperTimeline(caseId, plan.promotions, {
        importedAt: new Date().toISOString(),
        tagById: plan.tagById,
        note: `Second look: promoted ${plan.promotions.length} raw event(s) matching open questions`,
      });
    }

    const matched = resolutions.filter((r) => r.matchedEventIds.length > 0).length;
    return {
      meta: {
        promoted: plan.promotions.length,
        requests: requests.length,
        matched,
        leads: plan.leads.map((l) => l.reason).slice(0, 10),
        summary: summarizeSecondLook(plan),
        at: new Date().toISOString(),
      },
    };
  }

  // Second LLM opinion (issue #116). On-demand QA cross-check: a DIFFERENT model independently
  // re-synthesizes the case (Pass 1, non-destructive `dryRun`), then a reconcile pass (Pass 2)
  // annotates each disagreement (B-only / A-only finding, severity, ATT&CK technique) with a
  // rationale + recommendation. Returns the saved record; never mutates the case state — the
  // analyst adjudicates per delta via applySecondOpinion(). Throws (→ route 501/500) when the
  // second-opinion model isn't configured.
  async secondOpinion(caseId: string, opts: SynthThinkingInput = {}): Promise<SecondOpinion> {
    const provider = this.opts.secondOpinionProvider;
    if (!provider) throw new Error("second-opinion model not configured (set DFIR_AI_SECOND_OPINION_MODEL)");
    if (!this.opts.secondOpinionStore) throw new Error("second-opinion store not configured");
    if ((await this.opts.stateStore.load(caseId)).forensicTimeline.length === 0) {
      throw new Error("nothing to review — import evidence and synthesize the case first");
    }
    // Deep-reasoning toggle (#121) flows into BOTH synthesis passes below, so model A's freshened
    // synthesis and model B's independent pass reason equally hard for the comparison.

    // Pass 0 — freshen the PRIMARY synthesis so model A reflects the CURRENT timeline. Without this,
    // a stale saved A vs a fresh model-B run produces deltas that are staleness artifacts (e.g. the
    // deterministic gap-silence / high-severity backfill findings) rather than real model
    // disagreements. Uses skip-if-unchanged (no `force`), so it's a NO-OP (no AI call) when A is
    // already current — it only re-synthesizes when the in-scope timeline/IOCs/scope changed.
    const a = await this.synthesize(caseId, { deepReasoning: opts.deepReasoning, thinkingTokens: opts.thinkingTokens });

    // Pass 1 — independent synthesis with model B over the SAME current timeline/context, routed
    // through a different model and NOT persisted (dryRun). This is model B's analysis.
    const b = await this.synthesize(caseId, { dryRun: true, force: true, provider, deepReasoning: opts.deepReasoning, thinkingTokens: opts.thinkingTokens });

    const modelA = this.opts.synthesisModelLabel ?? (this.opts.synthesisProvider ?? this.opts.provider)?.name ?? "model A";
    const modelB = this.opts.secondOpinionModelLabel ?? provider.name;
    let record = buildSecondOpinion({ a, b, modelA, modelB, now: () => new Date().toISOString() });

    // Pass 2 — reconcile: annotate each disagreement with a rationale + recommendation. Best-effort:
    // if the reconcile call fails, keep the deterministic deltas (no rationale) rather than failing.
    if (record.deltas.length > 0) {
      const userPrompt = buildReconcilePrompt(a, b, record.deltas);
      const retries = this.opts.retries ?? 3;
      const backoffMs = this.opts.backoffMs ?? 500;
      try {
        const parsed = await this.withRetry(caseId, "second-opinion-reconcile", async () => {
          const raw = await this.analyzeRestored(caseId, a, provider, { systemPrompt: getReconcilePrompt(), userPrompt, images: [] }, "second-opinion-reconcile");
          return reconcileResponseSchema.parse(raw);
        }, retries, backoffMs);
        record = mergeReconcileVerdicts(record, parsed);
      } catch (err) {
        this.log.warn(`[second-opinion] reconcile pass failed: ${(err as Error).message}`, { caseId });
      }
    }

    await this.opts.secondOpinionStore.save(caseId, record);
    // Per-model quality telemetry (#74): stamp the agreement rate onto synth-meta so modelA vs modelB
    // can be compared empirically across runs, not just eyeballed on this one second-opinion panel.
    const deltaCount = record.deltas.length;
    const denom = record.agreementCount + deltaCount;
    await this.opts.synthMetaStore?.recordSecondOpinionPerf(caseId, {
      modelA,
      modelB,
      agreementCount: record.agreementCount,
      deltaCount,
      agreementRate: denom > 0 ? record.agreementCount / denom : 0,
      at: record.generatedAt,
    });
    return record;
  }

  // Accept or reject ONE second-opinion delta. The analyst's decision is recorded on the delta, and
  // ALL currently-accepted deltas are (re-)applied onto the live case state (idempotent) — so an
  // accept adds/edits the finding/severity/technique now and survives the next synthesis (the same
  // re-apply runs in synthesize()). A reject just records the decision; state is unchanged.
  async applySecondOpinion(caseId: string, deltaId: string, accept: boolean): Promise<{ record: SecondOpinion; state: InvestigationState }> {
    if (!this.opts.secondOpinionStore) throw new Error("second-opinion store not configured");
    const current = await this.opts.secondOpinionStore.load(caseId);
    if (!current) throw new Error("no second opinion to act on — run a second opinion first");
    if (!current.deltas.some((d) => d.id === deltaId)) throw new Error(`unknown second-opinion delta: ${deltaId}`);
    return this.persistSecondOpinion(caseId, setDeltaStatus(current, deltaId, accept ? "accepted" : "rejected"));
  }

  // Bulk accept-all / reject-all: decide every still-PENDING delta at once (already-decided deltas
  // are left as the analyst set them), persist, and apply the accepted set to the case in ONE pass.
  async applyAllSecondOpinion(caseId: string, accept: boolean): Promise<{ record: SecondOpinion; state: InvestigationState }> {
    if (!this.opts.secondOpinionStore) throw new Error("second-opinion store not configured");
    const current = await this.opts.secondOpinionStore.load(caseId);
    if (!current) throw new Error("no second opinion to act on — run a second opinion first");
    return this.persistSecondOpinion(caseId, setAllPendingStatus(current, accept ? "accepted" : "rejected"));
  }

  // Save the (re)decided record, then re-apply ALL accepted deltas onto the live state (idempotent).
  // Shared by the single + bulk apply methods so both persist and broadcast identically.
  private async persistSecondOpinion(caseId: string, record: SecondOpinion): Promise<{ record: SecondOpinion; state: InvestigationState }> {
    await this.opts.secondOpinionStore!.save(caseId, record);
    const state = await this.opts.stateStore.load(caseId);
    const applied = applyAcceptedSecondOpinion(state, record);
    if (applied !== state) {
      await this.opts.stateStore.save(applied);
      this.opts.onState?.(applied);
    }
    return { record, state: applied };
  }
}
