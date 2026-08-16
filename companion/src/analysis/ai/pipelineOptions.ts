import type { AIProvider, AnalyzeImage } from "../../providers/provider.js";
import type { Logger } from "../../logging/logger.js";
import type { AiControlStore } from "../aiControl.js";
import { AiCostStore } from "../aiCost.js";
import type { AnalysisRunStore } from "../analysisRunStore.js";
import type { AnonControlStore } from "../anonControl.js";
import type { DiscoveredEntitiesStore } from "../anonDiscovered.js";
import type { CustomEntitiesStore } from "../anonEntities.js";
import type { AssetOverridesStore } from "../assetOverrides.js";
import type { VelociraptorClientStore } from "../velociraptorClientStore.js";
import type { HostDuplicateDismissalStore } from "../hostDuplicateDismissals.js";
import type { ClockSkewStore } from "../clockSkewStore.js";
import { CorrelationProfileStore } from "../correlationProfile.js";
import type { FalsePositiveStore } from "../falsePositive.js";
import type { FindingsDiff } from "../findingsDiff.js";
import type { HuntOutcomeStore } from "../huntOutcomeStore.js";
import type { HypothesisStore } from "../hypothesisStore.js";
import type { ImportMetaStore } from "../importMeta.js";
import type { IncidentTypeStore } from "../incidentTypeStore.js";
import type { IocAliasStore } from "../iocAlias.js";
import type { KevStore } from "../kevStore.js";
import type { LearnedPatternStore } from "../learnedPatternStore.js";
import type { NotebookStore } from "../notebookStore.js";
import type { OcrRunner } from "../ocrRedact.js";
import type { OperationalMetricsStore } from "../operationalMetrics.js";
import type { PresidioClient } from "../presidio.js";
import type { PresidioPendingStore } from "../presidioPending.js";
import type { PlaybookStore } from "../playbookStore.js";
import type { ScopeStore } from "../scope.js";
import type { SecondOpinionStore } from "../secondOpinionStore.js";
import type { SourceTrustStore } from "../sourceTrustStore.js";
import type { StateLock } from "../stateLock.js";
import type { StateStore } from "../stateStore.js";
import type { InvestigationState } from "../stateTypes.js";
import type { SuperTimelineStore } from "../superTimelineStore.js";
import type { SynthMetaStore } from "../synthMeta.js";

/**
 * Everything an AnalysisPipeline can be wired with (#418).
 *
 * Moved out of pipeline.ts, which is now a facade over src/analysis/ai/. Almost every field here is
 * OPTIONAL and each one gates a feature: absent means the feature is simply off, which is how the
 * CLI scripts and most tests run with a fraction of the server's wiring. That is why the comments
 * matter more than usual — the type alone cannot tell you what NOT setting something costs you.
 *
 * The narrow context interfaces in this directory (AiCallContext, HuntContext, SynthesisContext, …)
 * are views onto this type. Each names the handful of fields its family may touch, so this stays the
 * single place a new option is declared while nothing gains access to it by accident.
 */
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
  operationalMetrics?: OperationalMetricsStore;
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
  // Analyst asset merges + the enrolled-fleet roster: together these resolve a host's short name,
  // FQDN and client id onto one canonical identity, so synthesis reads and ranks one host instead
  // of two. Absent → no resolution (the pre-gate behavior).
  assetOverridesStore?: AssetOverridesStore;
  velociraptorClientStore?: VelociraptorClientStore;
  // Pairs the analyst has judged to be different machines. Presence of this store is what ENABLES
  // the pre-synthesis merge gate: absent → the gate never runs, so CLI scripts and older tests are
  // unaffected. See analysis/hostDuplicateGate.ts.
  hostDuplicateDismissalStore?: HostDuplicateDismissalStore;
}
