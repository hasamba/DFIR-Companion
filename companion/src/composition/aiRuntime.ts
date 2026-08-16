/**
 * The AI runtime a real server run wires: four model providers, the optional Presidio gate, the OCR
 * runner, and the AnalysisPipeline that binds them to the case stores. Lifted out of startServer
 * by #416.
 *
 * FOUR PROVIDERS, NOT ONE, and the split is the point: a cheap vision model reads screenshots, a
 * stronger text model synthesizes, a dedicated model generates Velociraptor VQL (many models botch
 * it), and an opt-in second-opinion model cross-checks. Each can be absent — `undefined` disables
 * that capability rather than failing startup, which is what lets the companion run with no AI at
 * all and still import, detect and report.
 *
 * THE OCR RUNNER IS CONDITIONAL ON WHERE THE MODEL RUNS. It exists to redact PII out of the copy of
 * a screenshot that is SENT to the model — so if the model is local, nothing leaves the machine and
 * redaction is optional. Note that createApp is given its own unconditional runner regardless: the
 * redacted-export route needs OCR even when the pipeline does not.
 */
import type { CaseStore } from "../storage/caseStore.js";
import type { StateStore } from "../analysis/stateStore.js";
import type { StateLock } from "../analysis/stateLock.js";
import type { Logger } from "../logging/logger.js";
import type { KevStore } from "../analysis/kevStore.js";
import type { ClockSkewStore } from "../analysis/clockSkewStore.js";
import type { IncidentTypeStore } from "../analysis/incidentTypeStore.js";
import type { AnalysisRunStore } from "../analysis/analysisRunStore.js";
import type { OperationalMetricsStore } from "../analysis/operationalMetrics.js";
import type { SecondOpinionStore } from "../analysis/secondOpinionStore.js";
import type { VelociraptorClientStore } from "../analysis/velociraptorClientStore.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import type { Notifier } from "../integrations/notify/notifyDispatch.js";
import { PresidioPendingStore } from "../analysis/presidioPending.js";
import {
  HttpPresidioClient,
  resolvePresidioMinScore,
  resolvePresidioTimeoutMs,
} from "../analysis/presidio.js";
import { TesseractOcrRunner } from "../analysis/ocrRedact.js";
import { isLocalAiProvider } from "../analysis/anonymize.js";
import { visionEnv } from "../config/aiEnv.js";
import { findingEventsFromDiff } from "../analysis/notifications.js";
import {
  buildProvider,
  buildSynthesisProvider,
  buildVelociraptorProvider,
  buildSecondOpinionProvider,
  buildRuntimePipeline,
} from "./aiProviders.js";
import { logLine } from "../logging/serverLogger.js";

export interface AiRuntimeDeps {
  store: CaseStore;
  stateStore: StateStore;
  stateLock: StateLock;
  logger: Logger;
  kevStore: KevStore;
  clockSkewStore: ClockSkewStore;
  incidentTypeStore: IncidentTypeStore;
  analysisRunStore: AnalysisRunStore;
  operationalMetrics: OperationalMetricsStore;
  secondOpinionStore: SecondOpinionStore;
  velociraptorClientStore?: VelociraptorClientStore;
  notifier: Notifier;
  dashboardBaseUrl: string;
  /** Broadcast a fresh state to live dashboards (the LiveHub's broadcast). */
  onState: (state: InvestigationState) => void;
}

export function buildAiRuntime(deps: AiRuntimeDeps) {
  const {
    store,
    stateStore,
    stateLock,
    logger,
    kevStore,
    clockSkewStore,
    incidentTypeStore,
    analysisRunStore,
    operationalMetrics,
    secondOpinionStore,
    velociraptorClientStore,
    notifier,
    dashboardBaseUrl,
    onState,
  } = deps;
  const provider = buildProvider();
  const synthesisProvider = buildSynthesisProvider();
  const velociraptorProvider = buildVelociraptorProvider(); // dedicated VQL-hunt model (#70)
  const secondOpinionProvider = buildSecondOpinionProvider(); // dedicated second-opinion model (#116)
  // Model labels for the second-opinion comparison header (fall back to provider name in the pipeline).
  const synthesisModelLabel = process.env.DFIR_AI_SYNTH_MODEL ?? visionEnv(process.env, "MODEL") ?? undefined;
  const secondOpinionModelLabel = process.env.DFIR_AI_SECOND_OPINION_MODEL?.trim() || undefined;
  if (secondOpinionProvider)
    logLine(`[second-opinion] enabled — model "${secondOpinionModelLabel}" (${secondOpinionProvider.name})`);
  // Provide the Tesseract OCR runner only when the vision model is on an external (cloud)
  // provider — if the model is local, screenshots never leave the machine so redaction is
  // optional. Evidence-first: the runner only redacts the in-memory copy sent to the model.
  const visionIsLocalForPipeline = isLocalAiProvider(
    visionEnv(process.env, "PROVIDER"),
    visionEnv(process.env, "BASE_URL"),
  );
  const ocrRunner = !visionIsLocalForPipeline ? new TesseractOcrRunner() : undefined;
  // Optional Presidio layer (Task 7): a locally-run container that scans the ALREADY-MASKED
  // prompt for PII our own regex/exact-match anonymizer missed (principally names). Empty/unset
  // URL → presidio stays undefined and every code path in the pipeline gate is skipped, so
  // existing behaviour is completely unchanged when the analyst has not opted in.
  const presidioUrl = (process.env.DFIR_PRESIDIO_URL ?? "").trim();
  const presidioMinScore = resolvePresidioMinScore(process.env.DFIR_PRESIDIO_MIN_SCORE);
  const presidioTimeoutMs = resolvePresidioTimeoutMs(process.env.DFIR_PRESIDIO_TIMEOUT_MS);
  const presidio = presidioUrl
    ? {
        client: new HttpPresidioClient(presidioUrl, presidioTimeoutMs),
        url: presidioUrl,
        minScore: presidioMinScore,
      }
    : undefined;
  if (presidio)
    logLine(
      `[presidio] enabled — scanning masked AI prompts via ${presidioUrl} ` +
        `(minScore ${presidio.minScore}, ${presidioTimeoutMs}ms per request)`,
    );
  const wiredPipeline = buildRuntimePipeline({
    provider,
    synthesisProvider,
    velociraptorProvider,
    stateStore,
    store,
    stateLock,
    onState,
    ocrRunner,
    logger,
    kevStore,
    clockSkewStore,
    incidentTypeStore,
    analysisRunStore,
    operationalMetrics,
    velociraptorClientStore,
    presidio,
    presidioPendingStore: new PresidioPendingStore(store),
    secondOpinionProvider,
    secondOpinionStore,
    synthesisModelLabel,
    secondOpinionModelLabel,
    // After a real synthesis, page the matching channels for each new/escalated finding (#58).
    // Fully guarded — notifications are a side channel and must NEVER break synthesis.
    onSynth: (caseId, diff, state) => {
      try {
        const url = `${dashboardBaseUrl}/dashboard?caseId=${encodeURIComponent(caseId)}`;
        for (const ev of findingEventsFromDiff(caseId, diff, state.findings, state.updatedAt)) {
          notifier
            .dispatch({ ...ev, url })
            .catch((err) => logLine(`[notify] dispatch error: ${(err as Error).message}`));
        }
      } catch (err) {
        logLine(`[notify] onSynth error: ${(err as Error).message}`);
      }
    },
  });
  return { provider, secondOpinionProvider, ocrRunner, wiredPipeline };
}
