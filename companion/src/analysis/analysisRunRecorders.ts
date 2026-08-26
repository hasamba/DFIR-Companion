import type { EnrichSummary } from "../enrichment/enrichService.js";
import type { AIProvider } from "../providers/provider.js";
import type { AnonPolicy } from "./anonymize.js";
import { claimSnapshot, hashManifestValue } from "./analysisRunHash.js";
import { investigationOutput } from "./analysisRunSnapshot.js";
import type { AnalysisRunStore } from "./analysisRunStore.js";
import type { ScopeWindow } from "./scope.js";
import type { InvestigationState, Severity } from "./stateTypes.js";
import type { SynthesisCoverage } from "./synthMeta.js";

export function uniqueProviderModels(
  providers: Array<AIProvider | undefined>,
): Array<{ provider: string; model: string }> {
  const configured = providers.filter((provider): provider is AIProvider => provider !== undefined);
  return [
    ...new Map(
      configured.map((provider) => [
        `${provider.name}\n${provider.model}`,
        { provider: provider.name, model: provider.model },
      ]),
    ).values(),
  ];
}

interface DeepPassRecord {
  id: string;
  parentRunId?: string;
  startedAt: string;
  status?: "completed" | "failed";
  error?: string;
  provider: string;
  model: string;
  eventIds: string[];
  minSeverity: Severity;
  maxBatches: number;
  rowsPerBatch: number;
  scope: ScopeWindow;
  falsePositiveMarkers: number;
  batchesFailed: number;
  output: InvestigationState;
  observePrompt: string;
  synthesisPrompt: string;
}

export async function recordDeepPassRun(
  store: AnalysisRunStore | undefined,
  caseId: string,
  input: DeepPassRecord,
): Promise<void> {
  if (!store) return;
  await store.record(caseId, {
    id: input.id,
    kind: "deep-pass",
    parentRunId: input.parentRunId,
    status: input.status,
    error: input.error,
    startedAt: input.startedAt,
    finishedAt: new Date().toISOString(),
    versions: { schema: "deep-pass/v1" },
    input: {
      artifacts: [],
      eventIds: input.eventIds,
      entityIds: [],
      selectionHash: hashManifestValue(input.eventIds),
    },
    configuration: {
      promptHash: hashManifestValue({
        observe: input.observePrompt,
        synthesis: input.synthesisPrompt,
      }),
      provider: input.provider,
      model: input.model,
      parameters: {
        minSeverity: input.minSeverity,
        maxBatches: input.maxBatches,
        rowsPerBatch: input.rowsPerBatch,
      },
      filteringPolicy: {
        scope: { ...input.scope },
        falsePositiveMarkers: input.falsePositiveMarkers,
        infoEventsExcluded: true,
      },
    },
    execution: {
      retries: input.batchesFailed,
      warnings: input.batchesFailed
        ? [`${input.batchesFailed} batch(es) produced no usable observations`]
        : [],
    },
    output:
      input.status === "failed"
        ? { entityIds: [], hashes: [], claims: [] }
        : {
            entityIds: input.output.findings.map((finding) => finding.id),
            hashes: [
              {
                id: "investigation-conclusions",
                sha256: hashManifestValue(input.output.findings),
              },
            ],
            claims: input.output.findings.map((finding) =>
              claimSnapshot(finding.id, {
                title: finding.title,
                severity: finding.severity,
                description: finding.description,
                evidenceEventIds: finding.relatedEventIds,
              }),
            ),
          },
  });
}

interface SynthesisRecord {
  parentRunId?: string;
  startedAt: string;
  provider: string;
  model: string;
  eventIds: string[];
  inputState: InvestigationState;
  outputState: InvestigationState;
  prompt: string;
  maxEvents: number;
  thinkingTokens: number;
  correlationWindowSeconds: number;
  anonymizationPolicy: AnonPolicy;
  scope: ScopeWindow;
  falsePositiveMarkers: number;
  infoEventsExcluded: boolean;
  observationsIncluded: boolean;
  parseRetries: number;
  coverage: SynthesisCoverage;
}

export async function recordSynthesisRun(
  store: AnalysisRunStore | undefined,
  caseId: string,
  input: SynthesisRecord,
): Promise<void> {
  if (!store) return;
  await store.record(caseId, {
    kind: "synthesis",
    parentRunId: input.parentRunId,
    startedAt: input.startedAt,
    finishedAt: new Date().toISOString(),
    versions: { schema: "synthesis/v1" },
    input: {
      artifacts: [],
      eventIds: input.eventIds,
      entityIds: input.inputState.iocs.map((ioc) => ioc.id),
      selectionHash: hashManifestValue({
        eventIds: [...input.eventIds].sort(),
        existingFindingIds: input.inputState.findings.map((finding) => finding.id).sort(),
      }),
    },
    configuration: {
      promptHash: hashManifestValue(input.prompt),
      provider: input.provider,
      model: input.model,
      parameters: {
        maxEvents: input.maxEvents,
        thinkingTokens: input.thinkingTokens,
        correlationWindowSeconds: input.correlationWindowSeconds,
      },
      anonymizationPolicy: {
        enabled: input.anonymizationPolicy.enabled,
        categories: { ...input.anonymizationPolicy.categories },
        redactSecrets: input.anonymizationPolicy.redactSecrets,
        maskPublicIps: input.anonymizationPolicy.maskPublicIps,
      },
      filteringPolicy: {
        scope: { ...input.scope },
        falsePositiveMarkers: input.falsePositiveMarkers,
        infoEventsExcluded: input.infoEventsExcluded,
        observationsIncluded: input.observationsIncluded,
      },
    },
    execution: {
      retries: input.parseRetries,
      warnings: [
        ...(input.coverage.omittedBudget > 0
          ? [`${input.coverage.omittedBudget} event(s) omitted by the prompt budget`]
          : []),
        ...(input.coverage.omittedHighSeverity > 0
          ? [`${input.coverage.omittedHighSeverity} high-severity event(s) used deterministic backfill`]
          : []),
      ],
    },
    output: {
      entityIds: input.outputState.findings.map((finding) => finding.id),
      hashes: [
        {
          id: "investigation-conclusions",
          sha256: hashManifestValue({
            findings: input.outputState.findings,
            attackerPath: input.outputState.attackerPath,
            keyQuestions: input.outputState.keyQuestions,
            nextSteps: input.outputState.nextSteps,
          }),
        },
      ],
      claims: input.outputState.findings.map((finding) =>
        claimSnapshot(finding.id, {
          title: finding.title,
          severity: finding.severity,
          description: finding.description,
          evidenceEventIds: finding.relatedEventIds,
        }),
      ),
    },
  });
}

interface EnrichmentRecord {
  parentRunId?: string;
  startedAt: string;
  providerNames: string[];
  force: boolean;
  maxIocs: number;
  delayMs: number;
  inputState: InvestigationState;
  outputState: InvestigationState;
  summary: EnrichSummary;
}

export async function recordEnrichmentRun(
  store: AnalysisRunStore | undefined,
  caseId: string,
  input: EnrichmentRecord,
): Promise<void> {
  if (!store) return;
  await store.record(caseId, {
    kind: "enrichment",
    parentRunId: input.parentRunId,
    startedAt: input.startedAt,
    finishedAt: new Date().toISOString(),
    versions: {
      schema: "enrichment/v1",
      data: hashManifestValue([...input.providerNames].sort()),
    },
    input: {
      artifacts: [],
      eventIds: input.inputState.forensicTimeline
        .filter((event) => event.processName && event.parentName)
        .map((event) => event.id),
      entityIds: input.inputState.iocs.map((ioc) => ioc.id),
    },
    configuration: {
      provider: input.providerNames.join(","),
      parameters: {
        force: input.force,
        maxIocs: input.maxIocs,
        delayMs: input.delayMs,
      },
      filteringPolicy: {
        enabledProviders: input.providerNames,
        alreadyEnrichedSkipped: !input.force,
      },
    },
    execution: {
      retries: 0,
      warnings: [
        ...(input.summary.errors ? [`${input.summary.errors} provider lookup error(s)`] : []),
        ...(input.summary.unavailable.length
          ? [`unavailable providers: ${input.summary.unavailable.join(", ")}`]
          : []),
        // The cap deferring work is a property of THIS run, and the ledger is what a reviewer
        // reads to know whether the case was enriched completely.
        ...(input.summary.capped ? [`${input.summary.capped} IOC(s) deferred by maxIocs`] : []),
      ],
    },
    output: investigationOutput(input.outputState),
  });
}
