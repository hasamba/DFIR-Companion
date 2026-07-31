import type { AnalysisRunManifest } from "./analysisRunTypes.js";

export interface ReplayEnvironment {
  artifacts: Record<string, string>;
  eventIds: string[];
  providerModels: Array<{ provider: string; model: string }>;
  promptHashes: string[];
  templateHashes: string[];
  ruleHashes: string[];
  importerVersions: string[];
  applicationVersions?: string[];
  schemaVersions?: string[];
  dataVersions?: string[];
}

export interface ReplayPreflight {
  ready: boolean;
  blockers: string[];
}

export function checkReplayAvailability(
  run: AnalysisRunManifest,
  environment: ReplayEnvironment,
): ReplayPreflight {
  const blockers: string[] = [];
  for (const artifact of run.input.artifacts) {
    const current = environment.artifacts[artifact.path];
    if (!current) blockers.push(`source artifact unavailable: ${artifact.path}`);
    else if (current !== artifact.sha256) blockers.push(`source artifact changed: ${artifact.path}`);
  }
  const eventIds = new Set(environment.eventIds);
  for (const eventId of run.input.eventIds) {
    if (!eventIds.has(eventId)) blockers.push(`source event unavailable: ${eventId}`);
  }
  const config = run.configuration;
  if (config?.provider && config.model) {
    const available = environment.providerModels.some(
      (entry) => entry.provider === config.provider && entry.model === config.model,
    );
    if (!available) blockers.push(`provider/model unavailable: ${config.provider}/${config.model}`);
  }
  if (config?.promptHash && !environment.promptHashes.includes(config.promptHash)) {
    blockers.push(`prompt version unavailable: ${config.promptHash}`);
  }
  if (config?.templateHash && !environment.templateHashes.includes(config.templateHash)) {
    blockers.push(`template version unavailable: ${config.templateHash}`);
  }
  if (run.versions.rules && !environment.ruleHashes.includes(run.versions.rules)) {
    blockers.push(`rules version unavailable: ${run.versions.rules}`);
  }
  if (run.versions.importer && !environment.importerVersions.includes(run.versions.importer)) {
    blockers.push(`importer version unavailable: ${run.versions.importer}`);
  }
  if (
    environment.applicationVersions &&
    !environment.applicationVersions.includes(run.versions.application)
  ) {
    blockers.push(`application version unavailable: ${run.versions.application}`);
  }
  if (
    run.versions.schema &&
    environment.schemaVersions &&
    !environment.schemaVersions.includes(run.versions.schema)
  ) {
    blockers.push(`schema version unavailable: ${run.versions.schema}`);
  }
  if (
    run.versions.data &&
    environment.dataVersions &&
    !environment.dataVersions.includes(run.versions.data)
  ) {
    blockers.push(`data version unavailable: ${run.versions.data}`);
  }
  return { ready: blockers.length === 0, blockers };
}
