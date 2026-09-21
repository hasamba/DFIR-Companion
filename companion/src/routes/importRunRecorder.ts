import { hashManifestValue } from "../analysis/analysisRunHash.js";
import { importedArtifact, investigationOutput } from "../analysis/analysisRunSnapshot.js";
import { getCsvPrompt, getLogPrompt } from "../analysis/pipeline.js";
import type { InvestigationState, Severity } from "../analysis/stateTypes.js";
import type { ManifestValue } from "../analysis/analysisRunTypes.js";
import type { RouteContext } from "./context.js";

export interface ImportRunRecord {
  caseId: string;
  kind: string;
  storedName: string;
  startedAt: string;
  stateBefore: InvestigationState | null;
  minSeverity: Severity | undefined;
  assetHost?: string; // the analyst-declared host for this import (#1496) — part of what shaped the run
  path: "ai" | "deterministic";
  /**
   * The importer options the route parsed beyond the severity floor (THOR `minLevel`, Cyber
   * Triage `fileTelemetry`, LEAPP `platform`, …), keyed by importer. They change what the run
   * produced, so a manifest that omits them does not describe a reproducible run.
   */
  parameters?: Record<string, ManifestValue>;
}

export async function recordImportRun(ctx: RouteContext, input: ImportRunRecord): Promise<void> {
  const { options, store } = ctx;
  if (!options.analysisRunStore || !options.stateStore) return;
  const state = await options.stateStore.load(input.caseId);
  const textProvider = input.path === "ai" ? options.pipeline?.analysisTextProviderModel() : null;
  const prompt = input.kind === "csv" ? getCsvPrompt() : input.kind === "log" ? getLogPrompt() : null;
  const rules = options.taggerStore
    ? hashManifestValue((await options.taggerStore.readActive()).text)
    : undefined;
  await options.analysisRunStore.record(input.caseId, {
    kind: "import",
    startedAt: input.startedAt,
    finishedAt: new Date().toISOString(),
    versions: {
      importer: `${input.kind}/${ctx.importerRegistry().importers.has(input.kind) ? "custom-v1" : "builtin-v1"}`,
      schema: "investigation-state/v1",
      ...(rules ? { rules } : {}),
    },
    input: {
      artifacts: [await importedArtifact(store, input.caseId, input.storedName)],
      eventIds: [],
      entityIds: input.stateBefore
        ? [
            ...input.stateBefore.forensicTimeline.map((event) => event.id),
            ...input.stateBefore.iocs.map((ioc) => ioc.id),
          ]
        : [],
    },
    configuration: {
      ...(textProvider ?? {}),
      ...(prompt ? { promptHash: hashManifestValue(prompt) } : {}),
      parameters: {
        importPath: input.path,
        minSeverity: input.minSeverity ?? null,
        ...(input.assetHost ? { assetHost: input.assetHost } : {}), // the analyst's declaration is on the record (#1496)
        ...(input.parameters ?? {}),
      },
      filteringPolicy: {
        forensicMinimumSeverity: input.minSeverity ?? "case-default",
      },
    },
    output: investigationOutput(state),
  });
}
