import { hashManifestValue } from "../analysis/analysisRunHash.js";
import { SCAN_PAGE_ROWS } from "../analysis/forensicRows.js";
import { importedArtifact, investigationOutputStreamed } from "../analysis/analysisRunSnapshot.js";
import { baselineEntityIds, toImportBaseline, type ImportBaseline } from "../analysis/importBaseline.js";
import { getCsvPrompt, getLogPrompt } from "../analysis/pipeline.js";
import type { InvestigationState, Severity } from "../analysis/stateTypes.js";
import type { ManifestValue } from "../analysis/analysisRunTypes.js";
import type { RouteContext } from "./context.js";

export interface ImportRunRecord {
  caseId: string;
  kind: string;
  storedName: string;
  startedAt: string;
  /** What the import was diffed against: the section's baseline, or a full state (job resume). */
  baseline: ImportBaseline | InvestigationState | null;
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
  const stateStore = options.stateStore;
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
      entityIds: input.baseline ? baselineEntityIds(toImportBaseline(input.baseline)) : [],
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
    // Streamed (#1874): the output hash covers the whole case, read a page at a time.
    // Inside the state lock, so no writer lands between the overview and the pages it hashes.
    output: await ctx.runStateExclusive(input.caseId, async () =>
      investigationOutputStreamed(
        await stateStore.loadOverview(input.caseId),
        stateStore.forensicTimelineBatches(input.caseId, { limit: SCAN_PAGE_ROWS }),
      ),
    ),
  });
}
