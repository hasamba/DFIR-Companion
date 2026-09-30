import { hashManifestValue } from "../analysis/analysisRunHash.js";
import {
  importedArtifact,
  investigationFingerprintOfCase,
  STATE_HASH_ID,
} from "../analysis/analysisRunSnapshot.js";
import { baselineEntities, toImportBaseline, type ImportBaseline } from "../analysis/importBaseline.js";
import { importReceipt } from "../analysis/runEntityDelta.js";
import { getCsvPrompt, getLogPrompt } from "../analysis/pipeline.js";
import type { InvestigationState, Severity } from "../analysis/stateTypes.js";
import type { ManifestValue } from "../analysis/analysisRunTypes.js";
import type { StateStore } from "../analysis/stateStore.js";
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

/**
 * The case after the import, read inside the state lock (#1887): the fingerprint (hash id
 * STATE_HASH_ID) and the forensic and IOC ids in order, index-only. One exclusive section, so the
 * counts, the delta and the hash describe one snapshot. The fingerprint refreshes row facts and
 * migrates the case first, so the IOC read that follows finds the database.
 */
async function caseAfterImport(ctx: RouteContext, stateStore: StateStore, caseId: string) {
  return ctx.runStateExclusive(caseId, async () => {
    const fingerprint = await investigationFingerprintOfCase(stateStore, caseId);
    const events = await stateStore.forensicOutline(caseId, false);
    const iocs = await stateStore.iocJournal.outline(caseId);
    return { fingerprint, entities: [...events.ids, ...(iocs?.ids ?? [])] };
  });
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
  // #1887: the receipt lists what the import added and removed (events + IOCs) and the counts before
  // and after, not every id the case holds; the fingerprint still covers the whole case.
  const before = input.baseline ? baselineEntities(toImportBaseline(input.baseline)) : [];
  const after = await caseAfterImport(ctx, stateStore, input.caseId);
  const receipt = importReceipt(
    before,
    after.entities,
    [{ id: STATE_HASH_ID, sha256: after.fingerprint.sha256 }],
    after.fingerprint.findings,
  );
  await options.analysisRunStore.record(input.caseId, {
    kind: "import",
    startedAt: input.startedAt,
    finishedAt: new Date().toISOString(),
    versions: {
      importer: `${input.kind}/${ctx.importerRegistry().importers.has(input.kind) ? "custom-v1" : "builtin-v1"}`,
      schema: "investigation-state/v1",
      ...(rules ? { rules } : {}),
    },
    input: { artifacts: [await importedArtifact(store, input.caseId, input.storedName)], ...receipt.input },
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
    output: receipt.output,
  });
}
