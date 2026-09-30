import type { Express, Request, Response } from "express";
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { compareAnalysisRuns } from "../analysis/analysisRunCompare.js";
import { hashManifestValue } from "../analysis/analysisRunHash.js";
import { checkReplayAvailability, type ReplayEnvironment } from "../analysis/analysisRunReplay.js";
import { investigationOutput } from "../analysis/analysisRunSnapshot.js";
import type { AnalysisRunManifest } from "../analysis/analysisRunTypes.js";
import { createImportDebugRecorder, type ImportDebugRecorder } from "../analysis/importDebug.js";
import { IMPORT_KINDS } from "../analysis/importerSpec.js";
import { getCsvPrompt, getLogPrompt, getObservePrompt, getSynthesisPrompt } from "../analysis/pipeline.js";
import { createTaggerAccumulator, feedTaggerScope } from "../analysis/tagger.js";
import { runAndApplyTagger, type TaggerScope } from "../analysis/taggerRun.js";
import { defaultReportTemplate } from "../reports/reportTemplate.js";
import type { RouteContext } from "./context.js";
import { activeRulesHash, importReceiptOfCase } from "./importRunRecorder.js";
import { beginImportSection, type ImportSection } from "./importSection.js";
import { settleForensicImport } from "./importSettle.js";
import { routeSettleDeps } from "./routeSettleDeps.js";

// The replay-preflight inventory of every builtin importer's own pinned version. Derived from
// `IMPORT_KINDS` — the SAME single source of truth `importDetect.ts`'s own `ImportKind` union and
// `BUILTIN_KINDS`'s shadow guard already derive from (importerSpec.ts's own file header explains
// why: two hand-maintained copies of this list drifted once already, silently letting a custom
// importer shadow a builtin one). This list drifted the identical way: `okta`/`gws` (and, it turns
// out, `hindsight`/`macos`/`leapp`/`wer`/`linuxpersist`/`macospersist`/`rclone`) were missing here,
// which made replay-preflight report every import of those kinds as permanently unavailable
// (#1107). `"unknown"` is excluded — it is the detector's own no-match fallback, never an importer
// a manifest actually pins a version to.
export const BUILT_IN_IMPORT_KINDS = IMPORT_KINDS.filter((kind) => kind !== "unknown");

const CURRENT_SCHEMAS = [
  "investigation-state/v1",
  "tagger/v1",
  "enrichment/v1",
  "synthesis/v1",
  "deep-pass/v1",
  "report/v1",
];

function stringParameter(run: AnalysisRunManifest, key: string): string | undefined {
  const value = run.configuration?.parameters?.[key];
  return typeof value === "string" ? value : undefined;
}

function taggerScope(run: AnalysisRunManifest): TaggerScope {
  const scope = run.configuration?.filteringPolicy?.scope;
  if (scope === "both" || scope === "forensic" || scope === "super") return scope;
  throw new Error("tagger manifest has no valid scope");
}

function replayProvider(ctx: RouteContext, run: AnalysisRunManifest) {
  const { provider, model } = run.configuration ?? {};
  return provider && model ? ctx.options.pipeline?.analysisProvider(provider, model) : undefined;
}

async function selectedTemplateHash(ctx: RouteContext, caseId: string): Promise<string> {
  const { options } = ctx;
  if (!options.reportTemplateStore || !options.reportTemplateControlStore) {
    return hashManifestValue(defaultReportTemplate());
  }
  const { templateId } = await options.reportTemplateControlStore.load(caseId);
  const template = (await options.reportTemplateStore.get(templateId)) ?? defaultReportTemplate();
  return hashManifestValue(template);
}

async function artifactHashes(
  ctx: RouteContext,
  caseId: string,
  run: AnalysisRunManifest,
): Promise<Record<string, string>> {
  const base = resolve(ctx.store.caseDir(caseId));
  const out: Record<string, string> = {};
  for (const artifact of run.input.artifacts) {
    const path = resolve(base, artifact.path);
    if (path !== base && !path.startsWith(`${base}${sep}`)) continue;
    try {
      out[artifact.path] = createHash("sha256")
        .update(await readFile(path))
        .digest("hex");
    } catch {
      // Absence is represented by an omitted key; the preflight produces the actionable blocker.
    }
  }
  return out;
}

async function replayEnvironment(
  ctx: RouteContext,
  caseId: string,
  run: AnalysisRunManifest,
): Promise<ReplayEnvironment> {
  const { options } = ctx;
  const foundEvents = options.stateStore
    ? await options.stateStore.hasForensicEventIds(caseId, run.input.eventIds)
    : new Set<string>();
  const ruleHashes = options.taggerStore
    ? [hashManifestValue((await options.taggerStore.readActive()).text)]
    : [];
  const providerNames = (await ctx.enabledProvidersFor(caseId).catch(() => []))
    .map((provider) => provider.name)
    .sort();
  const importers = [
    ...BUILT_IN_IMPORT_KINDS.map((kind) => `${kind}/builtin-v1`),
    ...ctx.importerRegistry().meta.map((entry) => `${entry.id}/custom-v1`),
  ];
  return {
    artifacts: await artifactHashes(ctx, caseId, run),
    eventIds: [...foundEvents],
    providerModels: options.pipeline?.analysisProviderModels() ?? [],
    promptHashes: [
      hashManifestValue(getSynthesisPrompt()),
      hashManifestValue({ observe: getObservePrompt(), synthesis: getSynthesisPrompt() }),
      hashManifestValue(getCsvPrompt()),
      hashManifestValue(getLogPrompt()),
    ],
    templateHashes: [await selectedTemplateHash(ctx, caseId)],
    ruleHashes,
    importerVersions: importers,
    applicationVersions: [options.appVersion ?? "unknown"],
    schemaVersions: CURRENT_SCHEMAS,
    dataVersions: [hashManifestValue(providerNames)],
  };
}

async function replayImport(
  ctx: RouteContext,
  run: AnalysisRunManifest,
  debug?: ImportDebugRecorder,
): Promise<void> {
  const { options, store } = ctx;
  if (!options.stateStore || !options.analysisRunStore) throw new Error("analysis runs not configured");
  const artifact = run.input.artifacts[0];
  if (!artifact) throw new Error("import run has no source artifact");
  const kind = run.versions.importer?.split("/")[0];
  if (!kind) throw new Error("importer version is missing");
  const path = resolve(store.caseDir(run.caseId), artifact.path);
  // #1890: a replay imports into the case, so it holds the case's import section from its baseline
  // through its child run record, like every other import path (analysis/importLock.ts). Otherwise
  // an import running at the same time counts the replay's rows as its own (and sweeps them into its
  // undo checkpoint), and this receipt claims the other import's rows. Sized from the file on disk,
  // read inside the section: the source is already stored, so a memory-guard refusal loses nothing.
  const section = await beginImportSection(ctx.importLock, run.caseId, options.stateStore, {
    incomingBytes: (await stat(path)).size,
    wording: REPLAY_REFUSAL_WORDING,
  });
  try {
    const source: ReplaySource = {
      path,
      artifact,
      kind,
      stateStore: options.stateStore,
      runStore: options.analysisRunStore,
    };
    await replayImportSection(ctx, run, source, section, debug);
  } finally {
    section.release();
  }
  ctx.resynthesizeInBackground(run.caseId);
}

const REPLAY_REFUSAL_WORDING = {
  saved: "The replay's source file is still stored in the case",
  retry: "replay the run again",
};

interface ReplaySource {
  path: string;
  artifact: AnalysisRunManifest["input"]["artifacts"][number];
  kind: string;
  stateStore: NonNullable<RouteContext["options"]["stateStore"]>;
  runStore: NonNullable<RouteContext["options"]["analysisRunStore"]>;
}

/**
 * The replay itself, inside the case's import section: import, settle, child run record. #1891: it
 * settles through the same seam as a live import (routes/importSettle.ts) — super-timeline write,
 * content tagger, then demote — so a rule-promoted Info row is kept and kept rows reach the
 * super-timeline. That is settle parity with a live import run NOW (current rules and tagger
 * settings), not a full reproduction: the parent's severity floor and importer options are not
 * restored.
 */
async function replayImportSection(
  ctx: RouteContext,
  run: AnalysisRunManifest,
  { path, artifact, kind, stateStore, runStore }: ReplaySource,
  { baseline }: ImportSection,
  debug?: ImportDebugRecorder,
): Promise<void> {
  const settleDeps = routeSettleDeps(ctx);
  // Without a baseline there is nothing to settle or diff against: refuse before the case changes.
  if (!baseline || !settleDeps) throw new Error("the case could not be snapshotted for the replay");
  // Preflight checked the rules before the replay queued for the case; they may have changed while it
  // waited. Check again inside the section, and record the hash checked here (#1891 review).
  const rules = await activeRulesHash(ctx);
  if (run.versions.rules && rules !== run.versions.rules) {
    throw new Error("the tagger rules changed while the replay waited for the case");
  }
  const text = await readFile(path, "utf8");
  const startedAt = new Date().toISOString();
  const label = `replay-${run.id}`;
  // The kind is the recorded run's, so nothing was sniffed (#1736).
  debug?.detected(kind, { confident: true, decision: "replay" });
  await ctx.dispatchImport(kind, run.caseId, text, {
    label,
    ...(debug ? { debug } : {}),
    idPrefix: `replay-${Date.now()}`,
    importedAt: startedAt,
  });
  // The settle writes the "[import] … done" line itself (#1438).
  await settleForensicImport(settleDeps, run.caseId, baseline, label);
  // #1887: the same changed-only receipt a live import records (routes/importRunRecorder.ts).
  const receipt = await importReceiptOfCase(ctx, stateStore, run.caseId, baseline);
  await runStore.record(run.caseId, {
    kind: "import",
    parentRunId: run.id,
    startedAt,
    finishedAt: new Date().toISOString(),
    // The rules checked in the section — the active ones, as a live import records them.
    versions: { importer: run.versions.importer, schema: run.versions.schema, ...(rules ? { rules } : {}) },
    input: { artifacts: [artifact], ...receipt.input },
    configuration: run.configuration,
    output: receipt.output,
  });
}

async function replayTagger(ctx: RouteContext, run: AnalysisRunManifest): Promise<void> {
  const { options } = ctx;
  if (!options.taggerStore || !options.tagsStore || !options.stateStore || !options.analysisRunStore) {
    throw new Error("tagger or analysis runs not configured");
  }
  const startedAt = new Date().toISOString();
  const scope = taggerScope(run);
  const ruleset = await options.taggerStore.load();
  const state = await options.stateStore.load(run.caseId);
  // Streamed like the "Run tagger" route (#1444): the super side arrives one batch at a time.
  const acc = createTaggerAccumulator(ruleset);
  await feedTaggerScope(
    acc,
    scope,
    state.forensicTimeline,
    options.superTimelineStore ? options.superTimelineStore.eventBatches(run.caseId) : null,
  );
  const applied = await runAndApplyTagger({
    caseId: run.caseId,
    result: acc.finish(),
    ruleset,
    forensicTimeline: state.forensicTimeline,
    tagsStore: options.tagsStore,
    mutateForensic: scope !== "super",
  });
  const next = {
    ...state,
    forensicTimeline: applied.forensicTimeline,
    updatedAt: new Date().toISOString(),
  };
  if (applied.mutatedCount) await options.stateStore.save(next);
  await options.analysisRunStore.record(run.caseId, {
    kind: "deterministic",
    parentRunId: run.id,
    startedAt,
    finishedAt: new Date().toISOString(),
    versions: { schema: "tagger/v1", rules: run.versions.rules },
    input: {
      artifacts: [],
      // The forensic ids, as the manual "Run tagger" route records them (#1444): the super side
      // streamed through the accumulator and was never held as an array to list.
      eventIds: next.forensicTimeline.map((event) => event.id),
      entityIds: [],
    },
    configuration: run.configuration,
    output: investigationOutput(next),
  });
}

/**
 * Replay a synthesis run inside the SAME busy check as every other synthesis (#1599): an exclusive
 * `synthesis` job. It used to call synthesize() bare, so it could run alongside a live synthesis on
 * the same case — the overlap the anonymization switch caused on a lab case, by the same route.
 */
async function replaySynthesis(ctx: RouteContext, run: AnalysisRunManifest): Promise<void> {
  const { options } = ctx;
  if (!options.pipeline) throw new Error("pipeline not configured");
  // #1601: a replay runs the manifest's provider, not the current text model — name that one on
  // the job, so the served-model stamp matches the call that actually runs.
  const provider = replayProvider(ctx, run);
  const job = options.jobManager?.register({
    caseId: run.caseId,
    kind: "synthesis",
    label: "synthesis replay",
    cancellable: true,
    exclusive: true,
    ...(provider ? { model: { model: provider.model, provider: provider.name } } : {}),
  });
  try {
    await job?.ready;
    await options.pipeline.synthesize(run.caseId, {
      force: true,
      analysisParentRunId: run.id,
      provider,
      ...(job?.signal ? { signal: job.signal } : {}),
    });
    if (job) await options.jobManager?.finish(job.jobId);
  } catch (err) {
    if (job) await options.jobManager?.fail(job.jobId, err).catch(() => {});
    throw err;
  }
}

async function executeReplay(
  ctx: RouteContext,
  run: AnalysisRunManifest,
  debug?: ImportDebugRecorder,
): Promise<"completed" | "accepted"> {
  const { options } = ctx;
  switch (run.kind) {
    case "import":
      await replayImport(ctx, run, debug);
      return "completed";
    case "deterministic":
      await replayTagger(ctx, run);
      return "completed";
    case "enrichment":
      ctx.enrichInBackground(run.caseId, true, run.id);
      return "accepted";
    case "synthesis":
      await replaySynthesis(ctx, run);
      return "completed";
    case "deep-pass": {
      if (!options.pipeline) throw new Error("pipeline not configured");
      const floor = stringParameter(run, "minSeverity");
      if (floor !== "Critical" && floor !== "High" && floor !== "Medium" && floor !== "Low") {
        throw new Error("deep-pass manifest has no valid severity floor");
      }
      await options.pipeline.deepPass(run.caseId, {
        minSeverity: floor,
        analysisParentRunId: run.id,
        provider: replayProvider(ctx, run),
      });
      return "completed";
    }
    case "report":
      if (!options.reportWriter) throw new Error("report writer not configured");
      await options.reportWriter.writeAll(run.caseId, { parentRunId: run.id });
      return "completed";
  }
}

export function registerAnalysisRunRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/analysis-runs", async (req: Request, res: Response) => {
    if (!options.analysisRunStore) return res.status(501).json({ error: "analysis runs not configured" });
    const runs = await options.analysisRunStore.list(req.params.id);
    return res.status(200).json(
      runs.map((run) => ({
        id: run.id,
        sequence: run.sequence,
        kind: run.kind,
        status: run.status,
        parentRunId: run.parentRunId,
        startedAt: run.startedAt,
        finishedAt: run.finishedAt,
        durationMs: run.durationMs,
        versions: run.versions,
        configuration: run.configuration,
        execution: run.execution,
        input: {
          artifacts: run.input.artifacts,
          eventCount: run.input.eventIds.length,
          // #1887: an import receipt counts its entities; older manifests list them all.
          entityCount: run.input.entityCount ?? run.input.entityIds.length,
        },
        output: {
          entityCount: run.output.entityCount ?? run.output.entityIds.length,
          claimCount: run.output.claims.length,
        },
        manifestHash: run.manifestHash,
      })),
    );
  });

  app.get("/cases/:id/analysis-runs/integrity", async (req: Request, res: Response) => {
    if (!options.analysisRunStore) return res.status(501).json({ error: "analysis runs not configured" });
    const result = await options.analysisRunStore.verify(req.params.id);
    return res.status(result.ok ? 200 : 409).json(result);
  });

  app.get("/cases/:id/analysis-runs/compare", async (req: Request, res: Response) => {
    if (!options.analysisRunStore) return res.status(501).json({ error: "analysis runs not configured" });
    const fromId = typeof req.query.from === "string" ? req.query.from : "";
    const toId = typeof req.query.to === "string" ? req.query.to : "";
    if (!fromId || !toId) return res.status(400).json({ error: "from and to are required" });
    const [from, to] = await Promise.all([
      options.analysisRunStore.get(req.params.id, fromId),
      options.analysisRunStore.get(req.params.id, toId),
    ]);
    if (!from || !to) return res.status(404).json({ error: "analysis run not found" });
    return res.status(200).json(compareAnalysisRuns(from, to));
  });

  app.get("/cases/:id/analysis-runs/:runId", async (req: Request, res: Response) => {
    if (!options.analysisRunStore) return res.status(501).json({ error: "analysis runs not configured" });
    const run = await options.analysisRunStore.get(req.params.id, req.params.runId);
    return run ? res.status(200).json(run) : res.status(404).json({ error: "analysis run not found" });
  });

  app.post("/cases/:id/analysis-runs/:runId/replay", async (req: Request, res: Response) => {
    if (!options.analysisRunStore) return res.status(501).json({ error: "analysis runs not configured" });
    const run = await options.analysisRunStore.get(req.params.id, req.params.runId);
    if (!run) return res.status(404).json({ error: "analysis run not found" });
    const preflight = checkReplayAvailability(run, await replayEnvironment(ctx, req.params.id, run));
    if (!preflight.ready) return res.status(409).json(preflight);
    // An import replay is an import attempt, so it carries its own recorder (#1736).
    const debug = run.kind === "import" ? createImportDebugRecorder() : undefined;
    try {
      const status = await executeReplay(ctx, run, debug);
      return res.status(status === "accepted" ? 202 : 200).json({ accepted: true, parentRunId: run.id });
    } catch (err) {
      ctx.recordImportFailure(run.caseId, "replay", `replay-${run.id}`, err, debug); // the [import] FAILED line (#1438)
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
