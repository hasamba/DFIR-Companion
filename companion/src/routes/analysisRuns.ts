import type { Express, Request, Response } from "express";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { compareAnalysisRuns } from "../analysis/analysisRunCompare.js";
import { hashManifestValue } from "../analysis/analysisRunHash.js";
import { checkReplayAvailability, type ReplayEnvironment } from "../analysis/analysisRunReplay.js";
import { investigationOutput } from "../analysis/analysisRunSnapshot.js";
import type { AnalysisRunManifest } from "../analysis/analysisRunTypes.js";
import { getCsvPrompt, getLogPrompt, getObservePrompt, getSynthesisPrompt } from "../analysis/pipeline.js";
import { selectScopedEvents } from "../analysis/tagger.js";
import { runAndApplyTagger, type TaggerScope } from "../analysis/taggerRun.js";
import { defaultReportTemplate } from "../reports/reportTemplate.js";
import type { RouteContext } from "./context.js";

const BUILT_IN_IMPORT_KINDS = [
  "thor",
  "siem",
  "evtxxml",
  "chainsaw",
  "hayabusa",
  "velociraptor",
  "securityonion",
  "socrates",
  "network",
  "kape",
  "cybertriage",
  "m365",
  "aws",
  "cloud",
  "k8s",
  "osquery",
  "plaso",
  "sandbox",
  "memory",
  "email",
  "thehive",
  "auditd",
  "journald",
  "sysdig",
  "wazuh",
  "bashhistory",
  "ecar",
  "snort",
  "yara",
  "combinedlog",
  "asa",
  "syslog",
  "csv",
  "log",
] as const;

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

async function replayImport(ctx: RouteContext, run: AnalysisRunManifest): Promise<void> {
  const { options, store } = ctx;
  if (!options.stateStore || !options.analysisRunStore) throw new Error("analysis runs not configured");
  const artifact = run.input.artifacts[0];
  if (!artifact) throw new Error("import run has no source artifact");
  const kind = run.versions.importer?.split("/")[0];
  if (!kind) throw new Error("importer version is missing");
  const text = await readFile(resolve(store.caseDir(run.caseId), artifact.path), "utf8");
  const startedAt = new Date().toISOString();
  const before = await options.stateStore.load(run.caseId);
  await ctx.dispatchImport(kind, run.caseId, text, {
    label: `replay-${run.id}`,
    idPrefix: `replay-${Date.now()}`,
    importedAt: startedAt,
  });
  const after = await ctx.demoteForensicForCase(run.caseId);
  await options.analysisRunStore.record(run.caseId, {
    kind: "import",
    parentRunId: run.id,
    startedAt,
    finishedAt: new Date().toISOString(),
    versions: {
      importer: run.versions.importer,
      schema: run.versions.schema,
      rules: run.versions.rules,
    },
    input: {
      artifacts: [artifact],
      eventIds: [],
      entityIds: [...before.forensicTimeline.map((event) => event.id), ...before.iocs.map((ioc) => ioc.id)],
    },
    configuration: run.configuration,
    output: investigationOutput(after),
  });
  ctx.resynthesizeInBackground(run.caseId);
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
  const superEvents =
    scope !== "forensic" && options.superTimelineStore
      ? await options.superTimelineStore.all(run.caseId)
      : [];
  const events = selectScopedEvents(scope, state.forensicTimeline, superEvents);
  const applied = await runAndApplyTagger({
    caseId: run.caseId,
    events,
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
      eventIds: events.map((event) => event.id),
      entityIds: [],
    },
    configuration: run.configuration,
    output: investigationOutput(next),
  });
}

async function executeReplay(ctx: RouteContext, run: AnalysisRunManifest): Promise<"completed" | "accepted"> {
  const { options } = ctx;
  switch (run.kind) {
    case "import":
      await replayImport(ctx, run);
      return "completed";
    case "deterministic":
      await replayTagger(ctx, run);
      return "completed";
    case "enrichment":
      ctx.enrichInBackground(run.caseId, true, run.id);
      return "accepted";
    case "synthesis":
      if (!options.pipeline) throw new Error("pipeline not configured");
      await options.pipeline.synthesize(run.caseId, {
        force: true,
        analysisParentRunId: run.id,
        provider: replayProvider(ctx, run),
      });
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
          entityCount: run.input.entityIds.length,
        },
        output: {
          entityCount: run.output.entityIds.length,
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
    try {
      const status = await executeReplay(ctx, run);
      return res.status(status === "accepted" ? 202 : 200).json({ accepted: true, parentRunId: run.id });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
