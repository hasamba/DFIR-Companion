// AI Agent Forensics (#2690): the run lifecycle behind the panel.
//
//   start      — inside a case, or (no case open) in a NEW hidden sweep case linked to the chosen
//                server set with AI analysis off. Preflight → generate the artifact from the live rule
//                set → launch on the chosen endpoints → register the hunt like any bundle hunt (so the
//                existing collect imports hits into the forensic timeline and inventory into the
//                super-timeline) with the manifest-only upload policy → record the run.
//   refresh    — read the run's raw result rows back from Velociraptor, build the results-only report
//                (snippets redacted, panel/report only) and the upload manifest. Never reads upload contents.
//   addToCase  — file a sweep's rows into a real case through the evidence-first ingest, under that
//                case's import lock. No re-collection.
//   retention  — keep the newest SWEEP_RETENTION sweep cases; older ones lose only the Companion copy.

import type { CaseStore } from "../../storage/caseStore.js";
import type { ServerClients } from "../serverSets/types.js";
import type { ServerSetStore } from "../serverSets/serverSetStore.js";
import type { VeloHuntJob, VeloHuntStore } from "../../analysis/veloHuntStore.js";
import type { VelociraptorClient } from "./velociraptorApi.js";
import { activeAiAgentRuleSet } from "../../analysis/aiAgentActiveRules.js";
import { buildAiAgentReport } from "../../analysis/aiAgentReport.js";
import {
  AiAgentRunStore,
  capManifest,
  newAiAgentRunId,
  type AiAgentRun,
} from "../../analysis/aiAgentRunStore.js";
import { AI_AGENT_DEFAULT_UPLOAD_MAX_BYTES, buildAiAgentArtifact } from "./aiAgentArtifact.js";
import { AI_AGENT_HUNT_EXPIRY_SECONDS, launchAiAgentRun } from "./aiAgentLaunch.js";
import { preflightAiAgentRun, type AiAgentEndpoint } from "./aiAgentPreflight.js";
import { readUploadManifest } from "./uploadVql.js";
import { CLIENT_RE } from "./clientInventory.js";
import {
  SWEEP_CASE_KIND,
  isSweepCase,
  newSweepCaseId,
  sweepsBeyondRetention,
} from "../../storage/sweepCase.js";

export const AI_AGENT_BUNDLE_ID = "ai-agent-forensics";
const BUNDLE_NAME = "AI Agent Forensics (sensitive)";
const DEFAULT_WAIT_MINUTES = 30;
const MAX_ENDPOINTS = 200;
const MAX_STORED_ROWS = 20_000;

export class AiAgentRunError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

export interface AiAgentForensicsDeps {
  store: CaseStore;
  serverClients: ServerClients;
  serverSetStore?: ServerSetStore;
  veloHuntStore: VeloHuntStore;
  runStore: AiAgentRunStore;
  /** Turn AI analysis off for a new sweep case (routes pass ctx.setControl). */
  disableAi?(caseId: string): Promise<unknown>;
  startVeloHuntCollect(caseId: string, huntId: string): unknown;
  armCollectTimer(caseId: string, huntId: string, waitMinutes: number): void;
  scheduleVeloHuntStatusPoll(caseId: string, huntId: string): void;
  cancelVeloHuntTimersForCase(caseId: string): void;
  ingestVeloArtifactMap(
    caseId: string,
    mapJson: string,
    opts: { label: string; idBase: string; rows?: number },
  ): Promise<{ addedEvents: number; addedIocs: number }>;
  onChange?(caseId: string): void;
  log(line: string): void;
}

export interface AiAgentStartInput {
  caseId?: string; // absent → a new hidden sweep case
  serverSetId?: string; // sweep only: which set to run on (default set when absent)
  clientIds: string[];
  scopes?: string[];
  uploadMaxBytes?: number;
  waitMinutes?: number;
}

function veloFor(deps: AiAgentForensicsDeps, caseId: string): VelociraptorClient {
  const r = deps.serverClients.forCase(caseId);
  if (!r.ok) throw new AiAgentRunError(r.error, r.status);
  if (!r.servers.velociraptor)
    throw new AiAgentRunError(`Velociraptor is not configured in server set '${r.servers.setName}'`, 501);
  return r.servers.velociraptor;
}

/** The chosen clients' host names and OS, read live (bounded, validated ids). */
async function readEndpoints(client: VelociraptorClient, ids: string[]): Promise<AiAgentEndpoint[]> {
  const list = ids.map((c) => `'${c}'`).join(", ");
  const { rows } = await client.runProgram(
    `SELECT client_id, os_info.system AS OS, os_info.hostname AS Hostname, os_info.fqdn AS Fqdn FROM clients() WHERE client_id IN [${list}]`,
  );
  const found = new Map(
    (rows as Record<string, unknown>[]).map((r) => [
      String(r.client_id ?? ""),
      { os: String(r.OS ?? ""), hostname: String(r.Hostname || r.Fqdn || "") },
    ]),
  );
  return ids.map((clientId) => ({
    clientId,
    hostname: found.get(clientId)?.hostname || clientId,
    os: found.get(clientId)?.os ?? "",
  }));
}

function validClientIds(raw: unknown): string[] {
  const ids = Array.isArray(raw) ? [...new Set(raw.map((x) => String(x).trim()).filter(Boolean))] : [];
  if (ids.length === 0)
    throw new AiAgentRunError("pick at least one endpoint — a run never targets the fleet");
  if (ids.length > MAX_ENDPOINTS) throw new AiAgentRunError(`at most ${MAX_ENDPOINTS} endpoints per run`);
  const bad = ids.filter((c) => !CLIENT_RE.test(c));
  if (bad.length) throw new AiAgentRunError(`invalid Velociraptor client id(s): ${bad.join(", ")}`);
  return ids;
}

async function createSweepCase(deps: AiAgentForensicsDeps, serverSetId?: string): Promise<string> {
  const caseId = newSweepCaseId();
  const sets = deps.serverSetStore;
  const setId = serverSetId?.trim() || sets?.defaultId();
  if (sets && (!setId || !sets.has(setId)))
    throw new AiAgentRunError("no Velociraptor server set to run on — pick one or set a default", 409);
  await deps.store.createCase({
    caseId,
    name: `AI Agent Forensics sweep ${new Date().toISOString().slice(0, 16).replace("T", " ")}`,
    investigator: "AI Agent Forensics",
    aiProvider: null,
    kind: SWEEP_CASE_KIND,
  });
  if (sets && setId) sets.linkCase(caseId, setId);
  // A sweep is a results-only check: no AI analysis runs on it (the analyst files hits into a case).
  await deps.disableAi?.(caseId);
  return caseId;
}

/** Remove the Companion copy of sweeps beyond the retention window. Never touches Velociraptor. */
export async function enforceSweepRetention(
  deps: AiAgentForensicsDeps,
  keepCaseId?: string,
): Promise<string[]> {
  const old = sweepsBeyondRetention(await deps.store.listCases()).filter((m) => m.caseId !== keepCaseId);
  const removed: string[] = [];
  for (const meta of old) {
    try {
      deps.cancelVeloHuntTimersForCase(meta.caseId);
      await deps.store.deleteCaseFolder(meta.caseId, {
        afterDelete: async () => deps.serverSetStore?.unlinkCase(meta.caseId),
      });
      removed.push(meta.caseId);
    } catch (e) {
      deps.log(`[ai-agent] could not remove old sweep ${meta.caseId}: ${(e as Error).message}`);
    }
  }
  return removed;
}

/** Launch a run. Returns the case it lives in and the run record. */
export async function startAiAgentRun(
  deps: AiAgentForensicsDeps,
  input: AiAgentStartInput,
): Promise<{ caseId: string; run: AiAgentRun; sweep: boolean }> {
  const clientIds = validClientIds(input.clientIds);
  const sweep = !input.caseId;
  if (input.caseId && !(await deps.store.caseExists(input.caseId)))
    throw new AiAgentRunError("case not found", 404);
  const set = activeAiAgentRuleSet();
  const uploadMaxBytes = Math.max(0, Math.floor(input.uploadMaxBytes ?? AI_AGENT_DEFAULT_UPLOAD_MAX_BYTES));
  const bundle = buildAiAgentArtifact(set, { scopes: input.scopes, uploadMaxBytes }); // option errors before any case is made
  const caseId = input.caseId ?? (await createSweepCase(deps, input.serverSetId));
  const client = veloFor(deps, caseId);
  const endpoints = await readEndpoints(client, clientIds);
  const pre = await preflightAiAgentRun(endpoints, () =>
    client.listClientArtifacts("client", { refresh: true }),
  );
  if (pre.error) throw new AiAgentRunError(pre.error);
  const launch = await launchAiAgentRun(client, {
    bundle,
    clientIds: pre.clientIds,
    preserve: pre.preserve,
    uploadMaxBytes,
    description: BUNDLE_NAME,
  });
  const runId = newAiAgentRunId();
  const now = new Date();
  const waitMinutes = Math.min(24 * 60, Math.max(5, Math.floor(input.waitMinutes ?? DEFAULT_WAIT_MINUTES)));
  const job: VeloHuntJob = {
    bundleId: AI_AGENT_BUNDLE_ID,
    bundleName: BUNDLE_NAME,
    artifacts: bundle.artifacts.map((a) => a.name), // never the triage target: its rows are preservation only
    huntId: launch.huntId,
    guiUrl: launch.guiUrl,
    launchedAt: now.toISOString(),
    waitMinutes,
    collectAt: new Date(now.getTime() + waitMinutes * 60_000).toISOString(),
    status: "running",
    expirySeconds: AI_AGENT_HUNT_EXPIRY_SECONDS,
    uploadPolicy: "external",
    aiAgentRunId: runId,
    sensitive: true,
  };
  await deps.veloHuntStore.upsert(caseId, job);
  deps.armCollectTimer(caseId, launch.huntId, waitMinutes);
  deps.scheduleVeloHuntStatusPoll(caseId, launch.huntId);
  const byId = new Map(endpoints.map((e) => [e.clientId, e.hostname]));
  const run: AiAgentRun = {
    runId,
    huntId: launch.huntId,
    guiUrl: launch.guiUrl,
    launchedAt: now.toISOString(),
    serverSetId: deps.serverSetStore?.caseSetId(caseId),
    endpoints: launch.added.map((clientId) => ({ clientId, hostname: byId.get(clientId) ?? clientId })),
    failedEndpoints: launch.failed,
    skippedEndpoints: pre.skipped,
    scopes: bundle.scopes,
    uploadMaxBytes,
    ruleSetVersion: set.version,
    artifacts: launch.artifacts,
    preserved: pre.preserve,
    warnings: pre.warnings,
    sensitive: true,
  };
  await deps.runStore.upsert(caseId, run);
  if (sweep) await enforceSweepRetention(deps, caseId);
  deps.log(
    `[ai-agent] run ${runId} hunt ${launch.huntId} on ${launch.added.length} endpoint(s) in ${caseId}`,
  );
  deps.onChange?.(caseId);
  return { caseId, run, sweep };
}

/** Re-read the run's results from Velociraptor and rebuild its report + upload manifest. */
export async function refreshAiAgentRun(
  deps: AiAgentForensicsDeps,
  caseId: string,
  runId: string,
): Promise<AiAgentRun> {
  const run = await deps.runStore.get(caseId, runId);
  if (!run) throw new AiAgentRunError("run not found", 404);
  const client = veloFor(deps, caseId);
  const rows: Record<string, unknown>[] = [];
  const problems: string[] = [];
  for (const artifact of run.artifacts.filter((a) => a.startsWith("Custom.DFIRCompanion."))) {
    try {
      const read = await client.huntArtifactRows(run.huntId, artifact, [], undefined, true);
      for (const r of read.rows) rows.push(r as Record<string, unknown>);
      if (read.truncated) problems.push(`${artifact}: only the first ${read.rows.length} rows were read`);
    } catch (e) {
      problems.push(`${artifact}: ${(e as Error).message}`);
    }
  }
  const report = buildAiAgentReport(rows, activeAiAgentRuleSet());
  const manifest = await readUploadManifest(client, run.huntId).catch((e: Error) => {
    problems.push(`upload manifest: ${e.message}`);
    return null;
  });
  const updated = await deps.runStore.update(caseId, runId, (r) => ({
    ...r,
    report,
    rows: rows.slice(0, MAX_STORED_ROWS),
    ...(manifest ? { manifest: capManifest(manifest) } : {}),
    ...(problems.length ? { reportError: problems.join("; ") } : { reportError: undefined }),
  }));
  deps.onChange?.(caseId);
  return updated ?? run;
}

/** File a sweep's rows into a real case, evidence-first under that case's import lock. */
export async function addSweepToCase(
  deps: AiAgentForensicsDeps,
  sweepCaseId: string,
  runId: string,
  targetCaseId: string,
): Promise<{ addedEvents: number; addedIocs: number }> {
  const meta = await deps.store.getCaseMeta(sweepCaseId);
  if (!isSweepCase(meta)) throw new AiAgentRunError("not an AI Agent Forensics sweep", 404);
  const target = await deps.store.getCaseMeta(targetCaseId);
  if (!target || isSweepCase(target))
    throw new AiAgentRunError("pick an existing case to add the hits to", 404);
  const run = await deps.runStore.get(sweepCaseId, runId);
  if (!run) throw new AiAgentRunError("run not found", 404);
  const rows = run.rows ?? [];
  if (rows.length === 0) throw new AiAgentRunError("this sweep has no results yet — refresh it first", 409);
  const artifact =
    run.artifacts.find((a) => a.startsWith("Custom.DFIRCompanion.AIAgentForensics.")) ?? "AIAgentForensics";
  const out = await deps.ingestVeloArtifactMap(targetCaseId, JSON.stringify({ [artifact]: rows }), {
    label: `ai-agent-forensics_${run.huntId}.json`,
    idBase: `aiagent-${run.huntId}`,
    rows: rows.length,
  });
  const at = new Date().toISOString();
  await deps.runStore.update(sweepCaseId, runId, (r) => ({
    ...r,
    addedTo: [...(r.addedTo ?? []), { caseId: targetCaseId, at, events: out.addedEvents }],
  }));
  deps.onChange?.(targetCaseId);
  return out;
}

/** Every sweep case with its run, newest first (the panel's case-less list). */
export async function listSweeps(
  deps: AiAgentForensicsDeps,
): Promise<{ caseId: string; run: AiAgentRun | null }[]> {
  const metas = (await deps.store.listCases()).filter(isSweepCase);
  return Promise.all(
    metas.map(async (m) => ({ caseId: m.caseId, run: (await deps.runStore.list(m.caseId))[0] ?? null })),
  );
}

export { AiAgentRunStore };
