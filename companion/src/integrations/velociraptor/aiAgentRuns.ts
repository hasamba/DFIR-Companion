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
import { aiAgentEndpointLabels, buildAiAgentReport } from "../../analysis/aiAgentReport.js";
import { AiAgentHostLedger, type AiAgentHostOptions } from "../../analysis/aiAgentHostLabels.js";
import {
  AiAgentRunStore,
  capManifest,
  newAiAgentRunId,
  type AiAgentRun,
} from "../../analysis/aiAgentRunStore.js";
import { AI_AGENT_DEFAULT_UPLOAD_MAX_BYTES, buildAiAgentArtifact } from "./aiAgentArtifact.js";
import { AI_AGENT_HUNT_EXPIRY_SECONDS, launchAiAgentRun } from "./aiAgentLaunch.js";
import { preflightAiAgentRun, type AiAgentEndpoint } from "./aiAgentPreflight.js";
import { readUploadManifestStatus } from "./uploadVql.js";
import { CLIENT_RE } from "./clientInventory.js";
import { CLIENT_LOOKUP_LIMIT } from "./clientSnapshot.js";
import { saveFiledRun, updateFiledRun, type FiledFrom } from "../../reports/aiAgentFiledRuns.js";
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
/** Same bound as the endpoint inventory read (`listClients`): one constant, in clientSnapshot.ts (#2887). */
export { CLIENT_LOOKUP_LIMIT };
/** Rows per evidence-first ingest when a sweep is filed into a case. */
const ADD_BATCH_ROWS = 10_000;

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
  /** A new sweep case was made for this request (routes grant the requester access to it). */
  onSweepCreated?(caseId: string): void;
  startVeloHuntCollect(caseId: string, huntId: string): unknown;
  armCollectTimer(caseId: string, huntId: string, waitMinutes: number): void;
  scheduleVeloHuntStatusPoll(caseId: string, huntId: string): void;
  cancelVeloHuntTimersForCase(caseId: string): void;
  ingestVeloArtifactMap(
    caseId: string,
    mapJson: string,
    opts: { label: string; idBase: string; rows?: number } & AiAgentHostOptions,
  ): Promise<{ addedEvents: number; addedIocs: number }>;
  onChange?(caseId: string): void;
  /**
   * An activity-log entry for a case (#2722): a run started, a sweep filed. Routes write it with
   * logActivity. The detail holds counts, ids, the rule version and scope ids — never a matched text
   * or path, which are attacker-controlled.
   */
  onActivity?(caseId: string, entry: { action: string; detail: string }): void;
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

interface EndpointLookup {
  endpoints: AiAgentEndpoint[];
  missing: string[];
  /** The full client list came back at the row limit, so it may not hold every enrolled endpoint. */
  truncated: boolean;
}

type FoundClient = { os: string; hostname: string };

const LIMIT_TEXT = CLIENT_LOOKUP_LIMIT.toLocaleString("en-US");

/**
 * The chosen clients' host names and OS, read live (bounded, validated ids), and the ids this server
 * does not know (`missing`): a client id that is not enrolled here is not on this server set.
 */
async function readEndpoints(
  client: VelociraptorClient,
  ids: string[],
  log: (line: string) => void,
): Promise<EndpointLookup> {
  // The whole client list, matched here — the same read that fills the endpoint picker. A server-side
  // `WHERE client_id IN [...]` filter returned no rows on a live server for an enrolled endpoint, so
  // Run refused an endpoint the picker had just listed.
  const { rows, reason } = await client.runProgram(
    `SELECT client_id, os_info.system AS OS, os_info.hostname AS Hostname, os_info.fqdn AS Fqdn FROM clients() LIMIT ${CLIENT_LOOKUP_LIMIT}`,
  );
  const wanted = new Set(ids);
  const found = new Map<string, FoundClient>(
    (rows as Record<string, unknown>[])
      .filter((r) => wanted.has(String(r.client_id ?? "")))
      .map((r) => [
        String(r.client_id ?? ""),
        { os: String(r.OS ?? ""), hostname: String(r.Hostname || r.Fqdn || "") },
      ]),
  );
  const listMissing = ids.filter((id) => !found.has(id));
  // A failed clients() query returns no rows: say why, never blame the ids.
  if (listMissing.length && reason?.trim())
    throw new AiAgentRunError(`could not read the endpoints from Velociraptor: ${reason.trim()}`, 502);
  // A list cut at the limit may leave out an enrolled endpoint (#2880): look up only those ids by
  // their exact id. client_info() on this server never returns another server's client (#2725).
  const truncated = rows.length >= CLIENT_LOOKUP_LIMIT;
  const byId = truncated && listMissing.length ? await readClientsById(client, listMissing, log) : null;
  const all = new Map([...found, ...(byId ?? [])]);
  const endpoints = ids.map((clientId) => ({
    clientId,
    hostname: all.get(clientId)?.hostname || clientId,
    os: all.get(clientId)?.os ?? "",
  }));
  const missing = ids.filter((id) => !all.has(id));
  if (truncated)
    log(
      `[ai-agent] the Velociraptor client list reached the ${LIMIT_TEXT} row limit; ` +
        `${listMissing.length} picked endpoint(s) were not in it, ${missing.length} still not found by id` +
        (missing.length ? `: ${missing.join(", ")}` : ""),
    );
  return { endpoints, missing, truncated };
}

/**
 * The exact by-id lookup for ids a truncated client list left out: one program, one client_info() per
 * id (ids are CLIENT_RE-validated before they reach here). Fails safe — an error, or a row that names
 * an id nobody asked for, leaves the id not found, so it is still refused.
 */
async function readClientsById(
  client: VelociraptorClient,
  ids: string[],
  log: (line: string) => void,
): Promise<Map<string, FoundClient>> {
  const list = ids.map((id) => `'${id}'`).join(", ");
  const out = new Map<string, FoundClient>();
  try {
    const { rows, reason } = await client.runProgram(
      `SELECT client_info(client_id=_value) AS Info FROM foreach(row=[${list}])`,
    );
    if (reason?.trim()) log(`[ai-agent] the by-id client lookup reported: ${reason.trim()}`);
    for (const row of rows as { Info?: unknown }[]) {
      const info = (row?.Info ?? {}) as { client_id?: unknown; os_info?: Record<string, unknown> };
      const id = String(info.client_id ?? "");
      if (!ids.includes(id)) continue;
      const os = info.os_info ?? {};
      const system = String(os.system ?? "");
      const hostname = String(os.hostname || os.fqdn || "");
      // A stub row (an id with no OS info) is not proof the endpoint is enrolled here: refuse it.
      if (system || hostname) out.set(id, { os: system, hostname });
    }
  } catch (e) {
    log(`[ai-agent] the by-id client lookup failed: ${(e as Error).message}`);
  }
  return out;
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

/** The set a sweep runs on: the one asked for, else the default. Resolved BEFORE any case is made. */
function sweepSet(
  deps: AiAgentForensicsDeps,
  serverSetId?: string,
): { setId?: string; client: VelociraptorClient } {
  const sets = deps.serverSetStore;
  const setId = serverSetId?.trim() || sets?.defaultId();
  if (sets && (!setId || !sets.has(setId)))
    throw new AiAgentRunError("no Velociraptor server set to run on — pick one or set a default", 409);
  const r = setId ? deps.serverClients.forSet(setId) : deps.serverClients.forDefault();
  if (!r.ok) throw new AiAgentRunError(r.error, r.status);
  if (!r.servers.velociraptor)
    throw new AiAgentRunError(`Velociraptor is not configured in server set '${r.servers.setName}'`, 501);
  return { setId, client: r.servers.velociraptor };
}

async function createSweepCase(deps: AiAgentForensicsDeps, setId?: string): Promise<string> {
  const caseId = newSweepCaseId();
  await deps.store.createCase({
    caseId,
    name: `AI Agent Forensics sweep ${new Date().toISOString().slice(0, 16).replace("T", " ")}`,
    investigator: "AI Agent Forensics",
    aiProvider: null,
    kind: SWEEP_CASE_KIND,
  });
  if (deps.serverSetStore && setId) deps.serverSetStore.linkCase(caseId, setId);
  // A sweep is a results-only check: no AI analysis runs on it (the analyst files hits into a case).
  await deps.disableAi?.(caseId);
  deps.onSweepCreated?.(caseId);
  return caseId;
}

/** Undo a sweep case whose launch failed, so no hidden case is left without a run. */
async function discardSweepCase(deps: AiAgentForensicsDeps, caseId: string): Promise<void> {
  await deps.store
    .deleteCaseFolder(caseId, { afterDelete: async () => deps.serverSetStore?.unlinkCase(caseId) })
    .catch((e: Error) => deps.log(`[ai-agent] could not remove the failed sweep ${caseId}: ${e.message}`));
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
  const target = input.caseId ? { client: veloFor(deps, input.caseId) } : sweepSet(deps, input.serverSetId);
  const client = target.client;
  const { endpoints, missing, truncated } = await readEndpoints(client, clientIds, deps.log);
  // Inside a case, every endpoint must belong to the case's own server set (#2725): a case writer may
  // not reach a client of another set by naming its id.
  if (input.caseId && missing.length)
    throw new AiAgentRunError(
      `Not started: this case's Velociraptor server does not list endpoint ${missing.join(", ")}. ` +
        (truncated
          ? `The server's client list was cut at ${LIMIT_TEXT} rows, so this check could not see every endpoint. `
          : "") +
        "Untick it, or reopen the panel to reload the endpoint list, and press Run again.",
    );
  const pre = await preflightAiAgentRun(endpoints, () =>
    client.listClientArtifacts("client", { refresh: true }),
  );
  if (pre.error) throw new AiAgentRunError(pre.error);
  // The sweep case is made only now, right before the launch, and removed again if the launch fails.
  const caseId = input.caseId ?? (await createSweepCase(deps, "setId" in target ? target.setId : undefined));
  let launch: Awaited<ReturnType<typeof launchAiAgentRun>>;
  try {
    launch = await launchAiAgentRun(client, {
      bundle,
      clientIds: pre.clientIds,
      preserve: pre.preserve,
      uploadMaxBytes,
      description: BUNDLE_NAME,
    });
  } catch (e) {
    if (sweep) await discardSweepCase(deps, caseId);
    throw e;
  }
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
  deps.onActivity?.(caseId, {
    action: "ai-agent-run",
    detail: `started AI Agent Forensics on ${run.endpoints.length} endpoint(s) (hunt ${run.huntId}, rules ${run.ruleSetVersion}, scopes ${run.scopes.join(", ")})`,
  });
  deps.onChange?.(caseId);
  return { caseId, run, sweep };
}

const shortHost = (h: string): string => h.trim().toLowerCase().split(".")[0];

/** A launched endpoint that returned no row yet is listed as such — never silently absent. */
export function withSilentEndpoints(
  report: ReturnType<typeof buildAiAgentReport>,
  endpoints: { clientId: string; hostname: string }[],
): ReturnType<typeof buildAiAgentReport> {
  // Matched by client id (Codex review of #2722): a silent client sharing a reporting client's host
  // name must still be listed. Only a report endpoint with no client id (an older report) is matched
  // by host name.
  const seenIds = new Set(report.endpoints.flatMap((e) => (e.clientId ? [e.clientId] : [])));
  const seenNames = new Set(
    report.endpoints.filter((e) => !e.clientId).map((e) => shortHost(e.hostname ?? e.host)),
  );
  const silent = endpoints
    .filter(
      (e) =>
        !seenIds.has(e.clientId) &&
        !seenNames.has(shortHost(e.hostname)) &&
        !seenNames.has(shortHost(e.clientId)),
    )
    .map((e) => ({
      host: e.hostname || e.clientId,
      hostname: e.hostname || e.clientId,
      clientId: e.clientId,
      tools: [],
      mcpServers: [],
      credentialStores: 0,
      hits: 0,
      sigma: [],
      coverage: [
        { source: "run", status: "no results yet", detail: `client ${e.clientId} has returned no rows` },
      ],
    }));
  return silent.length
    ? aiAgentEndpointLabels({ ...report, endpoints: [...report.endpoints, ...silent] })
    : report;
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
  // Bring the timeline in step with the report: the paused hunt never reads "finished", so without
  // this only the fixed-delay collect would ever import its hits.
  deps.startVeloHuntCollect(caseId, run.huntId);
  const rows: Record<string, unknown>[] = [];
  const problems: string[] = [];
  const readIncomplete: { artifact: string; rowsRead: number }[] = [];
  for (const artifact of run.artifacts.filter((a) => a.startsWith("Custom.DFIRCompanion."))) {
    try {
      const read = await client.huntArtifactRows(run.huntId, artifact, [], undefined, true);
      for (const r of read.rows) rows.push(r as Record<string, unknown>);
      if (read.truncated) {
        readIncomplete.push({ artifact, rowsRead: read.rows.length });
        problems.push(
          `${artifact}: only the first ${read.rows.length} rows were read; at least one more was not`,
        );
      }
    } catch (e) {
      readIncomplete.push({ artifact, rowsRead: 0 });
      problems.push(`${artifact}: ${(e as Error).message}`);
    }
  }
  await deps.runStore.writeRows(caseId, runId, rows); // the complete set read — never capped
  // The manifest first, uncapped: the report joins each agent-home hit to its preserved copy's hash
  // (#2722). A manifest that could not be read leaves those hashes "not recorded".
  const read = await readUploadManifestStatus(client, run.huntId).catch((e: Error) => {
    problems.push(`upload manifest: ${e.message}`);
    return null;
  });
  if (read?.problem) problems.push(`upload manifest: ${read.problem}`);
  const manifest = read?.entries ?? null;
  const report = withSilentEndpoints(
    buildAiAgentReport(rows, activeAiAgentRuleSet(), new Date(), {
      manifest: read && !read.problem ? read.entries : null,
    }),
    run.endpoints,
  );
  const updated = await deps.runStore.update(caseId, runId, (r) => ({
    ...r,
    report,
    rows: undefined,
    rowCount: rows.length,
    readIncomplete,
    ...(manifest ? { manifest: capManifest(manifest) } : {}),
    ...(problems.length ? { reportError: problems.join("; ") } : { reportError: undefined }),
  }));
  deps.onChange?.(caseId);
  if (updated) await refreshReportCopies(deps, caseId, updated);
  return updated ?? run;
}

/** Bring the report copy in each case the sweep was filed into up to the re-read (#2744). Update only;
 *  a failed copy never fails the re-read — it is logged and the next case is tried. */
async function refreshReportCopies(
  deps: AiAgentForensicsDeps,
  sweepCaseId: string,
  run: AiAgentRun,
): Promise<void> {
  for (const targetCaseId of new Set((run.addedTo ?? []).map((a) => a.caseId))) {
    try {
      if (!(await deps.store.caseExists(targetCaseId))) continue;
      if (await updateFiledRun(deps.store, targetCaseId, run)) deps.onChange?.(targetCaseId);
    } catch (e) {
      deps.log(
        `[ai-agent] could not update the report copy of sweep ${sweepCaseId} in ${targetCaseId}: ${(e as Error).message}`,
      );
    }
  }
}

/** Keep the run's report-safe copy in the target case so its report outlives sweep retention (#2740).
 *  The hits are already filed: a failed copy never fails the filing — it is logged and noted. */
async function saveReportCopy(
  deps: AiAgentForensicsDeps,
  targetCaseId: string,
  run: AiAgentRun,
  filedFrom: FiledFrom,
): Promise<string> {
  try {
    await saveFiledRun(deps.store, targetCaseId, run, filedFrom);
    return "";
  } catch (e) {
    const why = (e as Error).message;
    deps.log(
      `[ai-agent] could not save the report copy of sweep ${filedFrom.sweepCaseId} into ${targetCaseId}: ${why}`,
    );
    return " (the report copy could not be saved; the run shows in the case report only while the sweep is kept)";
  }
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
  if (run.readIncomplete?.length) {
    const what = run.readIncomplete.map((x) => `${x.artifact}: only ${x.rowsRead} rows were read`).join("; ");
    throw new AiAgentRunError(
      `this sweep's results were not read in full (${what}; at least one more row was not read), so adding it would file a partial result — raise DFIR_VELOCIRAPTOR_COLLECT_MAX_ROWS, press Refresh results, then add it`,
      409,
    );
  }
  const rows = await deps.runStore.readRows(sweepCaseId, runId);
  if (rows.length === 0) throw new AiAgentRunError("this sweep has no results yet — refresh it first", 409);
  if (run.rowCount !== undefined && rows.length !== run.rowCount)
    throw new AiAgentRunError(
      `this sweep's stored results hold ${rows.length} of ${run.rowCount} rows — press Refresh results, then add it`,
      409,
    );
  const artifact =
    run.artifacts.find((a) => a.startsWith("Custom.DFIRCompanion.AIAgentForensics.")) ?? "AIAgentForensics";
  // Bounded batches, each evidence-first under the target case's import lock. A failed batch stops
  // the filing and says how far it got: a partial filing is never reported as success.
  // Each batch is parsed alone, so the host names two clients share are learned once over the whole
  // sweep and handed to every batch: a batch holding one of the two still names its client (#2745).
  const sweepHosts = AiAgentHostLedger.from();
  sweepHosts.learn(rows);
  const aiAgentHostClients = sweepHosts.sharedPairs();
  const out = { addedEvents: 0, addedIocs: 0 };
  for (let i = 0, part = 1; i < rows.length; i += ADD_BATCH_ROWS, part++) {
    const batch = rows.slice(i, i + ADD_BATCH_ROWS);
    try {
      const r = await deps.ingestVeloArtifactMap(targetCaseId, JSON.stringify({ [artifact]: batch }), {
        label: `ai-agent-forensics_${run.huntId}_part${part}.json`,
        idBase: `aiagent-${run.huntId}-${part}`,
        rows: batch.length,
        ...(aiAgentHostClients.length ? { aiAgentHostClients } : {}),
      });
      out.addedEvents += r.addedEvents;
      out.addedIocs += r.addedIocs;
    } catch (e) {
      throw new AiAgentRunError(
        `filing stopped after ${i} of ${rows.length} rows (batch ${part} failed: ${(e as Error).message}) — the case holds a partial result`,
        502,
      );
    }
  }
  const at = new Date().toISOString();
  const filed = await deps.runStore.update(sweepCaseId, runId, (r) => ({
    ...r,
    addedTo: [...(r.addedTo ?? []), { caseId: targetCaseId, at, events: out.addedEvents }],
  }));
  const copyNote = await saveReportCopy(deps, targetCaseId, filed ?? run, { sweepCaseId, at });
  const counts = `+${out.addedEvents} event(s), +${out.addedIocs} IOC(s)`;
  deps.onActivity?.(targetCaseId, {
    action: "ai-agent-add-to-case",
    detail: `added AI Agent Forensics sweep ${sweepCaseId} (hunt ${run.huntId}): ${counts}${copyNote}`,
  });
  deps.onActivity?.(sweepCaseId, {
    action: "ai-agent-add-to-case",
    detail: `filed into case ${targetCaseId}: ${counts}`,
  });
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
