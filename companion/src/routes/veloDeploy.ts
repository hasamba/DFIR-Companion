import { logActivityWithWarning, type NewActivityEntry } from "../analysis/activityLog.js";
import type { VeloHuntJob } from "../analysis/veloHuntStore.js";
import { matchClient, normalizeHuntExpirySeconds } from "../integrations/velociraptor/velociraptorApi.js";
import type { RouteContext } from "./context.js";
import { deployHuntBodyProblem, parseDeployHuntBody, type DeployHuntBody } from "./huntDeployBody.js";
import { resolveCaseVelo, type VeloTarget } from "./veloServers.js";

// The deploy-hunt core (#157), moved out of routes/velociraptor.ts so Watson's approved launches
// (phase 3) run the exact same path as the analyst's Deploy button: the same client call, collect
// timer, status poll, hunt outcome, fingerprint index and audit entry. The route parses the body and
// sends what this returns; Watson's writer reads `phase` to know whether anything reached an endpoint.

/** Who deployed: the analyst (Deploy button, or an approved Watson proposal) or an agent. */
export interface DeployActor {
  name: string;
  kind: "analyst" | "agent";
  /** Appended to every audit detail this deploy writes (Watson Auto: who switched Auto on, and when). */
  detailSuffix?: string;
}

/** The parsed body plus the two raw timing fields the route reads from the request as-is. */
export interface DeployHuntRequest extends DeployHuntBody {
  expirySeconds?: unknown;
  waitMinutes?: unknown;
}

/**
 * Where the deploy stopped:
 * - `invalid` — refused before any work (bad body, no Velociraptor): nothing ran.
 * - `before-launch` — failed before the launch call was made (e.g. no client matches the host): nothing ran.
 * - `launch-unknown` — the launch call itself failed: it may or may not have reached the endpoints.
 * - `launched` — the launch returned its ids (later bookkeeping may still have failed: see `status`).
 */
export type DeployPhase = "invalid" | "before-launch" | "launch-unknown" | "launched";

export interface DeployResult {
  status: number;
  body: Record<string, unknown>;
  phase: DeployPhase;
  launched?: { huntId?: string; flowId?: string; clientId?: string };
}

/**
 * Resolve a hostname → client_id from the set's persisted inventory (refreshing once on a miss) and
 * launch a single-client collection. Throws when no client matches. `beforeLaunch` runs right before
 * the call that may reach an endpoint — with no inventory store, that call also does the lookup.
 */
export async function collectHostResolved(
  ctx: RouteContext,
  vc: VeloTarget,
  hostname: string,
  vql: string,
  description: string,
  beforeLaunch: () => void = () => {},
) {
  const store = ctx.options.clientInventoryFor?.(vc.setId);
  if (store) {
    // Resolve from the inventory file; if the host isn't there yet, refresh once and retry (self-healing).
    let rec = matchClient((await store.load()).clients, hostname);
    if (!rec) {
      await ctx.refreshVeloClients(vc.setId);
      rec = matchClient((await store.load()).clients, hostname);
    }
    if (!rec)
      throw new Error(
        `No enrolled Velociraptor client matches host "${hostname}" — refresh the client list (Settings → Velociraptor) or run a fleet hunt instead`,
      );
    beforeLaunch();
    return await vc.client.collectOnClient(rec.clientId, vql, description, hostname);
  }
  beforeLaunch();
  return await vc.client.collectFromHost(hostname, vql, description);
}

function waitMinutesOf(raw: unknown): number {
  const reqWait = Number(raw);
  return Math.min(
    1440,
    Math.max(
      1,
      Number.isFinite(reqWait) && reqWait > 0 ? reqWait : Number(process.env.DFIR_VELO_HUNT_WAIT_MIN) || 10,
    ),
  );
}

/** Deploy one hunt (fleet) or collection (single host) for a case. Never throws. */
export async function deployCaseHunt(
  ctx: RouteContext,
  caseId: string,
  body: DeployHuntRequest,
  actor: DeployActor,
): Promise<DeployResult> {
  const { options } = ctx;
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);
  const audit = async (input: NewActivityEntry) => {
    const entry = { ...input, actor: actor.name, detail: input.detail + (actor.detailSuffix ?? "") };
    const warning = await logActivityWithWarning(options.activityLogStore, options.onActivity, caseId, entry);
    if (warning) logLine(`[velociraptor] AUDIT NOT WRITTEN — ${warning}`);
    return warning ? { auditWarning: warning } : {};
  };
  const target = resolveCaseVelo(ctx, caseId);
  if (!target.ok) return { status: target.status, body: { error: target.error }, phase: "invalid" };
  const vc = target.vc;
  const { vql, title, description, source, mitreTechniques, mode, hostname, relatedHypothesisId, coverage } =
    body;
  const bodyProblem = deployHuntBodyProblem({ vql, title, mode, hostname });
  if (bodyProblem) return { status: 400, body: { error: bodyProblem }, phase: "invalid" };
  const shared = {
    source,
    title,
    vql,
    mitreTechniques,
    serverSetId: vc.setId,
    ...(relatedHypothesisId ? { relatedHypothesisId } : {}),
    ...(coverage ? { coverage } : {}),
  };
  let phase: DeployPhase = "before-launch";
  let launched: DeployResult["launched"];
  try {
    if (mode === "collection") {
      logLine(`[velociraptor] deploy-hunt collection "${title}" on ${hostname}`);
      const markLaunch = () => (phase = "launch-unknown");
      const result = await collectHostResolved(ctx, vc, hostname, vql, description, markLaunch);
      phase = "launched";
      launched = { flowId: result.flowId, clientId: result.clientId };
      await ctx.recordHuntDeploy(caseId, {
        ...shared,
        hostname, // keys the durable launch index per host (Watson phase 3)
        flowId: result.flowId,
        clientId: result.clientId,
        deployedAt: new Date().toISOString(),
      });
      options.onVeloHunt?.(caseId);
      const warn = await audit({
        category: "hunt",
        action: "deploy-collection",
        detail: `collection "${title}" on ${hostname}`,
      });
      return { status: 200, body: { mode, ...result, ...warn }, phase, launched };
    }
    const expirySeconds = normalizeHuntExpirySeconds(body.expirySeconds); // relative; defaults to one hour
    logLine(`[velociraptor] deploy-hunt fleet "${title}" (expires in ${expirySeconds}s)`);
    phase = "launch-unknown";
    const launch = await vc.client.launchHunt(vql, description, { expirySeconds });
    phase = "launched";
    launched = { huntId: launch.huntId };
    const waitMinutes = waitMinutesOf(body.waitMinutes);
    if (options.veloHuntStore) {
      const now = new Date();
      const job: VeloHuntJob = {
        bundleId: `suggested:${source}`,
        bundleName: title,
        artifacts: launch.artifact ? [launch.artifact] : [],
        sources: launch.sources, // #157: the Custom.Hunt artifact's named sources (Pivot0…) so collect reads `artifact/source`
        huntId: launch.huntId,
        guiUrl: launch.guiUrl,
        launchedAt: now.toISOString(),
        waitMinutes,
        collectAt: new Date(now.getTime() + waitMinutes * 60_000).toISOString(),
        status: "running",
        expirySeconds,
      };
      await options.veloHuntStore.upsert(caseId, job);
      const timer = setTimeout(() => {
        ctx.startVeloHuntCollect(caseId, launch.huntId);
      }, waitMinutes * 60_000);
      timer.unref?.();
      ctx.veloHuntTimers().set(caseId, timer, launch.huntId);
      ctx.scheduleVeloHuntStatusPoll(caseId, launch.huntId);
    }
    await ctx.recordHuntDeploy(caseId, {
      ...shared,
      huntId: launch.huntId,
      deployedAt: new Date().toISOString(),
    });
    options.onVeloHunt?.(caseId);
    const warn = await audit({
      category: "hunt",
      action: "deploy-hunt",
      detail: `fleet hunt "${title}" deployed (${source})`,
      targetType: "hunt",
      targetId: launch.huntId,
    });
    return { status: 200, body: { mode, waitMinutes, ...launch, ...warn }, phase, launched };
  } catch (err) {
    const message = (err as Error).message;
    logLine(`[velociraptor] deploy-hunt ERROR: ${message}`);
    const warn = await audit({
      category: "hunt",
      action: mode === "collection" ? "deploy-collection" : "deploy-hunt",
      detail: `${mode === "collection" ? "collection" : "fleet hunt"} "${title}" failed: ${message}`,
      outcome: "error",
    });
    return { status: 502, body: { error: message, ...warn }, phase, ...(launched ? { launched } : {}) };
  }
}

/** The two timing fields deploy-hunt reads from the raw request body. */
export function pickTiming(raw: unknown): Pick<DeployHuntRequest, "expirySeconds" | "waitMinutes"> {
  const body = (raw ?? {}) as Record<string, unknown>;
  return { expirySeconds: body.expirySeconds, waitMinutes: body.waitMinutes };
}

export const RESERVED_SOURCE = "source watson is reserved for Watson";

/**
 * The analyst's POST /cases/:id/velociraptor/deploy-hunt: parse the raw body and deploy. A body that
 * claims `source: "watson"` is refused — only an approved Watson proposal launches as Watson.
 */
export async function deployAnalystHunt(
  ctx: RouteContext,
  caseId: string,
  raw: unknown,
  displayName: string | undefined,
): Promise<DeployResult> {
  if ((raw as { source?: unknown } | null)?.source === "watson") {
    return { status: 400, body: { error: RESERVED_SOURCE }, phase: "invalid" };
  }
  const body = { ...parseDeployHuntBody(raw), ...pickTiming(raw) };
  return deployCaseHunt(ctx, caseId, body, { name: displayName ?? "analyst", kind: "analyst" });
}
