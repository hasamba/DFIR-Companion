import type { Express, Request, Response } from "express";
import type { HuntDeployInput } from "../analysis/huntOutcomes.js";
import { requestAuthentication } from "../auth/types.js";
import { fingerprintStoreFor } from "../analysis/ai/watson/velo/fingerprintIndex.js";
import { resolveVeloLaunch, type LaunchResolution } from "../analysis/ai/watson/velo/launchResolve.js";
import type { VeloLaunchDeps } from "../analysis/ai/watson/velo/launchTypes.js";
import { matchClient } from "../integrations/velociraptor/clientInventory.js";
import type { RouteContext } from "./context.js";
import { deployCaseHunt } from "./veloDeploy.js";
import { caseVeloConnected } from "./watsonDeps.js";

// Watson phase 3: the seams an approved velo_launch proposal launches through (the existing deploy
// path, routes/veloDeploy.ts), and the route that answers an uncertain launch. Registered BEFORE the
// generic /watson/proposals/:pid/:action route, which would otherwise take "resolve" as an action.

const OUTCOMES: readonly LaunchResolution[] = ["launched", "retry"];

/** The launch seams for one request; the actor is the analyst who approved the proposal. */
export function watsonVeloLaunchDeps(ctx: RouteContext): VeloLaunchDeps {
  const { options, store } = ctx;
  return {
    launch: async (caseId, req, actor) => {
      const body = {
        vql: req.vql,
        title: req.title,
        description: req.title, // already flattened to one line, ≤200 chars
        source: "watson" as const,
        mitreTechniques: [],
        mode: req.mode,
        hostname: req.hostname ?? "",
        // A single-host collection reads live state: an empty result is not a miss.
        ...(req.mode === "collection" ? { coverage: "snapshot" as const } : {}),
      };
      const r = await deployCaseHunt(ctx, caseId, body, { name: actor, kind: "analyst" });
      const error = r.status >= 400 ? String(r.body.error ?? `HTTP ${r.status}`) : undefined;
      return { phase: r.phase, ...(r.launched ? { launched: r.launched } : {}), ...(error ? { error } : {}) };
    },
    fleet: {
      veloConnected: (id) => caseVeloConnected(ctx, id),
      ...(options.velociraptorClientStore
        ? { velociraptorClientStore: options.velociraptorClientStore }
        : {}),
    },
    matchClient,
    fingerprints: fingerprintStoreFor(store),
    log: (line) => ctx.serverLogger.info(line),
  };
}

type SendError = (res: Response, err: unknown) => Response;

export function registerWatsonVeloLaunchRoutes(app: Express, ctx: RouteContext, sendError: SendError): void {
  const { options, store } = ctx;
  app.post("/cases/:id/watson/proposals/:pid/resolve", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    const outcome = req.body?.outcome as LaunchResolution;
    if (!OUTCOMES.includes(outcome))
      return res.status(400).json({ error: "outcome must be launched or retry" });
    if (!options.watsonChatStore || !options.activityLogStore) {
      return res.status(501).json({ error: "Watson is not configured" });
    }
    if ((await store.getCaseMeta(caseId).catch(() => null)) === null) {
      return res.status(404).json({ error: "case not found" });
    }
    const deps = {
      chatStore: options.watsonChatStore,
      activity: options.activityLogStore,
      fingerprints: fingerprintStoreFor(store),
      recordDeploy: (id: string, input: HuntDeployInput) => ctx.recordHuntDeploy(id, input),
    };
    const actor = requestAuthentication(req)?.identity.displayName ?? "analyst";
    try {
      return res.status(200).json(await resolveVeloLaunch(deps, caseId, req.params.pid, outcome, actor));
    } catch (err) {
      return sendError(res, err);
    } finally {
      options.onWatson?.(caseId);
    }
  });
}
