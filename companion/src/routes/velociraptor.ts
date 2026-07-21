import type { Express, Request, Response } from "express";
import { reloadEnvPrefix } from "../settings/envManager.js";
import { logActivity } from "../analysis/activityLog.js";
import { parseMinSeverity } from "../analysis/severityFloor.js";
import { parseVeloRef } from "../analysis/veloRef.js";
import { buildVelociraptorClient, matchClient, ALL_CLIENTS, normalizeHuntExpirySeconds, type HuntTarget, type VeloArtifactInfo } from "../integrations/velociraptor/velociraptorApi.js";
import type { VeloMonitor } from "../analysis/veloMonitorStore.js";
import type { VeloHuntJob } from "../analysis/veloHuntStore.js";
import type { HuntOutcomeSource } from "../analysis/huntOutcomes.js";
import { resolveCollectVql } from "../analysis/collectDirectiveResolve.js";
import { resolveTimeScope, buildTimeScopePlan, type TimeScope } from "../analysis/veloTimeScope.js";
import type { ArtifactBundle } from "../analysis/artifactBundleStore.js";
import type { RouteContext } from "./context.js";

/**
 * Velociraptor endpoint-integration routes: the top-level /velociraptor/* API surface (run VQL, launch
 * hunts, client inventory, reconnect, single-host collections, triage-bundle artifacts, live-event
 * artifacts) and the per-case /cases/:id/velociraptor/* surface (suggest-hunts, run-bundle, collect,
 * import-external, hunt-jobs + status polling, deploy-hunt #157, hunt-rows, and the live CLIENT_EVENT
 * monitor CRUD #84).
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). The stateful
 * machinery these routes drive — the self-rescheduling live-monitor + hunt-status timer loops and the
 * hunt-collect/ingest cores — STAYS in createApp because its RESUME functions run once at startup and
 * from POST /velociraptor/reconnect (a route module can't be called at boot). This module reaches that
 * machinery through the RouteContext members it was graduated onto: refreshVeloClients, resumeVelo*,
 * scheduleVeloMonitor/pollVeloMonitor/stopVeloMonitorTimer, scheduleVeloHuntStatusPoll/pollVeloHuntStatus,
 * importVeloHuntResults, ingestVeloArtifactMap/ingestVeloUploads, createVeloMonitor, recordHuntDeploy
 * (stable methods) plus the veloHuntTimers() live accessor (the run-bundle/deploy-hunt routes set a
 * fixed-delay collect timer on that shared Map). The monitor/status timer Maps stay private to createApp.
 *
 * NOTE: import-velociraptor (generic JSON import) is NOT here — it lives in routes/import.ts. Only the
 * /velociraptor/* and /cases/:id/velociraptor/* endpoints moved.
 */
export function registerVelociraptorRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  // Module-private wrapper mirroring createApp's logLine (serverLogger.info), so the moved handler
  // bodies keep their original `logLine(...)` calls verbatim.
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);
  // Normalize a label/tag input that may arrive as a comma-separated string or an array of strings.
  // Module-private copy of createApp's toStringArray (a non-exported server.ts helper) so the moved
  // run-bundle / deploy-hunt bodies keep their original calls without importing across the route seam.
  const toStringArray = (v: unknown): string[] => {
    if (typeof v === "string") return v.split(",").map((s) => s.trim()).filter(Boolean);
    if (Array.isArray(v)) return v.map((s) => String(s).trim()).filter(Boolean);
    return [];
  };
  // Builds the Velociraptor client from current env (used by POST /velociraptor/reconnect). Defaults
  // to the env-based factory; tests inject a stub so no process is spawned.
  const rebuildVelo = options.rebuildVelociraptorClient ?? buildVelociraptorClient;

  // Resolve a hostname → client_id from the persisted inventory (refreshing once on a miss) and launch a
  // single-client collection. Throws when no client matches. Shared by the global /velociraptor/collect-host
  // route and the case-scoped /cases/:id/velociraptor/deploy-hunt route (#157). Requires the API client set.
  async function collectHostResolved(hostname: string, vql: string, description: string) {
    const client = options.velociraptorClient!;
    const store = options.velociraptorClientStore;
    if (store) {
      // Resolve from the inventory file; if the host isn't there yet, refresh once and retry (self-healing).
      let rec = matchClient((await store.load()).clients, hostname);
      if (!rec) { await ctx.refreshVeloClients(); rec = matchClient((await store.load()).clients, hostname); }
      if (!rec) throw new Error(`No enrolled Velociraptor client matches host "${hostname}" — refresh the client list (Settings → Velociraptor) or run a fleet hunt instead`);
      return await client.collectOnClient(rec.clientId, vql, description, hostname);
    }
    return await client.collectFromHost(hostname, vql, description);
  }

  // Run a VQL query against the configured Velociraptor server (via its API) and return the rows.
  // Powers the hunt-pivot modal's "Run in Velociraptor" button. 501 when not configured. The VQL is
  // analyst-authored (from the generated pivots) — localhost only, opt-in via DFIR_VELOCIRAPTOR_*.
  app.post("/velociraptor/run", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const vql = typeof req.body?.vql === "string" ? req.body.vql.trim() : "";
    if (!vql) return res.status(400).json({ error: "vql is required" });
    try {
      logLine(`[velociraptor] run query (${vql.length} chars)`);
      const result = await options.velociraptorClient.run(vql);
      logLine(`[velociraptor] query DONE -> ${result.total} rows${result.truncated ? " (truncated)" : ""}`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[velociraptor] query ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Launch a HUNT that runs the pivot VQL on ALL enrolled endpoints (packages it as a CLIENT
  // artifact, then creates the hunt). This is the dashboard's "Run hunt on all clients" action.
  app.post("/velociraptor/hunt", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const vql = typeof req.body?.vql === "string" ? req.body.vql.trim() : "";
    const description = typeof req.body?.description === "string" ? req.body.description : "";
    if (!vql) return res.status(400).json({ error: "vql is required" });
    const expirySeconds = normalizeHuntExpirySeconds(req.body?.expirySeconds);   // relative; defaults to one hour
    try {
      logLine(`[velociraptor] launch hunt: ${description.slice(0, 80)} (expires in ${expirySeconds}s)`);
      const result = await options.velociraptorClient.launchHunt(vql, description, { expirySeconds });
      logLine(`[velociraptor] hunt launched -> ${result.huntId} (artifact ${result.artifact}, ${result.sources.length} source(s))`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[velociraptor] hunt ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Read a launched hunt's results (rows collected from the endpoints so far). Polled by the dashboard.
  app.post("/velociraptor/hunt-results", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const huntId = typeof req.body?.huntId === "string" ? req.body.huntId.trim() : "";
    const artifact = typeof req.body?.artifact === "string" ? req.body.artifact.trim() : "";
    const sources = Array.isArray(req.body?.sources) ? req.body.sources.filter((s: unknown): s is string => typeof s === "string") : [];
    if (!huntId || !artifact) return res.status(400).json({ error: "huntId and artifact are required" });
    try {
      const result = await options.velociraptorClient.huntResults(huntId, artifact, sources);
      return res.status(200).json(result);
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Read the persisted client inventory (host ↔ client_id map). Empty when never refreshed.
  app.get("/velociraptor/clients", async (_req: Request, res: Response) => {
    if (!options.velociraptorClientStore) return res.status(200).json({ updatedAt: "", clients: [] });
    try {
      return res.status(200).json(await options.velociraptorClientStore.load());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Refresh the client inventory now (Settings → Velociraptor "Refresh client list"). 501 when the
  // API / store isn't configured; 502 on a query failure.
  app.post("/velociraptor/clients/refresh", async (_req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.velociraptorClientStore) return res.status(501).json({ error: "client inventory store not configured" });
    try {
      const count = await ctx.refreshVeloClients();
      const inv = await options.velociraptorClientStore.load();
      return res.status(200).json({ count, updatedAt: inv.updatedAt, clients: inv.clients });
    } catch (err) {
      logLine(`[velociraptor] client refresh ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Diagnostics for the live-monitor features when the picker / auto-discovery come back empty on a
  // real server (#84): the actual artifact `type` strings + counts, and the raw
  // GetClientMonitoringState() shape. Hit it in a browser (localhost) and share the JSON to pin down a
  // version's monitoring proto. 501 when the API isn't configured.
  app.get("/velociraptor/diag", async (_req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    try {
      return res.status(200).json(await options.velociraptorClient.diagnostics());
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Whether the Velociraptor API is configured + the inventory's freshness (so the dashboard can show
  // connection state without a probe). `configured` reflects the LIVE client (reconnect can flip it).
  app.get("/velociraptor/status", async (_req: Request, res: Response) => {
    let updatedAt = "", clientCount = 0;
    if (options.velociraptorClientStore) {
      try { const inv = await options.velociraptorClientStore.load(); updatedAt = inv.updatedAt; clientCount = inv.clients.length; } catch { /* empty */ }
    }
    return res.status(200).json({ configured: !!options.velociraptorClient, updatedAt, clients: clientCount });
  });

  // Re-read DFIR_VELOCIRAPTOR_* from .env (settings saved via the dashboard only write the file),
  // REBUILD the client, and refresh the client inventory — which doubles as a reachability probe
  // (`clients()` round-trips to the server). Lets the analyst connect after configuring Velociraptor,
  // or after the Velociraptor server comes back online, WITHOUT the #1-gotcha restart (the client is
  // stateless — it spawns the binary per query — but a rebuild also applies newly-saved config and
  // flips it on if the config path wasn't set at boot). Also re-arms any persisted live monitors that
  // couldn't be scheduled while the client was absent. Always 200; the body says configured/reachable.
  app.post("/velociraptor/reconnect", async (_req: Request, res: Response) => {
    try {
      await reloadEnvPrefix("DFIR_VELOCIRAPTOR_");
      options.velociraptorClient = rebuildVelo();
      if (!options.velociraptorClient) {
        return res.status(200).json({ configured: false, ok: false, error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
      }
      try {
        const count = await ctx.refreshVeloClients();
        const inv = options.velociraptorClientStore ? await options.velociraptorClientStore.load() : { updatedAt: "", clients: [] };
        void ctx.resumeVeloMonitors();   // arm monitors that couldn't start while the client was absent
        void ctx.resumeVeloHuntStatusPolls();   // and any hunt status polling that couldn't start either
        logLine(`[velociraptor] reconnected — ${count} enrolled client(s)`);
        return res.status(200).json({ configured: true, ok: true, clients: count, updatedAt: inv.updatedAt });
      } catch (err) {
        return res.status(200).json({ configured: true, ok: false, error: (err as Error).message });
      }
    } catch (err) {
      return res.status(500).json({ configured: false, ok: false, error: (err as Error).message });
    }
  });

  // Launch the VQL as a single-endpoint COLLECTION on ONE host (issue #70 — the playbook-hunt deploy
  // path for a task tied to exactly one endpoint). Resolves the host → client_id from the persisted
  // INVENTORY (refreshing it once on a miss), then runs collect_client on that client; returns the
  // flow + a GUI deep link. 501 when the Velociraptor API is off; 502 when no client matches the host.
  app.post("/velociraptor/collect-host", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const hostname = typeof req.body?.hostname === "string" ? req.body.hostname.trim() : "";
    const vql = typeof req.body?.vql === "string" ? req.body.vql.trim() : "";
    const description = typeof req.body?.description === "string" ? req.body.description : "";
    if (!hostname) return res.status(400).json({ error: "hostname is required" });
    if (!vql) return res.status(400).json({ error: "vql is required" });
    try {
      logLine(`[velociraptor] collect on host ${hostname}: ${description.slice(0, 80)}`);
      const result = await collectHostResolved(hostname, vql, description);
      logLine(`[velociraptor] collection launched -> flow ${result.flowId} on ${result.clientId} (${result.hostname})`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[velociraptor] collect ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Read a single COLLECTION flow's result rows so the dashboard can show them inline + auto-poll (the
  // per-flow analog of /velociraptor/hunt-results). Body `{ clientId, flowId, artifact, sources }`.
  app.post("/velociraptor/collect-results", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const clientId = typeof req.body?.clientId === "string" ? req.body.clientId.trim() : "";
    const flowId = typeof req.body?.flowId === "string" ? req.body.flowId.trim() : "";
    const artifact = typeof req.body?.artifact === "string" ? req.body.artifact.trim() : "";
    const sources = Array.isArray(req.body?.sources) ? req.body.sources.filter((s: unknown): s is string => typeof s === "string") : [];
    if (!clientId || !flowId || !artifact) return res.status(400).json({ error: "clientId, flowId and artifact are required" });
    try {
      const result = await options.velociraptorClient.collectionResults(clientId, flowId, artifact, sources);
      // Also report the flow's terminal STATE so the dashboard can surface an endpoint-side failure
      // (e.g. a bad plugin arg) instead of polling "no results yet". Best-effort — never fail the read.
      let flowState = "";
      let flowError = "";
      try {
        const st = await options.velociraptorClient.flowStatus(clientId, flowId);
        flowState = st.state;
        flowError = st.error;
      } catch { /* status read is best-effort */ }
      return res.status(200).json({ ...result, flowState, flowError });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // AI-suggest proactive Velociraptor VQL fleet-hunts from the case findings (issue #57). Single
  // text-only AI call, EPHEMERAL (no state change) — the dashboard shows each hunt's VQL + rationale
  // for review, then deploys the chosen one through POST /velociraptor/hunt (launchHunt). Needs an AI
  // provider; does NOT need the Velociraptor API (the VQL is useful to copy even when deploy is off).
  app.post("/cases/:id/velociraptor/suggest-hunts", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.pipeline.hasSynthesisProvider()) return res.status(501).json({ error: "AI provider not configured for hunt suggestions" });
    try {
      // Optional excludeVql → regenerate a DIFFERENT take (the per-card ↻ Regenerate button), mirroring
      // the playbook-hunt regen. Absent → a normal full suggestion pass.
      const excludeVql = typeof req.body?.excludeVql === "string" && req.body.excludeVql.trim() ? req.body.excludeVql : undefined;
      const suggestions = await options.pipeline.suggestHunts(req.params.id, excludeVql ? { excludeVql } : undefined);
      logLine(`[velociraptor] suggested ${suggestions.length} fleet-hunt(s) for ${req.params.id}`);
      return res.status(200).json({ suggestions });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── Velociraptor triage bundles ───────────────────────────────────────────────────────────
  // On-demand: list collectable CLIENT artifacts → build/save named bundles → run a bundle as a hunt
  // → after a delay, collect results, auto-import (deterministic Velociraptor importer) + synthesize.

  // List the server's collectable CLIENT artifacts (the bundle builder's picker source).
  app.get("/velociraptor/artifacts", async (_req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    try {
      const artifacts = await options.velociraptorClient.listClientArtifacts();
      return res.status(200).json({ artifacts });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Preview how ONE time scope maps onto a bundle's artifacts, WITHOUT launching anything: which
  // artifacts get bounded (and via which parameter), and which have no date parameter and so collect in
  // full. Bundles are global, so this route is too. Body: {preset} or {start,end}.
  app.post("/velociraptor/bundles/:id/time-scope-preview", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.artifactBundleStore) return res.status(501).json({ error: "bundle store not configured" });
    let bundle;
    try {
      bundle = await options.artifactBundleStore.get(req.params.id);
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
    if (!bundle) return res.status(404).json({ error: `bundle "${req.params.id}" not found` });

    // Split structurally, not by matching error text: resolveTimeScope only ever throws on the
    // ANALYST's input (bad date, end before start) → 400. The definitions fetch is I/O against the
    // Velociraptor server → any failure there is the server's fault → 502. Keeping them in separate
    // try/catch blocks means a reworded validation message (or a future server error that happens to
    // contain a matched phrase) can never get silently misclassified.
    let scope;
    try {
      scope = resolveTimeScope(req.body ?? {});
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
    if (!scope) return res.status(400).json({ error: "a time scope is required — pass a preset (24h/7d/30d/90d) or a custom start" });

    try {
      const definitions = await options.velociraptorClient.listClientArtifacts("client");
      const plan = buildTimeScopePlan({
        artifacts: bundle.artifacts, definitions, scope,
        corrections: bundle.timeScopeParamNames, bundleParams: bundle.params,
      });
      return res.status(200).json({ scope, scoped: plan.scoped, unscoped: plan.unscoped, degraded: plan.degraded });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Save the analyst's per-artifact time-scope parameter CORRECTIONS on a bundle, without re-sending the
  // whole bundle — the preview is shown from the run form, which has no bundle editor around it, so a
  // full POST /bundles would clobber fields it doesn't know about. Read-modify-write through the store
  // so every other field is preserved verbatim. This is a full REPLACE of timeScopeParamNames, not a
  // merge: sending {} clears every correction, and sending ANY partial map silently drops every
  // correction absent from it (not just the ones you meant to touch). The caller (the dashboard's
  // veloSaveTimeScopeParamNames) is responsible for merging against the bundle's currently-stored
  // corrections before calling this route — see the comment there for why that matters.
  app.put("/velociraptor/bundles/:id/time-scope-param-names", async (req: Request, res: Response) => {
    if (!options.artifactBundleStore) return res.status(501).json({ error: "bundle store not configured" });
    try {
      const bundle = await options.artifactBundleStore.get(req.params.id);
      if (!bundle) return res.status(404).json({ error: `bundle "${req.params.id}" not found` });
      const saved = await options.artifactBundleStore.save({
        ...bundle,
        timeScopeParamNames: req.body?.timeScopeParamNames ?? {},
      });
      return res.status(200).json(saved);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Fold the analyst's time scope (if any) into the bundle's hunt params, and derive the provenance
  // block recorded on the job. Behavior-preserving seam pulled out of run-bundle: with no time scope,
  // `huntParams` is `bundle.params` verbatim (same reference) and there's no provenance — exactly the
  // pre-time-scope behavior. Logs the scope summary, including which artifacts collect in full, since
  // that's what someone debugging a thinner-than-expected collection needs to see.
  function resolveScopedHuntParams(
    artifactsToRun: string[],
    definitions: VeloArtifactInfo[],
    timeScope: TimeScope | undefined,
    bundle: ArtifactBundle,
  ): { huntParams: Record<string, Record<string, string>> | undefined; timeScopeProvenance?: NonNullable<VeloHuntJob["timeScope"]> } {
    if (!timeScope) return { huntParams: bundle.params };
    const scopePlan = buildTimeScopePlan({
      artifacts: artifactsToRun, definitions, scope: timeScope,
      corrections: bundle.timeScopeParamNames, bundleParams: bundle.params,
    });
    const unscopedNames = scopePlan.unscoped.map((u) => u.artifact);
    const namesSuffix = unscopedNames.length
      ? ` (${unscopedNames.slice(0, 10).join(", ")}${unscopedNames.length > 10 ? `, +${unscopedNames.length - 10} more` : ""})`
      : "";
    logLine(`[velociraptor] time scope ${timeScope.start}${timeScope.end ? ` → ${timeScope.end}` : " → (open)"}: ${scopePlan.scoped.length}/${artifactsToRun.length} artifact(s) bounded, ${scopePlan.unscoped.length} collect in full${namesSuffix}${scopePlan.degraded ? " (server reported no parameter metadata)" : ""}`);
    return {
      huntParams: scopePlan.params,
      timeScopeProvenance: {
        start: timeScope.start, ...(timeScope.end ? { end: timeScope.end } : {}),
        scopedArtifacts: scopePlan.scoped.length, totalArtifacts: artifactsToRun.length,
        degraded: scopePlan.degraded,
      },
    };
  }

  // Run a saved bundle as a hunt (optionally scoped by label/OS), schedule auto-collect after
  // waitMinutes (default DFIR_VELO_HUNT_WAIT_MIN / bundle default / 10; clamped 1..1440), and respond
  // immediately. The hunt stays open on the server until its expiry — we just snapshot results later.
  app.post("/cases/:id/velociraptor/run-bundle", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.artifactBundleStore || !options.veloHuntStore) return res.status(501).json({ error: "bundle store not configured" });
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const bundleId = String(req.body?.bundleId ?? "").trim();
    if (!bundleId) return res.status(400).json({ error: "bundleId is required" });
    try {
      const bundle = await options.artifactBundleStore.get(bundleId);
      if (!bundle) return res.status(404).json({ error: `bundle "${bundleId}" not found` });
      if (!bundle.artifacts.length) return res.status(400).json({ error: "bundle has no artifacts" });

      const fallback = Number(process.env.DFIR_VELO_HUNT_WAIT_MIN) || bundle.defaultWaitMinutes || 10;
      const reqWait = Number(req.body?.waitMinutes);
      const waitMinutes = Math.min(1440, Math.max(1, Number.isFinite(reqWait) && reqWait > 0 ? reqWait : fallback));
      const os = ["windows", "linux", "darwin"].includes(String(req.body?.os)) ? (req.body.os as HuntTarget["os"]) : undefined;
      const target: HuntTarget = {
        includeLabels: toStringArray(req.body?.includeLabels),
        excludeLabels: toStringArray(req.body?.excludeLabels),
        os,
      };
      const minSeverity = parseMinSeverity(req.body?.minSeverity);   // applied to the import at collect time
      // A dwell-window-gated bundle (e.g. Dwell-Time Triage) records which window it was launched for,
      // and must not run untargeted — those raw host artifacts are only meaningful for a bounded window.
      const dwellWindowId = typeof req.body?.dwellWindowId === "string" && req.body.dwellWindowId.trim() ? req.body.dwellWindowId.trim() : undefined;
      // Per-collection timeout (seconds): run override > bundle default > Velociraptor's own default (600s).
      const reqTimeout = Number(req.body?.timeoutSeconds);
      const rawTimeout = Number.isFinite(reqTimeout) && reqTimeout > 0 ? reqTimeout : bundle.timeoutSeconds;
      const timeoutSeconds = typeof rawTimeout === "number" && rawTimeout > 0 ? Math.min(86_400, Math.max(60, Math.floor(rawTimeout))) : undefined;
      // Relative hunt expiry (seconds): run override > bundle default > the one-hour default.
      const expirySeconds = normalizeHuntExpirySeconds(
        Number(req.body?.expirySeconds) > 0 ? req.body.expirySeconds : bundle.expirySeconds,
      );

      // Resolve the analyst's collection window (undefined = all time, the default). Validation errors
      // are the analyst's input — fail with 400 BEFORE launching anything.
      let timeScope;
      try {
        timeScope = resolveTimeScope(req.body?.timeScope);
      } catch (e) {
        return res.status(400).json({ error: (e as Error).message });
      }

      // Pre-flight: Velociraptor's hunt() rejects the ENTIRE hunt if any named artifact doesn't exist
      // on the server, so one stale/misspelled name in a bundle (e.g. a starter list not yet verified
      // against THIS server) fails the whole run with an opaque "no hunt id". Intersect with the
      // server's known client artifacts, launch with the valid subset, and report which were unknown.
      // (Named `unknownArtifacts`, distinct from the JOB's collect-time `skippedArtifacts` = artifacts
      // that launched but failed to FETCH.) Best-effort: if the catalog lookup itself fails, launch the
      // bundle as-is rather than block on a diagnostics query.
      let artifactsToRun = bundle.artifacts;
      let unknownArtifacts: string[] = [];
      let definitions: VeloArtifactInfo[] = [];
      try {
        definitions = await options.velociraptorClient.listClientArtifacts("client");
        const known = new Set(definitions.map((a) => a.name));
        if (known.size) {
          const valid = bundle.artifacts.filter((a) => known.has(a));
          unknownArtifacts = bundle.artifacts.filter((a) => !known.has(a));
          if (!valid.length) {
            return res.status(400).json({ error: `none of this bundle's artifacts exist on the Velociraptor server — check the names in the bundle editor: ${bundle.artifacts.join(", ")}` });
          }
          artifactsToRun = valid;
          if (unknownArtifacts.length) logLine(`[velociraptor] bundle "${bundle.name}": skipping ${unknownArtifacts.length} artifact(s) not on this server: ${unknownArtifacts.join(", ")}`);
        }
      } catch (e) {
        logLine(`[velociraptor] artifact catalog check failed (launching bundle as-is): ${(e as Error).message}`);
      }

      // Fan the ONE chosen window out across the surviving artifacts' own date parameters, so each
      // collects less AT THE SOURCE. Artifacts with no date parameter keep collecting in full.
      const { huntParams, timeScopeProvenance } = resolveScopedHuntParams(artifactsToRun, definitions, timeScope, bundle);

      logLine(`[velociraptor] run bundle "${bundle.name}" (${artifactsToRun.length} artifact(s)${unknownArtifacts.length ? `, ${unknownArtifacts.length} skipped` : ""}), collect in ${waitMinutes}m, expires in ${expirySeconds}s${minSeverity ? `, min severity ${minSeverity}` : ""}${timeoutSeconds ? `, timeout ${timeoutSeconds}s` : ""}`);
      const launch = await options.velociraptorClient.launchArtifactHunt(artifactsToRun, bundle.name, target, { timeoutSeconds, params: huntParams, expirySeconds });
      const collectAt = new Date(Date.now() + waitMinutes * 60_000).toISOString();
      const job: VeloHuntJob = {
        bundleId: bundle.id, bundleName: bundle.name, artifacts: launch.artifacts,
        huntId: launch.huntId, guiUrl: launch.guiUrl,
        launchedAt: new Date().toISOString(), waitMinutes, collectAt,
        status: "running", target, minSeverity, timeoutSeconds, expirySeconds, filters: bundle.filters, dwellWindowId,
        ...(timeScopeProvenance ? { timeScope: timeScopeProvenance } : {}),
      };
      // Append this hunt (concurrent hunts are kept side by side, keyed by huntId) + its own timer.
      await options.veloHuntStore.upsert(caseId, job);
      // #157: record the bundle deploy (no VQL — bundles are artifact lists; outcome filled on collect).
      await ctx.recordHuntDeploy(caseId, { source: "bundle", title: bundle.name, huntId: launch.huntId, deployedAt: new Date().toISOString() });
      options.onVeloHunt?.(caseId);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "hunt", action: "run-bundle", detail: `ran bundle "${bundle.name}" (${artifactsToRun.length} artifact(s))`,
      });

      const timer = setTimeout(() => { void ctx.importVeloHuntResults(caseId, launch.huntId); }, waitMinutes * 60_000);
      timer.unref?.();
      ctx.veloHuntTimers().set(launch.huntId, timer);
      ctx.scheduleVeloHuntStatusPoll(caseId, launch.huntId);

      return res.status(202).json({ huntId: launch.huntId, guiUrl: launch.guiUrl, collectAt, waitMinutes, artifacts: launch.artifacts, unknownArtifacts, timeScope: job.timeScope });
    } catch (err) {
      logLine(`[velociraptor] run bundle ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Import an EXTERNAL Velociraptor hunt/flow (launched in the Velociraptor GUI, not by the Companion).
  // Paste a hunt id / flow / GUI URL; discover what it collected (for a flow, resolve the host) and
  // import via the SAME chain as every other Velociraptor import — optionally to the super-timeline only.
  app.post("/cases/:id/velociraptor/import-external", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const ref = parseVeloRef(String(req.body?.ref ?? ""));
    if (!ref) return res.status(400).json({ error: "paste a hunt id (H.…), a flow (C.…/F.…), or a Velociraptor GUI URL" });
    // A notebook URL shows the analyst's OWN filtered VQL query results — this server can only pull the
    // flow/hunt's complete raw collected rows (a different, much larger row set), which silently imports
    // far more than the analyst is looking at. Only the browser extension's "Push rows" button captures
    // the notebook's actual rendered/filtered results (it reads the GUI's own table), so redirect there.
    if (ref.isNotebookUrl) {
      return res.status(400).json({
        error: "this is a Velociraptor NOTEBOOK URL — importing it here would pull the flow/hunt's complete raw results, not your notebook's filtered query. Open the notebook in your browser and use the DFIR Companion extension's \"Push rows → DFIR-Companion\" button instead, which imports exactly what the notebook shows.",
      });
    }
    const minSeverity = parseMinSeverity(req.body?.minSeverity);
    const superOnly = req.body?.superTimelineOnly === true;
    // Uploaded reports (THOR/Hayabusa) only have a forensic-merge importer (dispatchImport) — routing
    // them to the super-timeline-only path would leak into the forensic timeline and break its
    // invariant (mirrors the same guard on the bundle-collect uploads step).
    if (ref.isUploadsUrl && superOnly) {
      return res.status(400).json({ error: "uploaded-file import doesn't support super-timeline-only mode — collect upload-based artifacts via a normal (forensic-timeline) import instead" });
    }
    const client = options.velociraptorClient;
    try {
      if (ref.kind === "hunt") {
        if (ref.isUploadsUrl) {
          const uploads = await client.huntUploads(ref.huntId);
          if (!uploads.length) {
            return res.status(200).json({ kind: "hunt", huntId: ref.huntId, addedEvents: 0, addedIocs: 0, uploadsOnly: true, note: "no uploaded report files found for this hunt yet (or none matched a supported format)" });
          }
          const out = await ctx.ingestVeloUploads(caseId, uploads, { minSeverity, label: `velo-hunt-uploads_${ref.huntId}` });
          options.onVeloHunt?.(caseId);
          return res.status(200).json({
            kind: "hunt", huntId: ref.huntId, uploadsOnly: true, imported: out.imported, skipped: out.skipped,
            addedEvents: out.addedEvents, addedIocs: out.addedIocs,
            ...(out.imported.length === 0 ? { note: "found uploaded file(s) but none could be imported — unsupported format, or an AI-dependent format (CSV/log) while AI is off for this case" } : {}),
          });
        }
        const arts = await client.getHuntArtifacts(ref.huntId);
        if (!arts.length) return res.status(404).json({ error: `hunt ${ref.huntId} not found on the server, or it collected no artifacts` });
        const { results } = await client.huntResultsByArtifact(ref.huntId, arts);
        if (!Object.keys(results).length) return res.status(200).json({ kind: "hunt", huntId: ref.huntId, artifacts: arts, addedEvents: 0, addedIocs: 0, superTimelineOnly: superOnly, note: "the hunt returned no rows yet" });
        const out = await ctx.ingestVeloArtifactMap(caseId, JSON.stringify(results), { label: `velo-hunt_${ref.huntId}.json`, idBase: ref.huntId, superOnly, minSeverity, veloUrl: client.huntGuiUrlFor(ref.huntId) });
        options.onVeloHunt?.(caseId);
        return res.status(200).json({ kind: "hunt", huntId: ref.huntId, artifacts: Object.keys(results), addedEvents: out.addedEvents, addedIocs: out.addedIocs, superTimelineOnly: superOnly });
      }
      if (ref.isUploadsUrl) {
        const uploads = await client.flowUploads(ref.clientId, ref.flowId);
        if (!uploads.length) {
          return res.status(200).json({ kind: "flow", clientId: ref.clientId, flowId: ref.flowId, addedEvents: 0, addedIocs: 0, uploadsOnly: true, note: "no uploaded report files found for this flow yet (or none matched a supported format)" });
        }
        const out = await ctx.ingestVeloUploads(caseId, uploads, { minSeverity, label: `velo-flow-uploads_${ref.flowId}` });
        options.onVeloHunt?.(caseId);
        return res.status(200).json({
          kind: "flow", clientId: ref.clientId, flowId: ref.flowId, uploadsOnly: true, imported: out.imported, skipped: out.skipped,
          addedEvents: out.addedEvents, addedIocs: out.addedIocs,
          ...(out.imported.length === 0 ? { note: "found uploaded file(s) but none could be imported — unsupported format, or an AI-dependent format (CSV/log) while AI is off for this case" } : {}),
        });
      }
      const info = await client.getFlowInfo(ref.clientId, ref.flowId);
      if (!info.artifacts.length) return res.status(404).json({ error: `flow ${ref.flowId} on ${ref.clientId} not found, or it collected no artifacts` });
      const map: Record<string, unknown[]> = {};
      for (const art of info.artifacts) {
        try { const r = await client.collectionResults(ref.clientId, ref.flowId, art); if (r.rows.length) map[art] = r.rows; }
        catch (e) { logLine(`[velociraptor] external flow ${ref.flowId}: artifact ${art} read failed: ${(e as Error).message}`); }
      }
      if (!Object.keys(map).length) return res.status(200).json({ kind: "flow", clientId: ref.clientId, flowId: ref.flowId, hostname: info.hostname, artifacts: info.artifacts, addedEvents: 0, addedIocs: 0, superTimelineOnly: superOnly, note: "the flow returned no rows" });
      const out = await ctx.ingestVeloArtifactMap(caseId, JSON.stringify(map), { label: `velo-flow_${ref.flowId}.json`, idBase: ref.flowId, superOnly, minSeverity, hostFallback: info.hostname, veloUrl: client.flowGuiUrlFor(ref.clientId, ref.flowId) });
      options.onVeloHunt?.(caseId);
      return res.status(200).json({ kind: "flow", clientId: ref.clientId, flowId: ref.flowId, hostname: info.hostname, artifacts: Object.keys(map), addedEvents: out.addedEvents, addedIocs: out.addedIocs, superTimelineOnly: superOnly });
    } catch (err) {
      logLine(`[velociraptor] import-external ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // All bundle hunts for a case (newest first) — status + countdown + outcome per hunt. [] when none.
  app.get("/cases/:id/velociraptor/hunt-jobs", async (req: Request, res: Response) => {
    if (!options.veloHuntStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.veloHuntStore.list(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Collect a specific hunt NOW (don't wait for its timer). Body `{ huntId }`; defaults to the most
  // recent hunt when omitted. Runs in the background; poll hunt-jobs. 404 when there's nothing to collect.
  app.post("/cases/:id/velociraptor/collect", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloHuntStore) return res.status(501).json({ error: "hunt store not configured" });
    const caseId = req.params.id;
    const wantedHuntId = String(req.body?.huntId ?? "").trim();
    const jobs = await options.veloHuntStore.list(caseId);
    const job = wantedHuntId ? jobs.find((j) => j.huntId === wantedHuntId) : jobs[0];
    if (!job) return res.status(404).json({ error: wantedHuntId ? `no Velociraptor hunt ${wantedHuntId} for this case` : "no Velociraptor hunt to collect for this case" });
    res.status(202).json({ accepted: true, huntId: job.huntId });
    void ctx.importVeloHuntResults(caseId, job.huntId);
  });

  // Manually run one status-poll tick for a hunt NOW instead of waiting for the next scheduled tick
  // (mirrors the live-monitor .../poll route) — used by ops to force a check, and by tests instead of
  // waiting out DFIR_VELO_HUNT_POLL_S. Awaits the poll so the response already reflects its outcome.
  app.post("/cases/:id/velociraptor/hunt-jobs/:huntId/poll-status", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloHuntStore) return res.status(501).json({ error: "hunt store not configured" });
    const caseId = req.params.id;
    const huntId = req.params.huntId;
    await ctx.pollVeloHuntStatus(caseId, huntId);
    const job = await options.veloHuntStore.get(caseId, huntId);
    if (!job) return res.status(404).json({ error: `no Velociraptor hunt ${huntId} for this case` });
    return res.status(200).json(job);
  });

  // ── Hunting feedback loop (#157) ─────────────────────────────────────────────────────────────

  // Deploy a SUGGESTED hunt for a case and record it in the hunting feedback loop. Two modes:
  //  - "hunt" (default): launch a fleet HUNT, register a VeloHuntJob, and schedule auto-collect after
  //    DFIR_VELO_HUNT_WAIT_MIN (like a bundle) so the outcome fills on its own; "Collect now" pulls early.
  //  - "collection": run a single-host COLLECTION (the playbook per-endpoint deploy path).
  // Either way the deployed VQL is recorded (so it's never re-proposed) and shows in the profile.
  // Body: { vql, title, description?, source?, mitreTechniques?, mode?, hostname?, waitMinutes? }.
  app.post("/cases/:id/velociraptor/deploy-hunt", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const caseId = req.params.id;
    const vql = typeof req.body?.vql === "string" ? req.body.vql.trim() : "";
    const title = typeof req.body?.title === "string" ? req.body.title.trim() : "";
    const description = typeof req.body?.description === "string" && req.body.description.trim() ? req.body.description : title;
    const rawSource = String(req.body?.source ?? "");
    const allowedSources: HuntOutcomeSource[] = ["fleet", "playbook", "technique"];   // "bundle" is server-set, not client-supplied
    const source: HuntOutcomeSource = allowedSources.includes(rawSource as HuntOutcomeSource) ? (rawSource as HuntOutcomeSource) : "fleet";
    const mitreTechniques = toStringArray(req.body?.mitreTechniques);
    const mode = req.body?.mode === "collection" ? "collection" : "hunt";
    const hostname = typeof req.body?.hostname === "string" ? req.body.hostname.trim() : "";
    // ACH hunt→hypothesis link (investigation-guidance #14, deferred): when the analyst deploys a hunt to
    // TEST a specific hypothesis, carry its id so an empty result counts as a MISS against that exact
    // hypothesis (→ eventual `exhausted`), not just a technique-overlap match.
    const relatedHypothesisId = typeof req.body?.relatedHypothesisId === "string" && req.body.relatedHypothesisId.trim()
      ? req.body.relatedHypothesisId.trim() : undefined;
    if (!vql) return res.status(400).json({ error: "vql is required" });
    if (!title) return res.status(400).json({ error: "title is required" });
    try {
      if (mode === "collection") {
        if (!hostname) return res.status(400).json({ error: "hostname is required for a collection" });
        logLine(`[velociraptor] deploy-hunt collection "${title}" on ${hostname}`);
        const result = await collectHostResolved(hostname, vql, description);
        // A collection is a per-host FLOW (no huntId), so its outcome isn't auto-collected — but recording
        // the deploy still excludes it from re-proposal and surfaces it in the hunting profile.
        await ctx.recordHuntDeploy(caseId, { source, title, vql, mitreTechniques, deployedAt: new Date().toISOString(), ...(relatedHypothesisId ? { relatedHypothesisId } : {}) });
        options.onVeloHunt?.(caseId);
        logActivity(options.activityLogStore, options.onActivity, caseId, {
          category: "hunt", action: "deploy-collection", detail: `collection "${title}" on ${hostname}`,
        });
        return res.status(200).json({ mode, ...result });
      }
      const expirySeconds = normalizeHuntExpirySeconds(req.body?.expirySeconds);   // relative; defaults to one hour
      logLine(`[velociraptor] deploy-hunt fleet "${title}" (expires in ${expirySeconds}s)`);
      const launch = await options.velociraptorClient.launchHunt(vql, description, { expirySeconds });
      // Register a collectible job AND schedule auto-collect (the same flow bundle hunts use) so the
      // outcome fills by huntId without the analyst remembering to collect — fleet hunt results trickle
      // in as clients check in, so we pull after the wait (and "Collect now" can pull early / re-pull).
      const reqWait = Number(req.body?.waitMinutes);
      const waitMinutes = Math.min(1440, Math.max(1, Number.isFinite(reqWait) && reqWait > 0 ? reqWait : (Number(process.env.DFIR_VELO_HUNT_WAIT_MIN) || 10)));
      if (options.veloHuntStore) {
        const now = new Date();
        const job: VeloHuntJob = {
          bundleId: `suggested:${source}`, bundleName: title, artifacts: launch.artifact ? [launch.artifact] : [],
          sources: launch.sources,   // #157: the Custom.Hunt artifact's named sources (Pivot0…) so collect reads `artifact/source`
          huntId: launch.huntId, guiUrl: launch.guiUrl, launchedAt: now.toISOString(), waitMinutes,
          collectAt: new Date(now.getTime() + waitMinutes * 60_000).toISOString(), status: "running", expirySeconds,
        };
        await options.veloHuntStore.upsert(caseId, job);
        const timer = setTimeout(() => { void ctx.importVeloHuntResults(caseId, launch.huntId); }, waitMinutes * 60_000);
        timer.unref?.();
        ctx.veloHuntTimers().set(launch.huntId, timer);
        ctx.scheduleVeloHuntStatusPoll(caseId, launch.huntId);
      }
      await ctx.recordHuntDeploy(caseId, { source, title, vql, mitreTechniques, huntId: launch.huntId, deployedAt: new Date().toISOString(), ...(relatedHypothesisId ? { relatedHypothesisId } : {}) });
      options.onVeloHunt?.(caseId);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "hunt", action: "deploy-hunt", detail: `fleet hunt "${title}" deployed (${source})`,
      });
      return res.status(200).json({ mode, waitMinutes, ...launch });
    } catch (err) {
      logLine(`[velociraptor] deploy-hunt ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // One-click deploy of a structured collection directive (investigation-guidance #8, phase 3). The
  // dashboard next-steps / key-questions Deploy button posts { hostname, artifact?, logSource? }; we
  // resolve those to a real client artifact VQL (collectDirectiveResolve) and launch a per-host
  // collection via the same collectHostResolved path deploy-hunt uses — which itself refuses a host that
  // isn't an enrolled client, the server-side backstop to the dashboard's own known-host gating. 400
  // when the directive names nothing collectable (the UI then shows a manual checklist instead).
  app.post("/cases/:id/velociraptor/collect-directive", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const caseId = req.params.id;
    const hostname = typeof req.body?.hostname === "string" ? req.body.hostname.trim() : "";
    const artifact = typeof req.body?.artifact === "string" ? req.body.artifact.trim() : "";
    const logSource = typeof req.body?.logSource === "string" ? req.body.logSource.trim() : "";
    if (!hostname) return res.status(400).json({ error: "hostname is required" });
    const resolved = resolveCollectVql({ artifact: artifact || undefined, logSource: logSource || undefined });
    if (!resolved) {
      return res.status(400).json({ error: `could not map "${artifact || logSource}" to a Velociraptor artifact — collect it manually` });
    }
    const title = `Collect ${resolved.artifact} on ${hostname}`;
    try {
      logLine(`[velociraptor] collect-directive ${resolved.artifact} on ${hostname}`);
      const result = await collectHostResolved(hostname, resolved.vql, title);
      await ctx.recordHuntDeploy(caseId, { source: "playbook", title, vql: resolved.vql, deployedAt: new Date().toISOString() });
      options.onVeloHunt?.(caseId);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "hunt", action: "deploy-collection", detail: `collection ${resolved.artifact} on ${hostname}`,
      });
      return res.status(200).json({ ...result, artifact: resolved.artifact, vql: resolved.vql });
    } catch (err) {
      logLine(`[velociraptor] collect-directive ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Read a recorded hunt's result rows ON DEMAND for the Hunting Profile's expandable view (#157) —
  // resolves the hunt's artifact(s)+sources from the persisted job (the profile only carries the hunt
  // id), so the analyst can review what a hunt found from the persistent profile after the ephemeral
  // suggestion card is gone. 404 when the job aged out of the (capped) list; 501 without the API.
  app.post("/cases/:id/velociraptor/hunt-rows", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloHuntStore) return res.status(501).json({ error: "hunt store not configured" });
    const huntId = String(req.body?.huntId ?? "").trim();
    if (!huntId) return res.status(400).json({ error: "huntId is required" });
    try {
      const job = await options.veloHuntStore.get(req.params.id, huntId);
      if (!job) return res.status(404).json({ error: "this hunt is no longer tracked (it aged out of the job list) — re-run it to see results" });
      const sourcesByArtifact = (job.sources?.length && job.artifacts.length === 1) ? { [job.artifacts[0]]: job.sources } : undefined;
      const { results, skipped } = await options.velociraptorClient.huntResultsByArtifact(job.huntId, job.artifacts, job.filters, sourcesByArtifact);
      const rows = Object.values(results).flat();
      return res.status(200).json({ rows, total: rows.length, artifacts: Object.keys(results), skipped });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // ── Live Velociraptor CLIENT_EVENT monitoring (#84) ───────────────────────────────────────────

  // List the server's CLIENT_EVENT (continuous monitoring) artifacts for the Monitor-mode picker.
  app.get("/velociraptor/event-artifacts", async (_req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    try {
      return res.status(200).json({ artifacts: await options.velociraptorClient.listClientArtifacts("client_event") });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // All live monitors for a case (with status + running stats). [] when monitoring isn't configured.
  app.get("/cases/:id/velociraptor/monitors", async (req: Request, res: Response) => {
    if (!options.veloMonitorStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.veloMonitorStore.list(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Start a live monitor: poll a CLIENT_EVENT artifact on one client and stream new rows into the case.
  // Body `{ clientId, artifact, pollSeconds?, hostname?, minSeverity? }`. Idempotent per (client,
  // artifact) — re-adding the same pair updates it in place. The cursor starts at "now" so only events
  // that arrive AFTER the monitor is created are ingested (no history backfill).
  app.post("/cases/:id/velociraptor/monitors", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: "case not found" });
    // `allClients` (or clientId === "*") watches the artifact across EVERY enrolled client in one
    // monitor — no specific endpoint to pick. Otherwise a real client id is required.
    const wantsAll = req.body?.allClients === true || String(req.body?.clientId ?? "").trim() === ALL_CLIENTS;
    const clientId = wantsAll ? ALL_CLIENTS : String(req.body?.clientId ?? "").trim();
    const artifact = String(req.body?.artifact ?? "").trim();
    if (!wantsAll && !/^C\.[A-Za-z0-9]+$/.test(clientId)) return res.status(400).json({ error: "a valid Velociraptor clientId (C....) is required, or set allClients:true" });
    if (!/^[A-Za-z0-9._]+$/.test(artifact)) return res.status(400).json({ error: "a valid CLIENT_EVENT artifact name is required" });
    try {
      const fallback = Number(options.veloMonitorPollSeconds) || 30;
      const reqPoll = Number(req.body?.pollSeconds);
      const pollSeconds = Math.min(3600, Math.max(5, Number.isFinite(reqPoll) && reqPoll > 0 ? Math.floor(reqPoll) : fallback));
      const hostname = String(req.body?.hostname ?? "").trim() || undefined;
      const minSeverity = parseMinSeverity(req.body?.minSeverity);
      const monitor = await ctx.createVeloMonitor(caseId, { clientId, artifact, pollSeconds, hostname, minSeverity, allClients: wantsAll });
      return res.status(202).json({ accepted: true, monitor });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Auto-monitor every client-event artifact ALREADY enabled in Velociraptor's client monitoring table
  // (#84 follow-up) — discovers them via GetClientMonitoringState() and starts an ALL-clients monitor
  // for each (idempotent: an existing monitor for the same artifact is refreshed, not duplicated). 422
  // with guidance when nothing is configured / the version's proto differs (set the override env var).
  app.post("/cases/:id/velociraptor/monitors/auto", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: "case not found" });
    try {
      const discovered = await options.velociraptorClient.listMonitoredArtifacts();
      if (!discovered.length) {
        // Capture the RAW monitoring-state shape (which varies by version) — logged AND returned in the
        // response so the analyst can see it in the dashboard and we can model DFIR_VELOCIRAPTOR_MONITORED_VQL.
        let rawSample = "";
        try {
          const raw = await options.velociraptorClient.monitoringStateRaw();
          rawSample = JSON.stringify(raw).slice(0, 2000);
          logLine(`[velo-monitor] auto: monitoring table returned no artifacts. Raw get_client_monitoring() shape: ${rawSample}`);
        } catch (e) { rawSample = `(read failed: ${(e as Error).message})`; logLine(`[velo-monitor] auto: monitoring-state read failed: ${(e as Error).message}`); }
        return res.status(422).json({ error: "no client-event artifacts found in Velociraptor's client monitoring table — enable some in Velociraptor → Client Monitoring first, or (if your version's monitoring proto differs) open /velociraptor/diag and share the output to set DFIR_VELOCIRAPTOR_MONITORED_VQL", discovered: [], rawSample });
      }
      const fallback = Number(options.veloMonitorPollSeconds) || 30;
      const reqPoll = Number(req.body?.pollSeconds);
      const pollSeconds = Math.min(3600, Math.max(5, Number.isFinite(reqPoll) && reqPoll > 0 ? Math.floor(reqPoll) : fallback));
      const minSeverity = parseMinSeverity(req.body?.minSeverity);
      const started: VeloMonitor[] = [];
      for (const artifact of discovered) {
        started.push(await ctx.createVeloMonitor(caseId, { clientId: ALL_CLIENTS, artifact, pollSeconds, minSeverity, allClients: true }));
      }
      logLine(`[velo-monitor] auto-started ${started.length} all-clients monitor(s) from the Velociraptor monitoring table for case ${caseId}`);
      return res.status(202).json({ accepted: true, discovered, started });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Stop a monitor (clears its timer + marks it stopped, but keeps the row so it can be resumed).
  app.post("/cases/:id/velociraptor/monitors/:mid/stop", async (req: Request, res: Response) => {
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    const caseId = req.params.id, id = req.params.mid;
    const monitor = await options.veloMonitorStore.get(caseId, id);
    if (!monitor) return res.status(404).json({ error: "monitor not found" });
    ctx.stopVeloMonitorTimer(caseId, id);
    await options.veloMonitorStore.upsert(caseId, { ...monitor, status: "stopped" });
    options.onVeloMonitor?.(caseId);
    return res.status(200).json({ ok: true });
  });

  // Resume a stopped monitor (re-arms its timer; keeps the persisted cursor so no re-ingest).
  app.post("/cases/:id/velociraptor/monitors/:mid/start", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    const caseId = req.params.id, id = req.params.mid;
    const monitor = await options.veloMonitorStore.get(caseId, id);
    if (!monitor) return res.status(404).json({ error: "monitor not found" });
    const resumed = { ...monitor, status: "active" as const, lastError: undefined };
    await options.veloMonitorStore.upsert(caseId, resumed);
    ctx.scheduleVeloMonitor(caseId, resumed);
    options.onVeloMonitor?.(caseId);
    return res.status(200).json({ ok: true });
  });

  // Poll a monitor NOW (don't wait for its timer) — a "check now" for the analyst. Runs one poll cycle
  // (which also re-arms an active monitor's timer) and returns the updated monitor.
  app.post("/cases/:id/velociraptor/monitors/:mid/poll", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    const caseId = req.params.id, id = req.params.mid;
    const monitor = await options.veloMonitorStore.get(caseId, id);
    if (!monitor) return res.status(404).json({ error: "monitor not found" });
    await ctx.pollVeloMonitor(caseId, id);
    return res.status(200).json({ ok: true, monitor: await options.veloMonitorStore.get(caseId, id) });
  });

  // Delete a monitor entirely (stop + remove the row).
  app.delete("/cases/:id/velociraptor/monitors/:mid", async (req: Request, res: Response) => {
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    const caseId = req.params.id, id = req.params.mid;
    ctx.stopVeloMonitorTimer(caseId, id);
    await options.veloMonitorStore.remove(caseId, id);
    options.onVeloMonitor?.(caseId);
    return res.status(204).end();
  });
}
