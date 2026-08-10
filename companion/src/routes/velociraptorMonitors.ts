import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import { parseMinSeverity } from "../analysis/severityFloor.js";
import { ALL_CLIENTS } from "../integrations/velociraptor/velociraptorApi.js";
import type { VeloMonitor } from "../analysis/veloMonitorStore.js";

// Live Velociraptor CLIENT_EVENT monitoring (#84): the event-artifact catalog and the per-case
// monitor CRUD (list, create, auto-suggest, start, stop, poll, delete).
//
// Lifted out of routes/velociraptor.ts, which the file-size ledger had frozen at 888 lines. The seam
// is real rather than convenient: everything else in that module is REQUEST/RESPONSE — run a query,
// launch a hunt, collect from a host, import results — a bounded exchange that finishes. A monitor
// is a standing subscription with a lifecycle of its own: it is created, polled on a timer, stopped,
// restarted and removed, and it owns background timers (scheduleVeloMonitor / stopVeloMonitorTimer)
// that nothing else here touches.
//
// MOVED VERBATIM. Route bodies, status codes and messages are unchanged; only the registration point
// moved, following the register*Routes convention already used across routes/.

export function registerVelociraptorMonitorRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);
  // Same `?refresh=1` bypass the artifact catalog in routes/velociraptor.ts uses; duplicated rather
  // than exported so neither module owns a two-line predicate on the other's behalf.
  const isRefresh = (req: Request): boolean => {
    const v = String(req.query?.refresh ?? "").toLowerCase();
    return v === "1" || v === "true";
  };

  // ── Live Velociraptor CLIENT_EVENT monitoring (#84) ───────────────────────────────────────────

  // List the server's CLIENT_EVENT (continuous monitoring) artifacts for the Monitor-mode picker.
  // Same short-TTL catalog cache + `?refresh=1` bypass as /velociraptor/artifacts above.
  app.get("/velociraptor/event-artifacts", async (req: Request, res: Response) => {
    if (!options.velociraptorClient)
      return res
        .status(501)
        .json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    try {
      return res.status(200).json({
        artifacts: await options.velociraptorClient.listClientArtifacts("client_event", {
          refresh: isRefresh(req),
        }),
      });
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
    if (!options.velociraptorClient)
      return res
        .status(501)
        .json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: "case not found" });
    // `allClients` (or clientId === "*") watches the artifact across EVERY enrolled client in one
    // monitor — no specific endpoint to pick. Otherwise a real client id is required.
    const wantsAll = req.body?.allClients === true || String(req.body?.clientId ?? "").trim() === ALL_CLIENTS;
    const clientId = wantsAll ? ALL_CLIENTS : String(req.body?.clientId ?? "").trim();
    const artifact = String(req.body?.artifact ?? "").trim();
    if (!wantsAll && !/^C\.[A-Za-z0-9]+$/.test(clientId))
      return res
        .status(400)
        .json({ error: "a valid Velociraptor clientId (C....) is required, or set allClients:true" });
    if (!/^[A-Za-z0-9._]+$/.test(artifact))
      return res.status(400).json({ error: "a valid CLIENT_EVENT artifact name is required" });
    try {
      const fallback = Number(options.veloMonitorPollSeconds) || 30;
      const reqPoll = Number(req.body?.pollSeconds);
      const pollSeconds = Math.min(
        3600,
        Math.max(5, Number.isFinite(reqPoll) && reqPoll > 0 ? Math.floor(reqPoll) : fallback),
      );
      const hostname = String(req.body?.hostname ?? "").trim() || undefined;
      const minSeverity = parseMinSeverity(req.body?.minSeverity);
      const monitor = await ctx.createVeloMonitor(caseId, {
        clientId,
        artifact,
        pollSeconds,
        hostname,
        minSeverity,
        allClients: wantsAll,
      });
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
    if (!options.velociraptorClient)
      return res
        .status(501)
        .json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
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
          logLine(
            `[velo-monitor] auto: monitoring table returned no artifacts. Raw get_client_monitoring() shape: ${rawSample}`,
          );
        } catch (e) {
          rawSample = `(read failed: ${(e as Error).message})`;
          logLine(`[velo-monitor] auto: monitoring-state read failed: ${(e as Error).message}`);
        }
        return res.status(422).json({
          error:
            "no client-event artifacts found in Velociraptor's client monitoring table — enable some in Velociraptor → Client Monitoring first, or (if your version's monitoring proto differs) open /velociraptor/diag and share the output to set DFIR_VELOCIRAPTOR_MONITORED_VQL",
          discovered: [],
          rawSample,
        });
      }
      const fallback = Number(options.veloMonitorPollSeconds) || 30;
      const reqPoll = Number(req.body?.pollSeconds);
      const pollSeconds = Math.min(
        3600,
        Math.max(5, Number.isFinite(reqPoll) && reqPoll > 0 ? Math.floor(reqPoll) : fallback),
      );
      const minSeverity = parseMinSeverity(req.body?.minSeverity);
      const started: VeloMonitor[] = [];
      for (const artifact of discovered) {
        started.push(
          await ctx.createVeloMonitor(caseId, {
            clientId: ALL_CLIENTS,
            artifact,
            pollSeconds,
            minSeverity,
            allClients: true,
          }),
        );
      }
      logLine(
        `[velo-monitor] auto-started ${started.length} all-clients monitor(s) from the Velociraptor monitoring table for case ${caseId}`,
      );
      return res.status(202).json({ accepted: true, discovered, started });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Stop a monitor (clears its timer + marks it stopped, but keeps the row so it can be resumed).
  app.post("/cases/:id/velociraptor/monitors/:mid/stop", async (req: Request, res: Response) => {
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    const caseId = req.params.id,
      id = req.params.mid;
    const monitor = await options.veloMonitorStore.get(caseId, id);
    if (!monitor) return res.status(404).json({ error: "monitor not found" });
    ctx.stopVeloMonitorTimer(caseId, id);
    await options.veloMonitorStore.upsert(caseId, { ...monitor, status: "stopped" });
    options.onVeloMonitor?.(caseId);
    return res.status(200).json({ ok: true });
  });

  // Resume a stopped monitor (re-arms its timer; keeps the persisted cursor so no re-ingest).
  app.post("/cases/:id/velociraptor/monitors/:mid/start", async (req: Request, res: Response) => {
    if (!options.velociraptorClient)
      return res
        .status(501)
        .json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    const caseId = req.params.id,
      id = req.params.mid;
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
    if (!options.velociraptorClient)
      return res
        .status(501)
        .json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    const caseId = req.params.id,
      id = req.params.mid;
    const monitor = await options.veloMonitorStore.get(caseId, id);
    if (!monitor) return res.status(404).json({ error: "monitor not found" });
    await ctx.pollVeloMonitor(caseId, id);
    return res.status(200).json({ ok: true, monitor: await options.veloMonitorStore.get(caseId, id) });
  });

  // Delete a monitor entirely (stop + remove the row).
  app.delete("/cases/:id/velociraptor/monitors/:mid", async (req: Request, res: Response) => {
    if (!options.veloMonitorStore) return res.status(501).json({ error: "monitor store not configured" });
    const caseId = req.params.id,
      id = req.params.mid;
    ctx.stopVeloMonitorTimer(caseId, id);
    await options.veloMonitorStore.remove(caseId, id);
    options.onVeloMonitor?.(caseId);
    return res.status(204).end();
  });
}
