import type { Express, Request, Response } from "express";
import type { AssetType } from "../analysis/assetGraph.js";
import { buildLoginGraph, loginEdgeEvents, DEFAULT_MAX_EDGES } from "../analysis/loginGraph.js";
import { mergeIocs } from "../analysis/iocMerge.js";
import type { RouteContext } from "./context.js";

/**
 * analysisGraph domain: the read-mostly ANALYSIS / VISUALIZATION projections derived from a case's
 * state, plus the two analyst-authored overlays that feed those views. Every read here is derived on
 * demand with the same scope/legitimate filtering as the report; no AI.
 *
 *   Graphs & rankings (options.reportWriter, pure reads):
 *   - GET    /cases/:id/asset-graph              — asset ↔ IoC graph. Optional ?from/?until time window (#83).
 *   - GET    /cases/:id/login-graph              — directed account→host logon graph (4624/4625, from the super-timeline).
 *   - GET    /cases/:id/login-graph/edge-events  — the events behind one login-graph edge (lazy drill-down).
 *   - GET    /cases/:id/evidence-graph           — causal evidence chain (process trees + lateral). Optional ?from/?until (#83).
 *   - GET    /cases/:id/lateral-paths            — ordered lateral-movement chains (entry→pivot→target, #92). Optional ?from/?until (#83).
 *   - GET    /cases/:id/phases                   — temporal attack phases (activity bursts).
 *   - GET    /cases/:id/beacon-candidates        — regular-interval C2 candidates (#82).
 *   - GET    /cases/:id/anomalies                — per-asset event-rate spikes (#175).
 *   - GET    /cases/:id/host-ranking             — suspicious host/account ranking (#202).
 *   - GET    /cases/:id/d3fend-countermeasures   — MITRE D3FEND countermeasures (#178).
 *   - GET    /cases/:id/attack-mitigations       — ATT&CK Mitigations (M-codes) (#178).
 *   - GET    /cases/:id/geo-map                  — geo-located IP IOC markers (#133).
 *   - GET    /cases/:id/geo-map.csv              — IP + geolocation CSV export (#133).
 *   - GET    /cases/:id/attack-layer.json        — MITRE ATT&CK Navigator layer export.
 *
 *   Asset-graph overrides (options.assetOverridesStore, analyst-authored graph edits):
 *   - GET    /cases/:id/asset-overrides                            — load overrides.
 *   - PUT    /cases/:id/asset-overrides/assets/:assetId            — rename / un-rename an asset.
 *   - POST   /cases/:id/asset-overrides/assets                     — create a manual asset.
 *   - DELETE /cases/:id/asset-overrides/assets/:assetId            — suppress / delete an asset.
 *   - POST   /cases/:id/asset-overrides/assets/:assetId/restore    — restore a suppressed asset.
 *   - POST   /cases/:id/asset-overrides/assets/:assetId/merge      — merge a duplicate asset (#82).
 *   - POST   /cases/:id/asset-overrides/assets/:assetId/unmerge    — un-merge a duplicate asset.
 *   - POST   /cases/:id/asset-overrides/links                      — add a manual asset↔IoC link.
 *   - DELETE /cases/:id/asset-overrides/links                      — suppress / delete a link.
 *
 *   IOC merging (options.stateStore + options.iocAliasStore, #82 — a REAL edit to InvestigationState,
 *   not an overlay, since IOCs are read directly by many consumers; see iocMerge.ts's header):
 *   - POST   /cases/:id/ioc-overrides/merge   — fold a duplicate IOC onto a canonical one.
 *   - DELETE /cases/:id/ioc-overrides/merge   — stop auto-routing a merged-away value (?value=...).
 *
 *   Saved timeframes / dwell-windows (options.dwellWindowStore, analyst-defined presence ranges):
 *   - GET    /cases/:id/dwell-windows                — list saved timeframes.
 *   - POST   /cases/:id/dwell-windows                — add a saved timeframe.
 *   - PUT    /cases/:id/dwell-windows/:windowId      — update a saved timeframe.
 *   - DELETE /cases/:id/dwell-windows/:windowId      — remove a saved timeframe.
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). Every handler
 * reaches its dependency through the STABLE ctx.options field only (reportWriter / assetOverridesStore
 * / onAssetOverrides / dwellWindowStore / onDwellWindow, plus superTimelineStore for the two
 * login-graph reads, which project the RAW super-timeline rather than the report) — no domain-local
 * state, no store to rebuild, and no new RouteContext graduations were needed.
 *
 * BOUNDARY: the interleaved read projections that happen to sit among these handlers in createApp
 * stay there because they belong to other domains — /cases/:id/adversary-hints (aiSynthesis, #46),
 * /cases/:id/stats + /cases/:id/mobile-summary + /cases/:id/presentation + /cases/:id/present/export
 * (reportsExport), and /cases/:id/swimlane (already moved to routes/timeline.ts). Only the
 * graph/map/ranking/anomaly/attack-layer projections + the asset-override / dwell-window overlays
 * move here.
 */
export function registerAnalysisGraphRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  // Narrow a query param to a plain string. Express parses repeated params (?a=1&a=2) as an
  // ARRAY — a blind `as string` cast would pass truthy guards and TypeError downstream.
  const s = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

  // Parse the optional ?from / ?until time-window query params (#83) shared by the asset/evidence
  // graph reads. Returns undefined when neither bound is present, so the builders take their
  // unfiltered path. Non-string (repeated) params narrow away to undefined and are simply ignored.
  const timeWindow = (req: Request): { from?: string; until?: string } | undefined => {
    const from = s(req.query.from), until = s(req.query.until);
    return from || until ? { from, until } : undefined;
  };

  // The asset ↔ IoC graph (compromised assets and the IoCs that touched each), derived on
  // demand from the current state with the same scope/legitimate filtering as the report.
  app.get("/cases/:id/asset-graph", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.assetGraph(req.params.id, timeWindow(req)));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Timesketch-style directed logon graph: accounts → hosts from 4624/4625 rows in the
  // SUPER-timeline (the raw complete record — plain Low 4624s never reach the forensic
  // timeline, and they are exactly what lateral-movement tracing needs). Pure parse + aggregate,
  // derived on demand, no AI. maxEdges caps by busiest-first with an explicit truncated flag.
  app.get("/cases/:id/login-graph", async (req: Request, res: Response) => {
    if (!options.superTimelineStore) return res.status(501).json({ error: "super-timeline not configured" });
    try {
      const raw = Number(s(req.query.maxEdges));
      const maxEdges = Number.isFinite(raw) && raw >= 1 ? Math.floor(raw) : DEFAULT_MAX_EDGES;
      const { events } = await options.superTimelineStore.query(req.params.id, { limit: Number.MAX_SAFE_INTEGER });
      return res.status(200).json({ ...buildLoginGraph(events, maxEdges), generatedAt: new Date().toISOString() });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // The events behind ONE login-graph edge — lazy-loaded when the analyst clicks it, so the
  // graph payload stays lean on 100K-event cases.
  app.get("/cases/:id/login-graph/edge-events", async (req: Request, res: Response) => {
    if (!options.superTimelineStore) return res.status(501).json({ error: "super-timeline not configured" });
    // Non-string (repeated/array) params narrow to undefined and hit the 400 below instead
    // of a data-dependent 500 inside loginEdgeEvents.
    const account = s(req.query.account), host = s(req.query.host), type = s(req.query.type), outcome = s(req.query.outcome);
    if (!account || !host) return res.status(400).json({ error: "account and host are required" });
    try {
      const rawLimit = Number(s(req.query.limit));
      const limit = Number.isFinite(rawLimit) && rawLimit >= 1 ? Math.floor(rawLimit) : 50;
      const { events } = await options.superTimelineStore.query(req.params.id, { limit: Number.MAX_SAFE_INTEGER });
      return res.status(200).json(loginEdgeEvents(events, {
        account, host,
        type: type || "Unknown",
        outcome: outcome === "failed" ? "failed" : "success",
        limit,
      }));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // The causal evidence chain graph (process trees + lateral movement), derived on demand
  // from the current state with the same scope/legitimate filtering as the report.
  app.get("/cases/:id/evidence-graph", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.evidenceGraph(req.params.id, timeWindow(req)));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Ordered lateral-movement chains (#92): entry host → pivot → ... → target, derived on demand
  // from the current state with the same scope/legitimate filtering as the report. Optional
  // ?from/?until (#83). Complements /evidence-graph's pairwise lateral_move edges with the
  // temporal sequencing they deliberately don't encode.
  app.get("/cases/:id/lateral-paths", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.lateralPaths(req.params.id, timeWindow(req)));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Temporal attack phases — the forensic timeline grouped into bursts of activity by time gap
  // (no AI). Derived on demand with the same scope/legitimate filtering as the report.
  app.get("/cases/:id/phases", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.phases(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Beacon / C2 candidates (#82): outbound connection channels whose inter-arrival intervals are too
  // regular to be human traffic, derived on demand from the forensic timeline's network events (same
  // scope/legitimate filtering as the report). Hunting leads, not verdicts. Powers the dashboard panel.
  app.get("/cases/:id/beacon-candidates", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.beaconCandidates(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Timeline anomalies (#175): per-asset event-rate spikes — assets whose event count in a time
  // bucket exceeds N× the median across all assets in that bucket. Derived on demand, no AI, same
  // scope/legitimate filtering as the report. Thresholds DFIR_ANOMALY_BUCKET_MINUTES / _SPIKE_FACTOR
  // / _MIN_EVENTS. Powers the dashboard Timeline Anomalies panel.
  app.get("/cases/:id/anomalies", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.anomalies(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Suspicious host/account ranking (#202): which entities carry the attack's signal, scored by
  // severity-weighted events + techniques + connective IOCs (not volume), plus a suggested scope
  // time window. Derived on read.
  app.get("/cases/:id/host-ranking", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.hostRanking(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // D3FEND defensive countermeasures (#178): per identified ATT&CK technique, the MITRE D3FEND
  // hardening/detection/isolation countermeasures from the bundled offline mapping. Derived on read.
  app.get("/cases/:id/d3fend-countermeasures", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.d3fendCountermeasures(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ATT&CK Mitigations (#178): concrete, actionable mitigations (M-codes) recommended for the case's
  // identified techniques, ranked by coverage. Offline, derived on read.
  app.get("/cases/:id/attack-mitigations", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.attackMitigations(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Geographic IP map (#133): markers for the case's geo-located IP IOCs, derived on demand with
  // the same scope filtering as the report (legit IOCs kept + rendered gray). Coordinates come
  // from the opt-in GeoIP enrichment, so the map is empty until IP IOCs are enriched.
  app.get("/cases/:id/geo-map", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.geoMap(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // IP + geolocation CSV export for the map panel (#133) — for external OSINT tooling.
  app.get("/cases/:id/geo-map.csv", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const csv = await options.reportWriter.geoMapCsv(req.params.id);
      res.type("text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="geo-map.csv"');
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(csv);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export a MITRE ATT&CK Navigator layer (JSON) for the case, generated on demand from the
  // current state (same scope/legitimate filtering as the report). Drops straight into the
  // Navigator's "Open Existing Layer → Upload from local"; techniques colored by severity.
  app.get("/cases/:id/attack-layer.json", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const layer = await options.reportWriter.attackLayer(req.params.id);
      res.type("application/json; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="attack-navigator-${req.params.id}.json"`);
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(JSON.stringify(layer, null, 2));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Manual asset-graph edits (renames, additions, suppressions, link overrides). Each write
  // pings live dashboard clients so the graph refreshes without a page reload.
  app.get("/cases/:id/asset-overrides", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    try {
      return res.status(200).json(await options.assetOverridesStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Rename (or un-rename) an asset by its graph id. Pass an empty name to clear the rename.
  app.put("/cases/:id/asset-overrides/assets/:assetId", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    const name = typeof req.body?.name === "string" ? req.body.name : "";
    try {
      const ov = await options.assetOverridesStore.rename(req.params.id, req.params.assetId, name);
      options.onAssetOverrides?.(req.params.id);
      return res.status(200).json(ov);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Create a manual asset (one not auto-derived from the forensic timeline).
  app.post("/cases/:id/asset-overrides/assets", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
    const type = typeof req.body?.type === "string" ? req.body.type.trim() : "host";
    if (!name) return res.status(400).json({ error: "name is required" });
    try {
      const result = await options.assetOverridesStore.addAsset(req.params.id, { name, type: type as AssetType });
      options.onAssetOverrides?.(req.params.id);
      return res.status(201).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Suppress an auto-derived asset or delete a manual one.
  app.delete("/cases/:id/asset-overrides/assets/:assetId", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    try {
      const ov = await options.assetOverridesStore.removeAsset(req.params.id, req.params.assetId);
      options.onAssetOverrides?.(req.params.id);
      return res.status(200).json(ov);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Restore a suppressed auto-derived asset (remove it from the removed list).
  app.post("/cases/:id/asset-overrides/assets/:assetId/restore", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    try {
      const ov = await options.assetOverridesStore.restoreAsset(req.params.id, req.params.assetId);
      options.onAssetOverrides?.(req.params.id);
      return res.status(200).json(ov);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Merge a duplicate asset onto a canonical one (#82). Body: { into }. Folds the duplicate's
  // IOC/finding/event links onto the canonical node on the next graph build.
  app.post("/cases/:id/asset-overrides/assets/:assetId/merge", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    const into = typeof req.body?.into === "string" ? req.body.into.trim() : "";
    if (!into) return res.status(400).json({ error: "into is required" });
    try {
      const ov = await options.assetOverridesStore.mergeAsset(req.params.id, req.params.assetId, into);
      options.onAssetOverrides?.(req.params.id);
      return res.status(200).json(ov);
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  // Un-merge a duplicate asset (remove it from the merge map).
  app.post("/cases/:id/asset-overrides/assets/:assetId/unmerge", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    try {
      const ov = await options.assetOverridesStore.unmergeAsset(req.params.id, req.params.assetId);
      options.onAssetOverrides?.(req.params.id);
      return res.status(200).json(ov);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Add a manual link between an asset and an IoC. Body: { asset, ioc }.
  app.post("/cases/:id/asset-overrides/links", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    const asset = typeof req.body?.asset === "string" ? req.body.asset.trim() : "";
    const ioc = typeof req.body?.ioc === "string" ? req.body.ioc.trim() : "";
    if (!asset || !ioc) return res.status(400).json({ error: "asset and ioc are required" });
    try {
      const ov = await options.assetOverridesStore.addLink(req.params.id, asset, ioc);
      options.onAssetOverrides?.(req.params.id);
      return res.status(201).json(ov);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Suppress (or delete) a link. Query params: ?asset=...&ioc=...
  app.delete("/cases/:id/asset-overrides/links", async (req: Request, res: Response) => {
    if (!options.assetOverridesStore) return res.status(501).json({ error: "asset overrides not configured" });
    const asset = typeof req.query?.asset === "string" ? req.query.asset : "";
    const ioc = typeof req.query?.ioc === "string" ? req.query.ioc : "";
    if (!asset || !ioc) return res.status(400).json({ error: "asset and ioc query params are required" });
    try {
      const ov = await options.assetOverridesStore.removeLink(req.params.id, asset, ioc);
      options.onAssetOverrides?.(req.params.id);
      return res.status(200).json(ov);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Merge a duplicate IOC onto a canonical one (#82). Body: { from, into }. Unlike the asset
  // overrides above, this is a REAL edit to InvestigationState (IOCs are read directly by many
  // consumers, not just the graph) — reversible via the existing import-undo checkpoint, and the
  // merge is recorded as an alias so a future re-synthesis re-extracting the same near-duplicate
  // value routes onto the canonical IOC instead of recreating it (see iocMerge.ts, iocAlias.ts).
  app.post("/cases/:id/ioc-overrides/merge", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    const from = typeof req.body?.from === "string" ? req.body.from.trim() : "";
    const into = typeof req.body?.into === "string" ? req.body.into.trim() : "";
    if (!from || !into) return res.status(400).json({ error: "from and into are required" });
    try {
      const stateStore = options.stateStore;
      let result: Awaited<ReturnType<typeof mergeIocs>> | undefined;
      await ctx.runStateExclusive(caseId, async () => {
        const state = await stateStore.load(caseId);
        result = mergeIocs(state, from, into);
        await ctx.pushImportCheckpoint(caseId, state, `merge IOC ${result.from.value} -> ${result.into.value}`);
        await stateStore.save(result.state);
        options.onState?.(result.state);
      });
      if (options.iocAliasStore && result) await options.iocAliasStore.add(caseId, result.from.value, result.into.id);
      options.onIocMerge?.(caseId);
      return res.status(200).json({ from: result!.from, into: result!.into });
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  // Stop auto-routing a merged-away value onto its former canonical IOC (#82). The historical
  // fold itself is only reversible via the import-undo "Undo" button. Query param: ?value=...
  app.delete("/cases/:id/ioc-overrides/merge", async (req: Request, res: Response) => {
    if (!options.iocAliasStore) return res.status(501).json({ error: "IOC alias store not configured" });
    const value = typeof req.query?.value === "string" ? req.query.value : "";
    if (!value) return res.status(400).json({ error: "value query param is required" });
    try {
      const map = await options.iocAliasStore.remove(req.params.id, value);
      options.onIocMerge?.(req.params.id);
      return res.status(200).json(map);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Saved timeframes (formerly "dwell-time windows") — analyst-defined attacker-presence time ranges.
  // CRUD over the per-case DwellWindowStore; each write pings live dashboard clients. The derived,
  // origin-filterable timeline view is now the super-timeline query route (GET .../super-timeline).
  app.get("/cases/:id/dwell-windows", async (req: Request, res: Response) => {
    if (!options.dwellWindowStore) return res.status(501).json({ error: "dwell windows not configured" });
    try {
      return res.status(200).json(await options.dwellWindowStore.list(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/dwell-windows", async (req: Request, res: Response) => {
    if (!options.dwellWindowStore) return res.status(501).json({ error: "dwell windows not configured" });
    try {
      const window = await options.dwellWindowStore.add(req.params.id, {
        label: req.body?.label, start: req.body?.start, end: req.body?.end,
      });
      options.onDwellWindow?.(req.params.id);
      return res.status(201).json(window);
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/dwell-windows/:windowId", async (req: Request, res: Response) => {
    if (!options.dwellWindowStore) return res.status(501).json({ error: "dwell windows not configured" });
    try {
      const updated = await options.dwellWindowStore.update(req.params.id, req.params.windowId, {
        label: req.body?.label, start: req.body?.start, end: req.body?.end,
      });
      if (!updated) return res.status(404).json({ error: "window not found" });
      options.onDwellWindow?.(req.params.id);
      return res.status(200).json(updated);
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/dwell-windows/:windowId", async (req: Request, res: Response) => {
    if (!options.dwellWindowStore) return res.status(501).json({ error: "dwell windows not configured" });
    try {
      const removed = await options.dwellWindowStore.remove(req.params.id, req.params.windowId);
      if (!removed) return res.status(404).json({ error: "window not found" });
      options.onDwellWindow?.(req.params.id);
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
