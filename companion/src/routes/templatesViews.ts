import type { Express, Request, Response } from "express";
import { BUILT_IN_DASHBOARD_VIEWS } from "../analysis/dashboardViews.js";
import { UnsafeStoreIdError } from "../storage/safeStoreId.js";
import type { RouteContext } from "./context.js";

/**
 * Uniform failure response for the stores below. A rejected id is the CALLER's mistake (#213) — a
 * traversal attempt or a stray character — so it is a 400, not the 500 that "something broke on the
 * server" implies. Everything else keeps the original 500.
 */
function storeFailure(res: Response, err: unknown): Response {
  const status = err instanceof UnsafeStoreIdError ? 400 : 500;
  return res.status(status).json({ error: (err as Error).message });
}

/**
 * User-managed template & view routes: case templates (#—), global report templates (#60),
 * dashboard view presets (#142), and Velociraptor artifact bundles.
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). Every handler
 * reads its backing store straight off options (options.templateStore / reportTemplateStore /
 * dashboardViewStore / artifactBundleStore), so nothing had to graduate onto RouteContext. NOTE:
 * the per-case report-generation/selection routes (/cases/:id/report*) are NOT here — they belong
 * to the reportsExport domain and stay in createApp.
 */
export function registerTemplatesViewsRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  // ── Case templates ──────────────────────────────────────────────────────────────────────
  // Built-in templates are always available; custom templates are saved to the templates dir.

  app.get("/templates", async (_req: Request, res: Response) => {
    if (!options.templateStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.templateStore.list());
    } catch (err) {
      return storeFailure(res, err);
    }
  });

  app.get("/templates/:id", async (req: Request, res: Response) => {
    if (!options.templateStore) return res.status(404).json({ error: "template store not configured" });
    try {
      const template = await options.templateStore.get(req.params.id);
      if (!template) return res.status(404).json({ error: `template "${req.params.id}" not found` });
      return res.status(200).json(template);
    } catch (err) {
      return storeFailure(res, err);
    }
  });

  app.post("/templates", async (req: Request, res: Response) => {
    if (!options.templateStore) return res.status(501).json({ error: "template store not configured" });
    try {
      const { name, description, recommendedImports, initialKeyQuestions, initialNextSteps, severityFloor, huntPlatforms, id } = req.body ?? {};
      if (!name) return res.status(400).json({ error: "name is required" });
      const saved = await options.templateStore.save({ id, name, description, recommendedImports, initialKeyQuestions, initialNextSteps, severityFloor: severityFloor ?? null, huntPlatforms });
      return res.status(201).json(saved);
    } catch (err) {
      return storeFailure(res, err);
    }
  });

  app.delete("/templates/:id", async (req: Request, res: Response) => {
    if (!options.templateStore) return res.status(501).json({ error: "template store not configured" });
    try {
      const found = await options.templateStore.delete(req.params.id);
      if (!found) return res.status(404).json({ error: `template "${req.params.id}" not found` });
      return res.status(204).send();
    } catch (err) {
      if ((err as Error).message.includes("built-in")) return res.status(400).json({ error: (err as Error).message });
      return storeFailure(res, err);
    }
  });

  // ── Report templates (issue #60) ─────────────────────────────────────────────────────────
  // Global, shared-across-cases branded layouts: accent colour, cover title/subtitle, running
  // header & footer, and which report sections appear and in what order. Built-ins are editable in
  // place (saving under a built-in id writes an override; DELETE resets it). Mirrors /bundles.
  app.get("/report-templates", async (_req: Request, res: Response) => {
    if (!options.reportTemplateStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.reportTemplateStore.list());
    } catch (err) {
      return storeFailure(res, err);
    }
  });

  app.get("/report-templates/:id", async (req: Request, res: Response) => {
    if (!options.reportTemplateStore) return res.status(501).json({ error: "report templates not configured" });
    try {
      const tpl = await options.reportTemplateStore.get(req.params.id);
      if (!tpl) return res.status(404).json({ error: `report template "${req.params.id}" not found` });
      return res.status(200).json(tpl);
    } catch (err) {
      return storeFailure(res, err);
    }
  });

  app.post("/report-templates", async (req: Request, res: Response) => {
    if (!options.reportTemplateStore) return res.status(501).json({ error: "report templates not configured" });
    try {
      const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
      if (!name) return res.status(400).json({ error: "name is required" });
      const saved = await options.reportTemplateStore.save(req.body);
      return res.status(201).json(saved);
    } catch (err) {
      return storeFailure(res, err);
    }
  });

  // Dashboard view presets (#142) — built-in + custom, role/phase-keyed layouts the dashboard applies
  // client-side (section show/hide/reorder + a per-view severity/top-N filter + a matching report
  // template). GLOBAL store beside cases/ (mirrors report templates): built-ins editable in place,
  // custom views via POST, reset/delete via DELETE.
  app.get("/dashboard-views", async (_req: Request, res: Response) => {
    if (!options.dashboardViewStore) return res.status(200).json({ views: BUILT_IN_DASHBOARD_VIEWS });
    try {
      return res.status(200).json({ views: await options.dashboardViewStore.list() });
    } catch (err) {
      return storeFailure(res, err);
    }
  });

  app.get("/dashboard-views/:id", async (req: Request, res: Response) => {
    if (!options.dashboardViewStore) return res.status(501).json({ error: "dashboard views not configured" });
    try {
      const view = await options.dashboardViewStore.get(req.params.id);
      if (!view) return res.status(404).json({ error: `dashboard view "${req.params.id}" not found` });
      return res.status(200).json(view);
    } catch (err) {
      return storeFailure(res, err);
    }
  });

  app.post("/dashboard-views", async (req: Request, res: Response) => {
    if (!options.dashboardViewStore) return res.status(501).json({ error: "dashboard views not configured" });
    try {
      const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
      if (!name) return res.status(400).json({ error: "name is required" });
      const sections = Array.isArray(req.body?.sections) ? req.body.sections : [];
      if (!sections.length) return res.status(400).json({ error: "at least one visible section is required" });
      const saved = await options.dashboardViewStore.save(req.body);
      return res.status(201).json(saved);
    } catch (err) {
      return storeFailure(res, err);
    }
  });

  // Delete a custom view, OR reset an edited built-in back to its shipped default (idempotent for a
  // pristine built-in). 404 only for an unknown non-built-in id.
  app.delete("/dashboard-views/:id", async (req: Request, res: Response) => {
    if (!options.dashboardViewStore) return res.status(501).json({ error: "dashboard views not configured" });
    try {
      const removed = await options.dashboardViewStore.delete(req.params.id);
      if (!removed && !options.dashboardViewStore.isBuiltIn(req.params.id)) {
        return res.status(404).json({ error: `dashboard view "${req.params.id}" not found` });
      }
      return res.status(204).send();
    } catch (err) {
      return storeFailure(res, err);
    }
  });

  // Delete a custom template, OR reset an edited built-in back to its shipped default (idempotent for
  // a pristine built-in). 404 only for an unknown non-built-in id.
  app.delete("/report-templates/:id", async (req: Request, res: Response) => {
    if (!options.reportTemplateStore) return res.status(501).json({ error: "report templates not configured" });
    try {
      const removed = await options.reportTemplateStore.delete(req.params.id);
      if (!removed && !options.reportTemplateStore.isBuiltIn(req.params.id)) {
        return res.status(404).json({ error: `report template "${req.params.id}" not found` });
      }
      return res.status(204).send();
    } catch (err) {
      return storeFailure(res, err);
    }
  });

  // ── Velociraptor triage bundles ───────────────────────────────────────────────────────────
  // Bundle CRUD (global / shared across cases). GET works even without a Velociraptor client so an
  // analyst can assemble bundles before connecting a server.
  app.get("/bundles", async (_req: Request, res: Response) => {
    if (!options.artifactBundleStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.artifactBundleStore.list());
    } catch (err) {
      return storeFailure(res, err);
    }
  });

  app.post("/bundles", async (req: Request, res: Response) => {
    if (!options.artifactBundleStore) return res.status(501).json({ error: "bundle store not configured" });
    try {
      const { id, name, description, artifacts, defaultWaitMinutes,
              timeoutSeconds, expirySeconds, params, filters, superTimelineOnly, timeScopeParamNames } = req.body ?? {};
      if (!name) return res.status(400).json({ error: "name is required" });
      if (!Array.isArray(artifacts) || artifacts.length === 0) return res.status(400).json({ error: "at least one artifact is required" });
      // Forward EVERY field the store supports. Destructuring a subset here silently wiped a built-in's
      // superTimelineOnly/timeout/params/filters on every dashboard edit — the store's own sanitizers are
      // the validation layer, so passing them through is safe.
      const saved = await options.artifactBundleStore.save({
        id, name, description, artifacts, defaultWaitMinutes,
        timeoutSeconds, expirySeconds, params, filters, superTimelineOnly, timeScopeParamNames,
      });
      return res.status(201).json(saved);
    } catch (err) {
      if ((err as Error).message.includes("built-in")) return res.status(400).json({ error: (err as Error).message });
      return storeFailure(res, err);
    }
  });

  // Delete a custom bundle, OR reset an edited built-in back to its shipped default (idempotent for a
  // pristine built-in). 404 only for an unknown non-built-in id.
  app.delete("/bundles/:id", async (req: Request, res: Response) => {
    if (!options.artifactBundleStore) return res.status(501).json({ error: "bundle store not configured" });
    try {
      const removed = await options.artifactBundleStore.delete(req.params.id);
      if (!removed && !options.artifactBundleStore.isBuiltIn(req.params.id)) {
        return res.status(404).json({ error: `bundle "${req.params.id}" not found` });
      }
      return res.status(204).send();
    } catch (err) {
      return storeFailure(res, err);
    }
  });
}
