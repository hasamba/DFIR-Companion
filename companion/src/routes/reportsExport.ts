import type { Express, Request, Response } from "express";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { injectPrintTrigger } from "../reports/html.js";
import { logActivity } from "../analysis/activityLog.js";
import { milestoneEvent } from "../analysis/notifications.js";
import { reloadEnvPrefix } from "../settings/envManager.js";
import { fetchIrisCase } from "../integrations/iris/irisImportFetch.js";
import { defaultIrisCaseName } from "../integrations/iris/irisExportStore.js";
import type { RouteContext } from "./context.js";

/**
 * Report generation / export / DFIR-IRIS + ClickUp domain: turning the synthesized case into
 * deliverables and shipping it to external systems. Pure structural move out of createApp (see
 * routes/system.ts for the conventions) — no handler logic changed. Groups:
 *   - report (POST generate / GET report/:file / GET report.docx) — (re)generate the Markdown+HTML
 *     report, serve the generated Markdown/HTML files (with the print-to-PDF trigger), and build the
 *     Word (.docx) attachment on demand.
 *   - export/stix (GET) — a STIX 2.1 bundle for the case, generated on demand.
 *   - report-meta (GET/PUT) — human-authored title-page / distribution / BIA / glossary metadata.
 *   - report-template (GET/PUT) — the PER-CASE selection of which global report template renders the
 *     report (the global report-template CRUD lives in routes/templatesViews.ts).
 *   - iris (GET status / POST reconnect / GET cases) — DFIR-IRIS integration status, runtime
 *     reconnect (re-read .env + rebuild the client), and the remote case picker.
 *   - iris-export (GET) — the IRIS case name a push would use right now (prefill for the push modal).
 *   - iris-import (POST) — pull an existing IRIS case into this Companion case and re-synthesize.
 *   - clickup-export (GET) — the last ClickUp export pointer (saved list id) for the modal prefill.
 *
 * BOUNDARY: the integration PUSH routes (/cases/:id/push/{iris,clickup,timesketch,misp,notion}) and
 * their per-integration /{clickup,misp,notion,timesketch}/status endpoints STAY in createApp — they
 * belong to their own integration surfaces (mirrors routes/pushNotify.ts leaving the integration
 * pushes behind). The whole-case encrypted archive (/cases/:id/export/encrypted +
 * /cases/import/encrypted) and /cases/:id/export/ioc-blocklist are NOT here (case-lifecycle /
 * un-enumerated export siblings — left for their owning domains). /cases/:id/export/redacted lives
 * in routes/anonymization.ts; the presentation / mobile-summary / executive-summary generators live
 * in routes/aiSynthesis.ts.
 *
 * Shared surface — reuses already-graduated ctx members plus three graduated for this domain:
 *   - store, options — stable ctx surface.
 *   - resynthesizeInBackground — already-graduated stable method (iris-import fires it after the
 *     deterministic map completes).
 *   - dispatchNotify — GRADUATED for this domain (see context.ts): the POST /cases/:id/report route
 *     fires the "Report generated" milestone through it. It's a stable const arrow in createApp
 *     (also used by create-case + the drop-import path, which stay), so it was graduated, not moved.
 *   - irisClient() / setIrisClient() / rebuildIrisClient() — the DFIR-IRIS client is a MUTABLE shared
 *     handle: POST /iris/reconnect rebuilds it at runtime and createApp's /cases/:id/push/iris (which
 *     stays) reads it. irisClient() (live accessor) already existed; setIrisClient() + rebuildIrisClient()
 *     were GRADUATED here (mirrors the nsrlDb()/setNsrlDb() pattern) so the moved reconnect route swaps
 *     the SAME binding createApp still reads. rebuildIrisClient() wraps createApp's
 *     `options.rebuildIrisClient ?? buildIrisClient`, keeping buildIrisClient's use inside server.ts
 *     (no route module imports a value from ../server.js).
 *
 * Module-private: logLine — a wrapper mirroring createApp's (serverLogger.info), so the moved
 * iris-import handler keeps its original logLine(...) calls verbatim.
 */
export function registerReportsExportRoutes(app: Express, ctx: RouteContext): void {
  const { store, options, dispatchNotify, resynthesizeInBackground } = ctx;

  // Module-private wrapper mirroring createApp's logLine (serverLogger.info), so the moved call
  // sites stay verbatim.
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);

  app.post("/cases/:id/report", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const paths = await options.reportWriter.writeAll(req.params.id);
      dispatchNotify(milestoneEvent(req.params.id, "Report generated", ["The case report (Markdown + HTML) was (re)generated."], new Date().toISOString()));
      logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "export", action: "report-generated", detail: "report (Markdown + HTML) regenerated",
      });
      return res.status(200).json(paths);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Serve a generated report file for viewing or download (export as Markdown or HTML).
  // Only the known report artifacts are served; `?download=1` forces a save dialog, and
  // `?print=1` (HTML only) injects a print trigger so the browser opens its print dialog —
  // the zero-dependency "Save as PDF" export. The on-disk file is never modified.
  app.get("/cases/:id/report/:file", async (req: Request, res: Response) => {
    const types: Record<string, string> = {
      "report.md": "text/markdown; charset=utf-8",
      "report.html": "text/html; charset=utf-8",
    };
    const file = req.params.file;
    if (!Object.prototype.hasOwnProperty.call(types, file)) {
      return res.status(400).json({ error: "unknown report file" });
    }
    try {
      const buf = await readFile(join(store.reportsDir(req.params.id), file));
      res.type(types[file]);
      const download = req.query.download !== undefined;
      if (download) {
        res.setHeader("Content-Disposition", `attachment; filename="${file}"`);
      }
      res.setHeader("Cache-Control", "private, no-cache");
      // PDF export: an opened-in-browser HTML report that auto-triggers the print dialog.
      // Mutually exclusive with download — the saved PDF must come from the print dialog, not a file.
      if (file === "report.html" && req.query.print !== undefined && !download) {
        return res.send(injectPrintTrigger(buf.toString("utf8")));
      }
      return res.send(buf);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return res.status(404).json({ error: "report not generated yet — POST /cases/:id/report first" });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export the incident report as a Word (.docx) attachment, generated on demand from the
  // current state (same scope/legitimate filtering as the report). Not persisted on disk —
  // the binary is built fresh per request so it doesn't churn the cases/ folder.
  app.get("/cases/:id/report.docx", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const buf = await options.reportWriter.docx(req.params.id);
      res.type("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
      res.setHeader("Content-Disposition", `attachment; filename="report-${req.params.id}.docx"`);
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(buf);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export a STIX 2.1 bundle (JSON) for the case, generated on demand from the current state
  // (same scope/legitimate filtering as the report). Drops straight into any TIP that ingests
  // STIX — OpenCTI, MISP, Anomali, ThreatConnect — making the case portable without lock-in.
  app.get("/cases/:id/export/stix", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const bundle = await options.reportWriter.stixBundle(req.params.id);
      res.type("application/json; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="stix-bundle-${req.params.id}.json"`);
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(JSON.stringify(bundle, null, 2));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Human-authored report metadata (title page, distribution, BIA, limitations, glossary,
  // recommendations…). GET returns the stored values (or defaults); PUT replaces them with a
  // normalized payload. These merge into report.md alongside the auto-derived sections.
  app.get("/cases/:id/report-meta", async (req: Request, res: Response) => {
    if (!options.reportMetaStore) return res.status(501).json({ error: "report metadata not configured" });
    try {
      return res.status(200).json(await options.reportMetaStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/report-meta", async (req: Request, res: Response) => {
    if (!options.reportMetaStore) return res.status(501).json({ error: "report metadata not configured" });
    try {
      const saved = await options.reportMetaStore.save(req.params.id, req.body);
      return res.status(200).json(saved);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Per-case selection of which report template renders the report. GET returns { templateId }
  // (default "standard"); PUT sets it and re-broadcasts so other dashboards refresh.
  app.get("/cases/:id/report-template", async (req: Request, res: Response) => {
    if (!options.reportTemplateControlStore) return res.status(501).json({ error: "report templates not configured" });
    try {
      return res.status(200).json(await options.reportTemplateControlStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/report-template", async (req: Request, res: Response) => {
    if (!options.reportTemplateControlStore) return res.status(501).json({ error: "report templates not configured" });
    const templateId = typeof req.body?.templateId === "string" ? req.body.templateId : undefined;
    try {
      const saved = await options.reportTemplateControlStore.set(req.params.id, { templateId });
      options.onReportTemplate?.(req.params.id);
      return res.status(200).json(saved);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Whether a DFIR-IRIS push/import target is configured (so the dashboard can show/hide the buttons).
  app.get("/iris/status", (_req: Request, res: Response) => {
    res.status(200).json({ configured: !!ctx.irisClient(), baseUrl: process.env.DFIR_IRIS_URL || options.irisOptions?.baseUrl });
  });

  // Re-read DFIR_IRIS_* from .env (settings saved via the dashboard only write the file), rebuild
  // the client, and ping to verify connectivity. Lets the analyst connect after configuring IRIS —
  // or after IRIS comes back online — without the #1-gotcha restart. Always 200; the body says
  // whether it's configured and reachable.
  app.post("/iris/reconnect", async (_req: Request, res: Response) => {
    try {
      await reloadEnvPrefix("DFIR_IRIS_");
      const client = ctx.rebuildIrisClient();
      ctx.setIrisClient(client);
      if (!client) return res.status(200).json({ configured: false, ok: false, error: "DFIR_IRIS_URL and DFIR_IRIS_KEY are not set" });
      try {
        await client.ping();
        return res.status(200).json({ configured: true, ok: true, baseUrl: process.env.DFIR_IRIS_URL });
      } catch (err) {
        return res.status(200).json({ configured: true, ok: false, baseUrl: process.env.DFIR_IRIS_URL, error: (err as Error).message });
      }
    } catch (err) {
      return res.status(500).json({ configured: false, ok: false, error: (err as Error).message });
    }
  });

  // List the cases on the configured DFIR-IRIS instance — powers the "Import from IRIS" picker
  // (issue #88). 501 when not configured. Errors map to 502 (the remote IRIS is unreachable).
  app.get("/iris/cases", async (_req: Request, res: Response) => {
    const irisClient = ctx.irisClient();
    if (!irisClient) return res.status(501).json({ error: "DFIR-IRIS not configured (set DFIR_IRIS_URL and DFIR_IRIS_KEY)" });
    try {
      const cases = await irisClient.listCases();
      return res.status(200).json({ cases });
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // The IRIS case name a push would use right now (saved override, or the computed default) —
  // lets the dashboard prefill the "Push to DFIR-IRIS" case-name field.
  app.get("/cases/:id/iris-export", async (req: Request, res: Response) => {
    if (!options.irisExportStore) return res.status(501).json({ error: "DFIR-IRIS not configured" });
    try {
      const caseId = req.params.id;
      const saved = await options.irisExportStore.load(caseId);
      const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
      return res.status(200).json({ caseName: saved.caseName, defaultCaseName: defaultIrisCaseName(caseId, caseMeta?.name) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import an EXISTING DFIR-IRIS case into this Companion case (issue #88) — the reverse of the
  // push. Pull the IRIS case's assets/IOCs/timeline (by IRIS case id or exact name), persist the
  // fetched payload as an evidence-first audit file, then map it DETERMINISTICALLY (no AI call)
  // into the forensic timeline + IOCs and re-synthesize. The fetched payload is the imported
  // "file" so the case keeps a faithful import audit row.
  app.post("/cases/:id/iris-import", async (req: Request, res: Response) => {
    const irisClient = ctx.irisClient();
    if (!irisClient) return res.status(501).json({ error: "DFIR-IRIS not configured (set DFIR_IRIS_URL and DFIR_IRIS_KEY)" });
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const irisCaseId = Number(req.body?.irisCaseId);
    const irisCaseName = typeof req.body?.irisCaseName === "string" ? req.body.irisCaseName.trim() : "";
    if (!Number.isFinite(irisCaseId) && !irisCaseName) {
      return res.status(400).json({ error: "irisCaseId or irisCaseName is required" });
    }

    try {
      logLine(`[iris] ${caseId} import START (iris case ${irisCaseName || `#${irisCaseId}`})`);
      const data = await fetchIrisCase(irisClient, {
        irisCaseId: Number.isFinite(irisCaseId) ? irisCaseId : undefined,
        caseName: irisCaseName || undefined,
      });
      if (data.assets.length === 0 && data.iocs.length === 0 && data.timeline.length === 0) {
        return res.status(400).json({ error: "the IRIS case has no assets, IOCs or timeline events to import" });
      }

      const payload = JSON.stringify(data, null, 2);
      const seq = await store.nextImportSeq(caseId);
      const safeBase = (data.caseName || `iris-case-${data.irisCaseId}`).replace(/[^\w.\-]+/g, "_").slice(0, 60) || "iris-case";
      const storedName = `${String(seq).padStart(4, "0")}_${safeBase}.json`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, payload);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName: `DFIR-IRIS case ${data.caseName ?? `#${data.irisCaseId}`}`,
        rows: data.timeline.length + data.assets.length, bytes: Buffer.byteLength(payload, "utf8"),
      });

      res.status(202).json({
        accepted: true, file: storedName,
        irisCaseId: data.irisCaseId, caseName: data.caseName,
        timeline: data.timeline.length, assets: data.assets.length, iocs: data.iocs.length,
      });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing DFIR-IRIS case ${data.caseName ?? `#${data.irisCaseId}`}` });
      void options.pipeline.importIris(caseId, data, { label: storedName, idPrefix: `iris${seq}`, importedAt })
        .then(() => {
          logLine(`[iris] ${caseId} import DONE (iris case ${data.caseName ?? `#${data.irisCaseId}`})`);
          options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
          resynthesizeInBackground(caseId);
        })
        .catch((err) => {
          logLine(`[iris] ${caseId} import ERROR: ${(err as Error).message}`);
          options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
        });
      return;
    } catch (err) {
      logLine(`[iris] ${caseId} import ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // The last ClickUp export pointer (saved list id) so the modal can prefill it.
  app.get("/cases/:id/clickup-export", async (req: Request, res: Response) => {
    if (!options.clickupExportStore) return res.status(501).json({ error: "ClickUp not configured" });
    try {
      return res.status(200).json(await options.clickupExportStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
