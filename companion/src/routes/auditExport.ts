import type { Express, Request, Response } from "express";
import { parseDestinationInput, redactDestination } from "../analysis/auditExport.js";
import type { RouteContext } from "./context.js";

/**
 * SIEM audit-export routes (#929): the global destination list (Splunk HEC / Elasticsearch /
 * syslog), a connection test, and an explicit history backfill.
 *
 * Own module rather than an addition to pushNotify.ts or caseLifecycle.ts — caseLifecycle.ts is at
 * its recorded size in the file-size ledger and takes no new lines.
 *
 * Every response goes through redactDestination. The HEC token, the Elasticsearch password and the
 * API key never reach the browser; it learns only whether each is set, which is what the Settings
 * form needs to render "already set" on a field the analyst must not have to retype.
 */
export function registerAuditExportRoutes(app: Express, ctx: RouteContext): void {
  const { options, serverLogger } = ctx;

  const notConfigured = (res: Response): Response =>
    res.status(501).json({ error: "audit export not configured" });

  // Status is the destination list joined with what this process has observed per destination, so
  // the pane can say "last sent 12:05, 412 records" or show the live error. The two halves are
  // deliberately separate: the list is durable, the attempt history is not.
  app.get("/audit-export", async (_req: Request, res: Response) => {
    if (!options.auditExportStore) return res.status(200).json({ configured: false, destinations: [] });
    try {
      const destinations = await options.auditExportStore.load();
      const statuses = new Map((options.auditExporter?.status() ?? []).map((s) => [s.destinationId, s]));
      return res.status(200).json({
        configured: true,
        destinations: destinations.map((d) => ({
          ...redactDestination(d),
          status: statuses.get(d.id) ?? { destinationId: d.id, sentTotal: 0 },
        })),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/audit-export", async (req: Request, res: Response) => {
    if (!options.auditExportStore) return notConfigured(res);
    const parsed = parseDestinationInput(req.body);
    if (!parsed.ok || !parsed.draft) {
      return res.status(400).json({ error: parsed.error ?? "invalid destination" });
    }
    try {
      // ADDED DISABLED, SEEDED, THEN ENABLED — in that order, and not as a flourish. A destination
      // that is enabled the moment it exists has no delivery position yet, and an unset position
      // means "start at line 1", so the very next analyst action would drag the case's whole
      // history to the collector. Staying disabled until the position is at the current end closes
      // that window completely: nothing can read it as enabled in between.
      const wantEnabled = parsed.draft.enabled;
      const destination = await options.auditExportStore.add({ ...parsed.draft, enabled: false });
      let created = destination;
      if (wantEnabled) {
        await options.auditExporter?.seed(destination.id);
        created = (await options.auditExportStore.update(destination.id, parsed.draft)) ?? destination;
      }
      serverLogger.info(
        `[audit-export] destination added: ${created.type} "${created.name}" (${created.id})${created.enabled ? " — enabled, forwarding from now on" : " — disabled"}`,
      );
      return res.status(201).json(redactDestination(created));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/audit-export/:id", async (req: Request, res: Response) => {
    if (!options.auditExportStore) return notConfigured(res);
    try {
      const existing = await options.auditExportStore.get(req.params.id);
      if (!existing) return res.status(404).json({ error: "audit destination not found" });
      // `existing` is what lets a blank redacted credential keep the saved one — and what refuses
      // to carry it across a type change (parseDestinationInput).
      const parsed = parseDestinationInput(req.body, existing);
      if (!parsed.ok || !parsed.draft) {
        return res.status(400).json({ error: parsed.error ?? "invalid destination" });
      }
      // Seeded BEFORE the write, and only on an off -> on transition. Before, because the
      // destination is still disabled in the store at that moment, so no drain can read it and
      // start from line 1. Only on the transition, because re-seeding an already-enabled
      // destination on an unrelated edit — a rename — would silently skip whatever was appended
      // since its last send.
      if (parsed.draft.enabled && !existing.enabled) {
        await options.auditExporter?.seed(req.params.id);
      }
      const updated = await options.auditExportStore.update(req.params.id, parsed.draft);
      if (!updated) return res.status(404).json({ error: "audit destination not found" });
      return res.status(200).json(redactDestination(updated));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/audit-export/:id", async (req: Request, res: Response) => {
    if (!options.auditExportStore) return notConfigured(res);
    try {
      const removed = await options.auditExportStore.remove(req.params.id);
      if (!removed) return res.status(404).json({ error: "audit destination not found" });
      // Drop the delivery positions too. Without this, a destination removed and re-added under a
      // new id is fine, but a stale entry for the old id would sit in the cursor file forever.
      await options.auditExportCursors?.clearDestination(req.params.id);
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // One clearly-marked test record. Bypasses the enabled flag so a destination can be verified
  // before it is switched on.
  app.post("/audit-export/test", async (req: Request, res: Response) => {
    if (!options.auditExporter) return notConfigured(res);
    try {
      const destinationId = typeof req.body?.destinationId === "string" ? req.body.destinationId : undefined;
      const results = await options.auditExporter.test(destinationId, new Date().toISOString());
      if (!results.length) return res.status(404).json({ error: "no matching destination to test" });
      return res.status(200).json({ results });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Re-send every case's history to one destination. Explicit and analyst-pressed: enabling a
  // destination forwards only what happens next, because a switch that silently ships a year of
  // history to a production SIEM is not a switch anyone wants to discover by pressing it.
  app.post("/audit-export/:id/backfill", async (req: Request, res: Response) => {
    if (!options.auditExporter) return notConfigured(res);
    try {
      const results = await options.auditExporter.backfill(req.params.id);
      const sent = results.reduce((n, r) => n + r.sent, 0);
      const failed = results.filter((r) => !r.ok);
      return res.status(200).json({
        sent,
        cases: results.length,
        failed: failed.map((f) => ({ caseId: f.caseId, error: f.error })),
      });
    } catch (err) {
      const message = (err as Error).message;
      if (/not found/i.test(message)) return res.status(404).json({ error: message });
      return res.status(500).json({ error: message });
    }
  });
}
