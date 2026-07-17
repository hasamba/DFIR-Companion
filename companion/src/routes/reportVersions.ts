import type { Express, Request, Response } from "express";
import { diffFindings } from "../analysis/findingsDiff.js";
import { diffIocs } from "../analysis/iocsDiff.js";
import { diffTimeline } from "../analysis/timelineDiff.js";
import type { RouteContext } from "./context.js";

/**
 * Report versioning (#77): list the version snapshots a case has accumulated (one per report
 * regeneration, deduped when nothing changed — see ReportVersionStore.snapshot), diff two of them
 * (added/removed findings + severity changes, IOC changes, timeline changes — reusing the same
 * *Diff.ts primitives the import pipeline uses), and restore an earlier version's editable
 * report-meta (title page, distribution, BIA, glossary, recommendations…) as the CURRENT report-meta,
 * so the next "Generate Report" click renders with it. Restoring does not touch findings/IOCs/timeline
 * (those come from the live investigation state, not the archived version) and does not regenerate the
 * report itself — the analyst reviews the restored fields, then regenerates from the dashboard as usual.
 */
export function registerReportVersionsRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/report-versions", async (req: Request, res: Response) => {
    if (!options.reportVersionStore) return res.status(501).json({ error: "report versioning not configured" });
    try {
      return res.status(200).json(await options.reportVersionStore.list(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Diff two stored versions' findings/IOCs/forensic-timeline. `from`/`to` are version ids from the
  // list above; `to` defaults to the most recent version when omitted.
  app.get("/cases/:id/report-versions/diff", async (req: Request, res: Response) => {
    if (!options.reportVersionStore) return res.status(501).json({ error: "report versioning not configured" });
    const caseId = req.params.id;
    const fromId = typeof req.query.from === "string" ? req.query.from : "";
    let toId = typeof req.query.to === "string" ? req.query.to : "";
    if (!fromId) return res.status(400).json({ error: "from is required" });
    try {
      if (!toId) {
        const versions = await options.reportVersionStore.list(caseId);
        toId = versions[0]?.id ?? "";
      }
      const [from, to] = await Promise.all([
        options.reportVersionStore.get(caseId, fromId),
        toId ? options.reportVersionStore.get(caseId, toId) : Promise.resolve(null),
      ]);
      if (!from || !to) return res.status(404).json({ error: "version not found" });
      return res.status(200).json({
        from: { id: from.id, createdAt: from.createdAt, version: from.version },
        to: { id: to.id, createdAt: to.createdAt, version: to.version },
        findings: diffFindings(from.state.findings, to.state.findings),
        iocs: diffIocs(from.state.iocs, to.state.iocs),
        timeline: diffTimeline(from.state.forensicTimeline, to.state.forensicTimeline),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Restore a prior version's editable report-meta as the case's CURRENT report-meta. Returns the
  // saved (normalized) meta so the dashboard's report-meta form can refresh in place.
  app.post("/cases/:id/report-versions/:versionId/restore", async (req: Request, res: Response) => {
    if (!options.reportVersionStore) return res.status(501).json({ error: "report versioning not configured" });
    if (!options.reportMetaStore) return res.status(501).json({ error: "report metadata not configured" });
    const caseId = req.params.id;
    try {
      const version = await options.reportVersionStore.get(caseId, req.params.versionId);
      if (!version) return res.status(404).json({ error: "version not found" });
      const saved = await options.reportMetaStore.save(caseId, version.meta);
      return res.status(200).json(saved);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
