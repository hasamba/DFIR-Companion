import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import { parseWazuhAlerts, type WazuhImportOptions } from "../analysis/wazuhImport.js";
import { parseMinSeverity } from "../analysis/severityFloor.js";
import type { SettleDeps } from "./importSettle.js";
import { commitDedicatedImport, importerParameter, persistImportEvidence } from "./importCommit.js";
import { sendPipelineError } from "./presidioApproval.js";

/**
 * POST /cases/:id/import-wazuh — moved out of the size-ledgered routes/import.ts (#1736) so that
 * file could carry each dedicated route's debug recorder without growing. Registered at the same
 * position in the route stack, so route order is unchanged.
 */
export function registerWazuhImportRoute(
  app: Express,
  ctx: RouteContext,
  settleDeps: SettleDeps | null,
): void {
  const { store, options } = ctx;

  // Import Wazuh SIEM/EDR alert exports (alerts.json / NDJSON / API export envelope).
  // Evidence-first; mapped DETERMINISTICALLY (no AI call): rule.level drives severity,
  // rule.mitre.technique → MITRE, agent.name → asset, data fields → IOCs.
  app.post("/cases/:id/import-wazuh", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const pipeline = options.pipeline;
    const caseId = req.params.id;
    const text =
      typeof req.body?.text === "string"
        ? req.body.text
        : typeof req.body?.json === "string"
          ? req.body.json
          : "";
    const originalName = String(req.body?.filename ?? "wazuh-alerts.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const minSeverity = parseMinSeverity(req.body?.minSeverity);
    const wazuhOpts: WazuhImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseWazuhAlerts(text, wazuhOpts);
      if (preview.format === "empty" && preview.kept === 0)
        return res.status(400).json({
          error:
            "no parseable Wazuh alerts found (expected an array or NDJSON of Wazuh alert objects with rule.level, rule.description, and agent fields, or a Wazuh API export { data: { affected_items: [...] } })",
        });

      const { seq, storedName, importedAt } = await persistImportEvidence(store, caseId, {
        text: text,
        originalName,
        fallbackName: "wazuh-alerts.json",
        rows: preview.kept,
      });

      res.status(202).json({
        accepted: true,
        file: storedName,
        format: preview.format,
        events: preview.kept,
        records: preview.total,
        groups: preview.groups,
        iocs: preview.iocs.length,
      });

      options.onAiStatus?.(caseId, {
        status: "analyzing",
        phase: "extracting",
        at: importedAt,
        detail: `importing ${preview.kept} Wazuh alert(s)`,
      });
      commitDedicatedImport(ctx, settleDeps, {
        caseId,
        kind: "wazuh",
        storedName,
        importedAt,
        linesIn: text.split(/\r?\n/).length,
        path: "deterministic",
        minSeverity,
        parameters: { wazuh: importerParameter(wazuhOpts) },
        run: (withDebug) =>
          pipeline.importWazuh(caseId, text, {
            label: storedName,
            ...withDebug,
            idPrefix: `wz${seq}`,
            importedAt,
            wazuh: wazuhOpts,
            onProgress: (done, total) =>
              options.onAiStatus?.(caseId, {
                status: "analyzing",
                phase: "extracting",
                at: new Date().toISOString(),
                detail: `Wazuh import — ${done}/${total}`,
              }),
          }),
      });
      return;
    } catch (err) {
      return sendPipelineError(res, err);
    }
  });
}
