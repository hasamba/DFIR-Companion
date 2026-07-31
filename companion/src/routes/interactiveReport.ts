import type { Express, Request, Response } from "express";
import { renderInteractiveHtmlReport } from "../reports/interactiveHtml.js";
import { emptyReportMeta } from "../reports/reportMeta.js";
import { withNonce } from "../http/securityHeaders.js";
import type { RouteContext } from "./context.js";

// Interactive self-contained HTML report (#233). Serves the case as a single portable HTML file
// with all data embedded as a JSON blob and inline JS for filtering/expansion. Uses the same
// scope/false-positive filtering as the canonical report (via reportWriter.filteredState) so the
// interactive view agrees with report.md/report.html.
export function registerInteractiveReportRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;

  app.get("/cases/:id/report/interactive", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.reportWriter.filteredState(caseId);
      const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
      const reportMeta = options.reportMetaStore ? await options.reportMetaStore.load(caseId).catch(() => emptyReportMeta()) : emptyReportMeta();
      const html = renderInteractiveHtmlReport(state, caseMeta, reportMeta);
      res.type("text/html; charset=utf-8");
      res.setHeader("Cache-Control", "private, no-cache");
      // Stamp this response's CSP nonce into the inline stylesheet and scripts. Without it the
      // policy from createSecurityHeaders() blocks them, leaving an unstyled report with empty
      // interactive sections.
      return res.send(withNonce(html, String(res.locals.cspNonce ?? "")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return res.status(404).json({ error: "case not found" });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
