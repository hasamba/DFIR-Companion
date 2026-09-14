import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import { parseLeappTsv, type LeappImportOptions, type LeappPlatform } from "../analysis/mobileLeappImport.js";
import type { SettleDeps } from "./importSettle.js";
import { commitDedicatedImport, importerParameter, persistImportEvidence } from "./importCommit.js";

/**
 * POST /cases/:id/import-leapp — one iLEAPP / ALEAPP TSV artifact export.
 *
 * An explicit endpoint because auto-detection cannot reach these files: LEAPP names each export
 * after the artifact ("Installed Apps.tsv", "Call History.tsv"), a browser upload carries only
 * that basename, and a bare TSV has no in-content marker that could be claimed without stealing
 * every other tab-separated format. So the analyst names the platform here instead of renaming
 * every file to contain "iLEAPP".
 *
 * Moved out of routes/import.ts (#932 item 12) and put onto the same spine the generic import
 * route runs, which the dedicated `import-*` routes had skipped: the import lock + a pre-import
 * snapshot (routes/importSection.ts), then the forensic / super-timeline seam
 * (routes/importSettle.ts — dual-write, tag, demote), then the import record, the activity line
 * and the undo checkpoint. Before, this route called the importer and resynthesized: an Info row
 * (every LEAPP row is Info) stayed in the forensic timeline where the model reads it, never
 * reached the super-timeline, took no lock, and left no import record. #956 tracks the other
 * dedicated routes.
 *
 * A table with no time column is imported UNDATED, not refused — installed apps, permissions and
 * accounts are exactly the evidence a phone examination is for. The response says how many rows
 * carry no clock.
 */
export function registerLeappImportRoute(
  app: Express,
  ctx: RouteContext,
  settleDeps: SettleDeps | null,
): void {
  const { store, options } = ctx;

  app.post("/cases/:id/import-leapp", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const pipeline = options.pipeline;
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    const originalName = String(req.body?.filename ?? "leapp.tsv");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawPlatform = String(req.body?.platform ?? "")
      .trim()
      .toLowerCase();
    const platform: LeappPlatform =
      rawPlatform === "ios" ? "ios" : rawPlatform === "android" ? "android" : "unknown";
    // The extraction's subject device, as the analyst names it (#988): stamped as the rows' asset,
    // the identity the infection window partitions by. Never read from a row.
    const device = String(req.body?.device ?? "")
      .trim()
      .slice(0, 120);
    const leappOpts: LeappImportOptions = { platform, ...(device ? { device } : {}) };

    try {
      const preview = parseLeappTsv(text, originalName, leappOpts);
      if (preview.total === 0)
        return res.status(400).json({ error: "no parseable rows found (expected a LEAPP TSV export)" });

      const { seq, storedName, importedAt } = await persistImportEvidence(store, caseId, {
        text,
        originalName,
        fallbackName: "leapp.tsv",
        rows: preview.kept,
      });

      res.status(202).json({
        accepted: true,
        file: storedName,
        events: preview.kept,
        records: preview.total,
        groups: preview.groups,
        format: preview.format,
        iocs: preview.iocs.length,
        undated: preview.undated,
        // What the origin registry could say about this file's rows (#988), with its version.
        origin: preview.origin,
      });

      options.onAiStatus?.(caseId, {
        status: "analyzing",
        phase: "extracting",
        at: importedAt,
        detail: `importing ${preview.kept} LEAPP row(s)`,
      });

      commitDedicatedImport(ctx, settleDeps, {
        caseId,
        kind: "leapp",
        storedName,
        importedAt,
        linesIn: preview.total + 1,
        path: "deterministic",
        activitySuffix:
          (preview.undated ? `, ${preview.undated} undated` : "") +
          `, origin ${preview.origin.registry}: ${preview.origin.schemaMatches} covered, ${preview.origin.headersDiffer} headers differ, ${preview.origin.notCovered} not covered, ${preview.origin.excluded} excluded`,
        parameters: {
          leapp: importerParameter(leappOpts),
          // The registry's coverage of this file, durable in the run manifest (#988).
          leappOrigin: {
            registry: preview.origin.registry,
            schemaMatches: preview.origin.schemaMatches,
            headersDiffer: preview.origin.headersDiffer,
            notCovered: preview.origin.notCovered,
            excluded: preview.origin.excluded,
          },
        },
        run: () =>
          pipeline.importLeapp(caseId, text, {
            label: storedName,
            idPrefix: `lp${seq}`,
            importedAt,
            // The ORIGINAL name, not the stored one: the stored name is sequence-prefixed, and the
            // artifact's identity lives in the basename LEAPP chose.
            filename: originalName,
            leapp: leappOpts,
          }),
      });
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
