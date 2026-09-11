import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import { parseLeappTsv, type LeappImportOptions, type LeappPlatform } from "../analysis/mobileLeappImport.js";
import { logActivity } from "../analysis/activityLog.js";
import { beginImportSection, type ImportSection } from "./importSection.js";
import { settleForensicImport, type SettleDeps } from "./importSettle.js";

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
  const {
    store,
    options,
    importLock,
    recordImportFailure,
    recordAiError,
    pushImportCheckpoint,
    resynthesizeInBackground,
  } = ctx;

  app.post("/cases/:id/import-leapp", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    const originalName = String(req.body?.filename ?? "leapp.tsv");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawPlatform = String(req.body?.platform ?? "")
      .trim()
      .toLowerCase();
    const platform: LeappPlatform =
      rawPlatform === "ios" ? "ios" : rawPlatform === "android" ? "android" : "unknown";
    const leappOpts: LeappImportOptions = { platform };

    try {
      const preview = parseLeappTsv(text, originalName, leappOpts);
      if (preview.total === 0)
        return res.status(400).json({ error: "no parseable rows found (expected a LEAPP TSV export)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "leapp.tsv";
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId,
        sequenceNumber: seq,
        importedAt,
        filename: storedName,
        originalName,
        rows: preview.kept,
        bytes: Buffer.byteLength(text, "utf8"),
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
      });

      options.onAiStatus?.(caseId, {
        status: "analyzing",
        phase: "extracting",
        at: importedAt,
        detail: `importing ${preview.kept} LEAPP row(s)`,
      });

      // Same shape as the generic route: the section (lock + snapshot) is taken inside run() so the
      // 202 above never waits on another import, and released in the `finally` no matter what.
      let stateBefore: InvestigationState | null = null;
      let section: ImportSection | null = null;
      const pipeline = options.pipeline;
      const run = async (): Promise<void> => {
        section = await beginImportSection(importLock, caseId, options.stateStore);
        stateBefore = section.stateBefore;
        await pipeline.importLeapp(caseId, text, {
          label: storedName,
          idPrefix: `lp${seq}`,
          importedAt,
          // The ORIGINAL name, not the stored one: the stored name is sequence-prefixed, and the
          // artifact's identity lives in the basename LEAPP chose.
          filename: originalName,
          leapp: leappOpts,
        });
      };

      void run()
        .then(async () => {
          options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
          if (settleDeps && stateBefore) {
            try {
              const settled = await settleForensicImport(settleDeps, caseId, stateBefore);
              const { timelineDiff: tDiff, iocsDiff: iDiff } = settled;
              if (options.importMetaStore) {
                await options.importMetaStore.record(caseId, {
                  kind: "leapp",
                  file: storedName,
                  diff: tDiff,
                  superTimelineAddedCount: settled.superTimelineAddedCount,
                  iocsDiff: iDiff,
                  linesIn: preview.total + 1,
                  path: "deterministic",
                });
                options.onImportMeta?.(caseId);
              }
              void logActivity(options.activityLogStore, options.onActivity, caseId, {
                category: "import",
                action: "import",
                detail:
                  `leapp (${storedName}) — +${tDiff.added.length} event(s), +${iDiff.added.length} IOC(s)` +
                  (preview.undated ? `, ${preview.undated} undated` : ""),
              });
              if (tDiff.added.length || tDiff.removed.length || iDiff.added.length || iDiff.removed.length) {
                await pushImportCheckpoint(caseId, stateBefore, `leapp (${storedName})`);
              }
            } catch {
              /* non-fatal — the import itself is on disk and merged */
            }
          }
          resynthesizeInBackground(caseId);
        })
        .catch((err) => {
          recordImportFailure(caseId, "leapp", storedName, err);
          recordAiError(caseId, "import", err);
          options.onAiStatus?.(caseId, {
            status: "error",
            at: new Date().toISOString(),
            detail: (err as Error).message,
          });
        })
        .finally(() => {
          // Unconditional: a section left held would wedge every later import for this case.
          section?.release();
          section = null;
        });
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
