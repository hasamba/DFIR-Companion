import type { Express, Request, Response } from "express";
import { isTerminal, type Job } from "../analysis/jobRegistry.js";
import { logActivity } from "../analysis/activityLog.js";
import type { RouteContext } from "./context.js";

/**
 * State backups (#180) — GET /cases/:id/backups and POST /cases/:id/restore-backup.
 *
 * Automatic snapshots of SNAPSHOT_STATE_FILES before synthesis + on a timer.
 * List: GET /cases/:id/backups → { backups: BackupInfo[], summary: BackupSummary }
 * Restore: POST /cases/:id/restore-backup { filename } → { restored: string[] }
 * Both 404 when backupManager is absent (opt-in feature).
 *
 * Split out of routes/caseLifecycle.ts verbatim when the restore gained its activity-log entry
 * (#2177): that file sits at its size-ledger cap.
 */
export function registerStateBackupRoutes(app: Express, ctx: RouteContext): void {
  const { store, options, runStateExclusive } = ctx;

  app.get("/cases/:id/backups", async (req: Request, res: Response) => {
    if (!options.backupManager)
      return res.status(404).json({ error: "backup not configured — restart the server" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId)))
      return res.status(404).json({ error: `case ${caseId} does not exist` });
    try {
      const [backups, summary] = await Promise.all([
        options.backupManager.listBackups(caseId),
        options.backupManager.summary(caseId),
      ]);
      return res.status(200).json({ backups, summary });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/restore-backup", async (req: Request, res: Response) => {
    if (!options.backupManager)
      return res.status(404).json({ error: "backup not configured — restart the server" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId)))
      return res.status(404).json({ error: `case ${caseId} does not exist` });
    const filename = (req.body as { filename?: unknown })?.filename;
    if (typeof filename !== "string" || !filename.trim()) {
      return res.status(400).json({ error: "filename is required" });
    }
    try {
      // A restore replaces the investigation database, so it must not land on top of another
      // writer (#251). Two guards, because they close different windows:
      //   - runStateExclusive serializes against the short load→save critical sections (manual
      //     event/IOC adds, enrichment saves) that hold the same per-case lock.
      //   - Background jobs release that lock between their critical sections — synthesis holds it
      //     to save, not across the AI call — so a restore can slot into a gap and then be
      //     clobbered by the job's next save. No lock can serialize against that, so refuse while
      //     any job is in flight for this case and let the operator cancel it or wait it out.
      //     Every kind writes case state, hence the check is on all of them, not just synthesis.
      const outcome = await runStateExclusive(
        caseId,
        async (): Promise<{ busy: Job } | { restored: string[] }> => {
          const busy = options.jobManager?.list(caseId).find((j) => !isTerminal(j.status));
          if (busy) return { busy };
          return await options.backupManager!.restoreBackup(caseId, filename.trim());
        },
      );
      if ("busy" in outcome) {
        const { kind, id, label } = outcome.busy;
        return res.status(409).json({
          error: `a ${kind}${label ? ` (${label})` : ""} job is in progress for this case — cancel it or wait for it to finish, then restore`,
          jobId: id,
          kind,
        });
      }
      // A restore rolls the whole case back, so it goes on the case's audit trail (#2177). The
      // activity log is not a snapshot file, so the restore itself can never erase this entry.
      // "settings" keeps the SIEM export's category enum unchanged. Refusals above log nothing.
      void logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "settings",
        action: "backup-restore",
        detail: `restored case state from backup ${filename.trim()} (${outcome.restored.length} file(s): ${outcome.restored.join(", ")})`,
        targetType: "backup",
        targetId: filename.trim(),
      });
      return res.status(200).json(outcome);
    } catch (err) {
      const msg = (err as Error).message;
      if (msg.includes("not found") || msg.includes("invalid backup")) {
        return res.status(404).json({ error: msg });
      }
      return res.status(500).json({ error: msg });
    }
  });
}
