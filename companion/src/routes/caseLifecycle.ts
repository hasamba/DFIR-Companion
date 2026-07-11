import type { Express, Request, Response } from "express";
import { readFile } from "node:fs/promises";
import { ZodError } from "zod";
import { isValidCaseId } from "../storage/caseStore.js";
import { sanitizeCaseMeta } from "../analysis/casePassword.js";
import { buildInitialQuestions, buildInitialNextSteps } from "../analysis/templateStore.js";
import { milestoneEvent } from "../analysis/notifications.js";
import { seedDemoCase } from "../analysis/seedDemoCase.js";
import { archiveCase } from "../analysis/caseArchive.js";
import {
  exportEncryptedCase,
  importEncryptedCase,
  CaseImportConflictError,
  MIN_PASSWORD_LENGTH,
  dfircaseFilename,
} from "../analysis/caseExportArchive.js";
import { DecryptionError } from "../analysis/caseEncryption.js";
import { computeCaseStats } from "../analysis/caseStats.js";
import { logActivity, ACTIVITY_CATEGORIES, type ActivityCategory } from "../analysis/activityLog.js";
import { buildManualEvent } from "../analysis/manualEntry.js";
import { byEventTime } from "../analysis/forensicSort.js";
import { parseImporterSpec } from "../analysis/importerSpec.js";
import { getImporterPrompt } from "../analysis/pipeline.js";
import { getEnvForSettings, updateEnv as updateEnvFile, reloadEnvPrefix } from "../settings/envManager.js";
import { readPublicAsset } from "../serverAssets.js";
import { defaultIrisCaseName } from "../integrations/iris/irisExportStore.js";
import { pushCaseToIris } from "../integrations/iris/irisPush.js";
import { pushCaseToTimesketch, pushSuperTimelineToTimesketch } from "../integrations/timesketch/timesketchPush.js";
import { pushCaseToMisp } from "../integrations/misp/mispPush.js";
import { pushCaseToNotion, type NotionPushTarget } from "../integrations/notion/notionPush.js";
import { parseNotionPageId } from "../integrations/notion/notionClient.js";
import { pushPlaybookToClickUp } from "../integrations/clickup/clickupPush.js";
import type { Severity } from "../analysis/stateTypes.js";
import type { ImportMetadata } from "../types.js";
import type { IocBlocklistFormat, IocBlocklistOptions, BlocklistIocType } from "../reports/iocBlocklist.js";
import type { RouteContext } from "./context.js";

/**
 * Case-core "everything else" domain — the FINAL router-split extraction. Everything that remained in
 * createApp after the 15 prior domain modules, minus the password/unlock routes (routes/casePassword.ts).
 * Pure structural move out of createApp (see routes/system.ts for the conventions) — no handler logic
 * changed. This is the catch-all case-core surface; groups:
 *   - case lifecycle — GET/POST /cases (list/create), POST /cases/seed-demo, PATCH /cases/:id/status,
 *     POST /cases/:id/{archive,restore,delete}, GET /cases/:id/{state,stats}.
 *   - whole-case archives — GET /cases/:id/export/ioc-blocklist, POST /cases/:id/export/encrypted,
 *     POST /cases/import/encrypted, GET /cases/:id/backups, POST /cases/:id/restore-backup.
 *   - integration pushes + status/reconnect — /cases/:id/push/{iris,timesketch,timesketch-super,misp,
 *     notion,clickup} and the /{timesketch,misp,notion,clickup}/status + /timesketch/reconnect endpoints.
 *   - manual timeline event — POST /cases/:id/events.
 *   - declarative importers CRUD — GET/POST/DELETE /importers, /importers/{prompt,reload,precedence}.
 *   - background jobs — GET /api/jobs, GET /api/jobs/:id, POST /api/jobs/:id/cancel.
 *   - activity log — GET /cases/:id/activity-log.
 *   - settings/env + setup — GET/POST /settings/env, POST /settings/{ai-reload,reload}, GET /setup/status.
 *   - static app shell — GET /, /dashboard, /mobile, /manifest.webmanifest, /sw.js (these five were
 *     registered in startServer AFTER createApp returned; moved here so server.ts holds zero literal
 *     route registrations. The dynamic favicon/vendor loops (app.get(variable, …)) stay put — they are
 *     not literal-path registrations. NOTE: /dashboard and /mobile have no try/catch and now sit BEFORE
 *     the terminal error handler, so an (unreachable in a real install) asset-read failure yields the
 *     standard JSON 500 instead of Express's default HTML page — the only observable delta.)
 *
 * Module-private helpers moved verbatim (used only by routes here): removeCaseFromActiveListBestEffort,
 * deleteCaseFolderBestEffort (case archive/delete plumbing) and the RELOADABLE_PREFIXES allowlist.
 * logLine/errLine mirror createApp's (serverLogger.info/error) so the moved call sites stay verbatim.
 *
 * Shared surface — reuses stable ctx fields (store, options, serverLogger, hasAiProvider), stable helpers
 * (dispatchNotify, resynthesizeInBackground, syncPlaybook) and the live irisClient() accessor, plus five
 * members GRADUATED for this domain (see context.ts):
 *   - ensureDropFolders — create-case makes the drop inbox; the drop watcher (stays) also calls it.
 *   - runStateExclusive — the manual-event write serializes on the per-case state mutex the staying
 *     import/enrich/synthesis paths also use.
 *   - reloadImporters + importerPrecedence()/setImporterPrecedence — the importer CRUD routes mutate the
 *     in-memory registry + precedence that the staying detection seam (dispatchImport/resolveImportKind)
 *     reads, so the reload function + precedence accessor/setter were graduated rather than moved.
 *   - rebuildTimesketchClient — /timesketch/reconnect rebuilds the client from .env (mirrors
 *     ctx.rebuildIrisClient); the reconnect reassigns options.timesketchClient, which the push routes read.
 */
export function registerCaseLifecycleRoutes(app: Express, ctx: RouteContext): void {
  const {
    store, options, serverLogger, hasAiProvider,
    dispatchNotify, ensureDropFolders, runStateExclusive, resynthesizeInBackground,
    syncPlaybook, reloadImporters,
  } = ctx;
  // Module-private wrappers mirroring createApp's logLine/errLine (serverLogger.info/error) so the
  // moved call sites stay verbatim.
  const logLine = (msg: string): void => serverLogger.info(msg);
  const errLine = (msg: string): void => serverLogger.error(msg);

  // List existing cases (newest first) so the extension can present a picker of cases
  // to attach to — case CREATION lives in the dashboard, the extension only connects.
  app.get("/cases", async (_req: Request, res: Response) => {
    try {
      return res.status(200).json((await store.listCases()).map(sanitizeCaseMeta));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Create a case. This is the one place a case is born (the dashboard's New case form and
  // `npm run`-style tooling call it); the extension no longer creates cases. Rejects a
  // duplicate id so the form can't silently clobber an existing case's metadata/evidence.
  // Optional `templateId`: pre-populates key questions from the named template.
  app.post("/cases", async (req: Request, res: Response) => {
    try {
      const { caseId, name, investigator, aiProvider, templateId } = req.body ?? {};
      if (!caseId || !name) return res.status(400).json({ error: "caseId and name are required" });
      if (typeof caseId !== "string" || !isValidCaseId(caseId)) return res.status(400).json({ error: "caseId must use only letters, numbers, dots, dashes, or underscores, and may not contain path traversal" });
      if (await store.caseExists(caseId)) return res.status(409).json({ error: `case ${caseId} already exists` });
      const meta = await store.createCase({
        caseId, name, investigator: investigator ?? "unknown", aiProvider: aiProvider ?? null,
      });
      if (templateId && options.templateStore && options.stateStore) {
        const template = await options.templateStore.get(String(templateId));
        if (template && (template.initialKeyQuestions.length || template.initialNextSteps?.length)) {
          const state = await options.stateStore.load(caseId);
          if (template.initialKeyQuestions.length) state.keyQuestions = buildInitialQuestions(template);
          if (template.initialNextSteps?.length) state.nextSteps = buildInitialNextSteps(template);
          state.updatedAt = new Date().toISOString();
          await options.stateStore.save(state);
        }
      }
      dispatchNotify(milestoneEvent(caseId, `Investigation opened: ${name}`, [`Investigator: ${investigator ?? "unknown"}`], new Date().toISOString()));
      // Create the evidence drop folder for every new case (best-effort — never block case creation).
      await ensureDropFolders(caseId).catch(() => { /* the watcher re-ensures on its next poll */ });
      return res.status(201).json(sanitizeCaseMeta(meta));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Seed the built-in demo case ("GlobalTech Industries — BEC & Ransomware Precursor").
  // Accepts optional { caseId?: string, force?: boolean } in the body.
  // Returns 409 when the case already exists and force is not set; 201 on success.
  // Available in both the dev server and the portable EXE so users don't need tsx/Node installed.
  app.post("/cases/seed-demo", async (req: Request, res: Response) => {
    try {
      const caseId = typeof req.body?.caseId === "string" ? req.body.caseId : undefined;
      const force  = req.body?.force === true;
      const result = await seedDemoCase(store.casesRoot, { caseId, force });
      return res.status(201).json(result);
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === "EEXIST") return res.status(409).json({ error: e.message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── Case lifecycle (#119) ──────────────────────────────────────────────────────────────
  // Set a case's lifecycle status (open / closed). A closed case is eligible for archiving.
  app.patch("/cases/:id/status", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      if (!isValidCaseId(id)) return res.status(400).json({ error: "invalid caseId" });
      if (!await store.caseExists(id)) return res.status(404).json({ error: `case ${id} not found` });
      const { status } = req.body ?? {};
      if (status !== "open" && status !== "closed") return res.status(400).json({ error: "status must be 'open' or 'closed'" });
      const updated = await store.updateCaseMeta(id, { status });
      logLine(`[lifecycle] case=${id} status=${status}`);
      return res.status(200).json(sanitizeCaseMeta(updated));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Best-effort: moves a case out of the active list (into _archived/) and flips its status,
  // AFTER the caller has already fully built the archive/export bytes. Failure here must NOT
  // undo or discard the archive/export itself — the caller already has (or is about to send)
  // their file; it just means the case stays visible in the active list until retried.
  async function removeCaseFromActiveListBestEffort(
    id: string,
    logPrefix: string,
  ): Promise<{ removed: boolean; error?: string }> {
    try {
      await store.archiveCaseFolder(id);
      await store.updateCaseMeta(id, { status: "archived" });
      logLine(`${logPrefix} case=${id} removed from active list (moved to _archived/)`);
      return { removed: true };
    } catch (err) {
      errLine(`${logPrefix} case=${id} failed to remove from active list: ${(err as Error).message}`);
      return { removed: false, error: (err as Error).message };
    }
  }

  // Archive a case to a ZIP file (<casesRoot>/<caseId or name> (no password).zip). Intended for
  // closed cases. Returns the archive path and a manifest of archived files + checksums. With
  // { removeFromList: true }, additionally moves the case folder to _archived/ and sets
  // status: "archived" — non-destructive and reversible via POST /cases/:id/restore.
  app.post("/cases/:id/archive", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      if (!isValidCaseId(id)) return res.status(400).json({ error: "invalid caseId" });
      const meta = await store.getCaseMeta(id);
      if (!meta) return res.status(404).json({ error: `case ${id} not found` });
      if (meta.status === "archived") return res.status(400).json({ error: `case ${id} is already archived` });
      const removeFromList = (req.body as { removeFromList?: unknown })?.removeFromList === true;
      logLine(`[archive] starting archive for case=${id}`);
      const result = await archiveCase(store.casesRoot, id, {}, meta.name, store.caseDir(id));
      logLine(`[archive] done case=${id} files=${result.manifest.totalFiles} bytes=${result.manifest.totalBytes} path=${result.archivePath}`);
      let removedFromList = false;
      let removeFromListError: string | undefined;
      if (removeFromList) {
        const outcome = await removeCaseFromActiveListBestEffort(id, "[archive]");
        removedFromList = outcome.removed;
        removeFromListError = outcome.error;
      }
      return res.status(200).json({
        ...result,
        removedFromList,
        ...(removeFromListError ? { removeFromListError } : {}),
      });
    } catch (err) {
      errLine(`[archive] error case=${req.params.id}: ${(err as Error).message}`);
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Restore a case previously archived via the removeFromList option: moves it back from
  // _archived/ into the active cases root and sets status to "closed" (the state it must have
  // been in to be archived) — use PATCH /cases/:id/status afterward to reopen it if needed.
  app.post("/cases/:id/restore", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      if (!isValidCaseId(id)) return res.status(400).json({ error: "invalid caseId" });
      const meta = await store.getCaseMeta(id);
      if (!meta) return res.status(404).json({ error: `case ${id} not found` });
      if (meta.status !== "archived") return res.status(400).json({ error: `case ${id} is not archived` });
      await store.restoreCaseFolder(id);
      const updated = await store.updateCaseMeta(id, { status: "closed" });
      logLine(`[restore] case=${id} restored from _archived/`);
      return res.status(200).json(updated);
    } catch (err) {
      errLine(`[restore] error case=${req.params.id}: ${(err as Error).message}`);
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Best-effort: permanently deletes a case's folder AFTER the caller has already fully built any
  // requested archive. Failure here must NOT be treated as though the archive itself failed — the
  // caller already has (or is about to send) that file; this just means the case's folder remains
  // on disk until deletion is retried.
  async function deleteCaseFolderBestEffort(id: string): Promise<{ deleted: boolean; error?: string }> {
    try {
      await store.deleteCaseFolder(id);
      logLine(`[delete] case=${id} deleted`);
      return { deleted: true };
    } catch (err) {
      const message = (err as Error).message;
      errLine(`[delete] case=${id} failed to delete: ${message}`);
      return { deleted: false, error: message };
    }
  }

  // Permanently delete a case: optionally archives it first (ZIP or encrypted), then removes its
  // folder from disk entirely — irreversible. Only allowed once a case is closed or archived (an
  // open case must be closed first, mirroring the restriction on archiving). If the archive step
  // is requested and succeeds but the delete step then fails, the response still reflects the
  // successful archive (never silently discarded) — same principle as
  // removeCaseFromActiveListBestEffort above.
  // Known limitation: per-case in-memory state (capture buffers, synth timers/in-flight flags,
  // Velociraptor hunt timers, drop-folder scan trackers — all keyed by caseId) is never explicitly
  // cleared on delete, same pre-existing gap as archiveCaseFolder. A write already in flight when
  // a case is closed→archived→deleted in quick succession could still try to touch the now-gone
  // folder and error out. Accepted for now (writes are already blocked once closed/archived; this
  // is a single-user localhost tool) — not fixed here to avoid scope creep into unrelated timers.
  app.post("/cases/:id/delete", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      if (!isValidCaseId(id)) return res.status(400).json({ error: "invalid caseId" });
      const meta = await store.getCaseMeta(id);
      if (!meta) return res.status(404).json({ error: `case ${id} not found` });
      if (meta.status !== "closed" && meta.status !== "archived") {
        return res.status(400).json({ error: `case ${id} must be closed or archived before it can be deleted` });
      }
      const body = (req.body ?? {}) as { archiveFirst?: unknown; password?: unknown };
      const archiveFirst = body.archiveFirst;
      if (archiveFirst !== "none" && archiveFirst !== "zip" && archiveFirst !== "encrypted") {
        return res.status(400).json({ error: `archiveFirst must be 'none', 'zip', or 'encrypted'` });
      }

      if (archiveFirst === "encrypted") {
        const password = body.password;
        if (typeof password !== "string" || password.length < MIN_PASSWORD_LENGTH) {
          return res.status(400).json({ error: `password must be at least ${MIN_PASSWORD_LENGTH} characters` });
        }
        const archive = await exportEncryptedCase(store, id, password);
        const filename = dfircaseFilename(id, meta.name);
        const { deleted } = await deleteCaseFolderBestEffort(id);
        res.type("application/octet-stream");
        res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
        res.setHeader("Cache-Control", "private, no-cache");
        res.setHeader("X-Case-Deleted", String(deleted));
        return res.send(archive);
      }

      let archiveResult: Awaited<ReturnType<typeof archiveCase>> | undefined;
      if (archiveFirst === "zip") {
        archiveResult = await archiveCase(store.casesRoot, id, {}, meta.name, store.caseDir(id));
        logLine(`[delete] case=${id} archived to ZIP before deletion: ${archiveResult.archivePath}`);
      }

      const { deleted, error: deleteError } = await deleteCaseFolderBestEffort(id);

      return res.status(200).json({
        deleted,
        ...(deleteError ? { deleteError } : {}),
        ...(archiveResult ? { archivePath: archiveResult.archivePath, manifest: archiveResult.manifest } : {}),
      });
    } catch (err) {
      if ((err as Error).message.includes("does not exist")) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      errLine(`[delete] error case=${req.params.id}: ${(err as Error).message}`);
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/state", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const state = await options.stateStore.load(req.params.id);
      return res.status(200).json(state);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Per-IOC corroboration: { iocId: [tools that observed it] }, derived on demand by matching each
  // IOC value against the forensic events' sources (same scope/legitimate filtering as the report).
  // Powers the dashboard's "⊕ N sources" badge on IOCs (#35 Phase 3).
  // Case introspection stats (#241): totals, event-count-by-source, and daily import velocity for
  // the CURRENT case only — powers the Diagnostics tab "Case Statistics" panel. Derived on read,
  // no caching (same as host-ranking below). Disk usage is intentionally NOT included here — it's
  // global, not per-case, and already served by GET /disk-stats.
  app.get("/cases/:id/stats", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const state = await options.stateStore.load(req.params.id);
      const importLog: ImportMetadata[] = [];
      try {
        const log = await readFile(store.importsLogPath(req.params.id), "utf8");
        for (const line of log.split("\n")) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          try { importLog.push(JSON.parse(trimmed) as ImportMetadata); } catch { /* skip a malformed audit line */ }
        }
      } catch { /* no imports for this case yet */ }
      return res.status(200).json(computeCaseStats(state, importLog));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export a clean IOC block-list for network/firewall teams (issue #87). Supports three formats:
  // txt (one value per line, grouped by type, with header comments), csv (minimal columnar format
  // for TIP ingestion/ticketing), and stix (indicators-only STIX 2.1 bundle). Severity is derived
  // from the worst enrichment verdict; scope/legitimate filters always apply.
  //
  // Query params: format (txt|csv|stix, default txt), minSeverity (Critical|High|Medium|Low|Info,
  // default Medium), types (comma-separated ip,domain,url,hash,email), verdictOnly (true|false).
  app.get("/cases/:id/export/ioc-blocklist", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    const fmt = String(req.query.format ?? "txt");
    if (fmt !== "txt" && fmt !== "csv" && fmt !== "stix") {
      return res.status(400).json({ error: "format must be txt, csv, or stix" });
    }
    const opts: IocBlocklistOptions = {};
    const VALID_SEV: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
    const VALID_TYPES: BlocklistIocType[] = ["ip", "domain", "url", "hash", "email"];
    const { minSeverity, types, verdictOnly } = req.query;
    if (typeof minSeverity === "string" && VALID_SEV.includes(minSeverity as Severity)) {
      opts.minSeverity = minSeverity as Severity;
    }
    if (typeof types === "string" && types) {
      opts.types = types.split(",").filter((t): t is BlocklistIocType => VALID_TYPES.includes(t as BlocklistIocType));
    }
    if (verdictOnly === "true") opts.verdictOnly = true;
    try {
      const data = await options.reportWriter.iocBlocklist(req.params.id, fmt as IocBlocklistFormat, opts);
      const cid = req.params.id;
      res.setHeader("Cache-Control", "private, no-cache");
      if (fmt === "stix") {
        res.type("application/json; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="ioc-blocklist-${cid}.stix.json"`);
        return res.send(JSON.stringify(data, null, 2));
      } else if (fmt === "csv") {
        res.type("text/csv; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="ioc-blocklist-${cid}.csv"`);
        return res.send(data as string);
      } else {
        res.type("text/plain; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="ioc-blocklist-${cid}.txt"`);
        return res.send(data as string);
      }
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export the ENTIRE case as a password-encrypted archive (replaces issue #56's JSON-only
  // snapshot, which never included screenshots or raw evidence bytes — only references to them).
  // The whole case directory is zipped, then AES-256-GCM encrypted under a password the analyst
  // chooses. Only openable via another DFIR Companion's Import (see analysis/caseEncryption.ts +
  // caseExportArchive.ts). Password travels in the POST body, not the URL/query string.
  app.post("/cases/:id/export/encrypted", async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      if (!isValidCaseId(id)) return res.status(400).json({ error: "invalid caseId" });
      const password = (req.body as { password?: unknown })?.password;
      if (typeof password !== "string" || password.length < MIN_PASSWORD_LENGTH) {
        return res.status(400).json({ error: `password must be at least ${MIN_PASSWORD_LENGTH} characters` });
      }
      const meta = await store.getCaseMeta(id);
      if (meta?.status === "archived") return res.status(400).json({ error: `case ${id} is already archived` });
      const removeFromList = (req.body as { removeFromList?: unknown })?.removeFromList === true;
      const archive = await exportEncryptedCase(store, id, password);
      const filename = dfircaseFilename(id, meta?.name);
      let removedFromList = false;
      if (removeFromList) {
        const outcome = await removeCaseFromActiveListBestEffort(id, "[export]");
        removedFromList = outcome.removed;
      }
      res.type("application/octet-stream");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Cache-Control", "private, no-cache");
      res.setHeader("X-Case-Removed-From-List", String(removedFromList));
      return res.send(archive);
    } catch (err) {
      if ((err as Error).message.includes("does not exist")) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a `.dfircase` encrypted archive into a NEW case (replaces issue #56's snapshot
  // import). Body: { data: base64, password, targetCaseId? } — base64-in-JSON, matching this
  // codebase's existing convention for binary uploads elsewhere (no multipart/multer). 409 if the
  // target id already exists (the dashboard re-prompts with a new id), 400 on a wrong password,
  // corrupt archive, or malformed payload.
  app.post("/cases/import/encrypted", async (req: Request, res: Response) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      const { data, password, targetCaseId } = body;
      if (typeof data !== "string" || !data.trim()) {
        return res.status(400).json({ error: "data (base64) is required" });
      }
      if (typeof password !== "string" || !password) {
        return res.status(400).json({ error: "password is required" });
      }
      const fileBuffer = Buffer.from(data, "base64");
      const { meta, counts } = await importEncryptedCase(store, fileBuffer, password, {
        targetCaseId: typeof targetCaseId === "string" && targetCaseId.trim() ? targetCaseId.trim() : undefined,
      });
      // An archived case.json is written back byte-for-byte on import (see
      // caseExportArchive.ts), so an exported case that had a case-lock password carries
      // its salt+hash into the archive. Sanitize before responding — never let it reach
      // the client, same as every other route that serializes a CaseMeta.
      return res.status(201).json({ ...sanitizeCaseMeta(meta), counts });
    } catch (err) {
      if (err instanceof CaseImportConflictError) {
        return res.status(409).json({ error: err.message, caseId: err.caseId });
      }
      if (err instanceof DecryptionError) {
        return res.status(400).json({ error: err.message });
      }
      const msg = (err as Error).message;
      if (/not a valid case archive|invalid target case id/i.test(msg)) {
        return res.status(400).json({ error: msg });
      }
      return res.status(500).json({ error: msg });
    }
  });

  // ── State backups (#180) ─────────────────────────────────────────────────────────────────────
  // Automatic snapshots of SNAPSHOT_STATE_FILES before synthesis + on a timer.
  // List: GET /cases/:id/backups → { backups: BackupInfo[], summary: BackupSummary }
  // Restore: POST /cases/:id/restore-backup { filename } → { restored: string[] }
  // Both 404 when backupManager is absent (opt-in feature).

  app.get("/cases/:id/backups", async (req: Request, res: Response) => {
    if (!options.backupManager) return res.status(404).json({ error: "backup not configured — restart the server" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: `case ${caseId} does not exist` });
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
    if (!options.backupManager) return res.status(404).json({ error: "backup not configured — restart the server" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: `case ${caseId} does not exist` });
    const filename = (req.body as { filename?: unknown })?.filename;
    if (typeof filename !== "string" || !filename.trim()) {
      return res.status(400).json({ error: "filename is required" });
    }
    try {
      const result = await options.backupManager.restoreBackup(caseId, filename.trim());
      return res.status(200).json(result);
    } catch (err) {
      const msg = (err as Error).message;
      if (msg.includes("not found") || msg.includes("invalid backup")) {
        return res.status(404).json({ error: msg });
      }
      return res.status(500).json({ error: msg });
    }
  });
  // Push a case to DFIR-IRIS: find-or-create the case by name, then push assets→assets,
  // IOCs→IOCs, forensic timeline→timeline, executive summary→case summary, everything else→notes.
  // Body: { caseName? } — an explicit override; otherwise the name from the last push is reused
  // (irisExportStore), falling back to "<case id> — <friendly name>" on the very first push.
  app.post("/cases/:id/push/iris", async (req: Request, res: Response) => {
    const irisClient = ctx.irisClient(); // live accessor — POST /iris/reconnect can rebuild it at runtime
    if (!irisClient) return res.status(501).json({ error: "DFIR-IRIS not configured (set DFIR_IRIS_URL and DFIR_IRIS_KEY)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      const meta = options.reportMetaStore ? await options.reportMetaStore.load(caseId) : undefined;
      // Push the analyst-curated playbook (status-aware) when available, else the raw next steps.
      const playbookTasks = options.playbookStore ? await syncPlaybook(caseId) : undefined;
      const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
      const saved = options.irisExportStore ? await options.irisExportStore.load(caseId) : { caseName: "" };
      const requested = typeof req.body?.caseName === "string" ? req.body.caseName.trim() : "";
      let targetCaseName: string;
      if (requested) {
        targetCaseName = requested;
      } else if (saved.caseName) {
        targetCaseName = saved.caseName;
      } else {
        // First push under the new naming scheme — check whether this case was already pushed
        // under the OLD bare-case-id scheme (pre-dates the case-name override feature) so we
        // don't fork a duplicate IRIS case; only fall back to the computed default if not.
        const legacy = await irisClient.findCaseByName(caseId).catch(() => null);
        targetCaseName = legacy ? caseId : defaultIrisCaseName(caseId, caseMeta?.name);
      }
      logLine(`[iris] ${caseId} push START -> "${targetCaseName}"`);
      const result = await pushCaseToIris(
        irisClient,
        { caseName: targetCaseName, state, meta, playbookTasks: playbookTasks?.length ? playbookTasks : undefined },
        options.irisOptions,
      );
      if (options.irisExportStore) await options.irisExportStore.record(caseId, targetCaseName);
      logLine(`[iris] ${caseId} push DONE -> case ${result.caseId} (${result.created ? "created" : "updated"}); ` +
        `assets +${result.assets.added}/${result.assets.existing}, iocs +${result.iocs.added}/${result.iocs.existing}, ` +
        `timeline +${result.timeline.added}/${result.timeline.existing}, tasks +${result.tasks.added}/${result.tasks.existing}, ` +
        `notes ${result.notes}, warnings ${result.warnings.length}`);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export", action: "push-iris", detail: `pushed to DFIR-IRIS case ${result.caseId} (${result.created ? "created" : "updated"})`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[iris] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });
  // Whether a Timesketch push target is configured (so the dashboard can show/hide the button).
  app.get("/timesketch/status", (_req: Request, res: Response) => {
    res.status(200).json({ configured: !!options.timesketchClient, baseUrl: options.timesketchOptions?.baseUrl });
  });

  // Re-read DFIR_TIMESKETCH_* from .env (Settings only writes the file), rebuild the client, and log
  // in to verify connectivity — so the Setup wizard / Settings can connect after configuring Timesketch
  // (or after it comes back online) WITHOUT the #1-gotcha restart. Mirrors /iris/reconnect. Always 200;
  // the body says whether it's configured and reachable.
  app.post("/timesketch/reconnect", async (_req: Request, res: Response) => {
    try {
      await reloadEnvPrefix("DFIR_TIMESKETCH_");
      options.timesketchClient = ctx.rebuildTimesketchClient();
      if (!options.timesketchClient) {
        return res.status(200).json({ configured: false, ok: false, error: "DFIR_TIMESKETCH_URL, DFIR_TIMESKETCH_USER and DFIR_TIMESKETCH_PASSWORD are not all set" });
      }
      try {
        await options.timesketchClient.login();
        return res.status(200).json({ configured: true, ok: true, baseUrl: process.env.DFIR_TIMESKETCH_URL });
      } catch (err) {
        return res.status(200).json({ configured: true, ok: false, baseUrl: process.env.DFIR_TIMESKETCH_URL, error: (err as Error).message });
      }
    } catch (err) {
      return res.status(500).json({ configured: false, ok: false, error: (err as Error).message });
    }
  });

  // Push a case to Timesketch: log in, find-or-create the sketch by name (= the Companion case id),
  // then upload the forensic timeline as a timeline. The managed timeline is clean-replaced so a
  // re-push never duplicates events.
  app.post("/cases/:id/push/timesketch", async (req: Request, res: Response) => {
    if (!options.timesketchClient) return res.status(501).json({ error: "Timesketch not configured (set DFIR_TIMESKETCH_URL, DFIR_TIMESKETCH_USER and DFIR_TIMESKETCH_PASSWORD)" });
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.reportWriter.filteredState(caseId);
      logLine(`[timesketch] ${caseId} push START`);
      const result = await pushCaseToTimesketch(options.timesketchClient, { sketchName: caseId, state }, options.timesketchOptions);
      logLine(`[timesketch] ${caseId} push DONE -> sketch ${result.sketchId} (${result.created ? "created" : "updated"}); ` +
        `timeline "${result.timelineName}" events ${result.events}${result.replacedTimeline ? " (replaced)" : ""}, warnings ${result.warnings.length}`);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export", action: "push-timesketch", detail: `pushed to Timesketch sketch ${result.sketchId} (${result.created ? "created" : "updated"})`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[timesketch] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Push the super-timeline (forensic timeline + raw host-triage artifacts) to Timesketch: same
  // sketch as the forensic push (named after the case id), but a SEPARATE timeline inside it
  // ("DFIR Companion super timeline") so the two pushes never clean-replace each other. NOT
  // scope/false-positive filtered — the super-timeline is the raw complete record.
  app.post("/cases/:id/push/timesketch-super", async (req: Request, res: Response) => {
    if (!options.timesketchClient) return res.status(501).json({ error: "Timesketch not configured (set DFIR_TIMESKETCH_URL, DFIR_TIMESKETCH_USER and DFIR_TIMESKETCH_PASSWORD)" });
    if (!options.superTimelineStore) return res.status(501).json({ error: "super-timeline not configured" });
    const caseId = req.params.id;
    try {
      const { events } = await options.superTimelineStore.query(caseId, { limit: Number.MAX_SAFE_INTEGER });
      logLine(`[timesketch] ${caseId} super-timeline push START`);
      const result = await pushSuperTimelineToTimesketch(options.timesketchClient, { sketchName: caseId, events }, options.timesketchOptions);
      logLine(`[timesketch] ${caseId} super-timeline push DONE -> sketch ${result.sketchId} (${result.created ? "created" : "updated"}); ` +
        `timeline "${result.timelineName}" events ${result.events}${result.replacedTimeline ? " (replaced)" : ""}, warnings ${result.warnings.length}`);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export", action: "push-timesketch-super", detail: `pushed super-timeline to Timesketch sketch ${result.sketchId} (${result.created ? "created" : "updated"})`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[timesketch] ${caseId} super-timeline push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Whether a MISP push target is configured (so the dashboard can show/hide the button).
  app.get("/misp/status", (_req: Request, res: Response) => {
    res.status(200).json({ configured: !!options.mispPushClient, baseUrl: options.mispPushOptions?.baseUrl });
  });

  // Push a case to MISP: find-or-create the event by the idempotency tag, then push
  // IOCs as attributes and MITRE techniques as tags. Idempotent: re-push adds only
  // what's missing (attributes deduplicated by value).
  app.post("/cases/:id/push/misp", async (req: Request, res: Response) => {
    if (!options.mispPushClient) return res.status(501).json({ error: "MISP not configured (set DFIR_MISP_URL and DFIR_MISP_KEY)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      logLine(`[misp] ${caseId} push START`);
      const result = await pushCaseToMisp(options.mispPushClient, { caseId, state }, options.mispPushOptions);
      logLine(`[misp] ${caseId} push DONE -> event ${result.eventId} (${result.created ? "created" : "updated"}); ` +
        `attributes +${result.attributes.added}/${result.attributes.existing}, tags +${result.tags}, warnings ${result.warnings.length}`);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export", action: "push-misp", detail: `pushed to MISP event ${result.eventId} (${result.created ? "created" : "updated"})`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[misp] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Whether a Notion export target is configured (so the dashboard can show/hide the option and
  // decide whether to ask for a parent in the "new page" modal).
  app.get("/notion/status", (_req: Request, res: Response) => {
    res.status(200).json({
      configured: !!options.notionClient,
      hasDatabase: !!options.notionOptions?.databaseId,
      hasParent: !!options.notionOptions?.parentPageId,
    });
  });

  // Export a case into a Notion page. The Companion writes ALL its content inside ONE managed
  // toggle block it owns; a re-export refreshes that block and never touches the investigators'
  // own notes/screenshots. Body: { mode: "new"|"existing", page?, parent?, database? }.
  app.post("/cases/:id/push/notion", async (req: Request, res: Response) => {
    if (!options.notionClient) return res.status(501).json({ error: "Notion not configured (set DFIR_NOTION_TOKEN)" });
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    if (!options.notionExportStore) return res.status(501).json({ error: "notion export store not configured" });
    const caseId = req.params.id;
    const body = req.body ?? {};
    const mode = body.mode === "existing" ? "existing" : "new";

    const target: NotionPushTarget = { mode };
    if (mode === "existing") {
      const pageId = parseNotionPageId(typeof body.page === "string" ? body.page : "");
      if (!pageId) return res.status(400).json({ error: "could not read a Notion page id from the supplied page URL/ID" });
      target.pageId = pageId;
    } else {
      const parent = typeof body.parent === "string" ? parseNotionPageId(body.parent) : null;
      const database = typeof body.database === "string" ? parseNotionPageId(body.database) : null;
      if (parent) target.parentPageId = parent;
      if (database) target.databaseId = database;
    }

    try {
      const state = await options.reportWriter.filteredState(caseId);
      const meta = options.reportMetaStore ? await options.reportMetaStore.load(caseId) : undefined;
      logLine(`[notion] ${caseId} export START (${mode})`);
      const result = await pushCaseToNotion(
        options.notionClient,
        { caseName: caseId, state, meta },
        target,
        options.notionOptions,
        options.notionExportStore,
      );
      logLine(`[notion] ${caseId} export DONE -> page ${result.pageId} (${result.created ? "created" : "updated"}); ` +
        `+${result.blocksAppended} block(s) in ${result.batches} batch(es), archived ${result.blocksArchived}, warnings ${result.warnings.length}`);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export", action: "push-notion", detail: `pushed to Notion page ${result.pageId} (${result.created ? "created" : "updated"})`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[notion] ${caseId} export ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Whether a ClickUp push target is configured (so the dashboard can show/hide the option).
  app.get("/clickup/status", (_req: Request, res: Response) => {
    res.status(200).json({
      configured: !!options.clickupClient,
      hasDefaultList: !!options.clickupOptions?.defaultListId,
      defaultListId: options.clickupOptions?.defaultListId ?? "",
    });
  });

  // Push the Response Playbook to a ClickUp list as tasks. Body { listId? } — falls back to the
  // saved list, then the configured default. Re-export UPDATES the tasks it created (by remembered
  // id) instead of duplicating.
  app.post("/cases/:id/push/clickup", async (req: Request, res: Response) => {
    if (!options.clickupClient) return res.status(501).json({ error: "ClickUp not configured (set DFIR_CLICKUP_TOKEN)" });
    if (!options.clickupExportStore) return res.status(501).json({ error: "clickup export store not configured" });
    if (!options.playbookStore || !options.stateStore) return res.status(501).json({ error: "playbook not configured" });
    const caseId = req.params.id;
    try {
      const saved = await options.clickupExportStore.load(caseId);
      const requested = typeof req.body?.listId === "string" ? req.body.listId.trim() : "";
      const listId = requested || saved.listId || options.clickupOptions?.defaultListId || "";
      if (!listId) return res.status(400).json({ error: "a ClickUp list id is required" });
      const tasks = await syncPlaybook(caseId);
      if (!tasks.length) return res.status(400).json({ error: "the playbook is empty — run synthesis or add tasks first" });
      logLine(`[clickup] ${caseId} push START -> list ${listId} (${tasks.length} tasks)`);
      const result = await pushPlaybookToClickUp(
        options.clickupClient,
        { caseId, listId, tasks },
        options.clickupExportStore,
        new Date().toISOString(),
      );
      logLine(`[clickup] ${caseId} push DONE: +${result.created} created, ${result.updated} updated, ${result.skipped} skipped, warnings ${result.warnings.length}`);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "export", action: "push-clickup", detail: `pushed playbook to ClickUp list ${listId} — +${result.created} created, ${result.updated} updated`,
      });
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[clickup] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });
  // Manually add a forensic event the AI didn't catch. Appended to the timeline (kept sorted by
  // event time), then re-synthesized so it weaves into findings/MITRE (a high-severity manual
  // event earns a finding via the backfill). Synthesis preserves the timeline, so it survives.
  app.post("/cases/:id/events", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const event = buildManualEvent(req.body);
      const stateStore = options.stateStore;
      await runStateExclusive(caseId, async () => {
        const state = await stateStore.load(caseId);
        const forensicTimeline = [...state.forensicTimeline, event].sort(byEventTime);
        const next = { ...state, forensicTimeline, updatedAt: new Date().toISOString() };
        await stateStore.save(next);
        options.onState?.(next);
      });
      resynthesizeInBackground(caseId);
      logLine(`[manual] ${caseId} added event ${event.id} (${event.severity})`);
      return res.status(201).json(event);
    } catch (err) {
      if (err instanceof ZodError) return res.status(400).json({ error: err.issues.map((i) => i.message).join("; ") });
      return res.status(500).json({ error: (err as Error).message });
    }
  });
  // User-authored declarative importers (external plugin layer). GLOBAL, shared across cases — these
  // CRUD the registry of import shapes the analyst can add without code. Unconfigured ⇒ empty list /
  // 501 on writes. A save/delete/reload re-reads the on-disk registry (reloadImporters) so the in-
  // memory copy + the detection seam (resolveImportKind) stay current without the #1-gotcha restart.
  app.get("/importers", async (_req: Request, res: Response) => {
    if (!options.importerStore) return res.status(200).json({ importers: [], precedence: "builtin-first", errors: [] });
    return res.status(200).json({ importers: ctx.importerRegistry().meta, precedence: ctx.importerPrecedence(), errors: ctx.importerRegistry().errors });
  });

  app.get("/importers/prompt", (_req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "pipeline not configured" });
    return res.status(200).json({ prompt: getImporterPrompt() });
  });

  app.post("/importers", async (req: Request, res: Response) => {
    if (!options.importerStore) return res.status(501).json({ error: "custom importers not configured" });
    const body = req.body?.spec ?? req.body;
    const parsed = parseImporterSpec(body);
    if (!parsed.ok) return res.status(400).json({ error: "invalid importer", errors: parsed.errors });
    try {
      await options.importerStore.save(parsed.spec);
      await reloadImporters();
      return res.status(201).json({ id: parsed.spec.id });
    } catch (err) { return res.status(500).json({ error: (err as Error).message }); }
  });

  app.delete("/importers/:id", async (req: Request, res: Response) => {
    if (!options.importerStore) return res.status(501).json({ error: "custom importers not configured" });
    try {
      const removed = await options.importerStore.delete(req.params.id);
      if (!removed) return res.status(404).json({ error: "importer not found" });
      await reloadImporters();
      return res.status(200).json({ removed: true });
    } catch (err) { return res.status(500).json({ error: (err as Error).message }); }
  });

  app.post("/importers/reload", async (_req: Request, res: Response) => {
    if (!options.importerStore) return res.status(501).json({ error: "custom importers not configured" });
    try { await reloadImporters(); return res.status(200).json({ importers: ctx.importerRegistry().meta, errors: ctx.importerRegistry().errors }); }
    catch (err) { return res.status(500).json({ error: (err as Error).message }); }
  });

  app.put("/importers/precedence", async (req: Request, res: Response) => {
    if (!options.importerStore) return res.status(501).json({ error: "custom importers not configured" });
    const p = req.body?.precedence;
    if (p !== "builtin-first" && p !== "external-first") return res.status(400).json({ error: "precedence must be 'builtin-first' or 'external-first'" });
    try { await options.importerStore.setPrecedence(p); ctx.setImporterPrecedence(p); options.onImporters?.(); return res.status(200).json({ precedence: p }); }
    catch (err) { return res.status(500).json({ error: (err as Error).message }); }
  });
  // Background jobs (#225): list + inspect + cancel the heavy async operations (import / synthesis /
  // enrichment) tracked by the JobManager, so the dashboard can render a Jobs panel and stop a
  // long/stuck run. Read-only when no jobManager is wired (createApp-only unit tests) — empty list.
  app.get("/api/jobs", (req: Request, res: Response) => {
    const caseId = typeof req.query.caseId === "string" ? req.query.caseId : undefined;
    return res.status(200).json({ jobs: options.jobManager?.list(caseId) ?? [] });
  });
  app.get("/api/jobs/:id", (req: Request, res: Response) => {
    const job = options.jobManager?.get(req.params.id);
    if (!job) return res.status(404).json({ error: `unknown job: ${req.params.id}` });
    return res.status(200).json(job);
  });
  app.post("/api/jobs/:id/cancel", (req: Request, res: Response) => {
    if (!options.jobManager) return res.status(501).json({ error: "job manager not configured" });
    const result = options.jobManager.cancel(req.params.id);
    if (result.ok) return res.status(200).json(result.job);
    if (result.reason === "unknown") return res.status(404).json({ error: `unknown job: ${req.params.id}` });
    if (result.reason === "terminal") return res.status(409).json({ error: "job already finished" });
    return res.status(422).json({ error: "this job cannot be cancelled" });
  });

  // Per-case investigation activity log (#238): every security-relevant action taken on this
  // case, newest first. Filter by category; cap by limit (default 200, so a long-lived case
  // doesn't dump its entire history in one response).
  app.get("/cases/:id/activity-log", async (req: Request, res: Response) => {
    if (!options.activityLogStore) return res.status(501).json({ error: "activity log not configured" });
    const rawCategory = typeof req.query.category === "string" ? req.query.category : "";
    const category = (ACTIVITY_CATEGORIES as readonly string[]).includes(rawCategory) ? (rawCategory as ActivityCategory) : undefined;
    const rawLimit = Number(req.query.limit);
    const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(1000, Math.floor(rawLimit)) : 200;
    try {
      return res.status(200).json(await options.activityLogStore.load(req.params.id, { category, limit }));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
  // Settings: read/write the .env file so the dashboard can configure the companion.
  app.get("/settings/env", async (_req: Request, res: Response) => {
    try {
      const env = await getEnvForSettings();
      return res.json({ env });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/settings/env", async (req: Request, res: Response) => {
    try {
      const updates = req.body?.updates;
      if (!updates || typeof updates !== "object" || Array.isArray(updates)) {
        return res.status(400).json({ error: "updates must be an object" });
      }
      await updateEnvFile(updates as Record<string, string>);
      return res.json({ ok: true });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Apply the just-saved DFIR_AI_* values from .env into process.env WITHOUT a full restart, so the
  // first-run wizard (#181) can save → reload → POST /diagnostics/ai-test in one flow (buildProvider()
  // reads process.env live). This does NOT rebuild the analysis pipeline — /health.aiEnabled stays
  // false until a restart — it only lets the live connectivity probe see the new config. Mirrors the
  // IRIS/Velociraptor reconnect routes' reloadEnvPrefix pattern.
  app.post("/settings/ai-reload", async (_req: Request, res: Response) => {
    try {
      const applied = await reloadEnvPrefix("DFIR_AI_");
      return res.json({ ok: true, applied });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Generic counterpart of /settings/ai-reload for the comprehensive Setup wizard (#181): apply a
  // just-saved DFIR_<PREFIX>_* group from .env into process.env without a restart, so a "Save & test"
  // step sees the new config. ALLOWLISTED — the prefix must be a known integration group, so a request
  // can't reload arbitrary env (and the route never reads/returns secret VALUES, only the applied keys).
  const RELOADABLE_PREFIXES = new Set([
    "DFIR_AI_", "DFIR_IRIS_", "DFIR_VELOCIRAPTOR_", "DFIR_TIMESKETCH_", "DFIR_NOTION_", "DFIR_CLICKUP_",
    "DFIR_VT_", "DFIR_ABUSEIPDB_", "DFIR_HUNTINGCH_", "DFIR_MB_", "DFIR_CROWDSTRIKE_", "DFIR_SHODAN_",
    "DFIR_MISP_", "DFIR_YETI_", "DFIR_OPENCTI_", "DFIR_ROCKYRACCOON_", "DFIR_GEOIP_",
    "DFIR_LEAKCHECK_", "DFIR_HIBP_", "DFIR_DEHASHED_", "DFIR_PUSH_TOKEN", "DFIR_NSRL_", "DFIR_TOOL_",
  ]);
  app.post("/settings/reload", async (req: Request, res: Response) => {
    try {
      const prefix = typeof req.body?.prefix === "string" ? req.body.prefix.trim() : "";
      if (!prefix) return res.status(400).json({ error: "prefix is required" });
      if (!RELOADABLE_PREFIXES.has(prefix)) {
        return res.status(400).json({ error: `prefix not in the reloadable allowlist: ${prefix}` });
      }
      const applied = await reloadEnvPrefix(prefix);
      return res.json({ ok: true, applied });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Aggregate "is this integration configured?" status for the Setup wizard's progress (✓/○) — derived
  // live from process.env so it reflects values just saved+reloaded (no restart). Required-config groups
  // only: each entry is configured when its mandatory key(s) are present. No external calls, no secret
  // values — only booleans. (Per-feature deep status/connectivity lives in /iris/status etc.)
  app.get("/setup/status", (_req: Request, res: Response) => {
    const has = (k: string): boolean => !!(process.env[k] && process.env[k]!.trim());
    res.status(200).json({
      ai: !!hasAiProvider() || has("DFIR_AI_PROVIDER"),
      velociraptor: !!options.velociraptorClient || has("DFIR_VELOCIRAPTOR_API_CONFIG"),
      iris: !!ctx.irisClient() || (has("DFIR_IRIS_URL") && has("DFIR_IRIS_KEY")),
      timesketch: !!options.timesketchClient || (has("DFIR_TIMESKETCH_URL") && has("DFIR_TIMESKETCH_USER") && has("DFIR_TIMESKETCH_PASSWORD")),
      notion: !!options.notionClient || has("DFIR_NOTION_TOKEN"),
      clickup: !!options.clickupClient || has("DFIR_CLICKUP_TOKEN"),
      push: !!options.pushTokenStore || has("DFIR_PUSH_TOKEN"),
      notifications: !!options.notificationStore,
      enrichment: {
        virustotal: has("DFIR_VT_KEY"),
        abuseipdb: has("DFIR_ABUSEIPDB_KEY"),
        huntingch: has("DFIR_HUNTINGCH_KEY") || has("DFIR_MB_KEY"),
        crowdstrike: has("DFIR_CROWDSTRIKE_CLIENT_ID") && has("DFIR_CROWDSTRIKE_CLIENT_SECRET"),
        shodan: has("DFIR_SHODAN_KEY"),
        misp: has("DFIR_MISP_URL") && has("DFIR_MISP_KEY"),
        yeti: has("DFIR_YETI_URL") && has("DFIR_YETI_KEY"),
        opencti: has("DFIR_OPENCTI_URL") && has("DFIR_OPENCTI_KEY"),
        rockyraccoon: has("DFIR_ROCKYRACCOON_KEY"),
        geoip: has("DFIR_GEOIP_KEY"),
      },
      exposure: {
        leakcheck: has("DFIR_LEAKCHECK_KEY"),
        hibp: has("DFIR_HIBP_KEY"),
        dehashed: has("DFIR_DEHASHED_KEY"),
        shodan: has("DFIR_SHODAN_KEY"),
      },
      nsrl: has("DFIR_NSRL_DB") || has("DFIR_NSRL_FILE") || !!options.nsrlStore,
    });
  });
  // Redirect root to the dashboard.
  app.get("/", (_req, res) => {
    res.redirect("/dashboard");
  });

  // Serve the dashboard.
  app.get("/dashboard", async (_req, res) => {
    const html = await readPublicAsset("dashboard.html", "utf8");
    res.type("html").send(html);
  });

  // Mobile companion (#59): a read-only, phone-optimized view (timeline / findings / IOCs / status)
  // for quick glances during IR away from the workstation. It's a PWA — installable via the
  // web manifest + a minimal service worker (offline app-shell). All three are static files in
  // public/; the SW is served at root so its default control scope covers /mobile.
  app.get("/mobile", async (_req, res) => {
    const html = await readPublicAsset("mobile.html", "utf8");
    res.type("html").send(html);
  });

  app.get("/manifest.webmanifest", async (_req, res) => {
    try {
      const json = await readPublicAsset("manifest.webmanifest", "utf8");
      res.type("application/manifest+json").set("Cache-Control", "no-cache").send(json);
    } catch {
      res.status(404).end();
    }
  });

  app.get("/sw.js", async (_req, res) => {
    try {
      const js = await readPublicAsset("sw.js", "utf8");
      // no-cache + a same-origin allowed scope so the SW can control /mobile even if it's
      // ever moved into a subdirectory; browsers re-check sw.js on every navigation anyway.
      res.type("application/javascript").set("Cache-Control", "no-cache").set("Service-Worker-Allowed", "/").send(js);
    } catch {
      res.status(404).end();
    }
  });
}
