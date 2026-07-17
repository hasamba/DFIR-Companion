import type { Express, Request, Response } from "express";
import { join, basename } from "node:path";
import { open, readFile, mkdir, copyFile, stat } from "node:fs/promises";
import { parseCsv } from "../analysis/csvImport.js";
import { parseLogLines } from "../analysis/logImport.js";
import { parseThorReport } from "../analysis/thorImport.js";
import { parseSiemExport, type SiemImportOptions } from "../analysis/siemImport.js";
import { parseChainsawReport, type ChainsawImportOptions } from "../analysis/chainsawImport.js";
import { parseHayabusaTimeline, type HayabusaImportOptions } from "../analysis/hayabusaImport.js";
import { parseVelociraptorJson, type VelociraptorImportOptions } from "../analysis/velociraptorImport.js";
import { parseNetworkLogs, type NetworkImportOptions } from "../analysis/networkImport.js";
import { parseKapeCsv, type KapeImportOptions } from "../analysis/kapeImport.js";
import { parseCybertriage, type CybertriageImportOptions } from "../analysis/cybertriageImport.js";
import { parseM365Audit, type M365ImportOptions } from "../analysis/m365Import.js";
import { parseCloudTrail, type AwsImportOptions } from "../analysis/awsImport.js";
import { parseCloudActivity, type CloudActivityImportOptions } from "../analysis/cloudActivityImport.js";
import { parsePlasoCsv, type PlasoImportOptions } from "../analysis/plasoImport.js";
import { parseSandboxReport, type SandboxImportOptions } from "../analysis/sandboxImport.js";
import { parseMemory, type MemoryImportOptions } from "../analysis/memoryImport.js";
import { parseEmail, type EmailImportOptions } from "../analysis/emailImport.js";
import { parseTheHive } from "../analysis/theHiveImport.js";
import { parseAuditdLog, type AuditdImportOptions } from "../analysis/auditdImport.js";
import { parseJournald, type JournaldImportOptions } from "../analysis/journaldImport.js";
import { parseSysdig, type SysdigImportOptions } from "../analysis/sysdigImport.js";
import { parseWazuhAlerts, type WazuhImportOptions } from "../analysis/wazuhImport.js";
import { parseMinSeverity } from "../analysis/severityFloor.js";
import { diffTimeline, addedForensicEvents } from "../analysis/timelineDiff.js";
import { autoTagNewEvents } from "../analysis/taggerAuto.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import { FalsePositiveStore } from "../analysis/falsePositive.js";
import { matchFpPropagation } from "../analysis/fpPropagation.js";
import { diffIocs } from "../analysis/iocsDiff.js";
import { logActivity } from "../analysis/activityLog.js";
import { formatDropLogLines, appendDropLog, type DropLogEntry } from "../analysis/dropLog.js";
import { toolForExtension, suggestedToolForExtension, type ToolConfig } from "../integrations/tools/toolConfig.js";
import { summarizeUndoStack, applyUndo, applyRedo } from "../analysis/importUndo.js";
import type { Severity, InvestigationState } from "../analysis/stateTypes.js";
import type { PendingRawInput } from "../analysis/dropStatus.js";
import type { RouteContext } from "./context.js";

/**
 * Evidence import domain: the unified POST /cases/:id/import + POST /cases/:id/import-file entry
 * points, every per-format POST /cases/:id/import-<kind> route (THOR / SIEM / Chainsaw / Hayabusa /
 * Velociraptor JSON / network / KAPE / Cyber Triage / M365 / AWS / cloud-activity / Plaso / sandbox /
 * memory / email / TheHive / auditd / journald / sysdig / Wazuh / CSV / log), the GET
 * /cases/:id/import-meta banner, the #76 import undo/redo routes, and the evidence drop-folder
 * routes (POST /cases/:id/drop/run-pending batch tool run + GET /cases/:id/drop-status).
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). The heavy import
 * machinery itself stays in createApp — the drop-folder auto-import poller (scanCaseDrops) also drives
 * it, and the Velociraptor bundle collector reuses the same dispatch/synthesis chain — so this module
 * reaches it through the RouteContext members those helpers were graduated onto:
 *   dispatchImport, demoteForensicForCase, resynthesizeInBackground, pushImportCheckpoint,
 *   applyWhitelistToCase, applyNsrlToCase, applyDeobfuscationToCase, moveDropFile (stable methods),
 *   and the drop-watcher state maps dropSeen / dropScanning / dropPendingLogged (live accessors —
 *   the poller mutates the SAME maps, so they must be read live, never captured at registration).
 * Pre-existing ctx members reused: store, options, serverLogger, recordImportFailure, recordAiError,
 * getControl, runToolAndIngest, resolveImportKind + liveToolConfigs + customTools +
 * dropWatchEnabled (live accessors). (The AI CSV/log gates ask the pipeline directly via
 * options.pipeline.hasSynthesisProvider() — text work runs on the synthesis provider, so the
 * vision-only ctx.hasAiProvider would wrongly 501 an OCR-less install.)
 */
export function registerImportRoutes(app: Express, ctx: RouteContext): void {
  const {
    store, options, recordImportFailure, recordAiError, getControl,
    runToolAndIngest, pushImportCheckpoint, moveDropFile,
    dispatchImport, demoteForensicForCase, resynthesizeInBackground,
    applyWhitelistToCase, applyNsrlToCase, applyDeobfuscationToCase,
  } = ctx;

  // Automatic content-based tagger fired right after each import's super-timeline append (see
  // analysis/taggerAuto.ts): tag just the newly-imported events. Best-effort + gated on TAGGER_AUTO.
  const autoTagImported = (caseId: string, added: ForensicEvent[]): Promise<void> =>
    autoTagNewEvents(
      { taggerStore: options.taggerStore, tagsStore: options.tagsStore, stateStore: options.stateStore, onTags: options.onTags, onState: options.onState, logLine: (m) => ctx.serverLogger.info(m) },
      caseId, added,
    );

  // Poll interval reported by GET /drop-status. Reconstructed from the same env expression createApp
  // uses (DFIR_DROP_POLL_S, clamped 2..600s) — deterministic, so it matches the watcher's value.
  const dropPollMs = Math.min(600, Math.max(2, Number(process.env.DFIR_DROP_POLL_S) || 10)) * 1000;
  const dropDirOf = (caseId: string): string => join(store.caseDir(caseId), "drop");
  // Resolve which CONFIGURED tool handles a file extension: built-in preference first (via TOOL_DEFS),
  // then a custom tool that claims the extension. Rebuilt here (the createApp original read its closure
  // `customTools`); the live custom-tool list comes from ctx.
  const resolveToolForExt = (ext: string, configured: Map<string, ToolConfig>): string | null => {
    const builtin = toolForExtension(ext, configured);
    if (builtin) return builtin;
    const e = ext.toLowerCase();
    const custom = ctx.customTools().find((t) => configured.has(t.id) && t.extensions.some((x) => x.toLowerCase() === e));
    return custom ? custom.id : null;
  };
  // #76: restore a full investigation state from an undo/redo checkpoint, verbatim — findings, IOCs,
  // timeline, MITRE, attacker path, the lot (no AI re-synthesis; the snapshot already holds the exact
  // prior conclusions). Keeps the case id, stamps updatedAt. Returns the saved state so the caller
  // can broadcast it (null when no state store is wired — routes gate on this).
  async function restoreImportState(caseId: string, snapState: InvestigationState): Promise<InvestigationState | null> {
    if (!options.stateStore) return null;
    const next: InvestigationState = { ...snapState, caseId, updatedAt: new Date().toISOString() };
    await options.stateStore.save(next);
    return next;
  }

  // Batch-run EVERY pending raw drop file through its matching tool — the "Run tools on these N files"
  // button on the drop banner (ONE confirmation for the whole batch). Each ran/failed file is moved out
  // of drop/ (to _processed/_failed); files with no configured tool stay pending. Updates the drop
  // status so the banner reflects what's left. 501 tools/drop off. #211
  app.post("/cases/:id/drop/run-pending", async (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!options.toolRunner) return res.status(501).json({ error: "external tools not configured" });
    if (!options.dropStatusStore) return res.status(501).json({ error: "drop folder not enabled" });
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: `case ${caseId} does not exist` });
    // Serialize against the poller's scanCaseDrops sweep for this case: both are writers of
    // dropPendingLogged, and this route awaits per-file tool runs, so an overlapping sweep could
    // read a stale dropPendingLogged snapshot and clobber this route's deletes / emit a stray
    // PENDING line for a file this route just resolved.
    if (ctx.dropScanning().has(caseId)) return res.status(409).json({ error: "a drop sweep is in progress for this case, try again shortly" });
    ctx.dropScanning().add(caseId);
    try {
      const pending = (await options.dropStatusStore.load(caseId)).pendingRawInputs ?? [];
      const configured = ctx.liveToolConfigs()();
      const dropDir = dropDirOf(caseId);
      // ONE undo checkpoint for the whole "Run all" batch (the user clicked once): snapshot before, then
      // push a single checkpoint after if anything imported — so undo reverts the batch in one step.
      let before: InvestigationState | null = null;
      if (options.stateStore) { try { before = await options.stateStore.load(caseId); } catch { /* keep null */ } }
      let ran = 0, failed = 0, skipped = 0;
      const stillPending: PendingRawInput[] = [];
      const resolvedEntries: DropLogEntry[] = [];
      for (const p of pending) {
        const toolId = resolveToolForExt(p.ext, configured);
        if (!toolId) { skipped++; stillPending.push({ ...p, configured: false, suggestedTool: suggestedToolForExtension(p.ext) }); continue; }
        try {
          await runToolAndIngest(caseId, toolId, join(dropDir, p.relpath));
          await moveDropFile(dropDir, p.relpath, true).catch(() => { /* best-effort */ });
          resolvedEntries.push({ status: "IMPORTED", relpath: p.relpath, reason: `via ${toolId} (tool run)` });
          ran++;
        } catch (err) {
          failed++;
          recordImportFailure(caseId, "drop-tool", p.relpath, err);
          resolvedEntries.push({ status: "FAILED", relpath: p.relpath, reason: (err as Error)?.message ?? String(err) });
          await moveDropFile(dropDir, p.relpath, false).catch(() => { /* best-effort */ });
        }
        ctx.dropSeen().get(caseId)?.delete(p.relpath);   // moved out of the watched area — forget it
        ctx.dropPendingLogged().get(caseId)?.delete(p.relpath); // resolved — no longer pending
      }
      if (before && ran > 0) {
        const s = await options.stateStore?.load(caseId).catch(() => null);
        if (!s || s.forensicTimeline.length !== before.forensicTimeline.length || s.iocs.length !== before.iocs.length) {
          await pushImportCheckpoint(caseId, before, `Tools: drop batch (${ran} file${ran !== 1 ? "s" : ""})`);
        }
      }
      if (resolvedEntries.length > 0) {
        await appendDropLog(dropDir, formatDropLogLines(resolvedEntries, new Date().toISOString()))
          .catch((e) => ctx.serverLogger.info(`[drop] log append failed: ${(e as Error).message}`));
      }
      await options.dropStatusStore.record(caseId, { dropPath: dropDir, imported: [], failed: [], pendingRawInputs: stillPending });
      options.onDropStatus?.(caseId);
      return res.status(200).json({ ok: true, ran, failed, skipped });
    } finally {
      ctx.dropScanning().delete(caseId);
    }
  });

  // Unified import: ONE endpoint the dashboard's single "Import" button posts any data file to.
  // The server SNIFFS the file (filename + content) — JSON/NDJSON vs CSV vs log, then per-format
  // signatures — and dispatches to the matching importer (deterministic ones, or the AI CSV/log
  // path). Evidence-first: the raw file is persisted + audit-logged before analysis. The detected
  // `kind` is returned so a mis-route is visible. (The per-format routes below remain for
  // programmatic use.)
  app.post("/cases/:id/import", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (caseMeta?.status === "closed" || caseMeta?.status === "archived") {
      const action = caseMeta.status === "archived" ? "restore it" : "reopen it";
      return res.status(423).json({ error: `Case "${caseId}" is ${caseMeta.status} — ${action} before importing evidence` });
    }
    // Evidence-first parity with POST /captures + GET /state: never silently accept evidence for a
    // case that doesn't exist. "Connect" attaches without creating, so a typo'd / never-created case
    // id would otherwise 202-"accept" the import and orphan it on disk (no case meta, invisible in the
    // case list) — silent loss of forensic evidence. Fail loud so the analyst creates the case first.
    if (!(await store.caseExists(caseId))) {
      return res.status(404).json({ error: `case ${caseId} does not exist — create it in the dashboard first` });
    }
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json
      : typeof req.body?.csv === "string" ? req.body.csv : "";
    const originalName = String(req.body?.filename ?? "import.dat");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const kind = ctx.resolveImportKind()(originalName, text);
    if (kind === "unknown") {
      return res.status(400).json({ error: "could not detect the file type — not recognized as any supported import (THOR / SIEM-EDR / Chainsaw-EVTX / Hayabusa / Velociraptor / Suricata-Zeek / KAPE / Cyber Triage / M365-Entra / AWS / GCP-Azure / Plaso / Sandbox / Volatility-Rekall memory / Email-eml-msg / auditd / journald / sysdig-Falco / syslog / CSV / log)" });
    }
    if ((kind === "csv" || kind === "log") && !options.pipeline?.hasSynthesisProvider()) {
      return res.status(501).json({ error: "AI provider not configured for CSV/log analysis" });
    }

    // Cross-case signal: tell every dashboard an artifact import landed for THIS case, so one viewing
    // a different case warns "artifacts are arriving for another case" — parity with screenshots. The
    // extension's "Push to DFIR-Companion" hits this route, so this covers the extension-drift trap.
    options.onImport?.(caseId);

    // Optional minimum-severity floor (the old per-format "which minimum severity?" prompt,
    // restored for the single Import button). Gate-aware: imports that don't grade severity
    // (all-Info telemetry like KAPE/Plaso) are kept whole — see applySeverityFloor. A missing
    // / unrecognized value imports everything.
    const minSeverity = parseMinSeverity(req.body?.minSeverity);

    try {
      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.dat");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: 0, bytes: Buffer.byteLength(text, "utf8"),
      });

      // CSV/log imports are themselves an LLM call (free-form data the model must interpret), so
      // they respect the per-case AI toggle exactly like screenshot analysis + synthesis: with AI
      // OFF, the evidence is saved (above) but NOT sent to the model. Deterministic imports have no
      // LLM call, so they proceed and populate the timeline + IOCs regardless (synthesis still waits
      // for AI — see resynthesizeInBackground). This keeps "AI off" meaning no LLM call / nothing
      // leaves for the model, and stops the dashboard from claiming the AI is analyzing while off.
      const aiDependent = kind === "csv" || kind === "log";
      if (aiDependent && !(await getControl(caseId)).enabled) {
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `AI is off — ${kind.toUpperCase()} saved as evidence but not analyzed (turn AI on, then re-import)` });
        return res.status(202).json({ accepted: true, kind, file: storedName, minSeverity, analyzed: false, reason: "ai-off" });
      }

      res.status(202).json({ accepted: true, kind, file: storedName, minSeverity });

      const pipeline = options.pipeline;
      // #225: track the import as a job. Only AI imports (CSV/log — an LLM call) are cancellable;
      // deterministic imports parse synchronously and finish before a cancel could arrive.
      const job = options.jobManager?.register({ caseId, kind: "import", label: `${kind}: ${storedName}`, cancellable: aiDependent });
      const onProgress = (done: number, total: number): void => {
        options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `${kind} import — ${done}/${total}`,
        });
        if (job) options.jobManager?.progress(job.jobId, done, total, `${kind} import`);
      };
      const base = { label: storedName, idPrefix: `${seq}`, importedAt, onProgress, minSeverity, ...(job?.signal ? { signal: job.signal } : {}) };
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing (${kind})${minSeverity ? ` — min severity ${minSeverity}` : ""}` });

      const run = (): Promise<unknown> => dispatchImport(kind, caseId, text, base);

      // Snapshot the FULL investigation state BEFORE the import so the .then() below can (a) diff what
      // this import added (the "last import" banner) and (b) push a pre-import undo checkpoint (#76 —
      // the whole state, so undo also takes back the findings/MITRE the post-import synthesis derives).
      let stateBefore: InvestigationState | null = null;
      if (options.stateStore) {
        try { stateBefore = await options.stateStore.load(caseId); } catch { /* keep null */ }
      }

      run()
        .then(async () => {
          if (job) options.jobManager?.finish(job.jobId); // no-op if a cancel already marked it cancelled
          options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
          // Record what this import added to the forensic timeline + IOCs, BEFORE resynthesis (which
          // preserves both). Best-effort: a meta failure must not break the import.
          if (options.stateStore && stateBefore) {
            try {
              const imported = await options.stateStore.load(caseId);
              // Dual-write the newly-imported events into the super-timeline FIRST (superset of everything
              // imported, Info telemetry included); resolve the FULL events from the imported (pre-demote)
              // state since the diff is lossy.
              if (options.superTimelineStore) {
                const superDiff = diffTimeline(stateBefore.forensicTimeline, imported.forensicTimeline);
                const added = addedForensicEvents(imported.forensicTimeline, superDiff);
                if (added.length) { try { await options.superTimelineStore.append(caseId, added); options.onSuperTimeline?.(caseId); } catch { /* non-fatal */ } await autoTagImported(caseId, added); }
              }
              // Demote sub-threshold events out of forensic (kept in super), then compute the import-meta
              // diff + checkpoint decision on the POST-demote state so "+N events" counts only graded signal.
              const s = await demoteForensicForCase(caseId);
              const tDiff = diffTimeline(stateBefore.forensicTimeline, s.forensicTimeline);
              const iDiff = diffIocs(stateBefore.iocs, s.iocs);
              // Proactive FP-pattern propagation (#15b): does this import re-arrive with events matching a
              // known false-positive pattern? Match the NEW forensic events against the FP markers'
              // fingerprints and surface a one-click bulk-mark suggestion on the banner (never auto-mark).
              let fpPropagation: Awaited<ReturnType<typeof matchFpPropagation>> = [];
              try {
                const beforeIds = new Set(stateBefore.forensicTimeline.map((e) => e.id));
                const newEvents = s.forensicTimeline.filter((e) => !beforeIds.has(e.id));
                if (newEvents.length) {
                  const markers = await new FalsePositiveStore(store).load(caseId);
                  fpPropagation = matchFpPropagation(newEvents, markers);
                }
              } catch { /* non-fatal — propagation is a suggestion, never blocks the import */ }
              if (options.importMetaStore) {
                // Cap-hit truncation (#10 trigger b): consume the log-aggregation truncation the import
                // method stashed (log path only; null otherwise) and stamp it onto import-meta.
                const truncation = options.pipeline?.consumeImportTruncation?.(caseId) ?? null;
                await options.importMetaStore.record(caseId, { kind, file: storedName, diff: tDiff, iocsDiff: iDiff, linesIn: text.split(/\r?\n/).length, path: aiDependent ? "ai" : "deterministic", fpPropagation, truncation });
                options.onImportMeta?.(caseId);
              }
              logActivity(options.activityLogStore, options.onActivity, caseId, {
                category: "import", action: "import",
                detail: `${kind} (${storedName}) — +${tDiff.added.length} event(s), +${iDiff.added.length} IOC(s)`,
              });
              // #76: snapshot the pre-import state for undo — but only when the import actually changed
              // something (skip a no-op re-import so undo doesn't pile up dead levels).
              if (tDiff.added.length || tDiff.removed.length || iDiff.added.length || iDiff.removed.length) {
                await pushImportCheckpoint(caseId, stateBefore, `${kind} (${storedName})`);
              }
            } catch { /* non-fatal */ }
          }
          // Phase 2 (#35): auto-mark IOCs that match the global whitelist as legitimate BEFORE
          // re-synthesis, so known-good indicators drop out of the analysis. Best-effort.
          try {
            const wl = await applyWhitelistToCase(caseId);
            if (wl.added > 0) ctx.serverLogger.info(`[whitelist] ${caseId} auto-marked ${wl.added} imported IOC(s) legitimate`);
          } catch { /* non-fatal */ }
          // #63: auto-mark imported events/IOCs whose hash is in the global NSRL set (known-good
          // files) legitimate, also BEFORE re-synthesis, to reduce false positives. Best-effort.
          try {
            const ns = await applyNsrlToCase(caseId);
            if (ns.added > 0) ctx.serverLogger.info(`[nsrl] ${caseId} auto-marked ${ns.added} imported known-good item(s) legitimate`);
          } catch { /* non-fatal */ }
          // #97: decode obfuscated command lines (PowerShell -enc, base64) and extract hidden IOCs.
          try {
            const deob = await applyDeobfuscationToCase(caseId);
            if (deob.deobfuscated > 0) ctx.serverLogger.info(`[deobfuscate] ${caseId} decoded ${deob.deobfuscated} event(s), +${deob.newIocs} new IOC(s)`);
          } catch { /* non-fatal */ }
          resynthesizeInBackground(caseId);
        })
        .catch((err) => { if (job) options.jobManager?.fail(job.jobId, err); recordImportFailure(caseId, kind, storedName, err); recordAiError(caseId, "import", err); options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }); });
      return;
    } catch (err) {
      recordImportFailure(caseId, kind, originalName, err);
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a large file from the server's local filesystem by path — bypasses the browser
  // FileReader memory limit for files too large to upload through the dashboard (400 MB+).
  // Same pipeline as /import: detect kind → persist evidence → dispatchImport → diff → resynth.
  // Localhost-only tool: reading an operator-specified path is intentional (same trust level
  // as DFIR_NSRL_FILE / KEV import-file). Body: { path, minSeverity? }.
  app.post("/cases/:id/import-file", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (caseMeta?.status === "closed" || caseMeta?.status === "archived") {
      const action = caseMeta.status === "archived" ? "restore it" : "reopen it";
      return res.status(423).json({ error: `Case "${caseId}" is ${caseMeta.status} — ${action} before importing evidence` });
    }
    // Same evidence-first guard as POST /import + /captures + /state: never ingest into a case that
    // doesn't exist (it would write an orphaned, case-meta-less import on disk).
    if (!(await store.caseExists(caseId))) {
      return res.status(404).json({ error: `case ${caseId} does not exist — create it in the dashboard first` });
    }
    const filePath = typeof req.body?.path === "string" ? req.body.path.trim() : "";
    if (!filePath) return res.status(400).json({ error: "path is required (absolute path to a file on the server)" });
    const minSeverity = parseMinSeverity(req.body?.minSeverity);

    // Detect the import kind from a bounded HEAD sample — never read the whole file just to sniff
    // it. A Plaso super-timeline can exceed V8's ~512 MB max string length (readFile(utf8) throws
    // "Invalid string length"), so a sample-based sniff is the only way to even classify it.
    let sample: string;
    try {
      const fh = await open(filePath, "r");
      try {
        const buf = Buffer.alloc(1 << 18); // 256 KB — plenty for the header + many rows
        const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
        sample = buf.subarray(0, bytesRead).toString("utf8");
      } finally { await fh.close(); }
    } catch (err) {
      return res.status(400).json({ error: `cannot read file: ${(err as Error).message}` });
    }
    if (!sample.trim()) return res.status(400).json({ error: "file is empty" });

    const originalName = basename(filePath);
    const kind = ctx.resolveImportKind()(originalName, sample);
    if (kind === "unknown") {
      return res.status(400).json({ error: "could not detect the file type — not recognized as any supported import format" });
    }
    if ((kind === "csv" || kind === "log") && !options.pipeline?.hasSynthesisProvider()) {
      return res.status(501).json({ error: "AI provider not configured for CSV/log analysis" });
    }

    // Plaso streams from disk line-by-line (handles 500 MB+ super-timelines that can't be held as a
    // string at all); every other kind is read into one string and dispatched as usual. A non-Plaso
    // file too big to string-decode fails with a clear, actionable error instead of an OOM crash.
    const streaming = kind === "plaso";
    let text = "";
    if (!streaming) {
      try {
        text = await readFile(filePath, "utf8");
      } catch (err) {
        const m = (err as Error).message;
        if (/Invalid string length/i.test(m)) {
          return res.status(413).json({ error: `file is too large to import as ${kind} (exceeds the ~512 MB in-memory limit); only Plaso super-timelines support streaming import — split or convert the file` });
        }
        return res.status(400).json({ error: `cannot read file: ${m}` });
      }
      if (!text.trim()) return res.status(400).json({ error: "file is empty" });
    }

    options.onImport?.(caseId);

    try {
      const seq = await store.nextImportSeq(caseId);
      const safeName = originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.dat";
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      // Evidence-first: copy the raw file into the case's imports dir (by bytes, so a >512 MB file we
      // never string-decode is still persisted faithfully) and append the audit line.
      await mkdir(store.importsDir(caseId), { recursive: true });
      await copyFile(filePath, join(store.importsDir(caseId), storedName));
      const { size } = await stat(filePath);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: 0, bytes: size,
      });

      const aiDependent = kind === "csv" || kind === "log";
      if (aiDependent && !(await getControl(caseId)).enabled) {
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `AI is off — ${kind.toUpperCase()} saved as evidence but not analyzed (turn AI on, then re-import)` });
        return res.status(202).json({ accepted: true, kind, file: storedName, minSeverity, analyzed: false, reason: "ai-off" });
      }

      res.status(202).json({ accepted: true, kind, file: storedName, minSeverity });

      const pipeline = options.pipeline;
      // #225: track the local-path import as a job (this is the large-file path, so a cancel matters
      // most here). Only AI imports (CSV/log) are cancellable; deterministic parses finish quickly.
      const job = options.jobManager?.register({ caseId, kind: "import", label: `${kind}: ${storedName}`, cancellable: aiDependent });
      const onProgress = (done: number, total: number): void => {
        options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `${kind} import — ${done}/${total}`,
        });
        if (job) options.jobManager?.progress(job.jobId, done, total, `${kind} import`);
      };
      const base = { label: storedName, idPrefix: `${seq}`, importedAt, onProgress, minSeverity, ...(job?.signal ? { signal: job.signal } : {}) };
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing (${kind}) from path${minSeverity ? ` — min severity ${minSeverity}` : ""}` });

      let stateBefore: InvestigationState | null = null;
      if (options.stateStore) {
        try { stateBefore = await options.stateStore.load(caseId); } catch { /* keep null */ }
      }

      // Plaso streams from disk; everything else dispatches the in-memory string.
      const run = (): Promise<unknown> =>
        streaming ? pipeline.importPlasoFile(caseId, filePath, base) : dispatchImport(kind, caseId, text, base);

      run()
        .then(async () => {
          if (job) options.jobManager?.finish(job.jobId); // no-op if a cancel already marked it cancelled
          options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
          if (options.stateStore && stateBefore) {
            try {
              const imported = await options.stateStore.load(caseId);
              // Dual-write into the super-timeline FIRST (superset, Info telemetry included); resolve the
              // FULL events from the imported (pre-demote) state since the diff is lossy.
              if (options.superTimelineStore) {
                const superDiff = diffTimeline(stateBefore.forensicTimeline, imported.forensicTimeline);
                const added = addedForensicEvents(imported.forensicTimeline, superDiff);
                if (added.length) { try { await options.superTimelineStore.append(caseId, added); options.onSuperTimeline?.(caseId); } catch { /* non-fatal */ } await autoTagImported(caseId, added); }
              }
              // Demote sub-threshold events out of forensic (kept in super), then compute the import-meta
              // diff + checkpoint decision on the POST-demote state so "+N events" counts only graded signal.
              const s = await demoteForensicForCase(caseId);
              const tDiff = diffTimeline(stateBefore.forensicTimeline, s.forensicTimeline);
              const iDiff = diffIocs(stateBefore.iocs, s.iocs);
              // Proactive FP-pattern propagation (#15b): does this import re-arrive with events matching a
              // known false-positive pattern? Match the NEW forensic events against the FP markers'
              // fingerprints and surface a one-click bulk-mark suggestion on the banner (never auto-mark).
              let fpPropagation: Awaited<ReturnType<typeof matchFpPropagation>> = [];
              try {
                const beforeIds = new Set(stateBefore.forensicTimeline.map((e) => e.id));
                const newEvents = s.forensicTimeline.filter((e) => !beforeIds.has(e.id));
                if (newEvents.length) {
                  const markers = await new FalsePositiveStore(store).load(caseId);
                  fpPropagation = matchFpPropagation(newEvents, markers);
                }
              } catch { /* non-fatal — propagation is a suggestion, never blocks the import */ }
              if (options.importMetaStore) {
                // Cap-hit truncation (#10 trigger b): consume the log-aggregation truncation the import
                // method stashed (log path only; null otherwise) and stamp it onto import-meta.
                const truncation = options.pipeline?.consumeImportTruncation?.(caseId) ?? null;
                await options.importMetaStore.record(caseId, { kind, file: storedName, diff: tDiff, iocsDiff: iDiff, linesIn: text.split(/\r?\n/).length, path: aiDependent ? "ai" : "deterministic", fpPropagation, truncation });
                options.onImportMeta?.(caseId);
              }
              if (tDiff.added.length || tDiff.removed.length || iDiff.added.length || iDiff.removed.length) {
                await pushImportCheckpoint(caseId, stateBefore, `${kind} (${storedName})`);
              }
            } catch { /* non-fatal */ }
          }
          try {
            const wl = await applyWhitelistToCase(caseId);
            if (wl.added > 0) ctx.serverLogger.info(`[whitelist] ${caseId} auto-marked ${wl.added} imported IOC(s) legitimate`);
          } catch { /* non-fatal */ }
          try {
            const ns = await applyNsrlToCase(caseId);
            if (ns.added > 0) ctx.serverLogger.info(`[nsrl] ${caseId} auto-marked ${ns.added} imported known-good item(s) legitimate`);
          } catch { /* non-fatal */ }
          try {
            const deob = await applyDeobfuscationToCase(caseId);
            if (deob.deobfuscated > 0) ctx.serverLogger.info(`[deobfuscate] ${caseId} decoded ${deob.deobfuscated} event(s), +${deob.newIocs} new IOC(s)`);
          } catch { /* non-fatal */ }
          resynthesizeInBackground(caseId);
        })
        .catch((err) => { if (job) options.jobManager?.fail(job.jobId, err); recordImportFailure(caseId, kind, storedName, err); recordAiError(caseId, "import", err); options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }); });
      return;
    } catch (err) {
      recordImportFailure(caseId, kind, originalName, err);
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a CSV result export (e.g. a Velociraptor artifact) as evidence and analyze
  // it like captured screenshots: extract dated forensic events + IOCs into the
  // timeline, then synthesize findings/TTPs/attacker-path. Evidence-first: the raw
  // CSV is persisted + audit-logged BEFORE any analysis; analysis runs in background.
  app.post("/cases/:id/import-csv", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.pipeline.hasSynthesisProvider()) return res.status(501).json({ error: "AI provider not configured for CSV analysis" });
    const caseId = req.params.id;
    const csv = typeof req.body?.csv === "string" ? req.body.csv : "";
    const originalName = String(req.body?.filename ?? "import.csv");
    if (!csv.trim()) return res.status(400).json({ error: "csv is required" });

    try {
      const { rows } = parseCsv(csv);
      if (rows.length === 0) return res.status(400).json({ error: "CSV has no data rows" });

      // Evidence-first: persist the raw CSV + append the audit line before analysis.
      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.csv");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, csv);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: rows.length, bytes: Buffer.byteLength(csv, "utf8"),
      });

      // Acknowledge immediately; the dashboard watches AI status + state over the WS.
      res.status(202).json({ accepted: true, file: storedName, rows: rows.length });

      // Background: extract events from the rows, then synthesize conclusions.
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${rows.length} CSV row(s)` });
      void options.pipeline.analyzeCsv(caseId, csv, {
        label: storedName,
        idPrefix: `m${seq}`,
        importedAt,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `CSV import — batch ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a generic log file (firewall, syslog, sshd, IIS/Apache/nginx access,
  // application logs — anything line-oriented, typically .log or .txt) as evidence.
  // Same evidence-first pattern as import-csv: persist + audit, then analyze in the
  // background (line-batched). The CSV path stays specialized for tabular exports.
  app.post("/cases/:id/import-log", async (req: Request, res: Response) => {
    if (!options.pipeline || !options.pipeline.hasSynthesisProvider()) return res.status(501).json({ error: "AI provider not configured for log analysis" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    const originalName = String(req.body?.filename ?? "import.log");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    try {
      // Validate and split lines up-front so we can reject empty files with a 400
      // (mirrors the CSV "no rows" check) — and so we report line count back to the UI.
      const { lines } = parseLogLines(text);
      if (lines.length === 0) return res.status(400).json({ error: "log file has no non-empty lines" });

      const seq = await store.nextImportSeq(caseId);
      // Preserve the original extension (.log / .txt / etc.) so it round-trips through
      // the evidence endpoint with the right content-type.
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.log");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: lines.length, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, lines: lines.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${lines.length} log line(s)` });
      void options.pipeline.analyzeLog(caseId, text, {
        label: storedName,
        idPrefix: `l${seq}`,
        importedAt,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `log import — batch ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a THOR (Nextron) scanner report (JSON-Lines from `thor --jsonfile`).
  // Evidence-first like the CSV/log paths; mapping is DETERMINISTIC (no AI extraction),
  // dropping scan-lifecycle/info noise. Synthesis (findings/attacker path) runs after.
  app.post("/cases/:id/import-thor", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const json = typeof req.body?.json === "string" ? req.body.json
      : typeof req.body?.text === "string" ? req.body.text : "";
    const originalName = String(req.body?.filename ?? "thor.json");
    if (!json.trim()) return res.status(400).json({ error: "json is required" });

    // Optional severity floor: keep only Alert / Alert+Warning / Alert+Warning+Notice.
    const rawLevel = String(req.body?.minLevel ?? "").trim().toLowerCase();
    const minLevel = rawLevel === "alert" ? "Alert" : rawLevel === "warning" ? "Warning" : rawLevel === "notice" ? "Notice" : undefined;
    const thorOpts = minLevel ? { minLevel } as const : undefined;

    try {
      // Parse up-front: reject a file with no real findings (only info/lifecycle rows),
      // and report kept/dropped counts back to the UI.
      const preview = parseThorReport(json, thorOpts);
      if (preview.total === 0) return res.status(400).json({ error: "no parseable THOR JSON lines" });
      if (preview.kept === 0) {
        return res.status(400).json({ error: `THOR report has no findings after dropping ${preview.dropped} info/lifecycle row(s)` });
      }

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "thor.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, json);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(json, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, findings: preview.kept, dropped: preview.dropped, total: preview.total });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} THOR finding(s)` });
      void options.pipeline.importThor(caseId, json, {
        label: storedName,
        idPrefix: `t${seq}`,
        importedAt,
        thor: thorOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `THOR import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a SIEM / EDR JSON export — the second JSON ingest path besides THOR, for
  // exports from Elastic/Kibana, Splunk, an EDR console, or a raw winlogbeat dump.
  // Evidence-first like the other imports; mapping is DETERMINISTIC (no AI extraction):
  // the container is unwrapped, Windows/Sysmon events get a per-EID mapping (others use
  // field auto-detection), and repetitive events aggregate. Synthesis runs after.
  app.post("/cases/:id/import-siem", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const json = typeof req.body?.json === "string" ? req.body.json
      : typeof req.body?.text === "string" ? req.body.text : "";
    const originalName = String(req.body?.filename ?? "siem.json");
    if (!json.trim()) return res.status(400).json({ error: "json is required" });

    // Optional severity floor: keep only events at/above this level (e.g. "low" drops
    // Info noise like logoffs / process-terminated). Default = keep everything.
    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const siemOpts: SiemImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      // Parse up-front: reject a file with no parseable records, and report counts to the UI.
      const preview = parseSiemExport(json, siemOpts);
      if (preview.total === 0) return res.status(400).json({ error: "no parseable SIEM/EDR records found (expected a JSON array, an Elastic/Kibana export, or NDJSON)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events after the '${rawLevel}' severity floor (${preview.total} record(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "siem.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, json);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(json, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} SIEM event(s)` });
      void options.pipeline.importSiem(caseId, json, {
        label: storedName,
        idPrefix: `s${seq}`,
        importedAt,
        siem: siemOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `SIEM import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import Chainsaw (WithSecure) hunt output or a raw EVTX-as-JSON dump — the third JSON
  // ingest path, and the richest for Windows IR. Evidence-first like the other imports;
  // mapping is DETERMINISTIC (no AI extraction): embedded EVTX events get the per-EID
  // Windows mapping and, for Chainsaw, the matched Sigma rule's level/tags drive
  // severity/MITRE. Synthesis runs after.
  app.post("/cases/:id/import-chainsaw", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const json = typeof req.body?.json === "string" ? req.body.json
      : typeof req.body?.text === "string" ? req.body.text : "";
    const originalName = String(req.body?.filename ?? "chainsaw.json");
    if (!json.trim()) return res.status(400).json({ error: "json is required" });

    // Optional severity floor (e.g. "medium" drops Low/Info detections and noise events).
    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const chainsawOpts: ChainsawImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      // Parse up-front: reject a file with no parseable records, and report counts to the UI.
      const preview = parseChainsawReport(json, chainsawOpts);
      if (preview.total === 0) return res.status(400).json({ error: "no parseable Chainsaw/EVTX records found (expected Chainsaw hunt JSON, or evtx_dump JSON/NDJSON)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events after the '${rawLevel}' severity floor (${preview.total} record(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "chainsaw.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, json);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(json, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, detections: preview.detections, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      const kind = preview.detections > 0 ? "Chainsaw" : "EVTX";
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} ${kind} event(s)` });
      void options.pipeline.importChainsaw(caseId, json, {
        label: storedName,
        idPrefix: `c${seq}`,
        importedAt,
        chainsaw: chainsawOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `${kind} import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a Hayabusa (Yamato Security) detection timeline — JSON/JSONL or CSV. Sister of
  // the Chainsaw path; evidence-first, mapping is DETERMINISTIC (no AI extraction): the
  // matched Sigma rule's level drives severity, its title/tactics/tags drive the
  // description + MITRE, and IOCs/asset/process-chain come from the rendered detail fields.
  app.post("/cases/:id/import-hayabusa", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "hayabusa.csv");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    // Optional severity floor (e.g. "medium" drops Low/Info detections + noise).
    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const hayabusaOpts: HayabusaImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      // Parse up-front: reject a file with no parseable records, and report counts to the UI.
      const preview = parseHayabusaTimeline(text, hayabusaOpts);
      if (preview.total === 0) return res.status(400).json({ error: "no parseable Hayabusa records found (expected a Hayabusa json-timeline or csv-timeline)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events after the '${rawLevel}' severity floor (${preview.total} record(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "hayabusa.csv");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} Hayabusa event(s)` });
      void options.pipeline.importHayabusa(caseId, text, {
        label: storedName,
        idPrefix: `h${seq}`,
        importedAt,
        hayabusa: hayabusaOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Hayabusa import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import Velociraptor native JSON (collection results / hunt export). Evidence-first;
  // mapping is DETERMINISTIC (no AI extraction): rows are classified (Sigma/YARA/EventLog/
  // generic) and mapped — detection rows verdict-driven, the rest auto-detect time + IOCs.
  app.post("/cases/:id/import-velociraptor", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "velociraptor.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    // Optional severity floor (e.g. "low" drops the Info-level raw-collection rows).
    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const vrOpts: VelociraptorImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseVelociraptorJson(text, vrOpts);
      if (preview.total === 0) return res.status(400).json({ error: "no parseable Velociraptor rows found (expected JSON array, JSONL collection results, or an artifact map)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events after the '${rawLevel}' severity floor (${preview.total} row(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "velociraptor.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, rows: preview.total, detections: preview.detections, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} Velociraptor event(s)` });
      void options.pipeline.importVelociraptor(caseId, text, {
        label: storedName,
        idPrefix: `v${seq}`,
        importedAt,
        velociraptor: vrOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Velociraptor import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import network-monitor logs — Suricata eve.json + Zeek JSON (Security Onion's network
  // side). Evidence-first; mapping is DETERMINISTIC (no AI extraction): the timeline is built
  // from the detections (Suricata alerts + Zeek notices); telemetry contributes IOCs only.
  app.post("/cases/:id/import-network", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "eve.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    // Optional severity floor on the alert events (e.g. "medium" drops Suricata priority-3).
    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const netOpts: NetworkImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseNetworkLogs(text, netOpts);
      if (preview.total === 0) return res.status(400).json({ error: "no parseable Suricata/Zeek records found (expected Suricata eve.json or Zeek JSON, as NDJSON or an array)" });
      if (preview.kept === 0 && preview.iocs.length === 0) return res.status(400).json({ error: `no detections or IOCs found (${preview.total} record(s) parsed${rawLevel ? `, after the '${rawLevel}' floor` : ""})` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "eve.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, alerts: preview.alerts, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} network detection(s)` });
      void options.pipeline.importNetwork(caseId, text, {
        label: storedName,
        idPrefix: `n${seq}`,
        importedAt,
        network: netOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Network import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a KAPE / Eric Zimmerman Tools CSV (Prefetch, Amcache, ShimCache, LNK, JumpLists,
  // UsnJrnl, MFT, SRUM, Recycle Bin, Shellbags). Evidence-first; the EZ tool is detected from
  // the CSV header and mapped DETERMINISTICALLY (no AI extraction), reading the artifact's own time.
  app.post("/cases/:id/import-kape", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.csv === "string" ? req.body.csv : "";
    const originalName = String(req.body?.filename ?? "kape.csv");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const kapeOpts: KapeImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseKapeCsv(text, kapeOpts);
      if (preview.artifact === "unknown") return res.status(400).json({ error: "unrecognized CSV — expected a KAPE / Eric Zimmerman Tools export (Prefetch, Amcache, ShimCache, LNK, JumpLists, UsnJrnl, MFT, SRUM, RecycleBin, Shellbags)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events from the ${preview.artifact} CSV (${preview.total} row(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "kape.csv");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, artifact: preview.artifact, events: preview.kept, rows: preview.total, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} ${preview.artifact} event(s)` });
      void options.pipeline.importKape(caseId, text, {
        label: storedName,
        idPrefix: `k${seq}`,
        importedAt,
        kape: kapeOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `${preview.artifact} import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a Cyber Triage timeline export (JSONL / JSON array / CSV). Evidence-first; mapping is
  // DETERMINISTIC (no AI extraction): scored rows map verdict-first, unscored process/task rows
  // become Info evidence, the bulk File super-timeline is dropped unless `fileTelemetry` is set.
  app.post("/cases/:id/import-cybertriage", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json
      : typeof req.body?.csv === "string" ? req.body.csv : "";
    const originalName = String(req.body?.filename ?? "cybertriage.jsonl");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const fileTelemetry = req.body?.fileTelemetry === true || /^(1|true|yes)$/i.test(String(req.body?.fileTelemetry ?? ""));
    const ctOpts: CybertriageImportOptions | undefined =
      minSeverity || fileTelemetry ? { ...(minSeverity ? { minSeverity } : {}), ...(fileTelemetry ? { fileTelemetry } : {}) } : undefined;

    try {
      const preview = parseCybertriage(text, ctOpts);
      if (preview.format === "empty") return res.status(400).json({ error: "unrecognized file — expected a Cyber Triage timeline export (JSONL / JSON array / CSV with event_timestamp,epoch_timestamp,timestamp_description columns)" });
      if (preview.kept === 0 && preview.iocs.length === 0) return res.status(400).json({ error: `no events or IOCs from the Cyber Triage export (${preview.total} row(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "cybertriage.jsonl");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, rows: preview.total, notable: preview.notable, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} Cyber Triage event(s)` });
      void options.pipeline.importCybertriage(caseId, text, {
        label: storedName,
        idPrefix: `ct${seq}`,
        importedAt,
        cybertriage: ctOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Cyber Triage import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import Microsoft 365 Unified Audit Log + Entra ID sign-in / directory audit data
  // (cloud/identity IR). Evidence-first; mapping is DETERMINISTIC (no AI extraction): each
  // record is classified and mapped, severity derived from the operation / Entra risk verdict.
  app.post("/cases/:id/import-m365", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "m365.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const m365Opts: M365ImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseM365Audit(text, m365Opts);
      if (preview.total === 0 || preview.format === "empty") return res.status(400).json({ error: "no parseable M365/Entra records found (expected a Unified Audit Log export — CSV or JSON — or Entra sign-in/audit JSON)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events after the '${rawLevel}' severity floor (${preview.total} record(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "m365.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} M365/Entra event(s)` });
      void options.pipeline.importM365(caseId, text, {
        label: storedName,
        idPrefix: `m${seq}`,
        importedAt,
        m365: m365Opts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `M365 import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import AWS CloudTrail logs (cloud IR). Evidence-first; mapping is DETERMINISTIC (no AI
  // extraction): each API-call record is mapped, severity derived from the action + denied/
  // root/console-failure bumps; the caller sourceIPAddress becomes an IOC.
  app.post("/cases/:id/import-aws", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "cloudtrail.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const awsOpts: AwsImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseCloudTrail(text, awsOpts);
      if (preview.format === "empty" && preview.kept === 0) return res.status(400).json({ error: "no parseable CloudTrail records found (expected a { Records: [...] } envelope, NDJSON, or a JSON array of CloudTrail events)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "cloudtrail.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} CloudTrail event(s)` });
      void options.pipeline.importAws(caseId, text, {
        label: storedName,
        idPrefix: `a${seq}`,
        importedAt,
        aws: awsOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `CloudTrail import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import GCP Cloud Audit Logs + Azure Activity Log (cloud IR). Evidence-first; mapping is
  // DETERMINISTIC (no AI extraction): each record is routed (GCP/Azure) and mapped, severity
  // derived from the action + denied bump; the caller IP becomes an IOC.
  app.post("/cases/:id/import-cloud-activity", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "cloud-activity.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const cloudOpts: CloudActivityImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseCloudActivity(text, cloudOpts);
      if (preview.format === "empty" && preview.kept === 0) return res.status(400).json({ error: "no parseable GCP/Azure records found (expected GCP Cloud Audit Logs or an Azure Activity Log export, as JSON array or NDJSON)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "cloud-activity.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, events: preview.kept, records: preview.total, groups: preview.groups, format: preview.format, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} ${preview.format} event(s)` });
      void options.pipeline.importCloudActivity(caseId, text, {
        label: storedName,
        idPrefix: `g${seq}`,
        importedAt,
        cloud: cloudOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Cloud activity import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a Plaso / log2timeline super-timeline (psort CSV — dynamic or l2tcsv). Evidence-first;
  // mapping is DETERMINISTIC (no AI extraction): each row is an Info evidence event read at its
  // own time, with IOCs scraped from the message + source file path.
  app.post("/cases/:id/import-plaso", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.csv === "string" ? req.body.csv : "";
    const originalName = String(req.body?.filename ?? "plaso.csv");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const plasoOpts: PlasoImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parsePlasoCsv(text, plasoOpts);
      if (preview.format === "unknown") return res.status(400).json({ error: "unrecognized CSV — expected a Plaso psort export (dynamic: datetime,message,… or l2tcsv: date,time,…,desc,…)" });
      if (preview.kept === 0) return res.status(400).json({ error: `no events from the Plaso ${preview.format} CSV (${preview.total} row(s) parsed)` });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "plaso.csv");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, rows: preview.total, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} Plaso event(s)` });
      void options.pipeline.importPlaso(caseId, text, {
        label: storedName,
        idPrefix: `p${seq}`,
        importedAt,
        plaso: plasoOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Plaso import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a malware-sandbox detonation report (CAPEv2 or CrowdStrike Falcon Sandbox).
  // Evidence-first; mapping is DETERMINISTIC (no AI extraction): the verdict + each signature
  // map to events, and dropped/extracted hashes + network indicators are harvested as IOCs.
  app.post("/cases/:id/import-sandbox", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "sandbox.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const sandboxOpts: SandboxImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseSandboxReport(text, sandboxOpts);
      if (preview.format === "empty" && preview.kept === 0) return res.status(400).json({ error: "no parseable sandbox report found (expected a CAPEv2 report.json or a CrowdStrike Falcon Sandbox summary JSON)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "sandbox.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, signatures: preview.signatures, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} sandbox event(s)` });
      void options.pipeline.importSandbox(caseId, text, {
        label: storedName,
        idPrefix: `sb${seq}`,
        importedAt,
        sandbox: sandboxOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Sandbox import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import memory-forensics tool output (Volatility 3 JSON renderer or Rekall JSON). Evidence-first;
  // mapping is DETERMINISTIC (no AI call): pslist/psscan/pstree → process-tree events, netscan →
  // connection events, malfind → injected-code (T1055), cmdline/svcscan/modules → evidence; the
  // foreign IPs / file paths / process names are harvested as IOCs.
  app.post("/cases/:id/import-memory", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "memory.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const dllTelemetry = req.body?.dllTelemetry === true || String(req.body?.dllTelemetry ?? "").toLowerCase() === "true";
    const memoryOpts: MemoryImportOptions = { filename: originalName, ...(minSeverity ? { minSeverity } : {}), ...(dllTelemetry ? { dllTelemetry } : {}) };

    try {
      const preview = parseMemory(text, memoryOpts);
      if (preview.format === "empty" && preview.kept === 0) return res.status(400).json({ error: "no parseable memory output found (expected a Volatility 3 JSON-renderer array or a Rekall JSON statement list)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "memory.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, tool: preview.tool, events: preview.kept, injected: preview.injected, connections: preview.connections, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} memory event(s)` });
      void options.pipeline.importMemory(caseId, text, {
        label: storedName,
        idPrefix: `mem${seq}`,
        importedAt,
        memory: memoryOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Memory import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import an email artifact (.eml RFC 2822, or best-effort .msg). Evidence-first; mapped
  // DETERMINISTICALLY (no AI call): one event at the Date: header, severity from SPF/DKIM/DMARC +
  // sender heuristics, URLs/domains/IP/attachment-names as IOCs. Covers ATT&CK T1566 (Phishing).
  app.post("/cases/:id/import-email", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.eml === "string" ? req.body.eml : "";
    const originalName = String(req.body?.filename ?? "message.eml");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const rawLevel = String(req.body?.minSeverity ?? "").trim().toLowerCase();
    const minSeverity: Severity | undefined =
      rawLevel === "critical" ? "Critical" : rawLevel === "high" ? "High"
      : rawLevel === "medium" ? "Medium" : rawLevel === "low" ? "Low"
      : rawLevel === "info" ? "Info" : undefined;
    const emailOpts: EmailImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseEmail(text, emailOpts);
      if (preview.format === "empty" && preview.kept === 0) return res.status(400).json({ error: "no parseable email found (expected an .eml RFC 2822 message, or an Outlook .msg export)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "message.eml");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, subject: preview.subject, sender: preview.sender, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing email "${preview.subject.slice(0, 60)}"` });
      void options.pipeline.importEmail(caseId, text, {
        label: storedName,
        idPrefix: `em${seq}`,
        importedAt,
        email: emailOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Email import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a TheHive 5 case, alert, or observable export. Evidence-first; mapped
  // DETERMINISTICALLY (no AI call): case/alert records → events, severity from TheHive's 1–4
  // scale, MITRE from ATT&CK-tagged tags, TLP/PAP prepended; observables → IOCs by dataType.
  app.post("/cases/:id/import-thehive", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    const originalName = String(req.body?.filename ?? "thehive-export.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    try {
      const preview = parseTheHive(text);
      if (preview.format === "empty") return res.status(400).json({ error: "no parseable TheHive records found (expected a case/alert JSON export or an observable list)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "thehive-export.json";
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, total: preview.total, observables: preview.observables, iocs: preview.iocCount });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing TheHive export (${preview.format})` });
      void options.pipeline.importTheHive(caseId, text, {
        label: storedName,
        idPrefix: `th${seq}`,
        importedAt,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `TheHive import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a Linux auditd log (raw audit.log / `ausearch` record format, or an `aureport` table).
  // Evidence-first; mapped DETERMINISTICALLY (no AI call): records grouped by serial, per-type
  // severity/MITRE, read at the audit() epoch.
  app.post("/cases/:id/import-auditd", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.log === "string" ? req.body.log : "";
    const originalName = String(req.body?.filename ?? "audit.log");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const minSeverity = parseMinSeverity(req.body?.minSeverity);
    const auditdOpts: AuditdImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseAuditdLog(text, auditdOpts);
      if (preview.format === "empty") return res.status(400).json({ error: "no parseable auditd records found (expected raw audit.log / ausearch 'type=… msg=audit(…)' lines or an aureport table)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "audit.log");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, records: preview.total, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} auditd event(s)` });
      void options.pipeline.importAuditd(caseId, text, {
        label: storedName,
        idPrefix: `ad${seq}`,
        importedAt,
        auditd: auditdOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `auditd import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a systemd-journald structured log (`journalctl -o json` / `-o json-pretty`). Evidence-first;
  // mapped DETERMINISTICALLY (no AI call): severity from PRIORITY + tradecraft bumps, read at the
  // entry's own µs-epoch time.
  app.post("/cases/:id/import-journald", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "journal.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const minSeverity = parseMinSeverity(req.body?.minSeverity);
    const journaldOpts: JournaldImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseJournald(text, journaldOpts);
      if (preview.format === "empty") return res.status(400).json({ error: "no parseable journald entries found (expected `journalctl -o json` / `-o json-pretty` output)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "journal.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, entries: preview.total, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} journald event(s)` });
      void options.pipeline.importJournald(caseId, text, {
        label: storedName,
        idPrefix: `jd${seq}`,
        importedAt,
        journald: journaldOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `journald import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a sysdig / Falco export (Falco alert JSON and/or sysdig `-j` event JSON). Evidence-first;
  // mapped DETERMINISTICALLY (no AI call): Falco rule hits → detections (verdict-first), raw sysdig
  // syscall events → Info evidence, read at each event's own time.
  app.post("/cases/:id/import-sysdig", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "falco.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const minSeverity = parseMinSeverity(req.body?.minSeverity);
    const sysdigOpts: SysdigImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseSysdig(text, sysdigOpts);
      if (preview.format === "empty") return res.status(400).json({ error: "no parseable sysdig/Falco records found (expected Falco alert JSON or sysdig `-j` event JSON; a binary .scap must be exported to JSON first)" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "falco.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, records: preview.total, alerts: preview.alerts, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} sysdig/Falco event(s)` });
      void options.pipeline.importSysdig(caseId, text, {
        label: storedName,
        idPrefix: `sd${seq}`,
        importedAt,
        sysdig: sysdigOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `sysdig import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import Wazuh SIEM/EDR alert exports (alerts.json / NDJSON / API export envelope).
  // Evidence-first; mapped DETERMINISTICALLY (no AI call): rule.level drives severity,
  // rule.mitre.technique → MITRE, agent.name → asset, data fields → IOCs.
  app.post("/cases/:id/import-wazuh", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json : "";
    const originalName = String(req.body?.filename ?? "wazuh-alerts.json");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const minSeverity = parseMinSeverity(req.body?.minSeverity);
    const wazuhOpts: WazuhImportOptions | undefined = minSeverity ? { minSeverity } : undefined;

    try {
      const preview = parseWazuhAlerts(text, wazuhOpts);
      if (preview.format === "empty" && preview.kept === 0) return res.status(400).json({ error: "no parseable Wazuh alerts found (expected an array or NDJSON of Wazuh alert objects with rule.level, rule.description, and agent fields, or a Wazuh API export { data: { affected_items: [...] } })" });

      const seq = await store.nextImportSeq(caseId);
      const safeName = (originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "wazuh-alerts.json");
      const storedName = `${String(seq).padStart(4, "0")}_${safeName}`;
      const importedAt = new Date().toISOString();
      await store.saveImport(caseId, storedName, text);
      await store.appendImport(caseId, {
        caseId, sequenceNumber: seq, importedAt, filename: storedName,
        originalName, rows: preview.kept, bytes: Buffer.byteLength(text, "utf8"),
      });

      res.status(202).json({ accepted: true, file: storedName, format: preview.format, events: preview.kept, records: preview.total, groups: preview.groups, iocs: preview.iocs.length });

      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing ${preview.kept} Wazuh alert(s)` });
      void options.pipeline.importWazuh(caseId, text, {
        label: storedName,
        idPrefix: `wz${seq}`,
        importedAt,
        wazuh: wazuhOpts,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `Wazuh import — ${done}/${total}`,
        }),
      })
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); resynthesizeInBackground(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Last-import metadata: when the last import ran + what it added to the forensic timeline.
  // Backs the dashboard's "last import N ago - +N new events" banner and per-row "new" highlight.
  app.get("/cases/:id/import-meta", async (req: Request, res: Response) => {
    if (!options.importMetaStore) return res.status(501).json({ error: "import metadata not configured" });
    try {
      return res.status(200).json(await options.importMetaStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Evidence drop folder: the last sweep's summary (imported / failed files) for the dashboard
  // "📥 Drop: N imported, M failed" banner. `enabled` reflects DFIR_DROP_ENABLED; `dropPath` tells
  // the analyst where to drop files (the browser can't open it, so it's shown + copyable).
  app.get("/cases/:id/drop-status", async (req: Request, res: Response) => {
    if (!options.dropStatusStore) return res.status(501).json({ error: "drop folder not configured" });
    try {
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const status = await options.dropStatusStore.load(req.params.id);
      const dropPath = status.dropPath || dropDirOf(req.params.id);
      return res.status(200).json({ enabled: ctx.dropWatchEnabled(), pollSeconds: dropPollMs / 1000, dropPath, status });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // #76 Import undo/redo. Imports can flood the dashboard; these let the analyst roll the forensic
  // timeline + IOCs back to the pre-import snapshot (and redo). The synthesis-derived conclusions are
  // re-derived from the restored timeline by resynthesizeInBackground, exactly as on import.

  // Current undo/redo state (button enable + labels). Lightweight summary, not the raw snapshots.
  app.get("/cases/:id/import/undo-stack", async (req: Request, res: Response) => {
    if (!options.importUndoStore) return res.status(501).json({ error: "import undo not configured" });
    try {
      const stack = await options.importUndoStore.load(req.params.id);
      return res.status(200).json(summarizeUndoStack(stack, options.importUndoStore.depth()));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Undo the latest import: restore the full pre-import state (findings/IOCs/timeline/MITRE/attacker
  // path), push the current state to redo. No AI re-synthesis — the snapshot is the exact prior state.
  app.post("/cases/:id/import/undo", async (req: Request, res: Response) => {
    if (!options.importUndoStore || !options.stateStore) return res.status(501).json({ error: "import undo not configured" });
    const caseId = req.params.id;
    try {
      const stack = await options.importUndoStore.load(caseId);
      const state = await options.stateStore.load(caseId);
      const result = applyUndo(stack, state);
      if (!result) return res.status(400).json({ error: "nothing to undo" });
      const next = await restoreImportState(caseId, result.restore);
      await options.importUndoStore.save(caseId, result.stack);
      // The "last import" banner / NEW row highlights describe a change that has now been rolled back.
      if (options.importMetaStore) { try { await options.importMetaStore.clear(caseId); options.onImportMeta?.(caseId); } catch { /* non-fatal */ } }
      options.onImportUndo?.(caseId);
      if (next) options.onState?.(next);
      return res.status(200).json(summarizeUndoStack(result.stack, options.importUndoStore.depth()));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Redo the most-recently-undone import: re-apply its full state.
  app.post("/cases/:id/import/redo", async (req: Request, res: Response) => {
    if (!options.importUndoStore || !options.stateStore) return res.status(501).json({ error: "import undo not configured" });
    const caseId = req.params.id;
    try {
      const stack = await options.importUndoStore.load(caseId);
      const state = await options.stateStore.load(caseId);
      const result = applyRedo(stack, state);
      if (!result) return res.status(400).json({ error: "nothing to redo" });
      const next = await restoreImportState(caseId, result.restore);
      await options.importUndoStore.save(caseId, result.stack);
      if (options.importMetaStore) { try { await options.importMetaStore.clear(caseId); options.onImportMeta?.(caseId); } catch { /* non-fatal */ } }
      options.onImportUndo?.(caseId);
      if (next) options.onState?.(next);
      return res.status(200).json(summarizeUndoStack(result.stack, options.importUndoStore.depth()));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
