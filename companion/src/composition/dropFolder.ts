/**
 * The evidence drop folder — a per-case `cases/<id>/drop/` inbox where anything copied in, at any
 * depth, is auto-imported through the SAME chain as the Import button. Lifted out of createApp
 * by #416; its timer lifecycle is pinned by tests/server/timerLifecycle.test.ts.
 *
 * POLLING, NOT fs.watch. `cases/` very often lives in a Dropbox/OneDrive-synced folder, where watch
 * events are unreliable or arrive before the file is whole (the same reason atomicWrite retries
 * sync locks). One global self-rescheduling poller sweeps every case — mirroring resumeVeloMonitors
 * — and a file must be seen UNCHANGED (size + mtime) by two consecutive sweeps before it is read,
 * so a half-copied 4 GB image is never parsed as truncated evidence.
 *
 * THE MOVE IS THE DEDUP. On success a file goes to drop/_processed/, on failure to drop/_failed/,
 * and the scanner skips both subtrees — so there is no "already imported" ledger to keep in sync
 * with the filesystem. A file awaiting a tool is the one exception: it stays put (so the dashboard's
 * "Run <tool>" can still act on it) and is tracked in memory instead.
 *
 * SYMLINKS AND HARDLINKS ARE REFUSED, twice — once when listing, once immediately before reading
 * (TOCTOU: the path could be swapped in between). A synced cases/ root is exactly where a
 * symlink-to-/etc/shadow is realistic, and a hardlink is indistinguishable from a normal file via
 * stat — but a legitimately dropped file is always nlink === 1, so nlink > 1 means some other
 * directory entry aliases the same inode.
 *
 * ARMED ONLY WHEN options.dropStatusStore IS WIRED (i.e. by startServer), so createApp-only unit
 * tests never spin up a filesystem poller.
 */
import { basename, dirname, extname, join, relative } from "node:path";
import {
  readFile,
  readdir,
  stat,
  lstat,
  open,
  copyFile,
  mkdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import type { CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";
import type { AiControl } from "../analysis/aiControl.js";
import type { CaptureMetadata } from "../types.js";
import type { ToolConfig } from "../integrations/tools/toolConfig.js";
import { suggestedToolForExtension } from "../integrations/tools/toolConfig.js";
import { ingestCapture } from "../ingest/captureIngest.js";
import {
  selectReadyFiles,
  classifyDropFile,
  shouldIgnoreDropFile,
  isOversize,
  DROP_PROCESSED,
  DROP_FAILED,
  DROP_README,
  type DropFileStat,
} from "../analysis/dropScan.js";
import { formatDropLogLines, appendDropLog, buildSweepLogEntries } from "../analysis/dropLog.js";
import type { DropFailure, PendingRawInput } from "../analysis/dropStatus.js";
import { milestoneEvent, type NotificationEvent } from "../analysis/notifications.js";
import type { RegisteredJob } from "../analysis/jobManager.js";
import { logLine } from "../logging/serverLogger.js";

/** A case's drop inbox. Exported so the SO-CRATES hand-off can close its drop-log line (#416). */
export function dropDirOf(store: CaseStore, caseId: string): string {
  return join(store.caseDir(caseId), "drop");
}

const DROP_CONCURRENCY = 4;

const DROP_README_TEXT = [
  "DFIR Companion — evidence drop folder",
  "",
  "Copy artifacts into this folder (subfolders are fine — they're scanned recursively).",
  "Each file is auto-detected and imported into this case, exactly like the dashboard Import button.",
  "Images (.png/.jpg/...) are ingested as screenshot evidence.",
  "",
  "After processing, files move to _processed/ (success) or _failed/ (error).",
  "Failures are reported in the dashboard (📥 Drop banner) and any configured notification channel.",
  "A running history of every file processed (imported/failed/pending, with reasons) is kept in",
  "drop-log.txt in this same folder.",
  "",
  "This README, drop-log.txt, and the _processed/ and _failed/ subfolders are ignored by the scanner.",
  "",
].join("\n");

export interface DropFolderDeps {
  store: CaseStore;
  options: AppOptions;
  hasAiProvider: () => boolean;
  getControl: (caseId: string) => Promise<AiControl>;
  recordImportFailure: (caseId: string, kind: string, filename: string, err: unknown) => void;
  dispatchNotify: (event: NotificationEvent) => void;
  resolveImportKind: (filename: string, text: string) => string;
  ingestStreamed: (
    caseId: string,
    kind: string,
    text: string,
    originalName: string,
    minSeverity?: undefined,
  ) => Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }>;
  // External-tool routing for raw (non-text) inputs.
  liveToolConfigs: () => Map<string, ToolConfig>;
  resolveToolForExt: (ext: string, configured: Map<string, ToolConfig>) => string | null;
  rawExtClaimed: (ext: string) => boolean;
  runDropToolAndIngest: (
    caseId: string,
    toolId: string,
    fullPath: string,
    name: string,
    dropRelpath?: string,
  ) => Promise<boolean>;
  // A dropped image joins the SAME capture + vision path as POST /captures.
  indexCaptureText: (metadata: CaptureMetadata) => void;
  captureBuffers: Map<string, CaptureMetadata[]>;
  flush: (caseId: string) => Promise<void>;
}

export interface DropFolder {
  /** False when DFIR_DROP_ENABLED is off; the dashboard reports this. */
  readonly watchEnabled: boolean;
  /** Per-case size+mtime memory of files awaiting settle. Exposed for the drop-status route. */
  readonly seen: Map<string, Map<string, { size: number; mtimeMs: number }>>;
  /** Cases with a sweep in flight (a second sweep of the same case is skipped). */
  readonly scanning: Set<string>;
  /** Files already logged PENDING, so a waiting raw file gets one line, not one per poll. */
  readonly pendingLogged: Map<string, Set<string>>;
  ensureDropFolders(caseId: string): Promise<void>;
  moveDropFile(dropDir: string, relpath: string, ok: boolean): Promise<void>;
  scanCaseDrops(caseId: string): Promise<void>;
  /** Arm the global poller. Idempotent — a second call is a no-op. */
  startDropWatcher(): void;
}

export function createDropFolder(deps: DropFolderDeps): DropFolder {
  const {
    store,
    options,
    hasAiProvider,
    getControl,
    recordImportFailure,
    dispatchNotify,
    resolveImportKind,
    ingestStreamed,
    liveToolConfigs,
    resolveToolForExt,
    rawExtClaimed,
    runDropToolAndIngest,
    indexCaptureText,
    captureBuffers,
    flush,
  } = deps;

  const watchEnabled = (process.env.DFIR_DROP_ENABLED ?? "on").trim().toLowerCase() !== "off";
  const dropPollMs = Math.min(600, Math.max(2, Number(process.env.DFIR_DROP_POLL_S) || 10)) * 1000;
  const dropMaxBytes = Number(process.env.DFIR_DROP_MAX_BYTES) || 200 * 1024 * 1024;
  const seen = new Map<string, Map<string, { size: number; mtimeMs: number }>>();
  const scanning = new Set<string>();
  // Files logged as PENDING (relpath per case) so a still-waiting raw-tool file doesn't get a new
  // PENDING line every poll — only once when first seen pending, cleared once it resolves.
  const pendingLogged = new Map<string, Set<string>>();

  async function ensureDropFolders(caseId: string): Promise<void> {
    const dropDir = dropDirOf(store, caseId);
    await mkdir(join(dropDir, DROP_PROCESSED), { recursive: true });
    await mkdir(join(dropDir, DROP_FAILED), { recursive: true });
    const readme = join(dropDir, DROP_README);
    try {
      await stat(readme);
    } catch {
      await writeFile(readme, DROP_README_TEXT, "utf8").catch(() => {
        /* best-effort */
      });
    }
  }

  // Recursive walk of drop/, skipping the reserved subtrees + README + OS/sync junk (shouldIgnoreDropFile).
  // Symlinks and hardlinks are rejected here — see the file header for the threat model.
  async function listDropFiles(dropDir: string): Promise<DropFileStat[]> {
    const out: DropFileStat[] = [];
    const walk = async (dir: string): Promise<void> => {
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries) {
        const full = join(dir, e.name);
        const rel = relative(dropDir, full);
        if (shouldIgnoreDropFile(rel)) continue;
        if (e.isSymbolicLink()) continue; // never follow symlinks in the drop folder
        if (e.isDirectory()) {
          await walk(full);
          continue;
        }
        if (!e.isFile()) continue;
        try {
          const st = await lstat(full);
          if (st.isSymbolicLink() || st.nlink > 1) continue;
          out.push({ relpath: rel, size: st.size, mtimeMs: st.mtimeMs });
        } catch {
          /* vanished mid-walk */
        }
      }
    };
    await walk(dropDir);
    return out;
  }

  // Find a non-colliding destination (a re-dropped same-name file shouldn't clobber an earlier one).
  async function uniqueDest(path: string): Promise<string> {
    let candidate = path;
    const ext = extname(path);
    const stem = path.slice(0, path.length - ext.length);
    for (let n = 1; n < 1000; n++) {
      try {
        await stat(candidate);
      } catch {
        return candidate;
      } // ENOENT → free
      candidate = `${stem}_${n}${ext}`;
    }
    return candidate;
  }

  async function moveDropFile(dropDir: string, relpath: string, ok: boolean): Promise<void> {
    const src = join(dropDir, relpath);
    const dest = await uniqueDest(join(dropDir, ok ? DROP_PROCESSED : DROP_FAILED, relpath));
    await mkdir(dirname(dest), { recursive: true });
    try {
      // Guard against a symlink swap (TOCTOU): rename follows symlinks on some platforms, and
      // copyFile always does. Re-check before moving. Also refuse a hardlink (nlink > 1) — see
      // listDropFiles for why that's just as much a host-file-exfiltration vector as a symlink.
      const lst = await lstat(src);
      if (lst.isSymbolicLink())
        throw new Error("symlink detected in drop folder — refused to move (security)");
      if (lst.nlink > 1) throw new Error("hardlink detected in drop folder — refused to move (security)");
      await rename(src, dest);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EXDEV") {
        await copyFile(src, dest);
        await rm(src, { force: true });
      } else throw e;
    }
  }

  // Ingest one dropped image as screenshot evidence: transcode to webp (imageLoader sends screenshots
  // as image/webp, so a dropped png/jpg must be honest on disk + wire), then run the SAME capture +
  // vision trigger as POST /captures. triggerType "navigation" forces a prompt flush.
  async function ingestDroppedImage(
    caseId: string,
    fullPath: string,
    name: string,
    mtimeMs: number,
  ): Promise<void> {
    const raw = await readFile(fullPath);
    let webp: Buffer;
    try {
      const sharp = (await import("sharp")).default;
      webp = await sharp(raw).webp().toBuffer();
    } catch (e) {
      throw new Error(`not a readable image: ${(e as Error).message}`);
    }
    const metadata = await ingestCapture(store, {
      caseId,
      timestamp: new Date(mtimeMs).toISOString(),
      url: `drop://${name}`,
      tabTitle: name,
      triggerType: "navigation",
      imageBase64: webp.toString("base64"),
    });
    const willAnalyze =
      !metadata.isDuplicate &&
      Boolean(options.pipeline) &&
      hasAiProvider() &&
      (await getControl(caseId)).enabled;
    options.onCapture?.(caseId);
    indexCaptureText(metadata);
    if (willAnalyze) {
      const buf = captureBuffers.get(caseId) ?? [];
      buf.push(metadata);
      captureBuffers.set(caseId, buf);
      void flush(caseId);
    }
  }

  async function processDropFile(
    caseId: string,
    dropDir: string,
    file: DropFileStat,
  ): Promise<{ ok: boolean; reason?: string; pending?: PendingRawInput; submitted?: string }> {
    const full = join(dropDir, file.relpath);
    const name = basename(file.relpath);
    try {
      // TOCTOU guard: re-check that the path is not a symlink before reading. A file could have
      // been replaced with a symlink between listDropFiles and this read. Also refuse a hardlink
      // (nlink > 1) — indistinguishable from a normal file via stat, but a legitimately-dropped
      // file is always nlink === 1 (see listDropFiles).
      const lst = await lstat(full);
      if (lst.isSymbolicLink())
        return { ok: false, reason: "symlink detected in drop folder — refused to read (security)" };
      if (lst.nlink > 1)
        return { ok: false, reason: "hardlink detected in drop folder — refused to read (security)" };
      // A raw file an external tool handles (built-in EVTX/PCAP, or any extension a CUSTOM tool claims)
      // — can't be read as text. Run the configured tool against the on-disk file (size-independent, so
      // checked BEFORE the oversize cap), or surface it as pending so the dashboard offers "Run/Configure
      // <tool>". Auto-run is gated per-tool (#211). Images always go to the capture path, not here.
      const ext = extname(file.relpath).toLowerCase();
      // Sniff the head so an EXTENSIONLESS or hash-named sample (routine for malware) is still seen as
      // raw rather than read as text. Only the first 8 KB — the file may be gigabytes.
      let head: Buffer | undefined;
      try {
        const fh = await open(full, "r");
        try {
          const buf = Buffer.alloc(Math.min(8192, Math.max(0, file.size)));
          if (buf.length) await fh.read(buf, 0, buf.length, 0);
          head = buf;
        } finally {
          await fh.close();
        }
      } catch {
        /* unreadable head → fall back to extension-only classification */
      }

      // A raw file no text importer can read: a claimed extension, or anything the sniff says is binary.
      // NOT gated on options.toolRunner — that is the PROCESS SPAWNER, and SO-CRATES needs no spawner.
      // Gating here would drop a binary into the text path on a box with no local forensic binaries.
      if (classifyDropFile(file.relpath, head) === "raw-tool-input" || rawExtClaimed(ext)) {
        const configured = liveToolConfigs();
        // An extensionless binary is claimed by nobody, but SO-CRATES YARA-scans anything, so it is the
        // fallback whenever it is configured.
        const toolId = resolveToolForExt(ext, configured) ?? (configured.has("socrates") ? "socrates" : null);
        const cfg = toolId ? configured.get(toolId) : undefined;
        // A spawn tool additionally needs the process spawner; an HTTP tool does not.
        const runnable = !!cfg && cfg.autoRun && (cfg.transport === "http" || !!options.toolRunner);
        if (!toolId || !cfg || !runnable) {
          // Not runnable now → pending (banner). Do NOT move the file so a manual run can still act on it.
          return {
            ok: false,
            pending: {
              relpath: file.relpath,
              ext,
              suggestedTool: toolId ?? suggestedToolForExtension(ext),
              configured: !!toolId,
            },
          };
        }
        const async_ = await runDropToolAndIngest(caseId, toolId, full, name, file.relpath);
        // An HTTP tool has only been HANDED the file here; its verdicts land later (or the analysis
        // fails), so the sweep logs SUBMITTED and the job appends the outcome when it resolves.
        return async_
          ? { ok: true, submitted: `handed to ${toolId}; verdicts land when analysis finishes` }
          : { ok: true };
      }
      if (isOversize(file.size, dropMaxBytes)) {
        return {
          ok: false,
          reason: `too large (${Math.round(file.size / 1048576)} MB > ${Math.round(dropMaxBytes / 1048576)} MB cap) — use Import-from-path`,
        };
      }
      if (classifyDropFile(file.relpath) === "image") {
        await ingestDroppedImage(caseId, full, name, file.mtimeMs);
        return { ok: true };
      }
      const text = await readFile(full, "utf8");
      if (!text.trim()) return { ok: false, reason: "empty file" };
      const kind = resolveImportKind(name, text);
      if (kind === "unknown")
        return { ok: false, reason: "unrecognized file type (not a supported import format)" };
      const r = await ingestStreamed(caseId, kind, text, name, undefined);
      if (!r.analyzed)
        return {
          ok: false,
          reason: "AI is off — saved as evidence but not analyzed; enable AI and re-import",
        };
      return { ok: true };
    } catch (err) {
      recordImportFailure(caseId, "drop", name, err);
      return { ok: false, reason: (err as Error)?.message ?? String(err) };
    }
  }

  async function scanCaseDrops(caseId: string): Promise<void> {
    if (scanning.has(caseId)) return; // a previous sweep of this case is still running
    scanning.add(caseId);
    // Surface the auto-import sweep as a background job (registered below once we know files are
    // ready) so the dashboard Jobs panel shows drop-folder activity, exactly like a manual /import (#225).
    let job: RegisteredJob | undefined;
    try {
      const meta = await store.getCaseMeta(caseId).catch(() => null);
      if (meta?.status === "closed" || meta?.status === "archived") return; // don't auto-import into a closed or archived case (parity with /import)
      const dropDir = dropDirOf(store, caseId);
      await ensureDropFolders(caseId);
      const listing = await listDropFiles(dropDir);
      const { ready, nextSeen } = selectReadyFiles(listing, seen.get(caseId) ?? new Map());
      seen.set(caseId, nextSeen);
      if (ready.length === 0) return;

      // One job per sweep, kind "import" (same panel row as the Import button). Non-cancellable: the
      // sweep runs mixed importers that don't thread an abort signal, and a file already imported and
      // moved to _processed/ can't be un-imported — so there's nothing safe to cancel mid-flight.
      job = options.jobManager?.register({
        caseId,
        kind: "import",
        label: `drop import (${ready.length} file${ready.length === 1 ? "" : "s"})`,
      });
      if (job) await job.ready;

      const imported: string[] = [];
      // Handed to an asynchronous tool this sweep — logged SUBMITTED, with the outcome appended by the
      // job itself when the analysis resolves.
      const submitted: { relpath: string; reason: string }[] = [];
      const failed: DropFailure[] = [];
      const pendingRawInputs: PendingRawInput[] = [];
      let processed = 0;
      for (let i = 0; i < ready.length; i += DROP_CONCURRENCY) {
        const batch = ready.slice(i, i + DROP_CONCURRENCY);
        await Promise.all(
          batch.map(async (file) => {
            try {
              const res = await processDropFile(caseId, dropDir, file);
              if (res.pending) {
                // Raw input awaiting a tool: keep it in place (don't move, keep tracked) so the banner's
                // "Run <tool>" can act on it and a later config/auto-run picks it up next sweep.
                pendingRawInputs.push(res.pending);
                return;
              }
              // A submitted file still counts as "imported" for the dashboard's drop banner (it was
              // accepted and moved), but the drop-log records it as SUBMITTED until the analysis lands.
              if (res.ok && res.submitted) {
                imported.push(file.relpath);
                submitted.push({ relpath: file.relpath, reason: res.submitted });
              } else if (res.ok) imported.push(file.relpath);
              else failed.push({ relpath: file.relpath, reason: res.reason ?? "import failed" });
              await moveDropFile(dropDir, file.relpath, res.ok).catch((e) =>
                logLine(`[drop] move failed for ${file.relpath}: ${(e as Error).message}`),
              );
              nextSeen.delete(file.relpath); // moved out of the watched area — forget it
              pendingLogged.get(caseId)?.delete(file.relpath); // resolved — no longer pending
            } finally {
              if (job)
                options.jobManager?.progress(job.jobId, ++processed, ready.length, basename(file.relpath));
            }
          }),
        );
      }
      if (job) await options.jobManager?.finish(job.jobId);
      if (imported.length === 0 && failed.length === 0 && pendingRawInputs.length === 0) return;

      if (options.dropStatusStore) {
        try {
          await options.dropStatusStore.record(caseId, {
            dropPath: dropDir,
            imported,
            failed,
            pendingRawInputs,
          });
          options.onDropStatus?.(caseId);
        } catch (e) {
          logLine(`[drop] status record failed: ${(e as Error).message}`);
        }
      }

      // Folder-visible history (drop/drop-log.txt): every imported/failed file gets a line; a pending
      // raw-tool file gets ONE PENDING line the first time it's seen (pendingLogged dedups it across
      // the ~10s poll interval until it resolves).
      const { entries: logEntries, nextLoggedPending } = buildSweepLogEntries(
        // `imported` minus the async handoffs — those get a SUBMITTED line instead, so a file is
        // never claimed as imported before its verdicts actually land.
        {
          imported: imported.filter((r) => !submitted.some((s) => s.relpath === r)),
          submitted,
          failed,
          pendingRawInputs,
        },
        pendingLogged.get(caseId) ?? new Set<string>(),
      );
      pendingLogged.set(caseId, nextLoggedPending);
      if (logEntries.length > 0) {
        await appendDropLog(dropDir, formatDropLogLines(logEntries, new Date().toISOString())).catch((e) =>
          logLine(`[drop] log append failed: ${(e as Error).message}`),
        );
      }

      logLine(`[drop] ${caseId}: ${imported.length} imported, ${failed.length} failed`);
      if (failed.length > 0) {
        const lines = failed.slice(0, 20).map((x) => `• ${x.relpath} — ${x.reason}`);
        dispatchNotify(
          milestoneEvent(
            caseId,
            `Drop import: ${imported.length} imported, ${failed.length} failed`,
            lines,
            new Date().toISOString(),
          ),
        );
      }
    } catch (err) {
      // A sweep-level failure (listing/meta/store I/O) must terminate the job — a job stuck "running"
      // forever is a worse UI bug than the original invisibility. No-op if it already finished.
      if (job) await options.jobManager?.fail(job.jobId, err);
      throw err;
    } finally {
      scanning.delete(caseId);
    }
  }

  let dropTimer: NodeJS.Timeout | null = null;
  async function pollDropFolders(): Promise<void> {
    try {
      for (const c of await store.listCases()) await scanCaseDrops(c.caseId);
    } catch (e) {
      logLine(`[drop] poll error: ${(e as Error).message}`);
    } finally {
      // Re-arm in `finally`, so a sweep that threw does not silently end the watcher for the
      // lifetime of the process. tests/server/timerLifecycle.test.ts pins this.
      dropTimer = setTimeout(() => {
        void pollDropFolders();
      }, dropPollMs);
      dropTimer.unref();
    }
  }

  function startDropWatcher(): void {
    if (dropTimer) return;
    logLine(
      `[drop] watching evidence drop folders (poll every ${dropPollMs / 1000}s, cap ${Math.round(dropMaxBytes / 1048576)} MB)`,
    );
    dropTimer = setTimeout(() => {
      void pollDropFolders();
    }, dropPollMs);
    dropTimer.unref();
  }

  return {
    watchEnabled,
    seen,
    scanning,
    pendingLogged,
    ensureDropFolders,
    moveDropFile,
    scanCaseDrops,
    startDropWatcher,
  };
}
