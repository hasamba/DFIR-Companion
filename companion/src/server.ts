import express, { type Express, type Request, type Response, type NextFunction } from "express";
import { config as loadDotenv } from "dotenv";
import { join, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFile, readFile, rm } from "node:fs/promises";
import { ZodError } from "zod";
import { CaseStore } from "./storage/caseStore.js";
import { ingestCapture, CaseNotFoundError } from "./ingest/captureIngest.js";
import { AiControlStore, type AiControl } from "./analysis/aiControl.js";
import { LegitimateStore, markerId, type LegitimateMarker } from "./analysis/legitimate.js";
import { ScopeStore, type ScopeWindow } from "./analysis/scope.js";
import { parseCsv } from "./analysis/csvImport.js";
import { parseLogLines } from "./analysis/logImport.js";
import { parseThorReport } from "./analysis/thorImport.js";
import { enrichIocs, type EnrichLookupEvent } from "./enrichment/enrichService.js";
import { EnrichControlStore, resolveEnabledProviders } from "./enrichment/enrichControl.js";
import type { EnrichmentProvider } from "./enrichment/provider.js";
import { VirusTotalProvider } from "./enrichment/virustotal.js";
import { MalwareBazaarProvider } from "./enrichment/malwarebazaar.js";
import { AbuseIpdbProvider } from "./enrichment/abuseipdb.js";
import { MispProvider } from "./enrichment/misp.js";
import { RockyRaccoonProvider, type ParentChildResult } from "./enrichment/rockyraccoon.js";
import { YetiProvider } from "./enrichment/yeti.js";
import { buildTlsFetch } from "./enrichment/tlsFetch.js";
import { validateProcessChains, type ChainSummary } from "./enrichment/chainValidate.js";
import type { AnalysisPipeline } from "./analysis/pipeline.js";
import type { InvestigationState, InvestigationQuestion, QuestionStatus } from "./analysis/stateTypes.js";
import type { CaptureMetadata } from "./types.js";
import type { StateStore } from "./analysis/stateStore.js";
import type { ReportWriter } from "./reports/reportWriter.js";
import { ReportMetaStore } from "./reports/reportMeta.js";
import { CommentsStore } from "./analysis/comments.js";
import { buildManualEvent, buildManualIoc } from "./analysis/manualEntry.js";
import { byEventTime } from "./analysis/forensicSort.js";
import { IrisClient } from "./integrations/iris/irisClient.js";
import { pushCaseToIris, type IrisPushOptions } from "./integrations/iris/irisPush.js";
import { TimesketchClient } from "./integrations/timesketch/timesketchClient.js";
import { pushCaseToTimesketch, type TimesketchPushOptions } from "./integrations/timesketch/timesketchPush.js";

// Server console logging — every line is prefixed with an ISO-8601 timestamp so the local
// log can be correlated with case events and outbound threat-intel API calls. This is a
// localhost single-user tool, so the console IS the log; these helpers are the one place
// that formatting lives.
function ts(): string { return new Date().toISOString(); }
function logLine(msg: string): void { console.log(`${ts()} ${msg}`); }
function warnLine(msg: string): void { console.warn(`${ts()} ${msg}`); }
function errLine(msg: string): void { console.error(`${ts()} ${msg}`); }

// Truncate a long indicator (e.g. a SHA-256) for a readable one-line log entry.
function shortValue(value: string): string {
  return value.length > 24 ? `${value.slice(0, 24)}…` : value;
}

export type AiStatus = "analyzing" | "idle" | "error";
// What the AI is actually doing, so the dashboard can say "processing screenshots"
// vs "synthesizing" vs idle rather than a generic "analyzing".
export type AiPhase = "extracting" | "synthesizing";

export interface AiStatusEvent {
  status: AiStatus;
  at: string;        // ISO timestamp
  phase?: AiPhase;   // present when status === "analyzing"
  detail?: string;   // e.g. window size, or error message
}

export interface AppOptions {
  pipeline?: AnalysisPipeline;
  windowSize?: number;
  stateStore?: StateStore;
  reportWriter?: ReportWriter;
  // Human-authored report metadata (title page, distribution, BIA, glossary, recommendations…)
  // edited from the dashboard and merged into report.md.
  reportMetaStore?: ReportMetaStore;
  // Investigator comments on case entities (collaboration). onComments pings dashboard
  // clients over the WS to re-fetch when a comment is added/removed.
  commentsStore?: CommentsStore;
  onComments?: (caseId: string) => void;
  // Called when an AI analysis window starts / finishes / fails, so the
  // server can push a live "AI status" indicator to dashboard clients.
  onAiStatus?: (caseId: string, event: AiStatusEvent) => void;
  // When true, run the synthesis pass automatically (debounced) after capture
  // windows are analyzed, so the live dashboard shows findings/attacker path.
  autoSynthesize?: boolean;
  autoSynthesizeDebounceMs?: number;
  // Threat-intel enrichment providers (VirusTotal, MalwareBazaar, AbuseIPDB…).
  enrichmentProviders?: EnrichmentProvider[];
  enrichDelayMs?: number;
  enrichMaxIocs?: number;
  // Broadcast a fresh investigation state to dashboard clients (for routes that change
  // state outside the AI pipeline, e.g. enrichment).
  onState?: (state: InvestigationState) => void;
  // DFIR-IRIS push: a configured client (when DFIR_IRIS_URL/KEY are set) + mapping options
  // (customer/classification ids, base URL for the case link).
  irisClient?: IrisClient;
  irisOptions?: IrisPushOptions;
  // Timesketch push: a configured client (when DFIR_TIMESKETCH_URL/USER/PASSWORD are set) +
  // options (base URL for the sketch link, managed timeline name).
  timesketchClient?: TimesketchClient;
  timesketchOptions?: TimesketchPushOptions;
}

// Content type for an evidence file served back to the dashboard. CSVs/text are
// served as text/plain so a click opens them in a tab rather than downloading.
function evidenceContentType(file: string): string {
  const ext = file.slice(file.lastIndexOf(".")).toLowerCase();
  switch (ext) {
    case ".webp": return "image/webp";
    case ".png": return "image/png";
    case ".jpg":
    case ".jpeg": return "image/jpeg";
    case ".gif": return "image/gif";
    case ".csv":
    case ".log":
    case ".txt": return "text/plain; charset=utf-8";
    case ".json": return "application/json; charset=utf-8";
    default: return "application/octet-stream";
  }
}

export function createApp(store: CaseStore, options: AppOptions = {}): Express {
  const app = express();

  // Allow the browser extension (a chrome-extension:// origin) to reach this
  // localhost-only server. Binding is 127.0.0.1, so this is local-machine access.
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type");
    // Chromium Private Network Access: a request from an extension page to a
    // private address (127.0.0.1) is blocked unless the preflight allows it.
    res.header("Access-Control-Allow-Private-Network", "true");
    if (req.method === "OPTIONS") {
      res.sendStatus(204);
      return;
    }
    next();
  });

  // Log each request and its final status (useful for a local single-user tool).
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.on("finish", () => {
      logLine(`[req] ${req.method} ${req.url} -> ${res.statusCode}`);
    });
    next();
  });

  app.use(express.json({ limit: "25mb" }));

  // Lightweight reachability check used by the extension's connection status.
  // aiEnabled tells the dashboard whether an AI provider is configured at all.
  app.get("/health", (_req: Request, res: Response) => {
    res.status(200).json({ ok: true, service: "dfir-companion", aiEnabled: Boolean(options.pipeline), enrichEnabled: (options.enrichmentProviders?.length ?? 0) > 0 });
  });

  // How many captures have been recorded for a case (counts the audit-log lines).
  app.get("/cases/:id/captures/count", async (req: Request, res: Response) => {
    try {
      const log = await readFile(store.capturesLogPath(req.params.id), "utf8");
      const count = log.split("\n").filter((l) => l.trim().length > 0).length;
      return res.status(200).json({ count });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return res.status(200).json({ count: 0 });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  const windowSize = options.windowSize ?? 4;
  const buffers = new Map<string, CaptureMetadata[]>();
  const SIGNIFICANT = new Set(["navigation", "tab_switch"]);

  // Per-case AI on/off + last-analyzed sequence (cached, persisted to disk).
  const aiControl = new AiControlStore(store);
  const controlCache = new Map<string, AiControl>();
  async function getControl(caseId: string): Promise<AiControl> {
    let c = controlCache.get(caseId);
    if (!c) { c = await aiControl.load(caseId); controlCache.set(caseId, c); }
    return c;
  }
  async function setControl(caseId: string, patch: Partial<AiControl>): Promise<AiControl> {
    const next = { ...(await getControl(caseId)), ...patch };
    controlCache.set(caseId, next);
    await aiControl.save(caseId, next);
    return next;
  }

  // Debounced live synthesis: after capture windows are analyzed, re-derive the
  // findings / MITRE / attacker path so the dashboard updates as you browse.
  const autoSynth = options.autoSynthesize ?? false;
  const synthDebounceMs = options.autoSynthesizeDebounceMs ?? 8000;
  const synthTimers = new Map<string, ReturnType<typeof setTimeout>>();
  const synthInFlight = new Set<string>();

  function scheduleSynthesis(caseId: string): void {
    if (!autoSynth || !options.pipeline) return;
    const existing = synthTimers.get(caseId);
    if (existing) clearTimeout(existing);
    synthTimers.set(caseId, setTimeout(() => {
      synthTimers.delete(caseId);
      if (synthInFlight.has(caseId)) { scheduleSynthesis(caseId); return; } // busy — retry after debounce
      synthInFlight.add(caseId);
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "synthesizing", at: new Date().toISOString(), detail: "synthesizing conclusions" });
      options.pipeline!.synthesize(caseId)
        .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); autoEnrichIfEnabled(caseId); })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }))
        .finally(() => synthInFlight.delete(caseId));
    }, synthDebounceMs));
  }

  async function flush(caseId: string): Promise<void> {
    const buf = buffers.get(caseId) ?? [];
    if (buf.length === 0 || !options.pipeline) return;
    buffers.set(caseId, []);
    options.onAiStatus?.(caseId, {
      status: "analyzing",
      phase: "extracting",
      at: new Date().toISOString(),
      detail: `${buf.length} screenshot(s)`,
    });
    try {
      await options.pipeline.analyzeWindow(caseId, buf);
      // Analysis recovered — drop any stale failure marker from a prior window.
      await rm(join(store.stateDir(caseId), "pending_analysis.json"), { force: true });
      const maxSeq = Math.max(...buf.map((c) => c.sequenceNumber));
      const cur = await getControl(caseId);
      if (maxSeq > cur.lastAnalyzedSeq) await setControl(caseId, { lastAnalyzedSeq: maxSeq });
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      scheduleSynthesis(caseId); // live findings/attacker path
    } catch (err) {
      const seqs = buf.map((c) => c.sequenceNumber);
      await writeFile(
        join(store.stateDir(caseId), "pending_analysis.json"),
        JSON.stringify({ pending: seqs, error: (err as Error).message }, null, 2),
        "utf8",
      );
      options.onAiStatus?.(caseId, {
        status: "error",
        at: new Date().toISOString(),
        detail: (err as Error).message,
      });
    }
  }

  // Analyze every non-duplicate capture taken since lastAnalyzedSeq — used when AI
  // is switched back on after capturing with it off. Runs in the background.
  async function backfill(caseId: string): Promise<void> {
    if (!options.pipeline) return;
    let control = await getControl(caseId);
    let captures: CaptureMetadata[];
    try {
      const log = await readFile(store.capturesLogPath(caseId), "utf8");
      captures = log.split("\n").filter((l) => l.trim().length > 0).map((l) => JSON.parse(l) as CaptureMetadata);
    } catch {
      return;
    }
    const pending = captures.filter((c) => !c.isDuplicate && c.sequenceNumber > control.lastAnalyzedSeq);
    if (pending.length === 0) return;
    options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `catching up on ${pending.length} screenshot(s)` });
    try {
      for (let i = 0; i < pending.length; i += windowSize) {
        const win = pending.slice(i, i + windowSize);
        await options.pipeline.analyzeWindow(caseId, win);
        control = await setControl(caseId, { lastAnalyzedSeq: Math.max(...win.map((c) => c.sequenceNumber)) });
      }
      await rm(join(store.stateDir(caseId), "pending_analysis.json"), { force: true });
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      scheduleSynthesis(caseId);
    } catch (err) {
      options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
    }
  }

  // List existing cases (newest first) so the extension can present a picker of cases
  // to attach to — case CREATION lives in the dashboard, the extension only connects.
  app.get("/cases", async (_req: Request, res: Response) => {
    try {
      return res.status(200).json(await store.listCases());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Create a case. This is the one place a case is born (the dashboard's New case form and
  // `npm run`-style tooling call it); the extension no longer creates cases. Rejects a
  // duplicate id so the form can't silently clobber an existing case's metadata/evidence.
  app.post("/cases", async (req: Request, res: Response) => {
    try {
      const { caseId, name, investigator, aiProvider } = req.body ?? {};
      if (!caseId || !name) return res.status(400).json({ error: "caseId and name are required" });
      if (await store.caseExists(caseId)) return res.status(409).json({ error: `case ${caseId} already exists` });
      const meta = await store.createCase({
        caseId, name, investigator: investigator ?? "unknown", aiProvider: aiProvider ?? null,
      });
      return res.status(201).json(meta);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/captures", async (req: Request, res: Response) => {
    try {
      const metadata = await ingestCapture(store, req.body);
      res.status(201).json(metadata);
      // Evidence is always stored; AI analysis only runs when enabled for the case.
      if (!metadata.isDuplicate && options.pipeline && (await getControl(metadata.caseId)).enabled) {
        const buf = buffers.get(metadata.caseId) ?? [];
        buf.push(metadata);
        buffers.set(metadata.caseId, buf);
        if (buf.length >= windowSize || SIGNIFICANT.has(metadata.triggerType)) {
          void flush(metadata.caseId);
        }
      }
      return;
    } catch (err) {
      if (err instanceof ZodError) return res.status(400).json({ error: "invalid payload", details: err.issues });
      if (err instanceof CaseNotFoundError) {
        return res.status(404).json({ error: `case ${err.caseId} does not exist — create it in the dashboard first` });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/state", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const state = await options.stateStore.load(req.params.id);
      return res.status(200).json(state);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Serve a piece of evidence (a screenshot or an imported CSV) by filename so the
  // dashboard can link findings/events straight to the artifact they came from.
  // Strictly sandboxed: only a bare filename within the case's screenshots/ or
  // imports/ dir is allowed (no path separators, no "..").
  app.get("/cases/:id/evidence/:file", async (req: Request, res: Response) => {
    const file = req.params.file;
    if (!/^[A-Za-z0-9._-]+$/.test(file) || file.includes("..")) {
      return res.status(400).json({ error: "invalid evidence filename" });
    }
    const candidates = [
      join(store.screenshotsDir(req.params.id), file),
      join(store.importsDir(req.params.id), file),
    ];
    for (const path of candidates) {
      try {
        const buf = await readFile(path);
        res.type(evidenceContentType(file));
        res.setHeader("Cache-Control", "private, max-age=300");
        return res.send(buf);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
          return res.status(500).json({ error: (err as Error).message });
        }
      }
    }
    return res.status(404).json({ error: "evidence not found" });
  });

  app.post("/cases/:id/report", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const paths = await options.reportWriter.writeAll(req.params.id);
      return res.status(200).json(paths);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Serve a generated report file for viewing or download (export as Markdown or HTML).
  // Only the known report artifacts are served; `?download=1` forces a save dialog.
  app.get("/cases/:id/report/:file", async (req: Request, res: Response) => {
    const types: Record<string, string> = {
      "report.md": "text/markdown; charset=utf-8",
      "report.html": "text/html; charset=utf-8",
    };
    const file = req.params.file;
    if (!Object.prototype.hasOwnProperty.call(types, file)) {
      return res.status(400).json({ error: "unknown report file" });
    }
    try {
      const buf = await readFile(join(store.reportsDir(req.params.id), file));
      res.type(types[file]);
      if (req.query.download !== undefined) {
        res.setHeader("Content-Disposition", `attachment; filename="${file}"`);
      }
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(buf);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return res.status(404).json({ error: "report not generated yet — POST /cases/:id/report first" });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // The asset ↔ IoC graph (compromised assets and the IoCs that touched each), derived on
  // demand from the current state with the same scope/legitimate filtering as the report.
  app.get("/cases/:id/asset-graph", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.assetGraph(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export just the incident (forensic) timeline as CSV, generated on demand from the
  // current state (same scope/legitimate filtering as the report) — no full report needed.
  app.get("/cases/:id/incident-timeline.csv", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const csv = await options.reportWriter.incidentTimelineCsv(req.params.id);
      res.type("text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="incident-timeline.csv"');
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(csv);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Export the incident (forensic) timeline as Timesketch-compatible JSONL, generated on demand
  // from the current state (same scope/legitimate filtering as the report). Upload it into a
  // Timesketch sketch manually, or use the Push-to-Timesketch button below to do it in one click.
  app.get("/cases/:id/timeline.jsonl", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const jsonl = await options.reportWriter.timesketchJsonl(req.params.id);
      res.type("application/x-ndjson; charset=utf-8");
      res.setHeader("Content-Disposition", 'attachment; filename="timesketch-timeline.jsonl"');
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(jsonl);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Human-authored report metadata (title page, distribution, BIA, limitations, glossary,
  // recommendations…). GET returns the stored values (or defaults); PUT replaces them with a
  // normalized payload. These merge into report.md alongside the auto-derived sections.
  app.get("/cases/:id/report-meta", async (req: Request, res: Response) => {
    if (!options.reportMetaStore) return res.status(501).json({ error: "report metadata not configured" });
    try {
      return res.status(200).json(await options.reportMetaStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/report-meta", async (req: Request, res: Response) => {
    if (!options.reportMetaStore) return res.status(501).json({ error: "report metadata not configured" });
    try {
      const saved = await options.reportMetaStore.save(req.params.id, req.body);
      return res.status(200).json(saved);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Whether a DFIR-IRIS push target is configured (so the dashboard can show/hide the button).
  app.get("/iris/status", (_req: Request, res: Response) => {
    res.status(200).json({ configured: !!options.irisClient, baseUrl: options.irisOptions?.baseUrl });
  });

  // Push a case to DFIR-IRIS: find-or-create the case by name, then push assets→assets,
  // IOCs→IOCs, forensic timeline→timeline, executive summary→case summary, everything else→notes.
  app.post("/cases/:id/push/iris", async (req: Request, res: Response) => {
    if (!options.irisClient) return res.status(501).json({ error: "DFIR-IRIS not configured (set DFIR_IRIS_URL and DFIR_IRIS_KEY)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      const meta = options.reportMetaStore ? await options.reportMetaStore.load(caseId) : undefined;
      logLine(`[iris] ${caseId} push START`);
      const result = await pushCaseToIris(options.irisClient, { caseName: caseId, state, meta }, options.irisOptions);
      logLine(`[iris] ${caseId} push DONE -> case ${result.caseId} (${result.created ? "created" : "updated"}); ` +
        `assets +${result.assets.added}/${result.assets.existing}, iocs +${result.iocs.added}/${result.iocs.existing}, ` +
        `timeline +${result.timeline.added}/${result.timeline.existing}, tasks +${result.tasks.added}/${result.tasks.existing}, ` +
        `notes ${result.notes}, warnings ${result.warnings.length}`);
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
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[timesketch] ${caseId} push ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // AI analysis on/off per case. GET reads it; POST { enabled } sets it. Turning it
  // ON triggers a background backfill of everything captured while it was off.
  app.get("/cases/:id/ai-control", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await getControl(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/ai-control", async (req: Request, res: Response) => {
    try {
      const enabled = Boolean(req.body?.enabled);
      const prev = await getControl(req.params.id);
      const next = await setControl(req.params.id, { enabled });
      if (!enabled) {
        buffers.set(req.params.id, []); // drop pending buffer when pausing
        options.onAiStatus?.(req.params.id, { status: "idle", at: new Date().toISOString(), detail: "AI paused" });
      } else if (!prev.enabled) {
        void backfill(req.params.id); // resumed → analyze the gap
      }
      return res.status(200).json(next);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Client-confirmed legitimate findings/IOCs (false positives). Marking one
  // re-runs synthesis so the AI re-derives its conclusions without it.
  const legitimate = new LegitimateStore(store);

  // Threat-intel enrichment is OFF by default (OPSEC). When the analyst turns it on it
  // enriches the current IOCs and — via autoEnrichIfEnabled below — any IOCs added later.
  const enrichControl = new EnrichControlStore(store);

  // Provider classification (from the configured set) + the per-case enabled subset.
  const allProviders = options.enrichmentProviders ?? [];
  const configuredNames = allProviders.map((p) => p.name);
  const localNames = allProviders.filter((p) => p.scope === "local").map((p) => p.name);
  async function enabledProvidersFor(caseId: string): Promise<EnrichmentProvider[]> {
    const enabled = new Set(resolveEnabledProviders(await enrichControl.load(caseId), configuredNames, localNames));
    return allProviders.filter((p) => enabled.has(p.name));
  }

  function enrichInBackground(caseId: string, force = false): void {
    if (allProviders.length === 0 || !options.stateStore) return;
    void (async () => {
      const providers = await enabledProvidersFor(caseId);
      if (providers.length === 0) return;     // nothing enabled for this case
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `enriching IOCs (${providers.map((p) => p.name).join(", ")})` });
      const state = await options.stateStore!.load(caseId);
      logLine(`[enrich] ${caseId} START providers=[${providers.map((p) => p.name).join(", ")}] force=${force} iocs=${state.iocs.length}`);
      const { iocs, summary } = await enrichIocs(state.iocs, {
        providers,
        delayMs: options.enrichDelayMs,
        maxIocs: options.enrichMaxIocs,
        force,
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `enriching IOC ${done}/${total}`,
        }),
        // One audit line per outbound threat-intel API call: which provider, indicator, result.
        onLookup: (e: EnrichLookupEvent) => logLine(
          `[enrich] ${caseId} ${e.provider} ${e.kind} ${shortValue(e.value)} -> ${e.outcome}${e.detail ? ` (${e.detail})` : ""} ${e.ms}ms`,
        ),
      });
      logLine(`[enrich] ${caseId} DONE queried=${summary.queried} hits=${summary.withHits} errors=${summary.errors} skipped=${summary.skipped}`);
      // Re-load + write only the iocs so we don't clobber a concurrent state change.
      const latest = await options.stateStore!.load(caseId);
      const byValue = new Map(iocs.map((i) => [i.value, i]));
      let merged = { ...latest, iocs: latest.iocs.map((i) => byValue.get(i.value) ?? i), updatedAt: new Date().toISOString() };

      // Process-chain validation: if a RockyRaccoon provider is present, validate
      // parent→child relationships on the forensic timeline (anomalous chains are a
      // strong signal). Uses the same throttle/cap as IOC enrichment.
      const rocky = providers.find((p): p is EnrichmentProvider & { checkParentChild: (p: string, c: string) => Promise<ParentChildResult | null> } =>
        typeof (p as { checkParentChild?: unknown }).checkParentChild === "function");
      let chainSummary: ChainSummary | undefined;
      if (rocky) {
        const { events, summary: cs } = await validateProcessChains(merged.forensicTimeline, {
          check: (p, c) => rocky.checkParentChild(p, c),
          delayMs: options.enrichDelayMs,
          maxChecks: options.enrichMaxIocs,
          force,
        });
        merged = { ...merged, forensicTimeline: events };
        chainSummary = cs;
      }

      await options.stateStore!.save(merged);
      options.onState?.(merged);
      const chainNote = chainSummary ? `; chains ${chainSummary.anomalies} anomalous/${chainSummary.checked}` : "";
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `enriched ${summary.withHits}/${summary.queried} (errors ${summary.errors})${chainNote}` });
    })().catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
  }

  // After IOCs change (synthesis/import), enrich the new ones if the toggle is on. The
  // cache means already-enriched IOCs are skipped, so this only queries fresh indicators.
  function autoEnrichIfEnabled(caseId: string): void {
    if (allProviders.length === 0) return;
    enabledProvidersFor(caseId).then((ps) => { if (ps.length > 0) enrichInBackground(caseId); }).catch(() => {});
  }

  function resynthesizeInBackground(caseId: string): void {
    if (!options.pipeline) return;
    options.onAiStatus?.(caseId, { status: "analyzing", phase: "synthesizing", at: new Date().toISOString(), detail: "re-synthesizing without legitimate items" });
    options.pipeline.synthesize(caseId)
      .then(() => { options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }); autoEnrichIfEnabled(caseId); })
      .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
  }

  app.get("/cases/:id/legitimate", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await legitimate.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/legitimate", async (req: Request, res: Response) => {
    try {
      const rawKind = req.body?.kind;
      const kind: LegitimateMarker["kind"] =
        rawKind === "ioc" ? "ioc" : rawKind === "event" ? "event" : "finding";
      const ref = String(req.body?.ref ?? "").trim();
      if (!ref) return res.status(400).json({ error: "ref is required" });
      const note = String(req.body?.note ?? "");
      // Optional human-readable label (e.g. a forensic event's description) so the
      // "Confirmed Legitimate" panel can show something meaningful for opaque ids.
      const label = req.body?.label != null ? String(req.body.label) : undefined;
      const markers = await legitimate.load(req.params.id);
      const id = markerId(kind, ref);
      const marker: LegitimateMarker = { id, kind, ref, note, markedAt: new Date().toISOString(), ...(label ? { label } : {}) };
      const next = [...markers.filter((m) => m.id !== id), marker];
      await legitimate.save(req.params.id, next);
      resynthesizeInBackground(req.params.id); // re-derive conclusions without it
      return res.status(200).json(next);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
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
      const state = await options.stateStore.load(caseId);
      const forensicTimeline = [...state.forensicTimeline, event].sort(byEventTime);
      const next = { ...state, forensicTimeline, updatedAt: new Date().toISOString() };
      await options.stateStore.save(next);
      options.onState?.(next);
      resynthesizeInBackground(caseId);
      logLine(`[manual] ${caseId} added event ${event.id} (${event.severity})`);
      return res.status(201).json(event);
    } catch (err) {
      if (err instanceof ZodError) return res.status(400).json({ error: err.issues.map((i) => i.message).join("; ") });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Manually add an IOC the AI didn't catch. Appended to the case IOCs (deduped by value) and
  // enriched if enrichment is enabled for the case.
  app.post("/cases/:id/iocs", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    try {
      const ioc = buildManualIoc(req.body);
      const state = await options.stateStore.load(caseId);
      if (state.iocs.some((i) => i.value.toLowerCase() === ioc.value.toLowerCase())) {
        return res.status(409).json({ error: `IOC already exists: ${ioc.value}` });
      }
      const next = { ...state, iocs: [...state.iocs, ioc], updatedAt: new Date().toISOString() };
      await options.stateStore.save(next);
      options.onState?.(next);
      autoEnrichIfEnabled(caseId);
      logLine(`[manual] ${caseId} added ioc ${ioc.id} (${ioc.type})`);
      return res.status(201).json(ioc);
    } catch (err) {
      if (err instanceof ZodError) return res.status(400).json({ error: err.issues.map((i) => i.message).join("; ") });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/legitimate/remove", async (req: Request, res: Response) => {
    try {
      const id = String(req.body?.id ?? "");
      const markers = await legitimate.load(req.params.id);
      const next = markers.filter((m) => m.id !== id);
      await legitimate.save(req.params.id, next);
      resynthesizeInBackground(req.params.id);
      return res.status(200).json(next);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Investigation time-window. Setting it re-synthesizes so out-of-scope events
  // (and the findings/IOCs derived from them) drop out of the analysis.
  const scopeStore = new ScopeStore(store);

  app.get("/cases/:id/scope", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await scopeStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/scope", async (req: Request, res: Response) => {
    try {
      const norm = (v: unknown): string | null => {
        const s = String(v ?? "").trim();
        if (!s) return null;
        const t = Date.parse(s);
        return Number.isNaN(t) ? null : new Date(t).toISOString();
      };
      const scope: ScopeWindow = { start: norm(req.body?.start), end: norm(req.body?.end) };
      await scopeStore.save(req.params.id, scope);
      resynthesizeInBackground(req.params.id); // re-derive within the window
      return res.status(200).json(scope);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a CSV result export (e.g. a Velociraptor artifact) as evidence and analyze
  // it like captured screenshots: extract dated forensic events + IOCs into the
  // timeline, then synthesize findings/TTPs/attacker-path. Evidence-first: the raw
  // CSV is persisted + audit-logged BEFORE any analysis; analysis runs in background.
  app.post("/cases/:id/import-csv", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
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
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
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

  // Threat-intel enrichment toggle (per case, default OFF for OPSEC). GET reads the
  // current state. POST { enabled } turns it on/off; turning it ON enriches the current
  // IOCs immediately AND auto-enriches any IOCs added later (imports/synthesis).
  // ⚠ Enrichment sends indicators to third-party services (VirusTotal/MalwareBazaar/
  // AbuseIPDB) — that's why it is off until the analyst opts in.
  app.get("/cases/:id/enrich-control", async (req: Request, res: Response) => {
    try {
      const enabled = new Set(resolveEnabledProviders(await enrichControl.load(req.params.id), configuredNames, localNames));
      return res.status(200).json({
        anyConfigured: allProviders.length > 0,
        // Each CONFIGURED provider with its scope (local = OPSEC-safe) and whether it's on for this case.
        providers: allProviders.map((p) => ({ name: p.name, scope: p.scope, enabled: enabled.has(p.name) })),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Set which providers are enabled for this case. Accepts `{ providers: string[] }`
  // (preferred) or legacy `{ enabled: boolean }`. Saving re-runs enrichment; per-provider
  // caching means only the newly-enabled providers query the existing IOCs.
  app.post("/cases/:id/enrich-control", async (req: Request, res: Response) => {
    if (allProviders.length === 0) return res.status(501).json({ error: "no enrichment providers configured (set DFIR_VT_KEY / DFIR_MB_KEY / DFIR_ABUSEIPDB_KEY / DFIR_MISP_* / DFIR_YETI_*)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    let providers: string[];
    if (Array.isArray(req.body?.providers)) providers = req.body.providers.map(String).filter((n: string) => configuredNames.includes(n));
    else if (typeof req.body?.enabled === "boolean") providers = req.body.enabled ? [...configuredNames] : [];
    else return res.status(400).json({ error: "providers (array of provider names) or enabled (boolean) is required" });
    try {
      await enrichControl.save(caseId, { providers });
      if (providers.length > 0) enrichInBackground(caseId);   // re-check; cache only queries newly-enabled / un-checked
      return res.status(200).json({ providers });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Manual one-shot re-scan (e.g. force re-query). Honors the same providers; does NOT
  // change the toggle. `{ force: true }` re-queries already-enriched IOCs.
  app.post("/cases/:id/enrich", async (req: Request, res: Response) => {
    const providers = options.enrichmentProviders ?? [];
    if (providers.length === 0) return res.status(501).json({ error: "no enrichment providers configured (set DFIR_VT_KEY / DFIR_MB_KEY / DFIR_ABUSEIPDB_KEY)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    const force = req.body?.force === true || req.query.force === "true";
    try {
      const state = await options.stateStore.load(caseId);
      enrichInBackground(caseId, force);
      return res.status(202).json({ accepted: true, iocs: state.iocs.length, providers: providers.map((p) => p.name) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // On-demand holistic synthesis: derive findings / MITRE / attacker path from the
  // forensic timeline. (Per-window capture builds the timeline; this writes the
  // conclusions.) Broadcasts the updated state to dashboard clients via onState.
  app.post("/cases/:id/synthesize", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    options.onAiStatus?.(caseId, { status: "analyzing", at: new Date().toISOString(), detail: "synthesizing conclusions" });
    try {
      // Explicit user action → force, so it always runs even if inputs are unchanged.
      const state = await options.pipeline.synthesize(caseId, { force: true });
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      return res.status(200).json({
        findings: state.findings.length,
        mitreTechniques: state.mitreTechniques.length,
        forensicEvents: state.forensicTimeline.length,
        attackerPath: Boolean(state.attackerPath),
      });
    } catch (err) {
      options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Ask the AI a free-form question about the case ("was data exfiltrated?"). Single-shot,
  // no state change — returns a grounded answer + status + collection guidance (`pointer`).
  app.post("/cases/:id/ask", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const question = typeof req.body?.question === "string" ? req.body.question.trim() : "";
    if (!question) return res.status(400).json({ error: "question is required" });
    try {
      const answer = await options.pipeline.ask(req.params.id, question);
      return res.status(200).json(answer);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Add an analyst question to the case's open key questions (e.g. from Ask, when unknown).
  // It's pinned, so synthesis preserves it and answers it once the evidence supports it.
  app.post("/cases/:id/questions", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const question = typeof req.body?.question === "string" ? req.body.question.trim() : "";
    if (!question) return res.status(400).json({ error: "question is required" });
    const statusIn = String(req.body?.status ?? "unknown");
    const status: QuestionStatus = statusIn === "answered" || statusIn === "partial" ? statusIn : "unknown";
    try {
      const state = await options.stateStore.load(req.params.id);
      const nums = state.keyQuestions.map((q) => Number(/^aq(\d+)$/.exec(q.id)?.[1])).filter((n) => !Number.isNaN(n));
      const newQuestion: InvestigationQuestion = {
        id: `aq${(nums.length ? Math.max(...nums) : 0) + 1}`,
        question,
        status,
        answer: typeof req.body?.answer === "string" ? req.body.answer : "",
        pointer: typeof req.body?.pointer === "string" ? req.body.pointer : "",
        pinned: true,
      };
      const next = { ...state, keyQuestions: [...state.keyQuestions, newQuestion] };
      await options.stateStore.save(next);
      options.onState?.(next);
      return res.status(201).json(newQuestion);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Investigator comments on case entities (collaboration). GET lists them; POST adds one
  // to a `(targetType, targetId)` entity; DELETE removes by id. Add/remove ping live clients.
  app.get("/cases/:id/comments", async (req: Request, res: Response) => {
    if (!options.commentsStore) return res.status(501).json({ error: "comments not configured" });
    try {
      return res.status(200).json(await options.commentsStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/comments", async (req: Request, res: Response) => {
    if (!options.commentsStore) return res.status(501).json({ error: "comments not configured" });
    const targetType = typeof req.body?.targetType === "string" ? req.body.targetType.trim() : "";
    const targetId = typeof req.body?.targetId === "string" ? req.body.targetId.trim() : "";
    const text = typeof req.body?.text === "string" ? req.body.text.trim() : "";
    if (!targetType || !targetId || !text) return res.status(400).json({ error: "targetType, targetId and text are required" });
    try {
      const comment = await options.commentsStore.add(req.params.id, {
        targetType, targetId, text,
        author: typeof req.body?.author === "string" ? req.body.author : "",
      });
      options.onComments?.(req.params.id);
      return res.status(201).json(comment);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/comments/:commentId", async (req: Request, res: Response) => {
    if (!options.commentsStore) return res.status(501).json({ error: "comments not configured" });
    try {
      const removed = await options.commentsStore.remove(req.params.id, req.params.commentId);
      if (!removed) return res.status(404).json({ error: "comment not found" });
      options.onComments?.(req.params.id);
      return res.status(204).end();
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  return app;
}

import { StateStore as StateStoreImpl } from "./analysis/stateStore.js";
import { AnalysisPipeline as AnalysisPipelineImpl } from "./analysis/pipeline.js";
import { makeImageLoader } from "./analysis/imageLoader.js";
import { ProviderRegistry } from "./providers/provider.js";
import type { AIProvider as AnalyzeProvider } from "./providers/provider.js";
import { OpenAIProvider } from "./providers/openai.js";
import { OpenRouterProvider } from "./providers/openrouter.js";
import { OllamaCloudProvider } from "./providers/ollama.js";
import { LiteLlmProvider } from "./providers/litellm.js";
import { GeminiProvider } from "./providers/gemini.js";
import { WebSocketServer } from "ws";
import { LiveHub } from "./live/hub.js";
import { ReportWriter as ReportWriterImpl } from "./reports/reportWriter.js";

export interface ProviderParams {
  provider?: string;
  model?: string;
  apiKey?: string;
  imageDetail?: "high" | "low" | "auto";
  timeoutMs?: number;
  maxTokens?: number;
  // Override the provider's API base URL. Required for a self-hosted LiteLLM proxy
  // (and any OpenAI-compatible local endpoint); each provider keeps its own default
  // when this is unset. Empty string is treated as unset.
  baseUrl?: string;
}

// Build a provider from explicit params (so callers can build more than one,
// e.g. a cheap extraction model + a stronger synthesis model).
export function buildProviderFrom(params: ProviderParams): AnalyzeProvider | undefined {
  const name = params.provider;
  if (!name) return undefined;
  const model = params.model ?? "";
  const apiKey = params.apiKey ?? "";
  const imageDetail = params.imageDetail ?? "high";
  // Empty string → undefined so each provider falls back to its built-in default.
  const baseUrl = params.baseUrl?.trim() || undefined;
  // Strong models over a large timeline can take >60s — make the request timeout tunable.
  const timeoutMs = params.timeoutMs ?? (Number(process.env.DFIR_AI_TIMEOUT_MS) || 180_000);
  // Bound completion tokens. Without this, OpenRouter reserves the model's full max
  // output for its per-request credit check and can 402 a large request (e.g. THOR
  // synthesis) even when the account has credits. Tunable via DFIR_AI_MAX_TOKENS.
  const maxTokens = params.maxTokens ?? (Number(process.env.DFIR_AI_MAX_TOKENS) || 16000);
  const registry = new ProviderRegistry();
  registry.register(new OpenAIProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens }));
  registry.register(new OpenRouterProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens }));
  registry.register(new OllamaCloudProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens }));
  registry.register(new LiteLlmProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens }));
  registry.register(new GeminiProvider({ apiKey, model, baseUrl, timeoutMs, maxTokens }));
  return registry.get(name);
}

export function buildProvider(): AnalyzeProvider | undefined {
  return buildProviderFrom({
    provider: process.env.DFIR_AI_PROVIDER,
    model: process.env.DFIR_AI_MODEL,
    apiKey: process.env.DFIR_AI_KEY,
    baseUrl: process.env.DFIR_AI_BASE_URL,
    imageDetail: process.env.DFIR_AI_IMAGE_DETAIL as "high" | "low" | "auto" | undefined,
  });
}

// Synthesis model: dedicated DFIR_AI_SYNTH_* vars, falling back to the main model.
export function buildSynthesisProvider(): AnalyzeProvider | undefined {
  return buildProviderFrom({
    provider: process.env.DFIR_AI_SYNTH_PROVIDER ?? process.env.DFIR_AI_PROVIDER,
    model: process.env.DFIR_AI_SYNTH_MODEL ?? process.env.DFIR_AI_MODEL,
    apiKey: process.env.DFIR_AI_SYNTH_KEY ?? process.env.DFIR_AI_KEY,
    baseUrl: process.env.DFIR_AI_SYNTH_BASE_URL ?? process.env.DFIR_AI_BASE_URL,
    imageDetail: process.env.DFIR_AI_IMAGE_DETAIL as "high" | "low" | "auto" | undefined,
  });
}

// Build the threat-intel enrichment providers from env. Each is added only when its key
// is present (MalwareBazaar needs DFIR_MB_KEY for its API). Empty array → enrichment off.
// Optional per-provider TLS trust for a self-hosted intel host with an internal-CA or
// self-signed cert. Returns undefined (→ default, fully-verified global fetch) unless a
// DFIR_<NAME>_CA bundle or DFIR_<NAME>_INSECURE flag is set. Scoped to that provider only.
function tlsFetchFor(name: "MISP" | "YETI" | "IRIS" | "TIMESKETCH") {
  return buildTlsFetch({
    caCertPath: process.env[`DFIR_${name}_CA`],
    insecureSkipVerify: isEnvFlag(process.env[`DFIR_${name}_INSECURE`]),
    onWarn: (m) => warnLine(`[DFIR] ${name}: ${m}`),
  });
}

function isEnvFlag(value: string | undefined): boolean {
  return /^(1|true|yes|on)$/i.test(value ?? "");
}

// Build the DFIR-IRIS push client from env (DFIR_IRIS_URL + DFIR_IRIS_KEY). Returns
// undefined when not configured, which hides the dashboard's "Push to IRIS" button.
// TLS trust for a self-hosted IRIS honors DFIR_IRIS_CA / DFIR_IRIS_INSECURE.
export function buildIrisClient(): IrisClient | undefined {
  const baseUrl = process.env.DFIR_IRIS_URL;
  const apiKey = process.env.DFIR_IRIS_KEY;
  if (!baseUrl || !apiKey) return undefined;
  return new IrisClient({ baseUrl, apiKey, fetchFn: tlsFetchFor("IRIS") });
}

export function irisPushOptions(): IrisPushOptions {
  return {
    baseUrl: process.env.DFIR_IRIS_URL,
    customerId: Number(process.env.DFIR_IRIS_CUSTOMER_ID) || undefined,
    classificationId: Number(process.env.DFIR_IRIS_CLASSIFICATION_ID) || undefined,
  };
}

// Build the Timesketch push client from env (DFIR_TIMESKETCH_URL + USER + PASSWORD). Returns
// undefined when not configured, which hides the dashboard's "Push to Timesketch" button. TLS
// trust for a self-hosted Timesketch honors DFIR_TIMESKETCH_CA / DFIR_TIMESKETCH_INSECURE.
export function buildTimesketchClient(): TimesketchClient | undefined {
  const baseUrl = process.env.DFIR_TIMESKETCH_URL;
  const username = process.env.DFIR_TIMESKETCH_USER;
  const password = process.env.DFIR_TIMESKETCH_PASSWORD;
  if (!baseUrl || !username || !password) return undefined;
  return new TimesketchClient({ baseUrl, username, password, fetchFn: tlsFetchFor("TIMESKETCH") });
}

export function timesketchPushOptions(): TimesketchPushOptions {
  return {
    baseUrl: process.env.DFIR_TIMESKETCH_URL,
    timelineName: process.env.DFIR_TIMESKETCH_TIMELINE || undefined,
  };
}

export function buildEnrichmentProviders(): EnrichmentProvider[] {
  const providers: EnrichmentProvider[] = [];
  if (process.env.DFIR_VT_KEY) providers.push(new VirusTotalProvider({ apiKey: process.env.DFIR_VT_KEY }));
  if (process.env.DFIR_MB_KEY) providers.push(new MalwareBazaarProvider({ apiKey: process.env.DFIR_MB_KEY }));
  if (process.env.DFIR_ABUSEIPDB_KEY) providers.push(new AbuseIpdbProvider({ apiKey: process.env.DFIR_ABUSEIPDB_KEY }));
  if (process.env.DFIR_MISP_URL && process.env.DFIR_MISP_KEY) providers.push(new MispProvider({ baseUrl: process.env.DFIR_MISP_URL, apiKey: process.env.DFIR_MISP_KEY, fetchFn: tlsFetchFor("MISP") }));
  if (process.env.DFIR_ROCKYRACCOON_KEY) providers.push(new RockyRaccoonProvider({ apiKey: process.env.DFIR_ROCKYRACCOON_KEY }));
  if (process.env.DFIR_YETI_URL && process.env.DFIR_YETI_KEY) providers.push(new YetiProvider({ baseUrl: process.env.DFIR_YETI_URL, apiKey: process.env.DFIR_YETI_KEY, fetchFn: tlsFetchFor("YETI") }));
  return providers;
}

export function startServer(casesRoot: string, port = 4773): void {
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStoreImpl(store);
  const hub = new LiveHub();
  const reportMetaStore = new ReportMetaStore(store);
  const commentsStore = new CommentsStore(store);
  const reportWriter = new ReportWriterImpl(store, stateStore, new ScopeStore(store), new LegitimateStore(store), reportMetaStore);

  const provider = buildProvider();
  const synthesisProvider = buildSynthesisProvider();
  const wiredPipeline = provider
    ? new AnalysisPipelineImpl({ provider, synthesisProvider, stateStore, legitimateStore: new LegitimateStore(store), scopeStore: new ScopeStore(store), imageLoader: makeImageLoader(store), onState: (s) => hub.broadcast(s) })
    : undefined;

  // Live synthesis on by default — set DFIR_AI_AUTO_SYNTHESIZE=off to disable.
  const autoSynthesize = (process.env.DFIR_AI_AUTO_SYNTHESIZE ?? "on").toLowerCase() !== "off";
  const autoSynthesizeDebounceMs = Number(process.env.DFIR_AI_AUTO_SYNTHESIZE_MS) || 8000;

  const app = createApp(store, {
    pipeline: wiredPipeline,
    stateStore,
    reportWriter,
    reportMetaStore,
    commentsStore,
    onComments: (caseId) => hub.broadcastTo(caseId, { type: "comments_changed" }),
    autoSynthesize,
    autoSynthesizeDebounceMs,
    onAiStatus: (caseId, event) => hub.broadcastTo(caseId, { type: "ai_status", ...event }),
    onState: (s) => hub.broadcast(s),
    enrichmentProviders: buildEnrichmentProviders(),
    enrichDelayMs: Number(process.env.DFIR_ENRICH_DELAY_MS) || undefined,
    enrichMaxIocs: Number(process.env.DFIR_ENRICH_MAX) || undefined,
    irisClient: buildIrisClient(),
    irisOptions: irisPushOptions(),
    timesketchClient: buildTimesketchClient(),
    timesketchOptions: timesketchPushOptions(),
  });

  // Serve the logo + favicons from public/ (the dashboard <head> links these). Whitelisted
  // filenames only; browsers that auto-request /favicon.ico get the crisp 32px PNG.
  const iconFiles: Record<string, string> = {
    "/dfir-companion-logo.jpg": "image/jpeg",
    "/favicon-16.png": "image/png",
    "/favicon-32.png": "image/png",
    "/apple-touch-icon.png": "image/png",
    "/favicon.ico": "image/png",            // alias → favicon-32.png
  };
  for (const [route, type] of Object.entries(iconFiles)) {
    app.get(route, async (_req, res) => {
      const file = route === "/favicon.ico" ? "/favicon-32.png" : route;
      try {
        const buf = await readFile(new URL("../../public" + file, import.meta.url));
        res.type(type).set("Cache-Control", "public, max-age=86400").send(buf);
      } catch {
        res.status(404).end();
      }
    });
  }

  // Serve the dashboard.
  app.get("/dashboard", async (_req, res) => {
    const html = await readFile(new URL("../../public/dashboard.html", import.meta.url), "utf8");
    res.type("html").send(html);
  });

  const server = app.listen(port, "127.0.0.1", () => {
    logLine(`DFIR companion on http://127.0.0.1:${port} (dashboard at /dashboard)`);
  });

  // Friendly message instead of an unhandled-error stack trace when the port is taken.
  server.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      console.error(
        `\n[DFIR] Port ${port} is already in use — a DFIR companion is probably already running.\n` +
          `       Use the existing one (http://127.0.0.1:${port}/dashboard), or stop it first:\n` +
          `       PowerShell:  Get-NetTCPConnection -LocalPort ${port} -State Listen | ` +
          `ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }\n`,
      );
      process.exit(1);
    }
    throw err;
  });

  const wss = new WebSocketServer({ server, path: "/ws" });
  wss.on("connection", (socket, req) => {
    const caseId = new URL(req.url ?? "", "http://localhost").searchParams.get("caseId") ?? "";
    hub.subscribe(caseId, socket as unknown as import("./live/hub.js").SocketLike);
    socket.on("close", () => hub.unsubscribe(caseId, socket as unknown as import("./live/hub.js").SocketLike));
  });
}

// Entry point when run directly. Load companion/.env so users can keep config
// (AI provider/model/key, cases root) in a file instead of typing env vars.
if (process.argv[1] && process.argv[1].endsWith("server.ts")) {
  loadDotenv();
  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  // Anchor a relative cases root to the companion package directory, so the SAME
  // physical folder is used no matter which directory the server is launched from.
  // (Otherwise "./cases" resolves against cwd and you can end up with two folders.)
  const companionDir = fileURLToPath(new URL("../", import.meta.url)); // .../companion/
  const casesRoot = isAbsolute(raw) ? raw : resolve(companionDir, raw);
  logLine(`[DFIR] cases root: ${casesRoot}`);

  // Port can be overridden via DFIR_PORT (1-65535). Invalid → fall back to default
  // with a warning so a typo doesn't silently bind the wrong port.
  const DEFAULT_PORT = 4773;
  const rawPort = process.env.DFIR_PORT;
  let port = DEFAULT_PORT;
  if (rawPort !== undefined && rawPort !== "") {
    const parsed = Number(rawPort);
    if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535) {
      port = parsed;
    } else {
      warnLine(`[DFIR] ignoring invalid DFIR_PORT="${rawPort}" — using default ${DEFAULT_PORT}.`);
    }
  }
  startServer(casesRoot, port);
}
