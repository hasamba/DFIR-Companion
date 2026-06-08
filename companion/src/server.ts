import express, { type Express, type Request, type Response, type NextFunction } from "express";
import { config as loadDotenv } from "dotenv";
import { join, isAbsolute, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFile, readFile, rm } from "node:fs/promises";
import { ZodError } from "zod";
import { CaseStore, isValidCaseId } from "./storage/caseStore.js";
import { ingestCapture, CaseNotFoundError } from "./ingest/captureIngest.js";
import { AiControlStore, type AiControl } from "./analysis/aiControl.js";
import { AnonControlStore, type AnonControl } from "./analysis/anonControl.js";
import { CustomEntitiesStore, sanitizeCustomEntities } from "./analysis/anonEntities.js";
import { isLocalAiProvider, deriveKnownEntities } from "./analysis/anonymize.js";
import { LegitimateStore, markerId, type LegitimateMarker } from "./analysis/legitimate.js";
import { ScopeStore, type ScopeWindow } from "./analysis/scope.js";
import { parseCsv } from "./analysis/csvImport.js";
import { contextTokens as resolveContextTokens } from "./analysis/promptBudget.js";
import { resolveHuntPlatforms, HUNT_PLATFORMS, type HuntPlatform } from "./analysis/huntPlatforms.js";
import { parseLogLines } from "./analysis/logImport.js";
import { parseThorReport } from "./analysis/thorImport.js";
import { parseSiemExport } from "./analysis/siemImport.js";
import type { SiemImportOptions } from "./analysis/siemImport.js";
import { parseChainsawReport } from "./analysis/chainsawImport.js";
import type { ChainsawImportOptions } from "./analysis/chainsawImport.js";
import { parseHayabusaTimeline } from "./analysis/hayabusaImport.js";
import type { HayabusaImportOptions } from "./analysis/hayabusaImport.js";
import { parseVelociraptorJson } from "./analysis/velociraptorImport.js";
import type { VelociraptorImportOptions } from "./analysis/velociraptorImport.js";
import { parseNetworkLogs } from "./analysis/networkImport.js";
import type { NetworkImportOptions } from "./analysis/networkImport.js";
import { parseKapeCsv } from "./analysis/kapeImport.js";
import type { KapeImportOptions } from "./analysis/kapeImport.js";
import { parseCybertriage } from "./analysis/cybertriageImport.js";
import type { CybertriageImportOptions } from "./analysis/cybertriageImport.js";
import { parseM365Audit } from "./analysis/m365Import.js";
import type { M365ImportOptions } from "./analysis/m365Import.js";
import { parseCloudTrail } from "./analysis/awsImport.js";
import type { AwsImportOptions } from "./analysis/awsImport.js";
import { parseCloudActivity } from "./analysis/cloudActivityImport.js";
import type { CloudActivityImportOptions } from "./analysis/cloudActivityImport.js";
import { parsePlasoCsv } from "./analysis/plasoImport.js";
import type { PlasoImportOptions } from "./analysis/plasoImport.js";
import { parseSandboxReport } from "./analysis/sandboxImport.js";
import type { SandboxImportOptions } from "./analysis/sandboxImport.js";
import { detectImportKind } from "./analysis/importDetect.js";
import { parseMinSeverity } from "./analysis/severityFloor.js";
import { enrichIocs, type EnrichLookupEvent } from "./enrichment/enrichService.js";
import { EnrichControlStore, resolveEnabledProviders } from "./enrichment/enrichControl.js";
import { ProviderHealthCache } from "./enrichment/providerHealth.js";
import type { EnrichmentProvider } from "./enrichment/provider.js";
import { VirusTotalProvider } from "./enrichment/virustotal.js";
import { HuntingChProvider } from "./enrichment/huntingch.js";
import { CrowdStrikeProvider } from "./enrichment/crowdstrike.js";
import { AbuseIpdbProvider } from "./enrichment/abuseipdb.js";
import { MispProvider } from "./enrichment/misp.js";
import { RockyRaccoonProvider, type ParentChildResult } from "./enrichment/rockyraccoon.js";
import { YetiProvider } from "./enrichment/yeti.js";
import { buildTlsFetch } from "./enrichment/tlsFetch.js";
import { validateProcessChains, type ChainSummary } from "./enrichment/chainValidate.js";
import type { AnalysisPipeline } from "./analysis/pipeline.js";
import type { InvestigationState, InvestigationQuestion, QuestionStatus, Severity, ForensicEvent, IOC } from "./analysis/stateTypes.js";
import type { CaptureMetadata } from "./types.js";
import type { StateStore } from "./analysis/stateStore.js";
import type { ReportWriter } from "./reports/reportWriter.js";
import { ReportMetaStore } from "./reports/reportMeta.js";
import { injectPrintTrigger } from "./reports/html.js";
import { CommentsStore } from "./analysis/comments.js";
import { TagsStore } from "./analysis/tags.js";
import { SynthMetaStore } from "./analysis/synthMeta.js";
import { ImportMetaStore } from "./analysis/importMeta.js";
import { TemplateStore, buildInitialQuestions } from "./analysis/templateStore.js";
import { diffTimeline } from "./analysis/timelineDiff.js";
import { diffIocs } from "./analysis/iocsDiff.js";
import { readPublicAsset, isSeaRuntime } from "./serverAssets.js";
import { buildManualEvent, buildManualIoc } from "./analysis/manualEntry.js";
import { CustomerStore, parseList, sanitizeTargets } from "./analysis/customerStore.js";
import {
  buildCustomerExposureTargets,
  CustomerExposureStore,
  summarizeExposure,
  type CustomerExposureProvider,
} from "./analysis/customerExposure.js";
import { byEventTime } from "./analysis/forensicSort.js";
import { IrisClient } from "./integrations/iris/irisClient.js";
import { VelociraptorClient, buildVelociraptorClient } from "./integrations/velociraptor/velociraptorApi.js";
import { pushCaseToIris, type IrisPushOptions } from "./integrations/iris/irisPush.js";
import { TimesketchClient } from "./integrations/timesketch/timesketchClient.js";
import { pushCaseToTimesketch, type TimesketchPushOptions } from "./integrations/timesketch/timesketchPush.js";
import {
  DeHashedExposureProvider,
  HaveIBeenPwnedExposureProvider,
  LeakCheckExposureProvider,
  ShodanExposureProvider,
} from "./integrations/customerExposureProviders.js";

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
  aiConfigured?: boolean;
  windowSize?: number;
  // Safety-net flush interval. A `timer`/`click` capture buffers until `windowSize`
  // accumulates (only a `navigation`/`tab_switch` flushes early), so a lone screenshot could
  // sit unanalyzed indefinitely. A background sweep drains any non-empty buffer on this
  // interval so even a single capture is analyzed. Default 5 min; set 0 to disable.
  flushIntervalMs?: number;
  stateStore?: StateStore;
  reportWriter?: ReportWriter;
  // Human-authored report metadata (title page, distribution, BIA, glossary, recommendations…)
  // edited from the dashboard and merged into report.md.
  reportMetaStore?: ReportMetaStore;
  // Investigator comments on case entities (collaboration). onComments pings dashboard
  // clients over the WS to re-fetch when a comment is added/removed.
  commentsStore?: CommentsStore;
  onComments?: (caseId: string) => void;
  // Analyst triage tags on case entities (hand labels like confirmed-malicious / false-positive
  // / key-evidence, independent of AI severity). onTags pings dashboard clients over the WS to
  // re-fetch when a tag is added/removed.
  tagsStore?: TagsStore;
  onTags?: (caseId: string) => void;
  // Last-synthesis record (when it ran + findings diff) for the dashboard's "last synthesized N
  // ago" indicator and what-changed view. Read-only here; the pipeline writes it on each run.
  synthMetaStore?: SynthMetaStore;
  // Last-import record (when it ran + forensic-timeline diff) for the dashboard's "last import N
  // ago - +N new events" indicator and what-was-added view above the timeline. The unified /import
  // route writes it after the importer completes; onImportMeta pings dashboard clients to re-fetch.
  importMetaStore?: ImportMetaStore;
  onImportMeta?: (caseId: string) => void;
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
  // Customer Exposure is separate from IOC enrichment: only customer-owned domains/emails are
  // sent to breach-data providers. IOC domains are never queried here.
  customerExposureProviders?: CustomerExposureProvider[];
  customerExposureDelayMs?: number;
  // Provider reachability gate. A self-hosted MISP / YETI can be down; rather than fire one
  // doomed request per IOC, each provider is probed (cached `enrichHealthTtlMs`, default 60s)
  // before sending — a down provider is skipped this run. When `enrichHealthPollMs` is set
  // (>0), a background poller re-probes down providers on that interval and auto-resumes
  // enrichment for cases it had to skip, once the server is reachable again.
  enrichHealthTtlMs?: number;
  enrichHealthPollMs?: number;
  // Broadcast a fresh investigation state to dashboard clients (for routes that change
  // state outside the AI pipeline, e.g. enrichment).
  onState?: (state: InvestigationState) => void;
  // DFIR-IRIS push: a configured client (when DFIR_IRIS_URL/KEY are set) + mapping options
  // (customer/classification ids, base URL for the case link).
  irisClient?: IrisClient;
  irisOptions?: IrisPushOptions;
  // Velociraptor API: a configured client (when DFIR_VELOCIRAPTOR_API_CONFIG is set) lets the
  // dashboard run the generated hunt VQL against the server and show the rows inline.
  velociraptorClient?: VelociraptorClient;
  // Which hunt-query platforms the dashboard's 🔍 generator offers (DFIR_HUNT_PLATFORMS allowlist).
  // Exposed on /health so the dashboard renders only these cards. Undefined → all platforms.
  huntPlatforms?: HuntPlatform[];
  // Timesketch push: a configured client (when DFIR_TIMESKETCH_URL/USER/PASSWORD are set) +
  // options (base URL for the sketch link, managed timeline name).
  timesketchClient?: TimesketchClient;
  timesketchOptions?: TimesketchPushOptions;
  // Case templates: built-in + user-saved templates selectable at case creation.
  templateStore?: TemplateStore;
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
  const hasAiProvider = (): boolean => options.aiConfigured ?? Boolean(options.pipeline?.hasAiProvider());

  // Allow the browser extension (a chrome-extension:// origin) to reach this
  // localhost-only server. Binding is 127.0.0.1, so this is local-machine access.
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
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

  // JSON body limit. Bulk evidence imports (CSV / log / THOR / SIEM-EDR JSON exports) wrap the
  // whole file in the request body, and SIEM/EDR exports in particular are routinely tens to
  // hundreds of MB — so the cap is generous and configurable via DFIR_MAX_BODY_MB (default
  // 256 MB). Localhost-only single-user tool, so a large limit is not a DoS concern. Files
  // beyond a few hundred MB approach V8's max string length; for those, split the export.
  const maxBodyMb = Number(process.env.DFIR_MAX_BODY_MB) || 256;
  app.use(express.json({ limit: `${maxBodyMb}mb` }));

  // Turn body-parser failures into actionable JSON (instead of Express's default HTML page):
  // an over-limit upload → 413 with how to raise the cap; malformed JSON → 400. Placed right
  // after the parser so it catches its errors; normal requests skip it (4-arg = error-only).
  app.use((err: Error & { type?: string; status?: number }, _req: Request, res: Response, next: NextFunction) => {
    if (err?.type === "entity.too.large") {
      return res.status(413).json({ error: `upload exceeds the ${maxBodyMb} MB limit — raise DFIR_MAX_BODY_MB and restart the companion, or split the export into smaller files` });
    }
    if (err?.type === "entity.parse.failed") {
      return res.status(400).json({ error: "request body is not valid JSON" });
    }
    return next(err);
  });

  // Lightweight reachability check used by the extension's connection status.
  // aiEnabled tells the dashboard whether an AI provider is configured at all.
  app.get("/health", (_req: Request, res: Response) => {
    res.status(200).json({ ok: true, service: "dfir-companion", aiEnabled: hasAiProvider(), enrichEnabled: (options.enrichmentProviders?.length ?? 0) > 0, customerExposureEnabled: (options.customerExposureProviders?.length ?? 0) > 0, velociraptorEnabled: !!options.velociraptorClient, huntPlatforms: options.huntPlatforms ?? [...HUNT_PLATFORMS] });
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
    if (!autoSynth || !options.pipeline || !hasAiProvider()) return;
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
    if (buf.length === 0 || !options.pipeline || !hasAiProvider()) return;
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

  // Safety-net periodic flush. A `timer`/`click` capture buffers until `windowSize` accumulates
  // (only a `navigation`/`tab_switch` flushes early), so a single (or sub-window) capture could
  // otherwise sit unanalyzed indefinitely. Every `flushIntervalMs` (default 5 min) drain any
  // non-empty buffer so even one screenshot gets analyzed. `flush` is a no-op on an empty buffer
  // or when AI is unconfigured, and per-case buffers only hold captures for AI-enabled cases
  // (the route gates on `enabled`; pausing clears the buffer). `unref()` so the timer never keeps
  // the process — or a test runner — alive.
  const flushIntervalMs = options.flushIntervalMs ?? 5 * 60_000;
  if (flushIntervalMs > 0 && options.pipeline) {
    const sweep = setInterval(() => {
      for (const [caseId, buf] of buffers) {
        if (buf.length > 0) void flush(caseId);
      }
    }, flushIntervalMs);
    sweep.unref?.();
  }

  // Analyze every non-duplicate capture taken since lastAnalyzedSeq — used when AI
  // is switched back on after capturing with it off. Runs in the background.
  async function backfill(caseId: string): Promise<void> {
    if (!options.pipeline || !hasAiProvider()) return;
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
        if (template?.initialKeyQuestions.length) {
          const state = await options.stateStore.load(caseId);
          state.keyQuestions = buildInitialQuestions(template);
          state.updatedAt = new Date().toISOString();
          await options.stateStore.save(state);
        }
      }
      return res.status(201).json(meta);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // ── Case templates ──────────────────────────────────────────────────────────────────────
  // Built-in templates are always available; custom templates are saved to the templates dir.

  app.get("/templates", async (_req: Request, res: Response) => {
    if (!options.templateStore) return res.status(200).json([]);
    try {
      return res.status(200).json(await options.templateStore.list());
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/templates/:id", async (req: Request, res: Response) => {
    if (!options.templateStore) return res.status(404).json({ error: "template store not configured" });
    try {
      const template = await options.templateStore.get(req.params.id);
      if (!template) return res.status(404).json({ error: `template "${req.params.id}" not found` });
      return res.status(200).json(template);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/templates", async (req: Request, res: Response) => {
    if (!options.templateStore) return res.status(501).json({ error: "template store not configured" });
    try {
      const { name, description, recommendedImports, initialKeyQuestions, severityFloor, huntPlatforms, id } = req.body ?? {};
      if (!name) return res.status(400).json({ error: "name is required" });
      const saved = await options.templateStore.save({ id, name, description, recommendedImports, initialKeyQuestions, severityFloor: severityFloor ?? null, huntPlatforms });
      return res.status(201).json(saved);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/templates/:id", async (req: Request, res: Response) => {
    if (!options.templateStore) return res.status(501).json({ error: "template store not configured" });
    try {
      const found = await options.templateStore.delete(req.params.id);
      if (!found) return res.status(404).json({ error: `template "${req.params.id}" not found` });
      return res.status(204).send();
    } catch (err) {
      if ((err as Error).message.includes("built-in")) return res.status(400).json({ error: (err as Error).message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/captures", async (req: Request, res: Response) => {
    try {
      const metadata = await ingestCapture(store, req.body);
      res.status(201).json(metadata);
      // Evidence is always stored; AI analysis only runs when enabled for the case.
      if (!metadata.isDuplicate && options.pipeline && hasAiProvider() && (await getControl(metadata.caseId)).enabled) {
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
  // Only the known report artifacts are served; `?download=1` forces a save dialog, and
  // `?print=1` (HTML only) injects a print trigger so the browser opens its print dialog —
  // the zero-dependency "Save as PDF" export. The on-disk file is never modified.
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
      const download = req.query.download !== undefined;
      if (download) {
        res.setHeader("Content-Disposition", `attachment; filename="${file}"`);
      }
      res.setHeader("Cache-Control", "private, no-cache");
      // PDF export: an opened-in-browser HTML report that auto-triggers the print dialog.
      // Mutually exclusive with download — the saved PDF must come from the print dialog, not a file.
      if (file === "report.html" && req.query.print !== undefined && !download) {
        return res.send(injectPrintTrigger(buf.toString("utf8")));
      }
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

  // The causal evidence chain graph (process trees + lateral movement), derived on demand
  // from the current state with the same scope/legitimate filtering as the report.
  app.get("/cases/:id/evidence-graph", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      return res.status(200).json(await options.reportWriter.evidenceGraph(req.params.id));
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

  // Export the incident report as a Word (.docx) attachment, generated on demand from the
  // current state (same scope/legitimate filtering as the report). Not persisted on disk —
  // the binary is built fresh per request so it doesn't churn the cases/ folder.
  app.get("/cases/:id/report.docx", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const buf = await options.reportWriter.docx(req.params.id);
      res.type("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
      res.setHeader("Content-Disposition", `attachment; filename="report-${req.params.id}.docx"`);
      res.setHeader("Cache-Control", "private, no-cache");
      return res.send(buf);
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

  // Run a VQL query against the configured Velociraptor server (via its API) and return the rows.
  // Powers the hunt-pivot modal's "Run in Velociraptor" button. 501 when not configured. The VQL is
  // analyst-authored (from the generated pivots) — localhost only, opt-in via DFIR_VELOCIRAPTOR_*.
  app.post("/velociraptor/run", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const vql = typeof req.body?.vql === "string" ? req.body.vql.trim() : "";
    if (!vql) return res.status(400).json({ error: "vql is required" });
    try {
      logLine(`[velociraptor] run query (${vql.length} chars)`);
      const result = await options.velociraptorClient.run(vql);
      logLine(`[velociraptor] query DONE -> ${result.total} rows${result.truncated ? " (truncated)" : ""}`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[velociraptor] query ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Launch a HUNT that runs the pivot VQL on ALL enrolled endpoints (packages it as a CLIENT
  // artifact, then creates the hunt). This is the dashboard's "Run hunt on all clients" action.
  app.post("/velociraptor/hunt", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const vql = typeof req.body?.vql === "string" ? req.body.vql.trim() : "";
    const description = typeof req.body?.description === "string" ? req.body.description : "";
    if (!vql) return res.status(400).json({ error: "vql is required" });
    try {
      logLine(`[velociraptor] launch hunt: ${description.slice(0, 80)}`);
      const result = await options.velociraptorClient.launchHunt(vql, description);
      logLine(`[velociraptor] hunt launched -> ${result.huntId} (artifact ${result.artifact}, ${result.sources.length} source(s))`);
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[velociraptor] hunt ERROR: ${(err as Error).message}`);
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Read a launched hunt's results (rows collected from the endpoints so far). Polled by the dashboard.
  app.post("/velociraptor/hunt-results", async (req: Request, res: Response) => {
    if (!options.velociraptorClient) return res.status(501).json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const huntId = typeof req.body?.huntId === "string" ? req.body.huntId.trim() : "";
    const artifact = typeof req.body?.artifact === "string" ? req.body.artifact.trim() : "";
    const sources = Array.isArray(req.body?.sources) ? req.body.sources.filter((s: unknown): s is string => typeof s === "string") : [];
    if (!huntId || !artifact) return res.status(400).json({ error: "huntId and artifact are required" });
    try {
      const result = await options.velociraptorClient.huntResults(huntId, artifact, sources);
      return res.status(200).json(result);
    } catch (err) {
      return res.status(502).json({ error: (err as Error).message });
    }
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

  // Per-case anonymization control (default ON) + the analyst-added entity list. Screenshots can't
  // be tokenized, so the dashboard warns when anon is on and the vision provider is external.
  const anonControl = new AnonControlStore(store);
  const customEntities = new CustomEntitiesStore(store);
  const visionIsLocal = isLocalAiProvider(process.env.DFIR_AI_PROVIDER, process.env.DFIR_AI_BASE_URL);

  // Anonymization control: GET reports the control + whether screenshots are exposed (anon on +
  // external vision). POST updates it and, when `enabled` flips, forces a re-synth so conclusions
  // reflect the new wire policy (the skip-if-unchanged hash is keyed on real inputs and won't notice).
  app.get("/cases/:id/anon-control", async (req: Request, res: Response) => {
    try {
      const c = await anonControl.load(req.params.id);
      return res.status(200).json({ ...c, screenshotWarning: c.enabled && !visionIsLocal });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
  app.post("/cases/:id/anon-control", async (req: Request, res: Response) => {
    try {
      const cur = await anonControl.load(req.params.id);
      // Only accept KNOWN category keys with BOOLEAN values; anything else keeps the current value.
      // (A blind spread would let `{categories:{IP:null}}` persist a falsy non-boolean and silently
      // disable a category while `enabled` stays true.)
      const reqCats = (req.body?.categories ?? {}) as Record<string, unknown>;
      const categories = { ...cur.categories };
      for (const k of Object.keys(categories) as (keyof AnonControl["categories"])[]) {
        if (typeof reqCats[k] === "boolean") categories[k] = reqCats[k] as boolean;
      }
      const next: AnonControl = {
        enabled: typeof req.body?.enabled === "boolean" ? req.body.enabled : cur.enabled,
        categories,
        redactSecrets: typeof req.body?.redactSecrets === "boolean" ? req.body.redactSecrets : cur.redactSecrets,
      };
      await anonControl.save(req.params.id, next);
      if (next.enabled !== cur.enabled && options.pipeline && hasAiProvider()) {
        void options.pipeline.synthesize(req.params.id, { force: true }).catch(() => {});
      }
      return res.status(200).json({ ...next, screenshotWarning: next.enabled && !visionIsLocal });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // The entities that will be anonymized for a case: `auto` (derived from the timeline — grows as
  // the investigation does, read-only) + `custom` (analyst-added). POST replaces the custom list.
  app.get("/cases/:id/anon-entities", async (req: Request, res: Response) => {
    try {
      const custom = await customEntities.load(req.params.id);
      let auto = { hosts: [] as string[], accounts: [] as string[], internalDomains: [] as string[] };
      if (options.stateStore) {
        const d = deriveKnownEntities(await options.stateStore.load(req.params.id));
        auto = { hosts: d.hosts, accounts: d.accounts, internalDomains: d.internalDomains };
      }
      return res.status(200).json({ auto, custom });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
  app.post("/cases/:id/anon-entities", async (req: Request, res: Response) => {
    try {
      const entities = sanitizeCustomEntities(req.body?.entities);
      await customEntities.save(req.params.id, entities);
      return res.status(200).json({ custom: entities });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Customer exposure / breach-data lookups. This is deliberately NOT IOC enrichment:
  // only manually entered customer domains/emails plus observed emails under those customer
  // domains are sent to providers. Remote domains collected as IOCs are never queried here.
  const customerStore = new CustomerStore(store);
  const customerExposureStore = new CustomerExposureStore(store);
  const customerExposureProviders = options.customerExposureProviders ?? [];

  app.get("/cases/:id/customer-exposure", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    try {
      const state = await options.stateStore.load(req.params.id);
      const targets = await customerStore.load(req.params.id);
      return res.status(200).json({
        anyConfigured: customerExposureProviders.length > 0,
        providers: customerExposureProviders.map((p) => p.name),
        targets,
        effectiveTargets: buildCustomerExposureTargets(state, targets),
        exposure: await customerExposureStore.load(req.params.id),
      });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.put("/cases/:id/customer-exposure/targets", async (req: Request, res: Response) => {
    try {
      const targets = sanitizeTargets(req.body ?? {});
      await customerStore.save(req.params.id, targets);
      return res.status(200).json({ targets });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/customer-exposure/check", async (req: Request, res: Response) => {
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    if (customerExposureProviders.length === 0) {
      return res.status(501).json({ error: "no customer exposure providers configured (set DFIR_LEAKCHECK_KEY / DFIR_DEHASHED_KEY / DFIR_HIBP_KEY / DFIR_SHODAN_KEY)" });
    }
    const caseId = req.params.id;
    try {
      const state = await options.stateStore.load(caseId);
      const targets = await customerStore.load(caseId);
      // Provider selection (like the enrichment per-source picker): a `providers` list in the
      // request body wins (one-off run), else the saved selection (customer.json), else all
      // configured. A name not matching a configured provider is simply ignored.
      const requested = parseList(req.body?.providers).map((s) => s.trim()).filter(Boolean);
      const selection = requested.length ? requested : (targets.providers?.length ? targets.providers : null);
      const active = selection ? customerExposureProviders.filter((p) => selection.includes(p.name)) : customerExposureProviders;
      if (active.length === 0) return res.status(400).json({ error: "no matching exposure providers selected" });
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: "checking customer exposure" });
      const summary = await summarizeExposure(state, targets, active, {
        delayMs: options.customerExposureDelayMs,
      });
      await customerExposureStore.save(caseId, summary);
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `customer exposure: ${summary.results.length} hit(s), ${summary.errors.length} error(s)` });
      logLine(`[exposure] ${caseId} providers=[${summary.providers.join(", ")}] domains=${summary.targets.domains.length} emails=${summary.targets.emails.length} hits=${summary.results.length} errors=${summary.errors.length}`);
      return res.status(200).json(summary);
    } catch (err) {
      options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });

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

  // Shared reachability gate (one per server, so the cache survives across enrich runs: if a
  // self-hosted instance is down and three imports land within a minute, it's probed once,
  // not three times). Logs each real probe's verdict so the operator sees DOWN/UP transitions.
  const enrichHealth = new ProviderHealthCache({
    ttlMs: options.enrichHealthTtlMs,
    onProbe: (name, h) => logLine(`[enrich] health ${name} ${h.ok ? "UP" : `DOWN (${h.detail ?? "unreachable"})`}`),
  });
  // Cases whose last enrich run had to skip a provider that was down. The background poller
  // drains this and re-enriches once the server is reachable again (the per-provider cache
  // means only the still-unchecked IOCs are actually queried).
  const enrichPending = new Set<string>();

  function enrichInBackground(caseId: string, force = false): void {
    if (allProviders.length === 0 || !options.stateStore) return;
    void (async () => {
      const providers = await enabledProvidersFor(caseId);
      if (providers.length === 0) { enrichPending.delete(caseId); return; }     // nothing enabled — drop any stale pending mark so the poller can idle
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `enriching IOCs (${providers.map((p) => p.name).join(", ")})` });
      const state = await options.stateStore!.load(caseId);
      logLine(`[enrich] ${caseId} START providers=[${providers.map((p) => p.name).join(", ")}] force=${force} iocs=${state.iocs.length}`);
      const { iocs, summary } = await enrichIocs(state.iocs, {
        providers,
        delayMs: options.enrichDelayMs,
        maxIocs: options.enrichMaxIocs,
        force,
        health: enrichHealth,   // probe each provider (cached ~60s) before sending — skip the dead ones
        onProgress: (done, total) => options.onAiStatus?.(caseId, {
          status: "analyzing", phase: "extracting", at: new Date().toISOString(),
          detail: `enriching IOC ${done}/${total}`,
        }),
        // One audit line per outbound threat-intel API call: which provider, indicator, result.
        onLookup: (e: EnrichLookupEvent) => logLine(
          `[enrich] ${caseId} ${e.provider} ${e.kind} ${shortValue(e.value)} -> ${e.outcome}${e.detail ? ` (${e.detail})` : ""} ${e.ms}ms`,
        ),
      });
      const downNote = summary.unavailable.length ? ` unavailable=[${summary.unavailable.join(", ")}]` : "";
      logLine(`[enrich] ${caseId} DONE queried=${summary.queried} hits=${summary.withHits} errors=${summary.errors} skipped=${summary.skipped}${downNote}`);
      // Remember (or clear) this case for the background poller: if a provider was down we
      // couldn't finish, so retry it on recovery; if all reachable, drop any stale pending mark.
      if (summary.unavailable.length) enrichPending.add(caseId);
      else enrichPending.delete(caseId);
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
      const skipNote = summary.unavailable.length ? `; skipped ${summary.unavailable.join(", ")} (unreachable — will retry)` : "";
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString(), detail: `enriched ${summary.withHits}/${summary.queried} (errors ${summary.errors})${chainNote}${skipNote}` });
    })().catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
  }

  // After IOCs change (synthesis/import), enrich the new ones if the toggle is on. The
  // cache means already-enriched IOCs are skipped, so this only queries fresh indicators.
  function autoEnrichIfEnabled(caseId: string): void {
    if (allProviders.length === 0) return;
    enabledProvidersFor(caseId).then((ps) => { if (ps.length > 0) enrichInBackground(caseId); }).catch(() => {});
  }

  // Background reachability poller (opt-in via enrichHealthPollMs, set by startServer). It only
  // runs while a case is actually waiting on a down provider to recover (enrichPending non-empty):
  // its sole purpose is to resume those cases, so when enrichment is off everywhere it probes
  // nothing and emits no "[enrich] health … DOWN" noise. When it does run it re-probes only the
  // providers currently known-down — cheap — and, when one recovers, resumes the cases that had to
  // skip it. `.unref()` so it never holds the process open; tests don't set the option, so no timer starts.
  if (options.enrichHealthPollMs && options.enrichHealthPollMs > 0 && allProviders.some((p) => p.probe)) {
    let polling = false;   // guard against overlap if a probe round runs long
    const timer = setInterval(() => {
      if (polling) return;
      if (enrichPending.size === 0) return;   // no case waiting on a down provider — nothing to resume, so don't probe (or log)
      const down = allProviders.filter((p) => enrichHealth.peek(p.name)?.ok === false);
      if (down.length === 0) return;   // nothing to recover
      polling = true;
      void (async () => {
        for (const p of down) { enrichHealth.invalidate(p.name); await enrichHealth.check(p); }
        const recovered = down.some((p) => enrichHealth.peek(p.name)?.ok === true);
        if (recovered && enrichPending.size > 0) {
          const cases = [...enrichPending];
          enrichPending.clear();
          logLine(`[enrich] health recovered — resuming ${cases.length} case(s)`);
          for (const c of cases) enrichInBackground(c);
        }
      })().catch(() => {}).finally(() => { polling = false; });
    }, options.enrichHealthPollMs);
    timer.unref?.();
  }

  function resynthesizeInBackground(caseId: string): void {
    const pipeline = options.pipeline;
    if (!pipeline) return;
    if (!hasAiProvider()) { autoEnrichIfEnabled(caseId); return; }
    void (async () => {
      // Synthesis is an LLM call — respect the per-case AI toggle, exactly like the /captures
      // path (AI analysis only runs when enabled for the case). With AI off, a deterministic
      // import still populates the forensic timeline + IOCs; it just doesn't trigger LLM
      // synthesis — findings / attacker-path / MITRE wait until AI is turned on and the case is
      // re-synthesized. Enrichment is a separate, independently-gated feature (threat-intel
      // lookups, not an LLM call), so it still runs regardless of the AI toggle.
      if (!(await getControl(caseId)).enabled) { autoEnrichIfEnabled(caseId); return; }
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "synthesizing", at: new Date().toISOString(), detail: "re-synthesizing without legitimate items" });
      try {
        await pipeline.synthesize(caseId);
        options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
        autoEnrichIfEnabled(caseId);
      } catch (err) {
        options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message });
      }
    })();
  }

  app.get("/cases/:id/legitimate", async (req: Request, res: Response) => {
    try {
      return res.status(200).json(await legitimate.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Build a marker from one request item (kind/ref/note/label). Returns null when ref is empty
  // so the caller can reject (single) or skip (batch). Shared by the single + batch routes.
  const buildLegitMarker = (item: {
    kind?: unknown; ref?: unknown; note?: unknown; label?: unknown;
  }): LegitimateMarker | null => {
    const rawKind = item?.kind;
    const kind: LegitimateMarker["kind"] =
      rawKind === "ioc" ? "ioc" : rawKind === "event" ? "event" : "finding";
    const ref = String(item?.ref ?? "").trim();
    if (!ref) return null;
    const note = String(item?.note ?? "");
    // Optional human-readable label (e.g. a forensic event's description) so the
    // "Confirmed Legitimate" panel can show something meaningful for opaque ids.
    const label = item?.label != null ? String(item.label) : undefined;
    return { id: markerId(kind, ref), kind, ref, note, markedAt: new Date().toISOString(), ...(label ? { label } : {}) };
  };

  app.post("/cases/:id/legitimate", async (req: Request, res: Response) => {
    try {
      const marker = buildLegitMarker(req.body ?? {});
      if (!marker) return res.status(400).json({ error: "ref is required" });
      const markers = await legitimate.load(req.params.id);
      const next = [...markers.filter((m) => m.id !== marker.id), marker];
      await legitimate.save(req.params.id, next);
      resynthesizeInBackground(req.params.id); // re-derive conclusions without it
      return res.status(200).json(next);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Mark MANY entities legitimate in one shot — one read-modify-write + a SINGLE re-synthesis,
  // instead of N concurrent /legitimate calls that would race on legitimate.json (last write wins)
  // and each kick off their own re-synthesis. The dashboard's bulk "Mark Legitimate" uses this.
  // Body: { items: [{ kind, ref, note?, label? }, …], note? } — a top-level note is the fallback
  // reason for items that don't carry their own.
  app.post("/cases/:id/legitimate/batch", async (req: Request, res: Response) => {
    try {
      const rawItems = Array.isArray(req.body?.items) ? req.body.items : [];
      const fallbackNote = req.body?.note != null ? String(req.body.note) : "";
      const built = rawItems
        .map((it: { kind?: unknown; ref?: unknown; note?: unknown; label?: unknown }) =>
          buildLegitMarker({ ...it, note: it?.note ?? fallbackNote }))
        .filter((m: LegitimateMarker | null): m is LegitimateMarker => m !== null);
      if (!built.length) return res.status(400).json({ error: "at least one valid item (with a ref) is required" });
      const markers = await legitimate.load(req.params.id);
      // De-dupe within the batch and against existing markers (last occurrence wins) by id.
      const byId = new Map<string, LegitimateMarker>(markers.map((m) => [m.id, m]));
      for (const m of built) byId.set(m.id, m);
      const next = [...byId.values()];
      await legitimate.save(req.params.id, next);
      resynthesizeInBackground(req.params.id); // ONE re-synthesis for the whole batch
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

  // Unified import: ONE endpoint the dashboard's single "Import" button posts any data file to.
  // The server SNIFFS the file (filename + content) — JSON/NDJSON vs CSV vs log, then per-format
  // signatures — and dispatches to the matching importer (deterministic ones, or the AI CSV/log
  // path). Evidence-first: the raw file is persisted + audit-logged before analysis. The detected
  // `kind` is returned so a mis-route is visible. (The per-format routes below remain for
  // programmatic use.)
  app.post("/cases/:id/import", async (req: Request, res: Response) => {
    if (!options.pipeline) return res.status(501).json({ error: "AI pipeline not configured" });
    const caseId = req.params.id;
    const text = typeof req.body?.text === "string" ? req.body.text
      : typeof req.body?.json === "string" ? req.body.json
      : typeof req.body?.csv === "string" ? req.body.csv : "";
    const originalName = String(req.body?.filename ?? "import.dat");
    if (!text.trim()) return res.status(400).json({ error: "text is required" });

    const kind = detectImportKind(originalName, text);
    if (kind === "unknown") {
      return res.status(400).json({ error: "could not detect the file type — not recognized as any supported import (THOR / SIEM-EDR / Chainsaw-EVTX / Hayabusa / Velociraptor / Suricata-Zeek / KAPE / Cyber Triage / M365-Entra / AWS / GCP-Azure / Plaso / Sandbox / CSV / log)" });
    }
    if ((kind === "csv" || kind === "log") && !hasAiProvider()) {
      return res.status(501).json({ error: "AI provider not configured for CSV/log analysis" });
    }

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
      const onProgress = (done: number, total: number): void => options.onAiStatus?.(caseId, {
        status: "analyzing", phase: "extracting", at: new Date().toISOString(), detail: `${kind} import — ${done}/${total}`,
      });
      const base = { label: storedName, idPrefix: `${seq}`, importedAt, onProgress, minSeverity };
      options.onAiStatus?.(caseId, { status: "analyzing", phase: "extracting", at: importedAt, detail: `importing (${kind})${minSeverity ? ` — min severity ${minSeverity}` : ""}` });

      const run = (): Promise<unknown> => {
        switch (kind) {
          case "thor": return pipeline.importThor(caseId, text, base);
          case "siem": return pipeline.importSiem(caseId, text, base);
          case "chainsaw": return pipeline.importChainsaw(caseId, text, base);
          case "hayabusa": return pipeline.importHayabusa(caseId, text, base);
          case "velociraptor": return pipeline.importVelociraptor(caseId, text, base);
          case "network": return pipeline.importNetwork(caseId, text, base);
          case "kape": return pipeline.importKape(caseId, text, base);
          case "cybertriage": return pipeline.importCybertriage(caseId, text, base);
          case "m365": return pipeline.importM365(caseId, text, base);
          case "aws": return pipeline.importAws(caseId, text, base);
          case "cloud": return pipeline.importCloudActivity(caseId, text, base);
          case "plaso": return pipeline.importPlaso(caseId, text, base);
          case "sandbox": return pipeline.importSandbox(caseId, text, base);
          case "csv": return pipeline.analyzeCsv(caseId, text, base);
          case "log": return pipeline.analyzeLog(caseId, text, base);
          default: return Promise.reject(new Error(`unhandled import kind: ${kind as string}`));
        }
      };

      // Snapshot the forensic timeline + IOCs BEFORE the import so the .then() below can record what
      // this import added (the "last import" diff the dashboard shows above the timeline and IOCs).
      let timelineBefore: ForensicEvent[] = [];
      let iocsBefore: IOC[] = [];
      if (options.importMetaStore && options.stateStore) {
        try { const s = await options.stateStore.load(caseId); timelineBefore = s.forensicTimeline; iocsBefore = s.iocs; } catch { /* keep [] */ }
      }

      run()
        .then(async () => {
          options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
          // Record what this import added to the forensic timeline + IOCs, BEFORE resynthesis (which
          // preserves both). Best-effort: a meta failure must not break the import.
          if (options.importMetaStore && options.stateStore) {
            try {
              const s = await options.stateStore.load(caseId);
              await options.importMetaStore.record(caseId, {
                kind, file: storedName,
                diff: diffTimeline(timelineBefore, s.forensicTimeline),
                iocsDiff: diffIocs(iocsBefore, s.iocs),
              });
              options.onImportMeta?.(caseId);
            } catch { /* non-fatal */ }
          }
          resynthesizeInBackground(caseId);
        })
        .catch((err) => options.onAiStatus?.(caseId, { status: "error", at: new Date().toISOString(), detail: (err as Error).message }));
      return;
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Import a CSV result export (e.g. a Velociraptor artifact) as evidence and analyze
  // it like captured screenshots: extract dated forensic events + IOCs into the
  // timeline, then synthesize findings/TTPs/attacker-path. Evidence-first: the raw
  // CSV is persisted + audit-logged BEFORE any analysis; analysis runs in background.
  app.post("/cases/:id/import-csv", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for CSV analysis" });
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
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for log analysis" });
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

  // Reachability of the configured providers (for the dashboard's ●up/down dots). Probes each
  // one (cached ~60s, so opening the modal repeatedly is cheap) and reports its last verdict.
  // Providers without a probe() (external SaaS) report ok:true (no health endpoint to test).
  app.get("/enrich-health", async (_req: Request, res: Response) => {
    try {
      const health = await Promise.all(allProviders.map(async (p) => {
        const h = p.probe ? await enrichHealth.check(p) : { ok: true, checkedAt: 0 };
        return { name: p.name, scope: p.scope, probed: Boolean(p.probe), ok: h.ok, detail: h.detail };
      }));
      return res.status(200).json({ providers: health });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Set which providers are enabled for this case. Accepts `{ providers: string[] }`
  // (preferred) or legacy `{ enabled: boolean }`. Saving re-runs enrichment; per-provider
  // caching means only the newly-enabled providers query the existing IOCs.
  app.post("/cases/:id/enrich-control", async (req: Request, res: Response) => {
    if (allProviders.length === 0) return res.status(501).json({ error: "no enrichment providers configured (set DFIR_VT_KEY / DFIR_MB_KEY / DFIR_HUNTINGCH_KEY / DFIR_ABUSEIPDB_KEY / DFIR_CROWDSTRIKE_CLIENT_ID+_SECRET / DFIR_MISP_* / DFIR_YETI_*)" });
    if (!options.stateStore) return res.status(501).json({ error: "state store not configured" });
    const caseId = req.params.id;
    let providers: string[];
    if (Array.isArray(req.body?.providers)) providers = req.body.providers.map(String).filter((n: string) => configuredNames.includes(n));
    else if (typeof req.body?.enabled === "boolean") providers = req.body.enabled ? [...configuredNames] : [];
    else return res.status(400).json({ error: "providers (array of provider names) or enabled (boolean) is required" });
    try {
      await enrichControl.save(caseId, { providers });
      if (providers.length > 0) enrichInBackground(caseId);   // re-check; cache only queries newly-enabled / un-checked
      else enrichPending.delete(caseId);                      // disabled — stop the poller from waiting on a down provider for this case
      return res.status(200).json({ providers });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Manual one-shot re-scan (e.g. force re-query). Honors the same providers; does NOT
  // change the toggle. `{ force: true }` re-queries already-enriched IOCs.
  app.post("/cases/:id/enrich", async (req: Request, res: Response) => {
    const providers = options.enrichmentProviders ?? [];
    if (providers.length === 0) return res.status(501).json({ error: "no enrichment providers configured (set DFIR_VT_KEY / DFIR_MB_KEY / DFIR_HUNTINGCH_KEY / DFIR_ABUSEIPDB_KEY / DFIR_CROWDSTRIKE_CLIENT_ID+_SECRET)" });
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
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for synthesis" });
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

  // Ask the LLM a free-form question about the case ("was data exfiltrated?"). Single-shot,
  // no state change — returns a grounded answer + status + collection guidance (`pointer`).
  app.post("/cases/:id/ask", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for case questions" });
    const question = typeof req.body?.question === "string" ? req.body.question.trim() : "";
    if (!question) return res.status(400).json({ error: "question is required" });
    try {
      const answer = await options.pipeline.ask(req.params.id, question);
      return res.status(200).json(answer);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Generate a management-facing executive summary over the synthesized case (one text-only AI
  // call). The dashboard shows it and can save it into report-meta.executiveSummary, which then
  // overrides the auto-derived summary in the generated report.
  app.post("/cases/:id/executive-summary", async (req: Request, res: Response) => {
    if (!options.pipeline || !hasAiProvider()) return res.status(501).json({ error: "AI provider not configured for executive summary" });
    try {
      const result = await options.pipeline.executiveSummary(req.params.id);
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Last-synthesis metadata: when synthesis last actually ran + what changed in the findings.
  // Backs the dashboard's "last synthesized N ago" indicator and the what-changed diff view.
  app.get("/cases/:id/synth-meta", async (req: Request, res: Response) => {
    if (!options.synthMetaStore) return res.status(501).json({ error: "synth metadata not configured" });
    try {
      return res.status(200).json(await options.synthMetaStore.load(req.params.id));
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

  // Analyst triage tags on case entities (hand labels). GET lists them; POST attaches one to a
  // `(targetType, targetId)` entity (label normalized + deduped server-side); DELETE removes by
  // id. Add/remove ping live clients. Survives synthesis (side file, not InvestigationState).
  app.get("/cases/:id/tags", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    try {
      return res.status(200).json(await options.tagsStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/tags", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    const targetType = typeof req.body?.targetType === "string" ? req.body.targetType.trim() : "";
    const targetId = typeof req.body?.targetId === "string" ? req.body.targetId.trim() : "";
    const label = typeof req.body?.label === "string" ? req.body.label.trim() : "";
    if (!targetType || !targetId || !label) return res.status(400).json({ error: "targetType, targetId and label are required" });
    try {
      const tag = await options.tagsStore.add(req.params.id, {
        targetType, targetId, label,
        author: typeof req.body?.author === "string" ? req.body.author : "",
      });
      options.onTags?.(req.params.id);
      return res.status(201).json(tag);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/tags/:tagId", async (req: Request, res: Response) => {
    if (!options.tagsStore) return res.status(501).json({ error: "tags not configured" });
    try {
      const removed = await options.tagsStore.remove(req.params.id, req.params.tagId);
      if (!removed) return res.status(404).json({ error: "tag not found" });
      options.onTags?.(req.params.id);
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
import { AnthropicProvider } from "./providers/anthropic.js";
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
  // The model's context window (tokens) for the provider's pre-flight guard. Defaults from
  // DFIR_AI_CONTEXT_TOKENS (or 128000) so an oversized prompt is trimmed/clearly-errored.
  contextTokens?: number;
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
  // Context window for the pre-flight guard — same default the pipeline budgets against, so
  // a too-big prompt is trimmed by the pipeline and, as a backstop, caught here before the API.
  const contextTokens = params.contextTokens ?? resolveContextTokens();
  const registry = new ProviderRegistry();
  registry.register(new OpenAIProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens, contextTokens }));
  registry.register(new OpenRouterProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens, contextTokens }));
  registry.register(new OllamaCloudProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens, contextTokens }));
  registry.register(new LiteLlmProvider({ apiKey, model, baseUrl, imageDetail, timeoutMs, maxTokens, contextTokens }));
  registry.register(new GeminiProvider({ apiKey, model, baseUrl, timeoutMs, maxTokens }));
  registry.register(new AnthropicProvider({ apiKey, model, baseUrl, timeoutMs, maxTokens }));
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
  // Hunting.ch — the abuse.ch unified hunt (MalwareBazaar + ThreatFox + URLhaus + YARAify).
  // There's no separate MalwareBazaar source anymore: MalwareBazaar is one of its back-ends.
  // Uses the ONE abuse.ch Auth-Key; DFIR_MB_KEY (the legacy name for that key) still works.
  const abuseChKey = process.env.DFIR_HUNTINGCH_KEY || process.env.DFIR_MB_KEY;
  if (abuseChKey) providers.push(new HuntingChProvider({ apiKey: abuseChKey }));
  // CrowdStrike Falcon — Threat Intelligence only (Falcon Intelligence Indicators + MalQuery).
  if (process.env.DFIR_CROWDSTRIKE_CLIENT_ID && process.env.DFIR_CROWDSTRIKE_CLIENT_SECRET) {
    providers.push(new CrowdStrikeProvider({
      clientId: process.env.DFIR_CROWDSTRIKE_CLIENT_ID,
      clientSecret: process.env.DFIR_CROWDSTRIKE_CLIENT_SECRET,
      cloud: process.env.DFIR_CROWDSTRIKE_CLOUD,
      baseUrl: process.env.DFIR_CROWDSTRIKE_BASE_URL,
    }));
  }
  if (process.env.DFIR_ABUSEIPDB_KEY) providers.push(new AbuseIpdbProvider({ apiKey: process.env.DFIR_ABUSEIPDB_KEY }));
  if (process.env.DFIR_MISP_URL && process.env.DFIR_MISP_KEY) providers.push(new MispProvider({ baseUrl: process.env.DFIR_MISP_URL, apiKey: process.env.DFIR_MISP_KEY, fetchFn: tlsFetchFor("MISP") }));
  if (process.env.DFIR_ROCKYRACCOON_KEY) providers.push(new RockyRaccoonProvider({ apiKey: process.env.DFIR_ROCKYRACCOON_KEY }));
  if (process.env.DFIR_YETI_URL && process.env.DFIR_YETI_KEY) providers.push(new YetiProvider({ baseUrl: process.env.DFIR_YETI_URL, apiKey: process.env.DFIR_YETI_KEY, fetchFn: tlsFetchFor("YETI") }));
  return providers;
}

export function buildCustomerExposureProviders(): CustomerExposureProvider[] {
  const providers: CustomerExposureProvider[] = [];
  if (process.env.DFIR_LEAKCHECK_KEY) {
    providers.push(new LeakCheckExposureProvider({
      apiKey: process.env.DFIR_LEAKCHECK_KEY,
      domainLimit: Number(process.env.DFIR_LEAKCHECK_DOMAIN_LIMIT) || undefined,
    }));
  }
  if (process.env.DFIR_DEHASHED_KEY) {
    providers.push(new DeHashedExposureProvider({
      apiKey: process.env.DFIR_DEHASHED_KEY,
      baseUrl: process.env.DFIR_DEHASHED_BASE_URL,
    }));
  }
  if (process.env.DFIR_HIBP_KEY) {
    providers.push(new HaveIBeenPwnedExposureProvider({
      apiKey: process.env.DFIR_HIBP_KEY,
      userAgent: process.env.DFIR_HIBP_USER_AGENT || "DFIR Companion",
    }));
  }
  if (process.env.DFIR_SHODAN_KEY) {
    providers.push(new ShodanExposureProvider({ apiKey: process.env.DFIR_SHODAN_KEY }));
  }
  return providers;
}

export interface RuntimePipelineParams {
  provider?: AnalyzeProvider;
  synthesisProvider?: AnalyzeProvider;
  stateStore: StateStoreImpl;
  store: CaseStore;
  imageLoader?: ConstructorParameters<typeof AnalysisPipelineImpl>[0]["imageLoader"];
  onState?: (state: InvestigationState) => void;
}

export function buildRuntimePipeline(params: RuntimePipelineParams): AnalysisPipelineImpl {
  return new AnalysisPipelineImpl({
    provider: params.provider,
    synthesisProvider: params.synthesisProvider,
    stateStore: params.stateStore,
    legitimateStore: new LegitimateStore(params.store),
    scopeStore: new ScopeStore(params.store),
    imageLoader: params.imageLoader ?? makeImageLoader(params.store),
    onState: params.onState,
    anonStore: new AnonControlStore(params.store),
    customEntitiesStore: new CustomEntitiesStore(params.store),
    synthMetaStore: new SynthMetaStore(params.store),
  });
}

export function startServer(casesRoot: string, port = 4773, host = "127.0.0.1"): void {
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStoreImpl(store);
  const templateStore = new TemplateStore(join(dirname(casesRoot), "templates"));
  const hub = new LiveHub();
  const reportMetaStore = new ReportMetaStore(store);
  const commentsStore = new CommentsStore(store);
  const tagsStore = new TagsStore(store);
  const synthMetaStore = new SynthMetaStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const reportWriter = new ReportWriterImpl(store, stateStore, new ScopeStore(store), new LegitimateStore(store), reportMetaStore, new CustomerExposureStore(store));

  const provider = buildProvider();
  const synthesisProvider = buildSynthesisProvider();
  const wiredPipeline = buildRuntimePipeline({ provider, synthesisProvider, stateStore, store, onState: (s) => hub.broadcast(s) });

  // Live synthesis on by default — set DFIR_AI_AUTO_SYNTHESIZE=off to disable.
  const autoSynthesize = (process.env.DFIR_AI_AUTO_SYNTHESIZE ?? "on").toLowerCase() !== "off";
  const autoSynthesizeDebounceMs = Number(process.env.DFIR_AI_AUTO_SYNTHESIZE_MS) || 8000;

  // Safety-net flush: drain any non-empty capture buffer on this interval so a lone
  // `timer`/`click` screenshot is still analyzed instead of waiting for a full window.
  // Default 5 min; set DFIR_FLUSH_INTERVAL_MS=0 to disable.
  const flushIntervalMs = process.env.DFIR_FLUSH_INTERVAL_MS === "0"
    ? 0
    : (Number(process.env.DFIR_FLUSH_INTERVAL_MS) || undefined);

  const app = createApp(store, {
    pipeline: wiredPipeline,
    aiConfigured: Boolean(provider),
    flushIntervalMs,
    stateStore,
    reportWriter,
    reportMetaStore,
    commentsStore,
    onComments: (caseId) => hub.broadcastTo(caseId, { type: "comments_changed" }),
    tagsStore,
    onTags: (caseId) => hub.broadcastTo(caseId, { type: "tags_changed" }),
    synthMetaStore,
    importMetaStore,
    onImportMeta: (caseId) => hub.broadcastTo(caseId, { type: "import_meta_changed" }),
    autoSynthesize,
    autoSynthesizeDebounceMs,
    onAiStatus: (caseId, event) => hub.broadcastTo(caseId, { type: "ai_status", ...event }),
    onState: (s) => hub.broadcast(s),
    enrichmentProviders: buildEnrichmentProviders(),
    enrichDelayMs: Number(process.env.DFIR_ENRICH_DELAY_MS) || undefined,
    enrichMaxIocs: Number(process.env.DFIR_ENRICH_MAX) || undefined,
    customerExposureProviders: buildCustomerExposureProviders(),
    customerExposureDelayMs: Number(process.env.DFIR_EXPOSURE_DELAY_MS) || undefined,
    // Reachability gate: probe a self-hosted MISP/YETI before sending IOCs, cached this long
    // (default 60s in the cache). The poller re-checks down servers on the same cadence and
    // auto-resumes skipped cases on recovery — set DFIR_ENRICH_HEALTH_POLL_MS=0 to disable it.
    enrichHealthTtlMs: Number(process.env.DFIR_ENRICH_HEALTH_TTL_MS) || undefined,
    enrichHealthPollMs: process.env.DFIR_ENRICH_HEALTH_POLL_MS === "0" ? 0 : (Number(process.env.DFIR_ENRICH_HEALTH_POLL_MS) || 60_000),
    irisClient: buildIrisClient(),
    velociraptorClient: buildVelociraptorClient(),
    // Trim the dashboard's hunt-query modal to the tools this team runs (default: all).
    huntPlatforms: resolveHuntPlatforms(process.env.DFIR_HUNT_PLATFORMS),
    irisOptions: irisPushOptions(),
    timesketchClient: buildTimesketchClient(),
    timesketchOptions: timesketchPushOptions(),
    templateStore,
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
        const buf = await readPublicAsset(file);
        res.type(type).set("Cache-Control", "public, max-age=86400").send(buf);
      } catch {
        res.status(404).end();
      }
    });
  }

  // Redirect root to the dashboard.
  app.get("/", (_req, res) => {
    res.redirect("/dashboard");
  });

  // Serve the dashboard.
  app.get("/dashboard", async (_req, res) => {
    const html = await readPublicAsset("dashboard.html", "utf8");
    res.type("html").send(html);
  });

  // Bind host. Defaults to 127.0.0.1 (localhost-only — the OPSEC invariant for native runs).
  // Inside a container set DFIR_HOST=0.0.0.0 so the published port is reachable; the compose
  // file maps it to 127.0.0.1 on the HOST, so the localhost-only posture is preserved end-to-end.
  const server = app.listen(port, host, () => {
    const shownHost = host === "0.0.0.0" ? "127.0.0.1" : host;
    logLine(`DFIR companion on http://${shownHost}:${port} (dashboard at /dashboard)`);
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
// Matches three entries: the tsx dev entry (`server.ts`), the compiled production entry
// (`dist/server.js`, Docker image), and the single-executable bundle (`process.execPath`
// ends in `.exe`/the SEA binary). All three boot the server.
const entryPath = process.argv[1] ?? "";
const seaRuntime = isSeaRuntime();
if (seaRuntime || entryPath.endsWith("server.ts") || entryPath.endsWith("server.js")) {
  // In SEA mode anchor the package dir to the EXE's folder so .env / cases / public live
  // next to the binary. In dev/Docker mode keep the original behaviour (resolve against
  // this module's location → companion/).
  const companionDir = seaRuntime
    ? dirname(process.execPath) + "/"
    : fileURLToPath(new URL("../", import.meta.url)); // .../companion/
  loadDotenv({ path: seaRuntime ? join(companionDir, ".env") : undefined });
  const raw = process.env.DFIR_CASES_ROOT ?? "cases";
  // Anchor a relative cases root to the companion package directory, so the SAME
  // physical folder is used no matter which directory the server is launched from.
  // (Otherwise "./cases" resolves against cwd and you can end up with two folders.)
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

  // Bind host. Default 127.0.0.1 keeps the server localhost-only for native runs. The Docker
  // image sets DFIR_HOST=0.0.0.0 so the container's published port works; compose maps that
  // port to 127.0.0.1 on the host, so it never listens on the host's public interfaces.
  const host = process.env.DFIR_HOST && process.env.DFIR_HOST !== "" ? process.env.DFIR_HOST : "127.0.0.1";
  startServer(casesRoot, port, host);
}
