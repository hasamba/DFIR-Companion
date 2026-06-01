import express, { type Express, type Request, type Response, type NextFunction } from "express";
import { config as loadDotenv } from "dotenv";
import { join, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFile, readFile, rm } from "node:fs/promises";
import { ZodError } from "zod";
import { CaseStore } from "./storage/caseStore.js";
import { ingestCapture } from "./ingest/captureIngest.js";
import type { AnalysisPipeline } from "./analysis/pipeline.js";
import type { CaptureMetadata } from "./types.js";
import type { StateStore } from "./analysis/stateStore.js";
import type { ReportWriter } from "./reports/reportWriter.js";

export type AiStatus = "analyzing" | "idle" | "error";

export interface AiStatusEvent {
  status: AiStatus;
  at: string;        // ISO timestamp
  detail?: string;   // e.g. window size, or error message
}

export interface AppOptions {
  pipeline?: AnalysisPipeline;
  windowSize?: number;
  stateStore?: StateStore;
  reportWriter?: ReportWriter;
  // Called when an AI analysis window starts / finishes / fails, so the
  // server can push a live "AI status" indicator to dashboard clients.
  onAiStatus?: (caseId: string, event: AiStatusEvent) => void;
  // When true, run the synthesis pass automatically (debounced) after capture
  // windows are analyzed, so the live dashboard shows findings/attacker path.
  autoSynthesize?: boolean;
  autoSynthesizeDebounceMs?: number;
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
      console.log(`[req] ${req.method} ${req.url} -> ${res.statusCode}`);
    });
    next();
  });

  app.use(express.json({ limit: "25mb" }));

  // Lightweight reachability check used by the extension's connection status.
  // aiEnabled tells the dashboard whether an AI provider is configured at all.
  app.get("/health", (_req: Request, res: Response) => {
    res.status(200).json({ ok: true, service: "dfir-companion", aiEnabled: Boolean(options.pipeline) });
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
      options.onAiStatus?.(caseId, { status: "analyzing", at: new Date().toISOString(), detail: "synthesizing conclusions" });
      options.pipeline!.synthesize(caseId)
        .then(() => options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() }))
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
      at: new Date().toISOString(),
      detail: `analyzing ${buf.length} screenshot(s)`,
    });
    try {
      await options.pipeline.analyzeWindow(caseId, buf);
      // Analysis recovered — drop any stale failure marker from a prior window.
      await rm(join(store.stateDir(caseId), "pending_analysis.json"), { force: true });
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

  // /cases handler stays exactly as in Plan 1.
  app.post("/cases", async (req: Request, res: Response) => {
    try {
      const { caseId, name, investigator, aiProvider } = req.body ?? {};
      if (!caseId || !name) return res.status(400).json({ error: "caseId and name are required" });
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
      if (!metadata.isDuplicate && options.pipeline) {
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

  app.post("/cases/:id/report", async (req: Request, res: Response) => {
    if (!options.reportWriter) return res.status(501).json({ error: "report writer not configured" });
    try {
      const paths = await options.reportWriter.writeAll(req.params.id);
      return res.status(200).json(paths);
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
      const state = await options.pipeline.synthesize(caseId);
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
import { GeminiProvider } from "./providers/gemini.js";
import { WebSocketServer } from "ws";
import { LiveHub } from "./live/hub.js";
import { ReportWriter as ReportWriterImpl } from "./reports/reportWriter.js";

export interface ProviderParams {
  provider?: string;
  model?: string;
  apiKey?: string;
  imageDetail?: "high" | "low" | "auto";
}

// Build a provider from explicit params (so callers can build more than one,
// e.g. a cheap extraction model + a stronger synthesis model).
export function buildProviderFrom(params: ProviderParams): AnalyzeProvider | undefined {
  const name = params.provider;
  if (!name) return undefined;
  const model = params.model ?? "";
  const apiKey = params.apiKey ?? "";
  const imageDetail = params.imageDetail ?? "high";
  const registry = new ProviderRegistry();
  registry.register(new OpenAIProvider({ apiKey, model, imageDetail }));
  registry.register(new OpenRouterProvider({ apiKey, model, imageDetail }));
  registry.register(new OllamaCloudProvider({ apiKey, model, imageDetail }));
  registry.register(new GeminiProvider({ apiKey, model }));
  return registry.get(name);
}

export function buildProvider(): AnalyzeProvider | undefined {
  return buildProviderFrom({
    provider: process.env.DFIR_AI_PROVIDER,
    model: process.env.DFIR_AI_MODEL,
    apiKey: process.env.DFIR_AI_KEY,
    imageDetail: process.env.DFIR_AI_IMAGE_DETAIL as "high" | "low" | "auto" | undefined,
  });
}

// Synthesis model: dedicated DFIR_AI_SYNTH_* vars, falling back to the main model.
export function buildSynthesisProvider(): AnalyzeProvider | undefined {
  return buildProviderFrom({
    provider: process.env.DFIR_AI_SYNTH_PROVIDER ?? process.env.DFIR_AI_PROVIDER,
    model: process.env.DFIR_AI_SYNTH_MODEL ?? process.env.DFIR_AI_MODEL,
    apiKey: process.env.DFIR_AI_SYNTH_KEY ?? process.env.DFIR_AI_KEY,
    imageDetail: process.env.DFIR_AI_IMAGE_DETAIL as "high" | "low" | "auto" | undefined,
  });
}

export function startServer(casesRoot: string, port = 4773): void {
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStoreImpl(store);
  const hub = new LiveHub();
  const reportWriter = new ReportWriterImpl(store, stateStore);

  const provider = buildProvider();
  const synthesisProvider = buildSynthesisProvider();
  const wiredPipeline = provider
    ? new AnalysisPipelineImpl({ provider, synthesisProvider, stateStore, imageLoader: makeImageLoader(store), onState: (s) => hub.broadcast(s) })
    : undefined;

  // Live synthesis on by default — set DFIR_AI_AUTO_SYNTHESIZE=off to disable.
  const autoSynthesize = (process.env.DFIR_AI_AUTO_SYNTHESIZE ?? "on").toLowerCase() !== "off";
  const autoSynthesizeDebounceMs = Number(process.env.DFIR_AI_AUTO_SYNTHESIZE_MS) || 8000;

  const app = createApp(store, {
    pipeline: wiredPipeline,
    stateStore,
    reportWriter,
    autoSynthesize,
    autoSynthesizeDebounceMs,
    onAiStatus: (caseId, event) => hub.broadcastTo(caseId, { type: "ai_status", ...event }),
  });

  // Serve the dashboard.
  app.get("/dashboard", async (_req, res) => {
    const html = await readFile(new URL("../../public/dashboard.html", import.meta.url), "utf8");
    res.type("html").send(html);
  });

  const server = app.listen(port, "127.0.0.1", () => {
    console.log(`DFIR companion on http://127.0.0.1:${port} (dashboard at /dashboard)`);
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
  console.log(`[DFIR] cases root: ${casesRoot}`);
  startServer(casesRoot);
}
