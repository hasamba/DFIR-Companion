import express, { type Express, type Request, type Response } from "express";
import { join } from "node:path";
import { writeFile, readFile } from "node:fs/promises";
import { ZodError } from "zod";
import { CaseStore } from "./storage/caseStore.js";
import { ingestCapture } from "./ingest/captureIngest.js";
import type { AnalysisPipeline } from "./analysis/pipeline.js";
import type { CaptureMetadata } from "./types.js";
import type { StateStore } from "./analysis/stateStore.js";
import type { ReportWriter } from "./reports/reportWriter.js";

export interface AppOptions {
  pipeline?: AnalysisPipeline;
  windowSize?: number;
  stateStore?: StateStore;
  reportWriter?: ReportWriter;
}

export function createApp(store: CaseStore, options: AppOptions = {}): Express {
  const app = express();
  app.use(express.json({ limit: "25mb" }));

  const windowSize = options.windowSize ?? 4;
  const buffers = new Map<string, CaptureMetadata[]>();
  const SIGNIFICANT = new Set(["navigation", "tab_switch"]);

  async function flush(caseId: string): Promise<void> {
    const buf = buffers.get(caseId) ?? [];
    if (buf.length === 0 || !options.pipeline) return;
    buffers.set(caseId, []);
    try {
      await options.pipeline.analyzeWindow(caseId, buf);
    } catch (err) {
      const seqs = buf.map((c) => c.sequenceNumber);
      await writeFile(
        join(store.stateDir(caseId), "pending_analysis.json"),
        JSON.stringify({ pending: seqs, error: (err as Error).message }, null, 2),
        "utf8",
      );
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

export function buildProvider(): AnalyzeProvider | undefined {
  const name = process.env.DFIR_AI_PROVIDER;
  const model = process.env.DFIR_AI_MODEL ?? "";
  const apiKey = process.env.DFIR_AI_KEY ?? "";
  if (!name) return undefined;
  const registry = new ProviderRegistry();
  registry.register(new OpenAIProvider({ apiKey, model }));
  registry.register(new OpenRouterProvider({ apiKey, model }));
  registry.register(new OllamaCloudProvider({ apiKey, model }));
  registry.register(new GeminiProvider({ apiKey, model }));
  return registry.get(name);
}

export function startServer(casesRoot: string, port = 4773): void {
  const store = new CaseStore(casesRoot);
  const stateStore = new StateStoreImpl(store);
  const hub = new LiveHub();
  const reportWriter = new ReportWriterImpl(store, stateStore);

  const provider = buildProvider();
  const wiredPipeline = provider
    ? new AnalysisPipelineImpl({ provider, stateStore, imageLoader: makeImageLoader(store), onState: (s) => hub.broadcast(s) })
    : undefined;

  const app = createApp(store, { pipeline: wiredPipeline, stateStore, reportWriter });

  // Serve the dashboard.
  app.get("/dashboard", async (_req, res) => {
    const html = await readFile(new URL("../../public/dashboard.html", import.meta.url), "utf8");
    res.type("html").send(html);
  });

  const server = app.listen(port, "127.0.0.1", () => {
    console.log(`DFIR companion on http://127.0.0.1:${port} (dashboard at /dashboard)`);
  });

  const wss = new WebSocketServer({ server, path: "/ws" });
  wss.on("connection", (socket, req) => {
    const caseId = new URL(req.url ?? "", "http://localhost").searchParams.get("caseId") ?? "";
    hub.subscribe(caseId, socket as unknown as import("./live/hub.js").SocketLike);
    socket.on("close", () => hub.unsubscribe(caseId, socket as unknown as import("./live/hub.js").SocketLike));
  });
}

// Entry point when run directly.
if (process.argv[1] && process.argv[1].endsWith("server.ts")) {
  startServer(process.env.DFIR_CASES_ROOT ?? "cases");
}
