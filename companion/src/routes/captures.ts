import type { Express, Request, Response } from "express";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ZodError } from "zod";
import { ingestCapture, CaseNotFoundError } from "../ingest/captureIngest.js";
import { searchOcrIndex, isOcrSearchEnabled } from "../analysis/ocrSearch.js";
import type { RouteContext } from "./context.js";

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

/**
 * Capture / evidence / OCR routes: browser-extension screenshot ingest (/captures,
 * /cases/:id/captures/*), evidence file serving, and OCR full-text search.
 *
 * Pure structural move out of createApp (see routes/system.ts for the conventions). The heavy
 * capture→analyze→synthesize machinery (buffers, flush, getControl, the OCR index worker) stays
 * in createApp because the drop-watch ingest path and the AI-control routes share it; this module
 * reaches it through the RouteContext members it was graduated onto (captureBuffers(), flush,
 * getControl, indexCaptureText). Call live accessors (ctx.captureBuffers()) INSIDE the handler.
 */
export function registerCaptureRoutes(app: Express, ctx: RouteContext): void {
  const { store, options, serverLogger, hasAiProvider, getControl, flush, indexCaptureText } = ctx;

  // Buffer window size + which triggers force an early flush — mirrors the createApp constants
  // (re-derived from the same option so the two ingest paths stay in lockstep).
  const windowSize = options.windowSize ?? 4;
  const SIGNIFICANT = new Set(["navigation", "tab_switch"]);

  // Most-recent capture across ALL cases (in-memory; resets on restart). Powers the dashboard's
  // check-on-connect for the cross-case capture warning.
  let lastCapture: { caseId: string; at: number } | null = null;

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

  // The most-recent capture across ALL cases (in-memory; resets on restart) + its age in ms.
  // A freshly-connected dashboard checks this to warn when screenshots are landing on a different
  // case than the one it's viewing — catching the mismatch even without a live capture event.
  app.get("/captures/recent", (_req: Request, res: Response) => {
    if (!lastCapture) return res.status(200).json({ caseId: null });
    return res.status(200).json({ caseId: lastCapture.caseId, ageMs: Date.now() - lastCapture.at });
  });

  app.post("/captures", async (req: Request, res: Response) => {
    try {
      const rawCaseId = typeof req.body?.caseId === "string" ? req.body.caseId.trim() : "";
      if (rawCaseId) {
        const caseMeta = await store.getCaseMeta(rawCaseId).catch(() => null);
        if (caseMeta?.status === "closed" || caseMeta?.status === "archived") {
          const action = caseMeta.status === "archived" ? "restore it" : "reopen it";
          return res.status(423).json({ error: `Case "${rawCaseId}" is ${caseMeta.status} — ${action} before adding screenshots` });
        }
      }
      const metadata = await ingestCapture(store, req.body);
      // Pre-evaluate the analysis condition before responding so the dashboard knows whether
      // this capture will produce timeline events (mirrors the analyzed/reason pattern on /import).
      const willAnalyze = !metadata.isDuplicate && Boolean(options.pipeline) && hasAiProvider()
        && (await getControl(metadata.caseId)).enabled;
      res.status(201).json(
        !metadata.isDuplicate && !willAnalyze
          ? { ...metadata, analyzed: false, reason: "ai-off" as const }
          : metadata,
      );
      serverLogger.debug(
        `screenshot captured seq=${metadata.sequenceNumber} trigger=${metadata.triggerType} ` +
          `file=${metadata.screenshotFile || "(none)"}${metadata.isDuplicate ? " (duplicate — not analyzed)" : ""}`,
        { caseId: metadata.caseId },
      );
      // Cross-case signal: lets a dashboard warn when captures arrive for a case it isn't viewing
      // (live, via the WS broadcast) or detect it on connect (via /captures/recent).
      lastCapture = { caseId: metadata.caseId, at: Date.now() };
      options.onCapture?.(metadata.caseId);
      // Background OCR full-text index (#176) — independent of AI analysis (it's local + free),
      // so it runs whenever OCR search is enabled, not gated on the AI provider.
      indexCaptureText(metadata);
      // Evidence is always stored; AI analysis only runs when enabled for the case.
      if (willAnalyze) {
        const buffers = ctx.captureBuffers();
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

  // Screenshot OCR full-text search (#176). Scans the case's local OCR index for `q` and
  // returns one hit per matching screenshot (snippet + match count); the dashboard links each
  // hit back to the screenshot via GET /cases/:id/evidence/:file. Local-only, no AI.
  app.get("/cases/:id/ocr-search", async (req: Request, res: Response) => {
    try {
      if (!(await store.caseExists(req.params.id))) {
        return res.status(404).json({ error: `case ${req.params.id} does not exist` });
      }
      const q = typeof req.query.q === "string" ? req.query.q : "";
      if (q.trim().length === 0) return res.status(400).json({ error: "missing query parameter q" });
      const index = await store.loadOcrIndex(req.params.id);
      const hits = searchOcrIndex(index, q);
      return res.status(200).json({ enabled: isOcrSearchEnabled(), indexed: Object.keys(index).length, hits });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
