import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { ExportFormat, OperationalMetricsStore } from "./operationalMetrics.js";

export function exportFormatForPath(path: string): ExportFormat | null {
  if (
    !/(?:\/export(?:\/|$)|\/report(?:\.|\/|$)|timeline\.(?:csv|jsonl)$|attack-layer\.json$|custody\/manifest$)/.test(
      path,
    )
  )
    return null;
  if (/\.docx$/.test(path)) return "docx";
  if (/\.html$|\/interactive/.test(path)) return "html";
  if (/\.csv$/.test(path)) return "csv";
  if (/\.jsonl$/.test(path)) return "jsonl";
  if (/stix/.test(path)) return "stix";
  if (/attack-layer/.test(path)) return "attack";
  if (/archive|redacted/.test(path)) return "archive";
  if (/\.json$|manifest/.test(path)) return "json";
  if (/report|markdown/.test(path)) return "markdown";
  return "other";
}

/** Observe export responses using only a fixed format label; request paths never enter metrics. */
export function createOperationalHttpMetrics(metrics: OperationalMetricsStore | undefined): RequestHandler {
  return function operationalHttpMetrics(req: Request, res: Response, next: NextFunction): void {
    const format = exportFormatForPath(req.path);
    if (!metrics?.enabled || !format) return next();
    const startedAt = Date.now();
    res.once("finish", () => {
      const header = Number(res.getHeader("content-length"));
      void metrics.record({
        type: "export",
        format,
        durationMs: Math.max(0, Date.now() - startedAt),
        outputBytes: Number.isFinite(header) && header > 0 ? Math.floor(header) : 0,
        success: res.statusCode >= 200 && res.statusCode < 400,
      });
    });
    next();
  };
}
