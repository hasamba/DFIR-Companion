import type { Request } from "express";
import type { CaseStore } from "../storage/caseStore.js";
import type { Logger } from "../logging/logger.js";
import type { AppOptions } from "../server.js";
import type { CaptureMetadata } from "../types.js";
import type { AiControl } from "../analysis/aiControl.js";
import type { ImporterRegistry } from "../analysis/importerStore.js";
import type { IrisClient } from "../integrations/iris/irisClient.js";
import type { EnrichmentProvider } from "../enrichment/provider.js";
import type { ProviderHealthCache } from "../enrichment/providerHealth.js";
import type { ImporterFailure, AiError } from "../analysis/diagnostics.js";

/**
 * Dependencies shared across more than one route domain, built once in createApp and passed to
 * every registerXRoutes(app, ctx). Domain-local state (per-domain timers/caches) does NOT go here —
 * it stays as closure state inside the owning domain module. Fields are added here only when a
 * second domain needs them ("graduate on demand").
 *
 * Live state that createApp constructs AFTER this object (or rebinds at runtime, e.g. irisClient
 * on /iris/reconnect, importerRegistry after an async load) is exposed as an accessor function so
 * consumers always read the current binding rather than a value captured at construction time.
 */
export interface RouteContext {
  // ── Stable value fields ──────────────────────────────────────────────────────────────
  // Constructed before this object and never rebound; safe to read or destructure anywhere.
  readonly store: CaseStore;
  readonly options: AppOptions;
  readonly serverLogger: Logger;
  readonly appStartedAt: number;
  readonly recentImportFailures: ImporterFailure[]; // diagnostics ring, mutated in place by recordImportFailure
  readonly recentAiErrors: AiError[]; // diagnostics ring, mutated in place by recordAiError

  // ── Stable helper methods ────────────────────────────────────────────────────────────
  // Pure/stateless-facing helpers bound at construction; safe to destructure at registration scope.
  recordImportFailure(caseId: string, kind: string, filename: string, err: unknown): void;
  recordAiError(caseId: string, phase: string, err: unknown): void;
  readUnlockState(req: Request, id: string, salt: string): { unlocked: boolean; remembered: boolean };
  hasAiProvider(): boolean;
  // Capture→analyze machinery shared with the drop-watch ingest path and the AI-control routes
  // (all still in createApp). Graduated for routes/captures.ts's POST /captures handler:
  //   getControl         — read the per-case AI on/off + last-analyzed-seq control record.
  //   flush              — drain a case's capture buffer through the analysis pipeline.
  //   indexCaptureText   — queue a persisted screenshot for background OCR full-text indexing.
  // Stable (hoisted function declarations bound at construction); the LIVE state they touch
  // (buffers, synth in-flight, the OCR queue) is reached through the live accessors below.
  getControl(caseId: string): Promise<AiControl>;
  flush(caseId: string): Promise<void>;
  indexCaptureText(metadata: CaptureMetadata): void;

  // ── LIVE accessors ───────────────────────────────────────────────────────────────────
  // Call these INSIDE the request handler (or inside per-request logic like a preflight run),
  // never hoist to registration scope. They must be re-read per request: the underlying binding
  // is created AFTER this ctx literal or reassigned at runtime (e.g. irisClient on /iris/reconnect,
  // importerRegistry after its async load), so a value captured once would silently go stale.
  captureBuffers(): Map<string, CaptureMetadata[]>;
  synthInFlight(): Set<string>;
  importerRegistry(): ImporterRegistry;
  irisClient(): IrisClient | undefined;
  dropWatchEnabled(): boolean;
  enrichmentProviders(): EnrichmentProvider[];
  enrichHealth(): ProviderHealthCache;
}
