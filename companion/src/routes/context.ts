import type { Request } from "express";
import type { CaseStore } from "../storage/caseStore.js";
import type { Logger } from "../logging/logger.js";
import type { AppOptions } from "../server.js";

/**
 * Dependencies shared across more than one route domain, built once in createApp and passed to
 * every registerXRoutes(app, ctx). Domain-local state (per-domain timers/caches) does NOT go here —
 * it stays as closure state inside the owning domain module. Fields are added here only when a
 * second domain needs them ("graduate on demand").
 */
export interface RouteContext {
  readonly store: CaseStore;
  readonly options: AppOptions;
  readonly serverLogger: Logger;
  recordImportFailure(caseId: string, kind: string, filename: string, err: unknown): void;
  recordAiError(caseId: string, phase: string, err: unknown): void;
  readUnlockState(req: Request, id: string, salt: string): { unlocked: boolean; remembered: boolean };
}
