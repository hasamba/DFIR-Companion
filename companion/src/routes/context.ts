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
import type { Severity, InvestigationState } from "../analysis/stateTypes.js";
import type { ToolConfig } from "../integrations/tools/toolConfig.js";
import type { CustomTool } from "../integrations/tools/customToolStore.js";

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
/**
 * Options bag every pipeline.importX(...) call takes: the stored label + id prefix, the import
 * timestamp, an optional progress callback, an optional severity floor, and an optional cancel
 * signal. Shared by dispatchImport (graduated below) and the createApp import seams.
 */
export type ImportBase = {
  label: string;
  idPrefix: string;
  importedAt: string;
  onProgress?: (done: number, total: number) => void;
  minSeverity?: Severity;
  signal?: AbortSignal;
};

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
  // Run a raw text/log blob through the full import → diff → re-synthesize pipeline (the same chain
  // as the Import button). A hoisted async function in createApp shared by the /import, /tools and
  // Velociraptor ingest paths (still there); graduated for routes/pushNotify.ts's POST /cases/:id/push.
  ingestStreamed(
    caseId: string, kind: string, text: string, originalName: string, minSeverity?: Severity,
  ): Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }>;
  // External-tool runner machinery shared between the drop-folder auto-run path + the drop batch route
  // (both still in createApp) and routes/tools.ts. Stable (hoisted function declarations bound at
  // construction), so safe to destructure at registration scope:
  //   runToolAndIngest — run a configured tool against a contained raw file and ingest its output
  //                      through the same chain as the Import button (with an optional undo checkpoint).
  //   reloadCustomTools — refresh the in-memory custom-tool list after a custom-tool CRUD mutation.
  runToolAndIngest(
    caseId: string, toolId: string, targetPath: string, opts?: { undoLabel?: string },
  ): Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }>;
  reloadCustomTools(): Promise<void>;
  // Import machinery shared between routes/import.ts and the createApp import seams that stay
  // (the Velociraptor bundle collector reuses dispatchImport/demoteForensicForCase/resynthesize,
  // the drop-folder poller reuses moveDropFile, and the push/tool paths reuse the whitelist/NSRL/
  // deobfuscation post-processing + pushImportCheckpoint). Stable (hoisted function declarations
  // bound at construction), so safe to destructure at registration scope:
  //   dispatchImport            — route a detected import kind to the matching pipeline.importX(...).
  //   demoteForensicForCase     — drop sub-threshold telemetry to the super-timeline; returns state.
  //   resynthesizeInBackground  — fire the AI re-synthesis (+ auto-enrich) after an import lands.
  //   pushImportCheckpoint      — snapshot pre-import state onto the #76 undo stack (best-effort).
  //   applyWhitelistToCase / applyNsrlToCase / applyDeobfuscationToCase — pre-synthesis passes that
  //                               auto-mark known-good indicators + decode obfuscated commands.
  //   moveDropFile              — move a processed drop file to _processed/_failed (shared w/ poller).
  dispatchImport(kind: string, caseId: string, text: string, base: ImportBase): Promise<unknown>;
  demoteForensicForCase(caseId: string): Promise<InvestigationState>;
  resynthesizeInBackground(caseId: string): void;
  pushImportCheckpoint(caseId: string, beforeState: InvestigationState, label: string): Promise<void>;
  applyWhitelistToCase(caseId: string): Promise<{ matched: number; added: number }>;
  applyNsrlToCase(caseId: string): Promise<{ matchedIocs: number; matchedEvents: number; added: number }>;
  applyDeobfuscationToCase(caseId: string): Promise<{ deobfuscated: number; newIocs: number }>;
  moveDropFile(dropDir: string, relpath: string, ok: boolean): Promise<void>;

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
  // Detect the importer kind for a filename+text (honours user-authored custom importers). A `const`
  // arrow defined in createApp AFTER this ctx literal, so it's exposed as a live accessor — call
  // ctx.resolveImportKind() INSIDE the handler to reach the current binding, then invoke the result.
  resolveImportKind(): (filename: string, text: string) => string;
  // External-tool config + custom-tool list, both shared with the drop-folder code still in createApp
  // (resolveToolForExt/rawExtClaimed read customTools; the drop batch route + poller read
  // liveToolConfigs). Exposed as live accessors because they're built AFTER this ctx literal:
  //   liveToolConfigs   — a `const` arrow returning the merged built-in+custom tool config map read
  //                       LIVE from env; call ctx.liveToolConfigs() INSIDE the handler, then invoke it.
  //   customTools       — a mutable array reassigned by the async initial load + reloadCustomTools;
  //                       call ctx.customTools() per request to read the current list.
  liveToolConfigs(): () => Map<string, ToolConfig>;
  customTools(): CustomTool[];
  // Evidence drop-folder watcher state, SHARED between routes/import.ts (POST /drop/run-pending) and
  // the drop poller that stays in createApp (scanCaseDrops mutates the SAME Maps/Set). Exposed as live
  // accessors because the poller keeps writing them after this ctx literal is built — call
  // ctx.dropSeen()/dropScanning()/dropPendingLogged() INSIDE the handler and mutate the returned
  // collection in place; never capture it at registration scope:
  //   dropSeen          — per-case size+mtime snapshot used to detect a settled (fully-copied) file.
  //   dropScanning      — per-case in-flight-sweep guard (run-pending + the poller serialize on it).
  //   dropPendingLogged — per-case relpaths already logged PENDING, to dedupe the drop-log across polls.
  dropSeen(): Map<string, Map<string, { size: number; mtimeMs: number }>>;
  dropScanning(): Set<string>;
  dropPendingLogged(): Map<string, Set<string>>;
}
