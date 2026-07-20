import type { Request } from "express";
import type { CaseStore } from "../storage/caseStore.js";
import type { Logger } from "../logging/logger.js";
import type { AppOptions } from "../server.js";
import type { CaptureMetadata } from "../types.js";
import type { AiControl } from "../analysis/aiControl.js";
import type { ImporterRegistry, ImporterPrecedence } from "../analysis/importerStore.js";
import type { IrisClient } from "../integrations/iris/irisClient.js";
import type { TimesketchClient } from "../integrations/timesketch/timesketchClient.js";
import type { EnrichmentProvider } from "../enrichment/provider.js";
import type { ProviderHealthCache } from "../enrichment/providerHealth.js";
import type { NsrlDb } from "../analysis/nsrlDb.js";
import type { ImporterFailure, AiError, ImporterRunStat } from "../analysis/diagnostics.js";
import type { Severity, InvestigationState } from "../analysis/stateTypes.js";
import type { ToolConfig } from "../integrations/tools/toolConfig.js";
import type { CustomTool } from "../integrations/tools/customToolStore.js";
import type { VeloMonitor } from "../analysis/veloMonitorStore.js";
import type { HuntDeployInput } from "../analysis/huntOutcomes.js";
import type { HuntUpload } from "../integrations/velociraptor/velociraptorApi.js";
import type { PlaybookTask } from "../analysis/playbook.js";
import type { PlaybookControl } from "../analysis/playbookControl.js";
import type { NotificationEvent } from "../analysis/notifications.js";

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
  readonly importerRunStats: Map<string, ImporterRunStat>; // per-custom-importer last-run health (#84), keyed by importer id, mutated in place by dispatchImport
  // The HMAC secret (persisted next to the cases root) that signs/verifies case-unlock cookies. Graduated
  // for routes/casePassword.ts's unlock route: the staying case-lock GATE (createCaseLockGate) + readUnlockState
  // use the SAME secret, so it's graduated (a stable readonly value), not recomputed per module.
  readonly instanceSecret: Buffer;

  // ── Stable helper methods ────────────────────────────────────────────────────────────
  // Pure/stateless-facing helpers bound at construction; safe to destructure at registration scope.
  recordImportFailure(caseId: string, kind: string, filename: string, err: unknown): void;
  recordAiError(caseId: string, phase: string, err: unknown): void;
  readUnlockState(req: Request, id: string, salt: string): { unlocked: boolean; remembered: boolean };
  hasAiProvider(): boolean;
  // Per-case state mutex + drop-folder + importer-reload helpers graduated for routes/caseLifecycle.ts.
  // All defined in createApp and SHARED with code that stays (the state lock backs every import/enrich/
  // synthesis write; the drop watcher re-ensures the inbox; dispatchImport/resolveImportKind read the
  // in-memory importer registry + precedence that reloadImporters/setImporterPrecedence mutate), so they
  // were graduated rather than moved. runStateExclusive is a `const` arrow bound at construction;
  // ensureDropFolders/reloadImporters are hoisted `async function` declarations (safe to bind before
  // their textual definition, like the velociraptor set):
  //   runStateExclusive  — serialize a case's load→save critical section (manual-event add here).
  //   ensureDropFolders  — create the evidence drop inbox for a case (fired on case creation).
  //   reloadImporters    — re-read the on-disk declarative-importer registry into the in-memory copy +
  //                        precedence, then fire onImporters (the importer CRUD writes call it).
  runStateExclusive<T>(caseId: string, fn: () => Promise<T>): Promise<T>;
  ensureDropFolders(caseId: string): Promise<void>;
  reloadImporters(): Promise<void>;
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
  // AI-control write path + the AI off→on catch-up, graduated for routes/aiSynthesis.ts's
  // POST /cases/:id/ai-control handler. Both STAY in createApp because the capture/synth machinery
  // they touch stays private there:
  //   setControl — persist a patch to the per-case AI control record (updates the private
  //                controlCache that backs getControl) and return the merged record; also called by
  //                createApp's flush + backfill, so it was graduated rather than moved. controlCache
  //                itself stays fully private to createApp (only getControl/setControl read/write it;
  //                no route touches it directly).
  //   backfill   — on an AI off→on transition, analyze every capture taken since lastAnalyzedSeq then
  //                kick synthesis. Used ONLY by the moved ai-control route, but stays in createApp
  //                because it's wired to the PRIVATE synth machinery (scheduleSynthesis + its
  //                synthTimers debounce map, windowSize, autoSynth) that no route reaches — graduating
  //                this one member is far less surface than exporting all of that.
  // Both are hoisted `async function` declarations, so binding them at construction (before their
  // textual definition) is safe.
  setControl(caseId: string, patch: Partial<AiControl>): Promise<AiControl>;
  backfill(caseId: string): Promise<void>;
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
  // Threat-intel ENRICHMENT engine (routes/threatIntel.ts). The engine + its background reachability
  // poller stay in createApp (the poller re-arms enrichInBackground and drains enrichPending on
  // provider recovery, and resynthesize/import seams fire autoEnrichIfEnabled), so the moved enrich
  // routes reach it through these graduated members. All hoisted `function`/`async function`
  // declarations, so safe to bind at construction:
  //   enrichInBackground   — run (or re-run) IOC + process-chain enrichment for a case in the
  //                          background (force re-queries already-enriched IOCs). POST /enrich +
  //                          POST /enrich-control drive it.
  //   autoEnrichIfEnabled  — enrich a case's IOCs only if enrichment is enabled for it (fired after a
  //                          manual IOC add).
  //   enabledProvidersFor  — resolve the enrichment PROVIDER objects enabled for a case (the
  //                          bulk-enrich route enriches a selected subset with them).
  enrichInBackground(caseId: string, force?: boolean): void;
  autoEnrichIfEnabled(caseId: string): void;
  enabledProvidersFor(caseId: string): Promise<EnrichmentProvider[]>;
  // Velociraptor domain machinery shared with routes/velociraptor.ts. The live-monitor + hunt-status
  // subsystems are self-rescheduling timer loops that must survive a restart, so their RESUME functions
  // (resumeVeloMonitors / resumeVeloHuntStatusPolls) run once at the END of createApp AND from POST
  // /velociraptor/reconnect. A route module can't be invoked at startup, so the whole schedule/poll/
  // resume/collect machinery STAYS in createApp and the moved routes reach the pieces they need through
  // these graduated members. The monitor/status timer MAPS (veloMonitorTimers / veloStatusTimers) stay
  // fully PRIVATE to createApp — no route mutates them directly (they go through the helpers below); only
  // veloHuntTimers is exposed (live accessor, further down) because two routes set a collect timer on it.
  // All hoisted `function` declarations, so safe to bind at construction:
  //   refreshVeloClients          — snapshot the enrolled fleet into the persisted client inventory.
  //   resumeVeloMonitors / resumeVeloHuntStatusPolls — re-arm persisted monitors / hunt-status polls
  //                                 (the reconnect route reuses the SAME functions createApp fires at boot).
  //   scheduleVeloMonitor / pollVeloMonitor / stopVeloMonitorTimer — arm / run-once / cancel a monitor.
  //   scheduleVeloHuntStatusPoll / pollVeloHuntStatus — arm / run-once a hunt-status poll.
  //   importVeloHuntResults       — collect a hunt + import through the normal chain (also fired on a timer).
  //   ingestVeloArtifactMap / ingestVeloUploads — the /import-external hunt/flow-map + uploads ingest cores.
  //   createVeloMonitor           — build + persist + schedule one monitor (manual + auto-monitor routes).
  //   recordHuntDeploy            — record a deployed hunt in the #157 hunting-feedback-loop ledger.
  refreshVeloClients(): Promise<number>;
  resumeVeloMonitors(): Promise<void>;
  resumeVeloHuntStatusPolls(): Promise<void>;
  scheduleVeloMonitor(caseId: string, monitor: VeloMonitor): void;
  pollVeloMonitor(caseId: string, id: string): Promise<void>;
  stopVeloMonitorTimer(caseId: string, id: string): void;
  scheduleVeloHuntStatusPoll(caseId: string, huntId: string): void;
  pollVeloHuntStatus(caseId: string, huntId: string): Promise<void>;
  importVeloHuntResults(caseId: string, huntId: string): Promise<void>;
  ingestVeloArtifactMap(
    caseId: string,
    mapJson: string,
    opts: { label: string; idBase: string; superOnly?: boolean; minSeverity?: Severity; hostFallback?: string; veloUrl?: string },
  ): Promise<{ addedEvents: number; addedIocs: number; storedName: string }>;
  ingestVeloUploads(
    caseId: string,
    uploads: HuntUpload[],
    opts: { minSeverity?: Severity; label: string },
  ): Promise<{ addedEvents: number; addedIocs: number; imported: string[]; skipped: string[] }>;
  createVeloMonitor(
    caseId: string,
    spec: { clientId: string; artifact: string; pollSeconds: number; hostname?: string; minSeverity?: Severity; allClients?: boolean },
  ): Promise<VeloMonitor>;
  recordHuntDeploy(caseId: string, input: HuntDeployInput): Promise<void>;
  // Playbook derivation helpers (routes/playbookHunts.ts). Both are SHARED with createApp code that
  // stays — syncPlaybook is also called by the POST /cases/:id/push/iris route, and loadPlaybookControl
  // is a dependency of syncPlaybook — so they were graduated here rather than moved. Hoisted `function`
  // declarations in createApp (defined after this literal but safe to bind, like the velociraptor set):
  //   syncPlaybook        — re-derive the checklist against current state honoring the template setting
  //                         (no-op-safe write); returns the task list.
  //   loadPlaybookControl — read the per-case IR-template toggle (defaults when no store).
  syncPlaybook(caseId: string): Promise<PlaybookTask[]>;
  loadPlaybookControl(caseId: string): Promise<PlaybookControl>;
  // Fire a notification event to all matching channels (best-effort, fire-and-forget). A stable
  // const arrow in createApp shared by create-case + the drop-import path (both still there);
  // graduated for routes/reportsExport.ts's POST /cases/:id/report ("Report generated" milestone).
  dispatchNotify(event: NotificationEvent): void;

  // ── LIVE accessors ───────────────────────────────────────────────────────────────────
  // Call these INSIDE the request handler (or inside per-request logic like a preflight run),
  // never hoist to registration scope. They must be re-read per request: the underlying binding
  // is created AFTER this ctx literal or reassigned at runtime (e.g. irisClient on /iris/reconnect,
  // importerRegistry after its async load), so a value captured once would silently go stale.
  captureBuffers(): Map<string, CaptureMetadata[]>;
  synthInFlight(): Set<string>;
  importerRegistry(): ImporterRegistry;
  // The active importer precedence (builtin-first / external-first). A `let` in createApp read live by
  // dispatchImport/resolveImportKind (stay) and the moved GET /importers route; PUT /importers/precedence
  // rewrites it via setImporterPrecedence. Read via importerPrecedence() INSIDE the handler (mirrors
  // importerRegistry()); the setter reassigns the SAME createApp binding the detection seam reads.
  importerPrecedence(): ImporterPrecedence;
  setImporterPrecedence(precedence: ImporterPrecedence): void;
  irisClient(): IrisClient | undefined;
  // The DFIR-IRIS client is a MUTABLE shared handle: POST /iris/reconnect (routes/reportsExport.ts)
  // rebuilds it at runtime and createApp's /cases/:id/push/iris reads it. Mirrors nsrlDb()/setNsrlDb():
  //   setIrisClient    — reassign the shared binding (both the moved iris routes and the createApp
  //                      push/iris route read the SAME `let irisClient`); call INSIDE the handler.
  //   rebuildIrisClient — build a fresh client from the current .env, wrapping createApp's
  //                       `options.rebuildIrisClient ?? buildIrisClient` so buildIrisClient's use stays
  //                       inside server.ts (no route module imports a value from ../server.js).
  setIrisClient(client: IrisClient | undefined): void;
  rebuildIrisClient(): IrisClient | undefined;
  // Rebuild the Timesketch client from the current .env (mirrors rebuildIrisClient). Graduated for
  // routes/caseLifecycle.ts's POST /timesketch/reconnect, which reassigns options.timesketchClient with the
  // result; the timesketch push routes read options.timesketchClient live. Wraps createApp's
  // `options.rebuildTimesketchClient ?? buildTimesketchClient` so buildTimesketchClient's use stays in
  // server.ts (no route module imports a value from ../server.js). Call INSIDE the handler.
  rebuildTimesketchClient(): TimesketchClient | undefined;
  dropWatchEnabled(): boolean;
  enrichmentProviders(): EnrichmentProvider[];
  enrichHealth(): ProviderHealthCache;
  // Cases whose last enrich run had to skip a down provider — the background poller (createApp) drains
  // this Set on recovery. POST /cases/:id/enrich-control deletes a case from it when enrichment is
  // turned off; call ctx.enrichPending() INSIDE the handler and mutate the returned Set in place.
  enrichPending(): Set<string>;
  // The active NSRL RDS SQLite connection (#63) — a MUTABLE shared handle. createApp's applyNsrlToCase
  // reads it; the POST/DELETE /nsrl/db routes swap it at runtime. Read via nsrlDb() and reassign via
  // setNsrlDb() (both reach the SAME createApp `let`), never a value captured at registration.
  nsrlDb(): NsrlDb | undefined;
  setNsrlDb(db: NsrlDb | undefined): void;
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
  // Fixed-delay hunt auto-collect timers, keyed by huntId. SHARED between the moved run-bundle /
  // deploy-hunt routes (which set a collect timer on it) and importVeloHuntResults (which clears it on
  // collect, still in createApp) — exposed as a live accessor so the routes mutate the SAME Map; call
  // ctx.veloHuntTimers() INSIDE the handler and set/delete on the returned map.
  veloHuntTimers(): Map<string, NodeJS.Timeout>;
}
