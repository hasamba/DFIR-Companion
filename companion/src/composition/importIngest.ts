/**
 * The shared import spine: the declarative-importer registry, the kind→importer dispatch table,
 * evidence persistence, the forensic-gate demotion, and the streamed-ingest chain every non-route
 * import path funnels through. Lifted out of createApp by #416.
 *
 * `ingestStreamed` is the one worth reading. It mirrors the /import route's chain but is tuned for
 * HIGH-FREQUENCY streaming — the generic push endpoint (#84), the Velociraptor client-event poller,
 * the drop folder, an external tool's output — and the four differences are all deliberate:
 *
 *   AWAITS the deterministic import, so the caller can honestly report "+N events" in its response;
 *   BACKGROUNDS only the AI synthesis, which is the slow part and nobody's response depends on it;
 *   RECORDS import-meta ONLY on a non-empty diff, so a quiet poll cannot reset the dashboard's
 *     "NEW since last import" highlighting every 30 seconds;
 *   SKIPS the undo checkpoint, because per-poll snapshots of the whole case would flood the undo
 *     stack — callers that ARE a discrete analyst action (a manual tool run) push their own.
 *
 * THE DUAL-WRITE ORDER IS THE CONTRACT. New events go to the super-timeline FIRST, and only then
 * are sub-threshold ones demoted out of the forensic timeline. Reverse it and a demote racing
 * another import's dual-write can strip rows that exist in neither timeline — evidence lost, with
 * nothing logged. The import-meta diff is then computed on the POST-demote state so "+N events"
 * counts what actually entered the forensic timeline, not what was parsed.
 */
import { Buffer } from "node:buffer";
import type { CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";
import type { ImportBase } from "../routes/context.js";
import type { AiControl } from "../analysis/aiControl.js";
import type { ImporterRunStat } from "../analysis/diagnostics.js";
import { ImporterStore, type ImporterRegistry, type ImporterPrecedence } from "../analysis/importerStore.js";
import { detectImportWithCustom } from "../analysis/importDetect.js";
import { observeImport } from "../analysis/operationalImport.js";
import { demoteBelowSeverity, resolveForensicMinSeverity } from "../analysis/forensicGate.js";
import { diffTimeline, addedForensicEvents } from "../analysis/timelineDiff.js";
import { diffIocs } from "../analysis/iocsDiff.js";
import type { InvestigationState, Severity, ForensicEvent } from "../analysis/stateTypes.js";
import { logLine } from "../logging/serverLogger.js";

export interface ImportIngestDeps {
  store: CaseStore;
  options: AppOptions;
  runStateExclusive: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
  recordImporterRun: (id: string, patch: Omit<ImporterRunStat, "lastRunAt">) => void;
  redactErr: (err: unknown) => string;
  /** Content-based tagger run over just the events an import added (see analysis/taggerAuto.ts). */
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<void>;
  getControl: (caseId: string) => Promise<AiControl>;
  applyWhitelistToCase: (caseId: string) => Promise<{ matched: number; added: number }>;
  applyNsrlToCase: (caseId: string) => Promise<{ matchedIocs: number; matchedEvents: number; added: number }>;
  applyDeobfuscationToCase: (caseId: string) => Promise<{ deobfuscated: number; newIocs: number }>;
  resynthesizeInBackground: (caseId: string) => void;
}

export interface ImportIngest {
  /** The live declarative-importer registry. An accessor: it is loaded async and reloaded on CRUD. */
  importerRegistry(): ImporterRegistry;
  importerPrecedence(): ImporterPrecedence;
  setImporterPrecedence(precedence: ImporterPrecedence): void;
  reloadImporters(): Promise<void>;
  /** Detect an import kind, honouring user-authored importers and the configured precedence. */
  resolveImportKind(filename: string, text: string): string;
  /** Route a detected kind to its pipeline importer. Rejects on an unknown kind. */
  dispatchImport(kind: string, caseId: string, text: string, base: ImportBase): Promise<unknown>;
  /** Evidence-first persist: next sequence, save the raw file, append the audit line. */
  persistEvidence(
    caseId: string,
    originalName: string,
    text: string,
  ): Promise<{ storedName: string; importedAt: string; seq: number }>;
  /** Move sub-threshold events out of the forensic timeline (they live on in the super-timeline). */
  demoteForensicForCase(caseId: string): Promise<InvestigationState>;
  ingestStreamed(
    caseId: string,
    kind: string,
    text: string,
    originalName: string,
    minSeverity?: Severity,
  ): Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }>;
}

export function createImportIngest(deps: ImportIngestDeps): ImportIngest {
  const {
    store,
    options,
    runStateExclusive,
    recordImporterRun,
    redactErr,
    autoTagImported,
    getControl,
    applyWhitelistToCase,
    applyNsrlToCase,
    applyDeobfuscationToCase,
    resynthesizeInBackground,
  } = deps;

  // User-authored declarative importers (external plugin layer). Loaded async at startup; empty
  // until the load resolves (parity with the velociraptor inventory / iris reconnect self-heals).
  let registry: ImporterRegistry = { importers: new Map(), meta: [], errors: [] };
  let precedence: ImporterPrecedence = "builtin-first";
  const importerStore: ImporterStore | undefined = options.importerStore;
  if (importerStore) {
    importerStore
      .loadAll()
      .then((r) => {
        registry = r;
      })
      .catch(() => {
        /* keep empty */
      });
    importerStore
      .precedence()
      .then((p) => {
        precedence = p;
      })
      .catch(() => {
        /* default */
      });
  }
  async function reloadImporters(): Promise<void> {
    if (!importerStore) return;
    registry = await importerStore.loadAll();
    precedence = await importerStore.precedence();
    options.onImporters?.();
  }
  const resolveImportKind = (filename: string, text: string): string =>
    detectImportWithCustom(filename, text, registry.importers, precedence);

  // Dispatch a detected import kind to the matching pipeline importer. Shared by the unified /import
  // route and the Velociraptor bundle collector (which ingests uploaded JSON reports the same way).
  function dispatchImport(kind: string, caseId: string, text: string, base: ImportBase): Promise<unknown> {
    const pipeline = options.pipeline;
    if (!pipeline) return Promise.reject(new Error("AI pipeline not configured"));
    const startedAt = Date.now();
    const observe = <T>(work: Promise<T>): Promise<T> =>
      observeImport(options.operationalMetrics, { kind, idPrefix: base.idPrefix, text, startedAt }, work);
    // A user-authored declarative importer takes the matching kind first (its id is the kind).
    const custom = registry.importers.get(kind);
    if (custom) {
      let parsed: { total: number; kept: number; dropped: number } | null = null;
      return observe(
        pipeline
          .importDeclarative(caseId, text, {
            importer: custom,
            ...base,
            onParsed: (r) => {
              parsed = { total: r.total, kept: r.kept, dropped: r.dropped };
              recordImporterRun(kind, { lastStatus: "ok", ...parsed, lastError: null });
            },
          })
          .catch((err) => {
            recordImporterRun(kind, {
              lastStatus: "error",
              total: parsed?.total ?? 0,
              kept: parsed?.kept ?? 0,
              dropped: parsed?.dropped ?? 0,
              lastError: redactErr(err),
            });
            throw err;
          }),
      );
    }
    switch (kind) {
      case "thor":
        return observe(pipeline.importThor(caseId, text, base));
      case "siem":
        return observe(pipeline.importSiem(caseId, text, base));
      case "evtxxml":
        return observe(pipeline.importEvtxXml(caseId, text, base));
      case "chainsaw":
        return observe(pipeline.importChainsaw(caseId, text, base));
      case "hayabusa":
        return observe(pipeline.importHayabusa(caseId, text, base));
      case "velociraptor":
        return observe(pipeline.importVelociraptor(caseId, text, base));
      case "securityonion":
        return observe(pipeline.importSecurityOnion(caseId, text, base));
      case "socrates":
        return observe(pipeline.importSocrates(caseId, text, base));
      case "network":
        return observe(pipeline.importNetwork(caseId, text, base));
      case "kape":
        return observe(pipeline.importKape(caseId, text, base));
      case "cybertriage":
        return observe(pipeline.importCybertriage(caseId, text, base));
      case "m365":
        return observe(pipeline.importM365(caseId, text, base));
      case "aws":
        return observe(pipeline.importAws(caseId, text, base));
      case "cloud":
        return observe(pipeline.importCloudActivity(caseId, text, base));
      case "k8s":
        return observe(pipeline.importK8sAudit(caseId, text, base));
      case "osquery":
        return observe(pipeline.importOsquery(caseId, text, base));
      case "plaso":
        return observe(pipeline.importPlaso(caseId, text, base));
      case "sandbox":
        return observe(pipeline.importSandbox(caseId, text, base));
      case "memory":
        return observe(pipeline.importMemory(caseId, text, base));
      case "email":
        return observe(pipeline.importEmail(caseId, text, base));
      case "thehive":
        return observe(pipeline.importTheHive(caseId, text, base));
      case "auditd":
        return observe(pipeline.importAuditd(caseId, text, base));
      case "journald":
        return observe(pipeline.importJournald(caseId, text, base));
      case "sysdig":
        return observe(pipeline.importSysdig(caseId, text, base));
      case "wazuh":
        return observe(pipeline.importWazuh(caseId, text, base));
      case "bashhistory":
        return observe(pipeline.importBashHistory(caseId, text, base));
      case "ecar":
        return observe(pipeline.importEcar(caseId, text, base));
      case "snort":
        return observe(pipeline.importSnort(caseId, text, base));
      case "yara":
        return observe(pipeline.importYara(caseId, text, base));
      case "combinedlog":
        return observe(pipeline.importCombinedLog(caseId, text, base));
      case "asa":
        return observe(pipeline.importCiscoAsa(caseId, text, base));
      case "syslog":
        return observe(pipeline.importSyslog(caseId, text, base));
      case "csv":
        return observe(pipeline.analyzeCsv(caseId, text, base));
      case "log":
        return observe(pipeline.analyzeLog(caseId, text, base));
      default:
        return Promise.reject(new Error(`unhandled import kind: ${kind}`));
    }
  }

  // Evidence-first persist of an imported blob: next sequence, save the raw file, append the audit line.
  async function persistEvidence(
    caseId: string,
    originalName: string,
    text: string,
  ): Promise<{ storedName: string; importedAt: string; seq: number }> {
    const seq = await store.nextImportSeq(caseId);
    const safe = originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.dat";
    const storedName = `${String(seq).padStart(4, "0")}_${safe}`;
    const importedAt = new Date().toISOString();
    await store.saveImport(caseId, storedName, text);
    await store.appendImport(caseId, {
      caseId,
      sequenceNumber: seq,
      importedAt,
      filename: storedName,
      originalName,
      rows: 0,
      bytes: Buffer.byteLength(text, "utf8"),
    });
    return { storedName, importedAt, seq };
  }

  // Route sub-threshold (Info by default) telemetry to the super-timeline only. The super-timeline
  // already captured these events (dual-write at each import seam); here we drop them from the
  // forensic timeline so the AI only synthesizes graded signal. Promotion re-adds them if the analyst
  // wants (it goes through pipeline.promoteSuperTimeline, NOT this gate). Threshold: per-case
  // forensic-gate ?? DFIR_FORENSIC_MIN_SEVERITY ?? "Low". Returns the (possibly unchanged) state.
  //
  // The demote is CASE-WIDE, so with concurrent imports it can fire between another import's
  // pre-import snapshot and that import's dual-write, stripping rows the owning import had not yet
  // copied to super — they would then exist in neither timeline. The capture below closes that:
  // an event may only leave the forensic timeline after it is written to the super-timeline in this
  // same critical section. append() dedups by id, so re-capturing a row the seam already wrote is free.
  async function demoteForensicForCase(caseId: string): Promise<InvestigationState> {
    return runStateExclusive(caseId, async () => {
      const state = await options.stateStore!.load(caseId);
      if (!options.forensicGateControlStore) return state;
      const min = resolveForensicMinSeverity(
        (await options.forensicGateControlStore.load(caseId)).minSeverity,
        process.env.DFIR_FORENSIC_MIN_SEVERITY,
      );
      const { kept, demoted } = demoteBelowSeverity(state.forensicTimeline, min);
      if (!demoted.length) return state;
      if (options.superTimelineStore) {
        try {
          await options.superTimelineStore.append(caseId, demoted);
          options.onSuperTimeline?.(caseId);
        } catch {
          // Capture failed — keep the rows in the forensic timeline rather than dropping them
          // on the floor; the next import/demote will retry.
          return state;
        }
      }
      const next = { ...state, forensicTimeline: kept };
      await options.stateStore!.save(next);
      options.onState?.(next);
      return next;
    });
  }

  async function ingestStreamed(
    caseId: string,
    kind: string,
    text: string,
    originalName: string,
    minSeverity?: Severity,
  ): Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }> {
    const pipeline = options.pipeline;
    if (!pipeline) throw new Error("AI pipeline not configured");
    options.onImport?.(caseId); // cross-case signal (parity with /import + captures) for push/monitor ingest
    const { storedName, importedAt, seq } = await persistEvidence(caseId, originalName, text);

    // CSV/log are themselves an LLM call → respect the per-case AI toggle exactly like /import: with
    // AI OFF the evidence is saved but not sent to the model. Deterministic importers proceed.
    const aiDependent = kind === "csv" || kind === "log";
    if (aiDependent && !(await getControl(caseId)).enabled) {
      options.onAiStatus?.(caseId, {
        status: "idle",
        at: new Date().toISOString(),
        detail: `AI is off — ${kind.toUpperCase()} saved as evidence but not analyzed (turn AI on, then re-import)`,
      });
      return { storedName, addedEvents: 0, addedIocs: 0, analyzed: false };
    }

    const onProgress = (done: number, total: number): void =>
      options.onAiStatus?.(caseId, {
        status: "analyzing",
        phase: "extracting",
        at: new Date().toISOString(),
        detail: `${kind} import — ${done}/${total}`,
      });
    options.onAiStatus?.(caseId, {
      status: "analyzing",
      phase: "extracting",
      at: importedAt,
      detail: `importing (${kind})${minSeverity ? ` — min severity ${minSeverity}` : ""}`,
    });

    let stateBefore: InvestigationState | null = null;
    if (options.stateStore) {
      try {
        stateBefore = await options.stateStore.load(caseId);
      } catch {
        /* keep null */
      }
    }

    await dispatchImport(kind, caseId, text, {
      label: storedName,
      idPrefix: `${seq}`,
      importedAt,
      onProgress,
      minSeverity,
    });
    options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });

    let addedEvents = 0,
      addedIocs = 0;
    if (options.stateStore && stateBefore) {
      try {
        const imported = await options.stateStore.load(caseId);
        // Dual-write the newly-imported events into the super-timeline FIRST so it stays a superset of
        // everything imported (Info telemetry included). The diff is lossy, so resolve the FULL events
        // from the imported (pre-demote) state. Best-effort — a side record.
        if (options.superTimelineStore) {
          const superDiff = diffTimeline(stateBefore.forensicTimeline, imported.forensicTimeline);
          const added = addedForensicEvents(imported.forensicTimeline, superDiff);
          if (added.length) {
            try {
              await options.superTimelineStore.append(caseId, added);
              options.onSuperTimeline?.(caseId);
            } catch {
              /* non-fatal */
            }
            await autoTagImported(caseId, added);
          }
        }
        // Now demote sub-threshold events out of the forensic timeline (they live on in the super-
        // timeline). Compute the import-meta diff on the POST-demote state so "+N events" counts only
        // what actually entered forensic.
        const s = await demoteForensicForCase(caseId);
        const tDiff = diffTimeline(stateBefore.forensicTimeline, s.forensicTimeline);
        const iDiff = diffIocs(stateBefore.iocs, s.iocs);
        addedEvents = tDiff.added.length;
        addedIocs = iDiff.added.length;
        if (
          (addedEvents || addedIocs || tDiff.removed.length || iDiff.removed.length) &&
          options.importMetaStore
        ) {
          await options.importMetaStore.record(caseId, {
            kind,
            file: storedName,
            diff: tDiff,
            iocsDiff: iDiff,
          });
          options.onImportMeta?.(caseId);
        }
      } catch {
        /* non-fatal */
      }
    }
    // Auto-mark known-good IOCs/hashes legitimate (whitelist + NSRL) BEFORE re-synthesis, like /import.
    try {
      const wl = await applyWhitelistToCase(caseId);
      if (wl.added > 0) logLine(`[whitelist] ${caseId} auto-marked ${wl.added} pushed IOC(s) legitimate`);
    } catch {
      /* non-fatal */
    }
    try {
      const ns = await applyNsrlToCase(caseId);
      if (ns.added > 0)
        logLine(`[nsrl] ${caseId} auto-marked ${ns.added} pushed known-good item(s) legitimate`);
    } catch {
      /* non-fatal */
    }
    try {
      const deob = await applyDeobfuscationToCase(caseId);
      if (deob.deobfuscated > 0)
        logLine(
          `[deobfuscate] ${caseId} decoded ${deob.deobfuscated} pushed event(s), +${deob.newIocs} new IOC(s)`,
        );
    } catch {
      /* non-fatal */
    }
    resynthesizeInBackground(caseId);
    return { storedName, addedEvents, addedIocs, analyzed: true };
  }

  return {
    importerRegistry: () => registry,
    importerPrecedence: () => precedence,
    setImporterPrecedence: (next) => {
      precedence = next;
    },
    reloadImporters,
    resolveImportKind,
    dispatchImport,
    persistEvidence,
    demoteForensicForCase,
    ingestStreamed,
  };
}
