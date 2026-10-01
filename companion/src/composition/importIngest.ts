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
import { statusFromStore, withIngestAdmission } from "../analysis/caseIngestAdmission.js";
import { Buffer } from "node:buffer";
import type { ArtifactProvenance, CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";
import type { ImportLock } from "../analysis/importLock.js";
import type { ImportBase } from "../routes/context.js";
import type { AiControl } from "../analysis/aiControl.js";
import type { ImporterRunStat } from "../analysis/diagnostics.js";
import { ImporterStore, type ImporterRegistry, type ImporterPrecedence } from "../analysis/importerStore.js";
import { detectImportWithCustomEx } from "../analysis/importDecision.js";
import { createImportDebugRecorder, type ImportDebugRecorder } from "../analysis/importDebug.js";
import { emitImportDebug } from "../routes/importDebugEmit.js";
import { importingDetail } from "../routes/importNotes.js";
import {
  looksLikeMacLoginItemFilename,
  looksLikeUndecodedMacLoginItemFilename,
} from "../analysis/macBinaryDetect.js";
import { isBinaryPlist } from "../analysis/macosPersistence.js";
import { looksLikeBinaryText } from "../analysis/binaryText.js";
import { observeImport } from "../analysis/operationalImport.js";
import type { InvestigationState, Severity, ForensicEvent } from "../analysis/stateTypes.js";
import {
  captureImportBaseline,
  releaseImportBaseline,
  type ImportBaseline,
} from "../analysis/importBaseline.js";
import { createImportDemote } from "./importDemote.js";
import { settleStreamedImport, type StreamedSettleDeps } from "./importIngestSettle.js";
import { getServerLogger, logLine } from "../logging/serverLogger.js";
import { formatImportCancelled, formatImportMerged, formatImportStart } from "../logging/importLog.js";
import { parseMacLoginItemBtm } from "../analysis/macLoginItemImport.js";

export interface ImportIngestDeps {
  store: CaseStore;
  options: AppOptions;
  runStateExclusive: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
  /** One import writer per case, across every import path (see analysis/importLock.ts). */
  importLock: ImportLock;
  recordImporterRun: (id: string, patch: Omit<ImporterRunStat, "lastRunAt">) => void;
  redactErr: (err: unknown) => string;
  /** Content-based tagger run over just the events an import added (see analysis/taggerAuto.ts). */
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<void>;
  getControl: (caseId: string) => Promise<AiControl>;
  applyWhitelistToCase: (caseId: string) => Promise<{ matched: number; added: number }>;
  applyNsrlToCase: (caseId: string) => Promise<{ matchedIocs: number; matchedEvents: number; added: number }>;
  applyDeobfuscationToCase: (
    caseId: string,
    opts?: { reanalyzeStale?: boolean },
  ) => Promise<{ deobfuscated: number; newIocs: number; reanalyzed: number }>;
  resynthesizeInBackground: (caseId: string) => void;
}

// Declared in routes/context.ts (#1736) so RouteContext.ingestStreamed can name it without an upward
// import; re-exported here for the callers that have always taken it from this module.
import type { ModelCallHooks } from "../routes/context.js";
export type { ModelCallHooks } from "../routes/context.js";

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
    provenance?: ArtifactProvenance,
  ): Promise<{ storedName: string; importedAt: string; seq: number }>;
  /**
   * The same evidence-first persist for BYTES rather than text — a raw .evtx, a PCAP, any original
   * an external parser was run against. saveImport re-encodes as UTF-8, which mangles a binary, so
   * preserving an original byte-for-byte (#688) needs its own path. Returns the stored name.
   */
  persistRawEvidence(
    caseId: string,
    originalName: string,
    bytes: Buffer,
    provenance?: ArtifactProvenance,
    rows?: number,
  ): Promise<{ storedName: string; importedAt: string; seq: number }>;
  /** Move sub-threshold events out of the forensic timeline (they live on in the super-timeline). */
  demoteForensicForCase(caseId: string): Promise<InvestigationState>;
  /** The same demote, returning only the rows it removed — no load of the case (#1874). */
  demoteForensic(caseId: string): Promise<ForensicEvent[]>;
  ingestStreamed(
    caseId: string,
    kind: string,
    text: string,
    originalName: string,
    minSeverity?: Severity,
    provenance?: ArtifactProvenance,
    assetHost?: string,
    modelCall?: ModelCallHooks,
    /**
     * The attempt's debug recorder (#1736). A caller that detected the kind itself passes the one it
     * gave resolveImportKind, and hands the same one to recordImportFailure on a throw; without one
     * ingestStreamed makes its own, so the success line is still written.
     */
    debug?: ImportDebugRecorder,
  ): Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }>;
  /** The byte-native twin of ingestStreamed, for macOS Background Task Management (#933 item 8). */
  ingestMacLoginItemStreamed(
    caseId: string,
    bytes: Buffer,
    originalName: string,
    debug?: ImportDebugRecorder,
  ): Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }>;
}

export function createImportIngest(deps: ImportIngestDeps): ImportIngest {
  const {
    store,
    options,
    runStateExclusive,
    importLock,
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
  // A macOS login-item container is binary-only (#1301): under one of its names the TEXT path is
  // refused rather than sniffed, so an XML `plutil` export or a text-read of the binary can never
  // be minted as a launchd-job record. routes/import.ts turns "unknown" into the specific hint.
  // Deliberately ahead of the custom-importer registry too: a declarative text importer cannot
  // read a binary plist, so a custom kind claiming one of these names would only ever misparse.
  // The v1 SessionLoginItems.sfl (#1360) is refused here as well — no reader exists for it, and a
  // text-read of it would otherwise be sniffed as a binary launchd plist under the wrong label.
  // And so is EVERY other binary plist, by its `bplist0` magic (#1392): the name lists above cover
  // the login-item containers only, and any other bplist — an MRU .sfl2, an app's .plist — reached
  // the same sniffer and got the same wrong launchd row. No text importer can read one, so the
  // honest answer is a refusal that names the plutil conversion (importKindHints.ts).
  // `debug` (#1736) records the decision where it is made — confidence and rule — for the attempt.
  const resolveImportKind = (filename: string, text: string, debug?: ImportDebugRecorder): string => {
    const refused =
      looksLikeMacLoginItemFilename(filename) ||
      looksLikeUndecodedMacLoginItemFilename(filename) ||
      isBinaryPlist(text);
    const binary = !refused && looksLikeBinaryText(text); // any other binary, on decoded text (#1802)
    const d =
      refused || binary
        ? { kind: "unknown", confident: true, decision: refused ? "refused_binary_plist" : "refused_binary" }
        : detectImportWithCustomEx(filename, text, registry.importers, precedence);
    debug?.detected(d.kind, d);
    return d.kind;
  };

  // The import log's start/merged/cancelled lines (#1438), written with `{ caseId }` so they land in
  // the session log AND the case's own log. This is the seam every text import crosses on the way
  // in, so the last line before a crash always names the file and its size. A rejection other than
  // the analyst's own cancel is rethrown UNLOGGED: recordImportFailure owns the FAILED line, and a
  // second one here would double every failure in both logs.
  async function logImportOutcome<T>(
    caseId: string,
    label: string,
    startedAt: number,
    work: Promise<T>,
    debug?: ImportDebugRecorder,
  ): Promise<T> {
    try {
      const result = await work;
      getServerLogger().info(formatImportMerged(caseId, label, Date.now() - startedAt), { caseId });
      // "parsed", not "succeeded": the caller still settles, tags and demotes. A failure there
      // is recorded as "failed" afterwards; an entry point that owns the end may emit "succeeded".
      emitImportDebug(caseId, debug, "parsed");
      return result;
    } catch (err) {
      if ((err as { name?: unknown } | null)?.name === "AbortError") {
        getServerLogger().info(formatImportCancelled(caseId, label, Date.now() - startedAt), { caseId });
        emitImportDebug(caseId, debug, "cancelled");
      }
      throw err;
    }
  }

  // Dispatch a detected import kind to the matching pipeline importer. Shared by the unified /import
  // route and the Velociraptor bundle collector (which ingests uploaded JSON reports the same way).
  function dispatchImport(kind: string, caseId: string, text: string, base: ImportBase): Promise<unknown> {
    const pipeline = options.pipeline;
    if (!pipeline) return Promise.reject(new Error("AI pipeline not configured"));
    const startedAt = Date.now();
    getServerLogger().info(
      formatImportStart({ caseId, label: base.label, kind, bytes: Buffer.byteLength(text, "utf8") }),
      { caseId },
    );
    const observe = <T>(work: Promise<T>): Promise<T> =>
      logImportOutcome(
        caseId,
        base.label,
        startedAt,
        observeImport(options.operationalMetrics, { kind, idPrefix: base.idPrefix, text, startedAt }, work),
        base.debug,
      );
    base.debug?.detected(kind);
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
              base.debug?.counts(parsed);
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
    // No deterministic importer reads a generic csv/log: the AI extracts its events (#1736).
    if (kind === "csv" || kind === "log") base.debug?.fallback("ai_extraction");
    switch (kind) {
      case "thor":
        return observe(pipeline.importThor(caseId, text, base));
      case "siem":
        return observe(pipeline.importSiem(caseId, text, base));
      case "evtxxml":
        return observe(pipeline.importEvtxXml(caseId, text, base));
      // The analyst-declared host (#1496) reaches only the Windows-log importers, as their collector
      // fallback with basis "analyst"; every other kind ignores base.assetHost.
      case "chainsaw":
        return observe(pipeline.importChainsaw(caseId, text, { ...base, chainsaw: declaredHost(base) }));
      case "hayabusa":
        return observe(pipeline.importHayabusa(caseId, text, { ...base, hayabusa: declaredHost(base) }));
      case "velociraptor":
        return observe(
          pipeline.importVelociraptor(caseId, text, { ...base, velociraptor: declaredHost(base) }),
        );
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
      case "okta":
        return observe(pipeline.importOkta(caseId, text, base));
      case "azurestoragelog":
        return observe(pipeline.importAzureStorageLog(caseId, text, base));
      case "diskimagelog":
        return observe(pipeline.importDiskImageLog(caseId, text, base));
      case "awsflowlog":
        return observe(pipeline.importAwsFlowLog(caseId, text, base));
      case "azureflowlog":
        return observe(pipeline.importAzureFlowLog(caseId, text, base));
      case "gcpflowlog":
        return observe(pipeline.importGcpFlowLog(caseId, text, base));
      case "bulkextractorurl":
        return observe(pipeline.importBulkExtractorUrl(caseId, text, base));
      case "bulkextractorcarved":
        return observe(pipeline.importBulkExtractorCarved(caseId, text, base));
      case "flossresult":
        return observe(pipeline.importFlossResult(caseId, text, base));
      case "caparesult":
        return observe(pipeline.importCapaResult(caseId, text, base));
      case "olevbaresult":
        return observe(pipeline.importOlevbaResult(caseId, text, base));
      case "sqliterowstate":
        return observe(pipeline.importSqliteRowState(caseId, text, base));
      case "mobsfpermission":
        return observe(pipeline.importMobsfPermissions(caseId, text, base));
      case "exporterflow":
        return observe(pipeline.importExporterFlow(caseId, text, base));
      case "macfsevent":
        return observe(pipeline.importMacFsEvent(caseId, text, base));
      case "macspotlightusage":
        return observe(pipeline.importMacSpotlightUsage(caseId, text, base));
      // Byte-native (a binary keyed-archive bplist) -- dispatched directly by
      // POST /cases/:id/import-mac-login-item, never through this text-based path, which would
      // corrupt the bytes. An explicit rejection here, never the generic "unhandled import kind"
      // fallback, so a caller that somehow reaches this case gets a clear reason (#1013).
      case "macloginitem":
        return Promise.reject(
          new Error(
            "macloginitem is byte-native; use POST /cases/:id/import-mac-login-item, not dispatchImport",
          ),
        );
      case "gws":
        return observe(pipeline.importGoogleWorkspace(caseId, text, base));
      case "hindsight":
        return observe(pipeline.importHindsight(caseId, text, base));
      case "macos":
        return observe(pipeline.importMacos(caseId, text, base));
      case "leapp":
        return observe(pipeline.importLeapp(caseId, text, base));
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
      case "wer":
        return observe(pipeline.importWer(caseId, text, base));
      case "linuxpersist":
        return observe(pipeline.importLinuxPersist(caseId, text, base));
      case "macospersist":
        return observe(pipeline.importMacosPersist(caseId, text, base));
      case "rclone":
        return observe(pipeline.importRclone(caseId, text, base));
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
    provenance?: ArtifactProvenance,
  ): Promise<{ storedName: string; importedAt: string; seq: number }> {
    const seq = await store.nextImportSeq(caseId);
    const safe = originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.dat";
    const storedName = `${String(seq).padStart(4, "0")}_${safe}`;
    const importedAt = new Date().toISOString();
    await store.saveImport(caseId, storedName, text, provenance);
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

  // The bytes-in twin of persistEvidence. Same sequence allocation, same audit line, same custody
  // announcement — it differs only in writing a Buffer verbatim instead of a UTF-8 string, which is
  // what "preserve the original byte-for-byte" (#688) requires of a .evtx or a PCAP.
  async function persistRawEvidence(
    caseId: string,
    originalName: string,
    bytes: Buffer,
    provenance?: ArtifactProvenance,
    rows = 0,
  ): Promise<{ storedName: string; importedAt: string; seq: number }> {
    const seq = await store.nextImportSeq(caseId);
    const safe = originalName.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "evidence.bin";
    const storedName = `${String(seq).padStart(4, "0")}_${safe}`;
    const importedAt = new Date().toISOString();
    await store.saveRawImport(caseId, storedName, bytes, provenance);
    await store.appendImport(caseId, {
      caseId,
      sequenceNumber: seq,
      importedAt,
      filename: storedName,
      originalName,
      rows,
      bytes: bytes.byteLength,
    });
    return { storedName, importedAt, seq };
  }

  // The forensic gate's demote, and the settle tail both streamed entry points share (#1874).
  const demote = createImportDemote({ options, runStateExclusive });
  const settleDeps: StreamedSettleDeps = { options, runStateExclusive, autoTagImported, demote };
  // The section's snapshot (analysis/importBaseline.ts). Best-effort: null means no diff, never a failed import.
  const baselineOf = async (caseId: string): Promise<ImportBaseline | null> =>
    options.stateStore ? captureImportBaseline(options.stateStore, caseId).catch(() => null) : null;
  const releaseBaseline = (baseline: ImportBaseline | null): Promise<void> =>
    options.stateStore ? releaseImportBaseline(options.stateStore, baseline) : Promise.resolve();

  // #1920: every streamed ingest (/push, MCP, Velociraptor monitors, external tools, drop folder)
  // reserves the case against an archive before its first evidence write and releases once settled;
  // while an archive holds the case it is refused with CaseArchivingError, before anything is written.
  // An archived case takes no new evidence: a monitor deferred during an archive keeps its cursor.
  const statusOf = statusFromStore(store);
  const ingestStreamed: typeof ingestStreamedAdmitted = (caseId, ...rest) =>
    withIngestAdmission(store.casesRoot, caseId, () => ingestStreamedAdmitted(caseId, ...rest), statusOf);
  const ingestMacLoginItemStreamed: typeof ingestMacLoginItemAdmitted = (caseId, ...rest) =>
    withIngestAdmission(store.casesRoot, caseId, () => ingestMacLoginItemAdmitted(caseId, ...rest), statusOf);

  async function ingestStreamedAdmitted(
    caseId: string,
    kind: string,
    text: string,
    originalName: string,
    minSeverity?: Severity,
    provenance?: ArtifactProvenance,
    assetHost?: string, // the analyst-declared host (#1496): a drop subfolder named asset=<HOST>
    modelCall?: ModelCallHooks,
    debug: ImportDebugRecorder = createImportDebugRecorder(), // this attempt's (#1736)
  ): Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }> {
    const pipeline = options.pipeline;
    if (!pipeline) throw new Error("AI pipeline not configured");
    options.onImport?.(caseId); // cross-case signal (parity with /import + captures) for push/monitor ingest
    // `provenance` is how an external tool's run reaches the chain of custody (#688): the stored
    // output's custody record then carries the parser's version, argv, rule-set hash and stderr
    // instead of a bare "companion".
    const { storedName, importedAt, seq } = await persistEvidence(caseId, originalName, text, provenance);

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
    // Past the one AI-off gate: a model runs now, so the caller's job may name it (#1629).
    const signal = aiDependent ? modelCall?.signal : undefined;
    if (aiDependent) modelCall?.beforeModelRun?.(kind);

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
      detail: importingDetail(
        `importing (${kind})${minSeverity ? ` — min severity ${minSeverity}` : ""}`,
        kind,
        debug,
      ),
    });

    // One import writer per case, held from the snapshot through the diff below: /push, the MCP
    // ingest and the Velociraptor monitors all land here, none of them passes through the job queue,
    // and any of them writing inside another import's section would be counted as that import's own
    // work (and swept into its undo checkpoint). See analysis/importLock.ts.
    const counts = await importLock.runSized(caseId, { incomingBytes: text.length }, async () => {
      const baseline = await baselineOf(caseId);
      try {
        return await dispatchAndSettle(baseline);
      } finally {
        await releaseBaseline(baseline);
      }
    });
    async function dispatchAndSettle(
      baseline: ImportBaseline | null,
    ): Promise<{ addedEvents: number; addedIocs: number }> {
      await dispatchImport(kind, caseId, text, {
        label: storedName,
        idPrefix: `${seq}`,
        importedAt,
        onProgress,
        minSeverity,
        debug, // dispatchImport writes its succeeded / cancelled line
        ...(assetHost ? { assetHost } : {}),
        ...(signal ? { signal } : {}),
      });
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      // The one seam (routes/importSettle.ts): dual-write, tag, demote, diff post-demote.
      return settleStreamedImport(settleDeps, { caseId, kind, storedName, baseline });
    }
    const { addedEvents, addedIocs } = counts;
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

  /**
   * The byte-native twin of ingestStreamed, for macOS Background Task Management (#933 item 8,
   * #1013) — the one import kind `dispatchImport` refuses to carry (`macLoginItemImports.ts`'s own
   * header: byte-native, "NOT dispatched through ... dispatchImport"). Differs from ingestStreamed:
   *   PARSES FIRST, same order as routes/importMacLoginItem.ts — persisting a file that fails to
   *     parse (or parses to zero items) would leave a phantom "successful" ledger row for an import
   *     that never actually happened;
   *   calls `pipeline.importMacLoginItem()` directly, which applies its own state internally (it is
   *     not a delta the caller applies, unlike every dispatchImport-routed kind);
   *   settles INSIDE the same `importLock` section as the import call, not after it returns — the
   *     drop-folder sweep runs `DROP_CONCURRENCY=4` imports at once, and settling outside the
   *     section would reopen the exact demote race `demoteForensicForCase`'s own comment describes;
   *   no AI-off branch: `importMacLoginItem` is fully deterministic (no LLM call), unlike csv/log;
   *   no whitelist/NSRL/deobfuscation auto-mark pass: this importer never produces IOCs (bookmark
   *     path facts only), so those three would be guaranteed no-ops here.
   */
  async function ingestMacLoginItemAdmitted(
    caseId: string,
    bytes: Buffer,
    originalName: string,
    debug: ImportDebugRecorder = createImportDebugRecorder(), // this attempt's (#1736)
  ): Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }> {
    const pipeline = options.pipeline;
    if (!pipeline) throw new Error("AI pipeline not configured");
    const macPipeline = pipeline;
    options.onImport?.(caseId);
    // Only a login-item container reaches this path, so the kind is fixed, not sniffed.
    debug.detected("macloginitem", { confident: true, decision: "explicit_route" });

    const preview = parseMacLoginItemBtm(bytes);
    if (!preview) {
      throw new Error("no recognized login-item entries found (unrecognized BTM structure)");
    }
    // Guarded on `kept` (what actually becomes persisted/imported events), not `total` (items
    // scanned) — the two can diverge (a maxEvents cap, aggregation), and guarding on the wrong one
    // would leave a "successful" ledger row with rows: 0 and zero timeline events for a file that
    // never actually contributed anything (Ollama code review finding).
    if (preview.kept === 0) {
      throw new Error("BTM file parsed but contained no importable login items");
    }

    const { storedName, importedAt, seq } = await persistRawEvidence(
      caseId,
      originalName,
      bytes,
      undefined,
      preview.kept,
    );

    options.onAiStatus?.(caseId, {
      status: "analyzing",
      phase: "extracting",
      at: importedAt,
      detail: `importing ${preview.kept} macOS login item(s)`,
    });

    const { addedEvents, addedIocs } = await importLock.runExclusive(caseId, async () => {
      const baseline = await baselineOf(caseId);
      try {
        return await importAndSettle(baseline);
      } finally {
        await releaseBaseline(baseline);
      }
    });
    async function importAndSettle(
      baseline: ImportBaseline | null,
    ): Promise<{ addedEvents: number; addedIocs: number }> {
      // Same call routes/importMacLoginItem.ts makes; it applies its own state (mergeWithAliases +
      // save) internally rather than returning a delta this caller would apply. Bypasses
      // dispatchImport, so it writes its own start/merged lines (#1438).
      getServerLogger().info(
        formatImportStart({ caseId, label: storedName, kind: "macloginitem", bytes: bytes.length }),
        { caseId },
      );
      await logImportOutcome(
        caseId,
        storedName,
        Date.now(),
        macPipeline.importMacLoginItem(caseId, bytes, {
          label: storedName,
          idPrefix: `bt${seq}`,
          importedAt,
          debug,
        }),
        debug,
      );
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
      return settleStreamedImport(settleDeps, { caseId, kind: "macloginitem", storedName, baseline });
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
    persistRawEvidence,
    demoteForensicForCase: demote.demoteForensicForCase,
    demoteForensic: demote.demoteForensic,
    ingestStreamed,
    ingestMacLoginItemStreamed,
  };
}

// The Windows-log importers' option for an analyst-declared host (#1496); undefined when none.
function declaredHost(base: ImportBase): { hostFallback: string; hostFallbackBasis: "analyst" } | undefined {
  return base.assetHost ? { hostFallback: base.assetHost, hostFallbackBasis: "analyst" } : undefined;
}
