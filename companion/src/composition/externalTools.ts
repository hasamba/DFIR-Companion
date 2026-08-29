/**
 * External forensic tools (#211) and the SO-CRATES analysis hand-off. Lifted out of createApp by #416.
 *
 * Two transports, one ingest chain. A SPAWN tool (Hayabusa, the Velociraptor CLI, Suricata, YARA)
 * runs a local binary against a file on disk and its output goes straight through `ingestStreamed`.
 * An HTTP tool (SO-CRATES) is handed the bytes and answers LATER, so the call returns immediately
 * and a poller lands the verdicts. Callers that need to know which happened get a boolean back —
 * a sweep must log SUBMITTED rather than claim an import that has not happened yet.
 *
 * CONFIG IS READ LIVE, never captured. `liveToolConfigs()` re-reads DFIR_TOOL_* from env on every
 * call so POST /tools/reconnect applies a just-saved binary path without the #1-gotcha restart; the
 * runner itself is stateless. Custom tools are merged in from the in-memory store, which is why
 * that store is mirrored here (`reloadCustomTools`) rather than read async at each use.
 *
 * THE toolRunner GATE IS NARROW ON PURPOSE. It is the PROCESS SPAWNER, so only spawn-transport
 * tools need it. Gating HTTP tools on it too would make SO-CRATES unreachable on a machine with no
 * local forensic binaries — which is exactly the machine most likely to want a remote analyzer.
 *
 * ZIP HANDLING LIVES HERE, not in SO-CRATES: its upload handler builds the password list
 * server-side from the filename (an analyst-supplied password cannot reach it), and it extracts
 * through Python's zipfile, which cannot open AES archives at all.
 */
import { basename, join } from "node:path";
import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import type { Buffer } from "node:buffer";
import type { ArtifactProvenance, CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";
import { dropDirOf } from "./dropFolder.js";
import {
  loadAllToolConfigs,
  toolForExtension,
  SOCRATES_EXTS,
  type ToolConfig,
} from "../integrations/tools/toolConfig.js";
import { runToolAgainstFile, resolveContainedPath } from "../integrations/tools/runToolImport.js";
import { describeToolRun } from "../integrations/tools/toolProvenance.js";
import { customToolToConfig, type CustomTool } from "../integrations/tools/customToolStore.js";
import { RAW_TOOL_EXTS } from "../analysis/dropScan.js";
import { extractZipEntries } from "../analysis/zipExtract.js";
import {
  md5Buffer,
  probeAnalysis,
  uploadBuffer,
  checkStatus,
  fetchVerdicts,
} from "../integrations/socrates/socratesApi.js";
import { SocratesJobStore, type SocratesJob } from "../integrations/socrates/socratesJobStore.js";
import { pollUntilImported } from "../integrations/socrates/socratesPoller.js";
import { formatDropLogLines, appendDropLog, type DropLogEntry } from "../analysis/dropLog.js";
import type { InvestigationState, Severity } from "../analysis/stateTypes.js";
import { logLine } from "../logging/serverLogger.js";

export interface ExternalToolsDeps {
  store: CaseStore;
  options: AppOptions;
  resolveImportKind: (filename: string, text: string) => string;
  ingestStreamed: (
    caseId: string,
    kind: string,
    text: string,
    originalName: string,
    minSeverity?: Severity,
    provenance?: ArtifactProvenance,
  ) => Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }>;
  /** Persist a binary original verbatim as evidence (see ImportIngest.persistRawEvidence). */
  persistRawEvidence: (
    caseId: string,
    originalName: string,
    bytes: Buffer,
    provenance?: ArtifactProvenance,
  ) => Promise<{ storedName: string; importedAt: string; seq: number }>;
  pushImportCheckpoint: (caseId: string, beforeState: InvestigationState, label: string) => Promise<void>;
}

export interface ExternalTools {
  /** Per-case record of asynchronous SO-CRATES analyses (the dashboard polls it). */
  readonly socratesJobStore: SocratesJobStore;
  /** Built-in (env) + custom tool configs, resolved fresh on every call. */
  liveToolConfigs(): Map<string, ToolConfig>;
  /** The in-memory custom-tool mirror the dashboard lists. */
  customTools(): CustomTool[];
  reloadCustomTools(): Promise<void>;
  /** Which CONFIGURED tool handles this file extension, built-ins first. */
  resolveToolForExt(ext: string, configured: Map<string, ToolConfig>): string | null;
  /** Is this extension claimed by a raw type, SO-CRATES, or a defined custom tool. */
  rawExtClaimed(ext: string): boolean;
  /** Run whichever transport this tool uses. Resolves true when the work is ASYNCHRONOUS. */
  runDropToolAndIngest(
    caseId: string,
    toolId: string,
    fullPath: string,
    name: string,
    dropRelpath?: string,
  ): Promise<boolean>;
  runToolAndIngest(
    caseId: string,
    toolId: string,
    targetPath: string,
    opts?: { undoLabel?: string; preserveOriginal?: { bytes: Buffer; originalName: string } },
  ): Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }>;
  startSocratesAnalysis(
    caseId: string,
    input: { data: Buffer; filename: string; zipPassword?: string; dropRelpath?: string },
  ): Promise<{ jobIds: string[]; skippedNested: string[]; truncated: boolean }>;
}

export function createExternalTools(deps: ExternalToolsDeps): ExternalTools {
  const { store, options, resolveImportKind, ingestStreamed, persistRawEvidence, pushImportCheckpoint } =
    deps;

  const socratesJobs = new SocratesJobStore(store);

  // SO-CRATES pollers finish independently, but every ingest mutates the SAME case state behind the
  // per-case state lock. Firing them concurrently — a 25-entry archive, or several files dropped at
  // once — piles them all onto that lock. Chain them per case so verdicts land one at a time, in
  // completion order. The chain never rejects (each link swallows), so one bad import cannot wedge
  // every later one behind it.
  const socratesIngestChain = new Map<string, Promise<unknown>>();
  const queueSocratesIngest = <T>(caseId: string, fn: () => Promise<T>): Promise<T> => {
    const prev = socratesIngestChain.get(caseId) ?? Promise.resolve();
    const next = prev.then(fn, fn);
    socratesIngestChain.set(
      caseId,
      next.catch(() => {
        /* keep the chain alive after a failure */
      }),
    );
    return next;
  };

  // User-defined custom tools (#211) held in memory + refreshed on CRUD (mirrors importerRegistry), so
  // liveToolConfigs stays synchronous.
  let customTools: CustomTool[] = [];
  if (options.customToolStore)
    options.customToolStore
      .load()
      .then((t) => {
        customTools = t;
      })
      .catch(() => {
        /* keep empty */
      });
  async function reloadCustomTools(): Promise<void> {
    if (options.customToolStore) customTools = await options.customToolStore.load();
  }

  const liveToolConfigs = (): Map<string, ToolConfig> => {
    const out = new Map<string, ToolConfig>(
      (options.loadToolConfigs ?? (() => loadAllToolConfigs(process.env)))(),
    );
    for (const t of customTools) out.set(t.id, customToolToConfig(t));
    return out;
  };

  // Resolve which CONFIGURED tool handles a file extension: built-in preference first (via TOOL_DEFS),
  // then a custom tool that claims the extension.
  const resolveToolForExt = (ext: string, configured: Map<string, ToolConfig>): string | null => {
    const builtin = toolForExtension(ext, configured);
    if (builtin) return builtin;
    const e = ext.toLowerCase();
    const custom = customTools.find(
      (t) => configured.has(t.id) && t.extensions.some((x) => x.toLowerCase() === e),
    );
    return custom ? custom.id : null;
  };

  // Every file extension claimed by a built-in raw type, SO-CRATES, OR a defined custom tool (for drop
  // routing). SOCRATES_EXTS is included unconditionally — even when SO-CRATES is not configured — so a
  // dropped .exe is recognized as RAW and surfaces as pending ("configure a tool") instead of falling
  // through to the text path, which would read the binary as UTF-8 and ingest garbage.
  const rawExtClaimed = (ext: string): boolean =>
    RAW_TOOL_EXTS.has(ext.toLowerCase()) ||
    SOCRATES_EXTS.includes(ext.toLowerCase()) ||
    customTools.some((t) => t.extensions.some((x) => x.toLowerCase() === ext.toLowerCase()));

  // Run a raw on-disk file through whichever transport its tool uses, and ingest the result. Spawn
  // tools go through runToolAndIngest (synchronous); HTTP tools hand off to startSocratesAnalysis and
  // return immediately, with the poller landing the verdicts later. Shared by the drop-folder auto-run
  // and the "Run pending" batch so both behave identically.
  // Returns true when the work is ASYNCHRONOUS (handed off, not finished) so the caller can log
  // SUBMITTED rather than claiming an import that has not happened yet.
  async function runDropToolAndIngest(
    caseId: string,
    toolId: string,
    fullPath: string,
    name: string,
    dropRelpath?: string,
  ): Promise<boolean> {
    const cfg = liveToolConfigs().get(toolId);
    if (!cfg) throw new Error(`tool "${toolId}" is not configured`);
    if (cfg.transport === "http") {
      await startSocratesAnalysis(caseId, { data: await readFile(fullPath), filename: name, dropRelpath });
      return true;
    }
    const r = await runToolAndIngest(caseId, toolId, fullPath);
    if (!r.analyzed)
      throw new Error(`${toolId} ran but AI is off — output saved as evidence but not analyzed`);
    return false;
  }

  // Run a configured external tool against a raw on-disk file (contained in the case dir) and ingest its
  // output through the SAME chain as the Import button (ingestStreamed). Shared by the drop-folder
  // auto-run and the manual POST /cases/:id/tools/:toolId/run route. A custom tool's output kind is
  // "auto" → detected from the output. Throws when not configured / the run fails; the output work dir
  // is server-owned + auto-cleaned inside runToolAgainstFile.
  async function runToolAndIngest(
    caseId: string,
    toolId: string,
    targetPath: string,
    opts: { undoLabel?: string; preserveOriginal?: { bytes: Buffer; originalName: string } } = {},
  ): Promise<{ storedName: string; addedEvents: number; addedIocs: number; analyzed: boolean }> {
    const cfg = liveToolConfigs().get(toolId);
    if (!cfg) throw new Error(`tool "${toolId}" is not configured`);
    // The toolRunner is the PROCESS SPAWNER. Only spawn-transport tools need it — gating http tools
    // on it would make SO-CRATES unreachable on a machine with no local forensic binaries, which is
    // exactly the machine most likely to want it.
    if (cfg.transport === "http")
      throw new Error(`tool "${toolId}" is an HTTP tool — use startSocratesAnalysis`);
    if (!options.toolRunner) throw new Error("external tools not configured");
    const caseDir = store.caseDir(caseId);
    const contained = resolveContainedPath(caseDir, targetPath);

    // Keep the ORIGINAL, byte for byte, BEFORE the parser runs (#688). The Companion used to keep
    // only the tool's output, so an uploaded .evtx existed just long enough to be parsed and was
    // then deleted — leaving the case holding one tool's opinion of evidence nobody could re-examine
    // or re-parse with a second tool. Preserving first also means a parser that fails still leaves
    // the analyst their evidence. Only the upload path asks for this; the drop folder already keeps
    // the original in _processed/, and a case-relative target is already inside the case.
    let preservedName = "";
    if (opts.preserveOriginal) {
      const kept = await persistRawEvidence(
        caseId,
        opts.preserveOriginal.originalName,
        opts.preserveOriginal.bytes,
        {
          collectedBy: "companion",
          source: `original evidence preserved for ${toolId}`,
          trigger: "raw-evidence",
        },
      );
      preservedName = kept.storedName;
    }

    const { outputText, importKind, provenance } = await runToolAgainstFile({
      cfg,
      runner: options.toolRunner,
      targetPath: contained,
      workDir: join(caseDir, ".toolwork"),
    });
    const outName = `${basename(contained)}.${toolId}.out`;
    // Custom tools declare no fixed importer — detect the kind from the tool's output.
    const kind = importKind === "auto" ? resolveImportKind(outName, outputText) : importKind;
    if (kind === "unknown")
      throw new Error(`${toolId}: could not detect the tool output's format (not a recognized import)`);
    // ingestStreamed skips the undo checkpoint (built for high-frequency streaming), so a MANUAL tool
    // run (Import dialog / Run button) wouldn't be undoable. When a label is given, snapshot the
    // pre-import state and push an undo checkpoint if the import changed anything — parity with /import.
    let before: InvestigationState | null = null;
    if (opts.undoLabel && options.stateStore) {
      try {
        before = await options.stateStore.load(caseId);
      } catch {
        /* keep null */
      }
    }
    // The stored output's custody record now states HOW it was produced — parser version, argv,
    // rule-set hash, exit code, stderr tail, output hash — rather than a bare "companion" (#688).
    const r = await ingestStreamed(caseId, kind, outputText, outName, undefined, {
      collectedBy: "companion",
      trigger: `tool:${toolId}`,
      source: describeToolRun(provenance) + (preservedName ? ` | original ${preservedName}` : ""),
    });
    if (before && opts.undoLabel && (r.addedEvents > 0 || r.addedIocs > 0)) {
      await pushImportCheckpoint(caseId, before, opts.undoLabel);
    }
    return r;
  }

  // Submit one file (or every entry of a zip) to SO-CRATES and poll for results in the background.
  async function startSocratesAnalysis(
    caseId: string,
    input: { data: Buffer; filename: string; zipPassword?: string; dropRelpath?: string },
  ): Promise<{ jobIds: string[]; skippedNested: string[]; truncated: boolean }> {
    const cfg = liveToolConfigs().get("socrates");
    if (!cfg?.baseUrl)
      throw new Error("SO-CRATES is not configured — set DFIR_TOOL_SOCRATES_URL in Settings → Tools");
    const baseUrl = cfg.baseUrl;

    // Decide what to submit: the file itself, or each entry of an archive.
    let submissions: { data: Buffer; name: string; zipEntry?: string }[];
    let skippedNested: string[] = [];
    let truncated = false;
    if (input.data.subarray(0, 2).toString("latin1") === "PK") {
      const extracted = extractZipEntries(input.data, input.filename, input.zipPassword);
      skippedNested = extracted.skippedNested;
      truncated = extracted.truncated;
      submissions = extracted.entries.map((e) => ({
        data: e.data,
        name: basename(e.path),
        zipEntry: `${input.filename}!${e.path}`,
      }));
      if (submissions.length === 0) throw new Error(`"${input.filename}" contained no analyzable files`);
    } else {
      submissions = [{ data: input.data, name: input.filename }];
    }

    const jobIds: string[] = [];
    for (const sub of submissions) {
      // Already analyzed? Skip the upload — SO-CRATES keys everything by MD5, so an unchanged file
      // costs one request instead of a re-analysis.
      const localMd5 = md5Buffer(sub.data);
      const probe = await probeAnalysis(baseUrl, localMd5).catch(() => ({ status: "processing" as const }));
      // Poll under the md5 the SERVER reports, not the one we computed. They usually agree, but
      // SO-CRATES keys an archive on the hash of the file it extracts rather than the bytes it was
      // sent — so trusting our own hash would poll a key that never becomes ready.
      const md5 =
        probe.status === "ready"
          ? localMd5
          : (await uploadBuffer(baseUrl, sub.data, sub.name)).md5 || localMd5;

      const job: SocratesJob = {
        jobId: randomUUID(),
        md5,
        sourceName: input.filename,
        zipEntry: sub.zipEntry,
        status: "processing",
        startedAt: new Date().toISOString(),
      };
      await socratesJobs.upsert(caseId, job);
      jobIds.push(job.jobId);

      // Uploading evidence leaves a copy on the SO-CRATES host, keyed by MD5 and retained until
      // deleted. That belongs in the case record. Best-effort — never block the analysis.
      await options.custodyStore
        ?.recordExport(caseId, {
          exportedBy: "companion",
          destination: `SO-CRATES analysis at ${baseUrl} (md5 ${md5}, ${sub.zipEntry ?? sub.name})`,
        })
        .catch(() => {
          /* custody is best-effort */
        });

      // Fire and forget: the poller updates the job record, which the dashboard polls.
      void pollUntilImported(
        caseId,
        job,
        {
          store: socratesJobs,
          checkStatus: (m) => checkStatus(baseUrl, m),
          fetchVerdicts: (m) => fetchVerdicts(baseUrl, m),
          ingest: (cid, text, name) =>
            queueSocratesIngest(cid, async () => {
              const r = await ingestStreamed(cid, "socrates", text, name);
              return { addedEvents: r.addedEvents, addedIocs: r.addedIocs };
            }),
        },
        { maxAttempts: Math.max(1, Math.floor(cfg.timeoutMs / 5000)) },
      )
        .then(async (final) => {
          // Close the SUBMITTED line in drop-log.txt with what actually happened. Without this the
          // audit trail ends at "handed to socrates" and never says whether verdicts landed — and a
          // failed analysis would leave a file sitting in _processed/ with no recorded outcome.
          if (!input.dropRelpath) return;
          const entry: DropLogEntry =
            final.status === "imported"
              ? {
                  status: "IMPORTED",
                  relpath: input.dropRelpath,
                  reason: `via socrates — +${final.addedEvents ?? 0} event(s), +${final.addedIocs ?? 0} IOC(s)`,
                }
              : {
                  status: "FAILED",
                  relpath: input.dropRelpath,
                  reason: final.error ?? "SO-CRATES analysis failed",
                };
          await appendDropLog(
            dropDirOf(store, caseId),
            formatDropLogLines([entry], new Date().toISOString()),
          ).catch((e) => logLine(`[drop] log append failed: ${(e as Error).message}`));
        })
        .catch(() => {
          /* pollUntilImported already records failures on the job */
        });
    }

    return { jobIds, skippedNested, truncated };
  }

  return {
    socratesJobStore: socratesJobs,
    liveToolConfigs,
    customTools: () => customTools,
    reloadCustomTools,
    resolveToolForExt,
    rawExtClaimed,
    runDropToolAndIngest,
    runToolAndIngest,
    startSocratesAnalysis,
  };
}
