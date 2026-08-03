/**
 * The two standalone Velociraptor ingest paths for a hunt or flow the Companion did NOT launch —
 * what `POST /cases/:id/velociraptor/import-external` runs when an analyst pastes a Velociraptor
 * GUI URL. Split out of composition/veloHunts.ts (#416) once that file passed the 800-line limit.
 *
 * WHY THEY ARE SEPARATE FROM THE COLLECT. A collect is a hunt-LAUNCH concern: it owns the job
 * record, the hunt-outcome ledger, the run-to-run snapshot and the undo checkpoint, because the
 * Companion started that hunt and is accountable for it end to end. An external import owns none
 * of that — there is no job to update and no outcome to fill, only "read this result set into the
 * case". Mixing them would put four kinds of bookkeeping behind an `if` on a flag.
 *
 * They deliberately MIRROR the collect's rows and uploads steps rather than share them: the two
 * paths stay decoupled, and each one's comment says where its parallel lives, so a change to the
 * super-only field mapping is visibly a change in two places rather than invisibly one.
 */
import type { AppOptions } from "./appOptions.js";
import type { ImportBase } from "../routes/context.js";
import type { AiControl } from "../analysis/aiControl.js";
import type { HuntUpload } from "../integrations/velociraptor/velociraptorApi.js";
import { parseVelociraptorJson } from "../analysis/velociraptorImport.js";
import { applySeverityFloor } from "../analysis/severityFloor.js";
import { diffTimeline, addedForensicEvents } from "../analysis/timelineDiff.js";
import { diffIocs } from "../analysis/iocsDiff.js";
import type { InvestigationState, Severity, ForensicEvent } from "../analysis/stateTypes.js";
import { logLine } from "../logging/serverLogger.js";

export interface VeloExternalIngestDeps {
  options: AppOptions;
  persistEvidence: (
    caseId: string,
    originalName: string,
    text: string,
  ) => Promise<{ storedName: string; importedAt: string; seq: number }>;
  dispatchImport: (kind: string, caseId: string, text: string, base: ImportBase) => Promise<unknown>;
  resolveImportKind: (filename: string, text: string) => string;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<void>;
  demoteForensicForCase: (caseId: string) => Promise<InvestigationState>;
  getControl: (caseId: string) => Promise<AiControl>;
  applyWhitelistToCase: (caseId: string) => Promise<{ matched: number; added: number }>;
  applyNsrlToCase: (caseId: string) => Promise<{ matchedIocs: number; matchedEvents: number; added: number }>;
  resynthesizeInBackground: (caseId: string) => void;
}

export interface VeloExternalIngest {
  ingestVeloArtifactMap(
    caseId: string,
    mapJson: string,
    opts: {
      label: string;
      idBase: string;
      superOnly?: boolean;
      minSeverity?: Severity;
      hostFallback?: string;
      veloUrl?: string;
    },
  ): Promise<{ addedEvents: number; addedIocs: number; storedName: string }>;
  ingestVeloUploads(
    caseId: string,
    uploads: HuntUpload[],
    opts: { minSeverity?: Severity; label: string },
  ): Promise<{ addedEvents: number; addedIocs: number; imported: string[]; skipped: string[] }>;
}

export function createVeloExternalIngest(deps: VeloExternalIngestDeps): VeloExternalIngest {
  const {
    options,
    persistEvidence,
    dispatchImport,
    resolveImportKind,
    autoTagImported,
    demoteForensicForCase,
    getControl,
    applyWhitelistToCase,
    applyNsrlToCase,
    resynthesizeInBackground,
  } = deps;

  // Ingest ONE Velociraptor artifact-map JSON into a case — the shared core used by the external
  // hunt/flow import route (POST .../import-external). Mirrors collectVeloHuntOnce's rows step but is
  // self-contained for a single map (no uploads / hunt-outcome / checkpoint — those are hunt-launch
  // concerns). Routes to the forensic timeline (normal, + dual-write to the super-timeline) OR the
  // super-timeline ONLY (superOnly). `idBase` gives super-only events STABLE ids so re-importing the
  // same external hunt/flow dedups (dedupeAppend keys on id) instead of duplicating.
  async function ingestVeloArtifactMap(
    caseId: string,
    mapJson: string,
    opts: {
      label: string;
      idBase: string;
      superOnly?: boolean;
      minSeverity?: Severity;
      hostFallback?: string;
      veloUrl?: string;
    },
  ): Promise<{ addedEvents: number; addedIocs: number; storedName: string }> {
    const pipeline = options.pipeline;
    if (!pipeline) throw new Error("AI pipeline not configured");
    let stateBefore: InvestigationState | null = null;
    if (options.stateStore) {
      try {
        stateBefore = await options.stateStore.load(caseId);
      } catch {
        /* null */
      }
    }
    const { storedName, importedAt, seq } = await persistEvidence(caseId, opts.label, mapJson);

    if (opts.superOnly && options.superTimelineStore) {
      const artifact = storedName.replace(/^\d+_/, "").replace(/\.(json|jsonl|ndjson|csv)$/i, "");
      // The super-timeline is the COMPLETE record — do NOT aggregate near-identical rows (which would
      // collapse e.g. 221 collected rows to ~141), and lift the default 2000-event cap to the super
      // store's cap so a big collection isn't silently truncated.
      const parsed = parseVelociraptorJson(mapJson, {
        artifact,
        hostFallback: opts.hostFallback,
        aggregate: false,
        maxEvents: Number(process.env.DFIR_SUPERTIMELINE_MAX) || 100000,
      });
      const floored = applySeverityFloor(parsed.events, opts.minSeverity); // honor the import floor (no-op when unset) — the forensic path floors via importVelociraptor
      // Same field set as collectVeloHuntOnce's super-only mapping (intentional parallel — the two
      // paths stay decoupled).
      const events: ForensicEvent[] = floored.map((e, i) => ({
        id: `${opts.idBase}-e${i + 1}`,
        timestamp: e.timestamp,
        description: e.description,
        severity: e.severity,
        mitreTechniques: e.mitreTechniques ?? [],
        relatedFindingIds: [],
        sourceScreenshots: [storedName],
        ...(e.artifactName ? { artifactName: e.artifactName } : {}),
        ...(e.message ? { message: e.message } : {}),
        ...(opts.veloUrl ? { veloUrl: opts.veloUrl } : {}),
        sources: e.sources?.length ? e.sources : ["Velociraptor"],
        ...(e.asset ? { asset: e.asset } : {}),
        ...(e.path ? { path: e.path } : {}),
        ...(e.sha256 ? { sha256: e.sha256 } : {}),
        ...(e.md5 ? { md5: e.md5 } : {}),
      }));
      const superAdded = await options.superTimelineStore.append(caseId, events);
      options.onSuperTimeline?.(caseId);
      await autoTagImported(caseId, events);
      // Super-only imports never touch the forensic timeline, so the forensic diff below is always 0 —
      // report the SUPER-TIMELINE count instead so "+N events" reflects what actually landed.
      resynthesizeInBackground(caseId);
      return { addedEvents: superAdded, addedIocs: 0, storedName };
    }
    await pipeline.importVelociraptor(caseId, mapJson, {
      label: storedName,
      idPrefix: `${seq}`,
      importedAt,
      minSeverity: opts.minSeverity,
      velociraptor: opts.hostFallback ? { hostFallback: opts.hostFallback } : undefined,
      veloUrl: opts.veloUrl,
    });

    let addedEvents = 0,
      addedIocs = 0;
    if (options.stateStore && stateBefore) {
      try {
        const imported = await options.stateStore.load(caseId);
        // Dual-write into the super-timeline FIRST (superset, Info telemetry included) — the super-only
        // path early-returned above, so this is always the forensic path; the `!opts.superOnly` guard is
        // defensive. Resolve the FULL events from the imported (pre-demote) state since the diff is lossy.
        if (!opts.superOnly && options.superTimelineStore) {
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
        // Demote sub-threshold events out of forensic (kept in super), then compute the import-meta diff
        // on the POST-demote state so "+N events" counts only graded signal.
        const s = opts.superOnly ? imported : await demoteForensicForCase(caseId);
        const tDiff = diffTimeline(stateBefore.forensicTimeline, s.forensicTimeline);
        const iDiff = diffIocs(stateBefore.iocs, s.iocs);
        addedEvents = tDiff.added.length;
        addedIocs = iDiff.added.length;
        if (
          (addedEvents || addedIocs || tDiff.removed.length || iDiff.removed.length) &&
          options.importMetaStore
        ) {
          await options.importMetaStore.record(caseId, {
            kind: "velociraptor",
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
    try {
      await applyWhitelistToCase(caseId);
    } catch {
      /* non-fatal */
    }
    try {
      await applyNsrlToCase(caseId);
    } catch {
      /* non-fatal */
    }
    resynthesizeInBackground(caseId);
    return { addedEvents, addedIocs, storedName };
  }

  // Import ONLY a hunt/flow's uploaded report files (e.g. THOR), skipping rows entirely — used when
  // the analyst pastes the Velociraptor GUI's "Uploaded Files" tab URL specifically (ref.isUploadsUrl).
  // Mirrors collectVeloHuntOnce's uploads step (same resolveImportKind + dispatchImport chain) but
  // standalone, with ONE before/after diff across every uploaded file instead of hunt-job bookkeeping.
  async function ingestVeloUploads(
    caseId: string,
    uploads: HuntUpload[],
    opts: { minSeverity?: Severity; label: string },
  ): Promise<{ addedEvents: number; addedIocs: number; imported: string[]; skipped: string[] }> {
    const pipeline = options.pipeline;
    if (!pipeline) throw new Error("AI pipeline not configured");
    let stateBefore: InvestigationState | null = null;
    if (options.stateStore) {
      try {
        stateBefore = await options.stateStore.load(caseId);
      } catch {
        /* null */
      }
    }

    const imported: string[] = [];
    const skipped: string[] = [];
    let lastStoredName: string | undefined;
    for (const up of uploads) {
      const kind = resolveImportKind(up.name, up.content);
      if (kind === "unknown") {
        skipped.push(up.name);
        continue;
      }
      // CSV/log are themselves an LLM call — respect the per-case AI toggle exactly like every other
      // import path (dispatchImport's own CSV/log routes, and the bundle-collect uploads step).
      // With AI off, skip entirely rather than persisting evidence that never analyzes.
      if ((kind === "csv" || kind === "log") && !(await getControl(caseId)).enabled) {
        skipped.push(up.name);
        continue;
      }
      try {
        const { storedName, importedAt, seq } = await persistEvidence(caseId, up.name, up.content);
        lastStoredName = storedName;
        await dispatchImport(kind, caseId, up.content, {
          label: storedName,
          idPrefix: `${seq}`,
          importedAt,
          minSeverity: opts.minSeverity,
        });
        imported.push(up.name);
      } catch (e) {
        logLine(`[velociraptor] uploads-only import failed (${up.name}): ${(e as Error).message}`);
        skipped.push(up.name);
      }
    }

    let addedEvents = 0,
      addedIocs = 0;
    if (imported.length && options.stateStore && stateBefore) {
      try {
        const afterImport = await options.stateStore.load(caseId);
        if (options.superTimelineStore) {
          const superDiff = diffTimeline(stateBefore.forensicTimeline, afterImport.forensicTimeline);
          const added = addedForensicEvents(afterImport.forensicTimeline, superDiff);
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
        const s = await demoteForensicForCase(caseId);
        const tDiff = diffTimeline(stateBefore.forensicTimeline, s.forensicTimeline);
        const iDiff = diffIocs(stateBefore.iocs, s.iocs);
        addedEvents = tDiff.added.length;
        addedIocs = iDiff.added.length;
        if (
          (addedEvents || addedIocs || tDiff.removed.length || iDiff.removed.length) &&
          options.importMetaStore &&
          lastStoredName
        ) {
          await options.importMetaStore.record(caseId, {
            kind: "velociraptor",
            file: lastStoredName,
            diff: tDiff,
            iocsDiff: iDiff,
          });
          options.onImportMeta?.(caseId);
        }
      } catch {
        /* non-fatal */
      }
      try {
        await applyWhitelistToCase(caseId);
      } catch {
        /* non-fatal */
      }
      try {
        await applyNsrlToCase(caseId);
      } catch {
        /* non-fatal */
      }
      resynthesizeInBackground(caseId);
    }
    return { addedEvents, addedIocs, imported, skipped };
  }

  return { ingestVeloArtifactMap, ingestVeloUploads };
}
