/**
 * The Velociraptor hunt lifecycle: status polling, collect coalescing, the collect itself, and the
 * two standalone ingest paths for hunts the Companion did not launch. Lifted out of createApp by
 * #416 — the block the issue called out as the riskiest, because a mistake here fails silently.
 * Its timer behaviour is pinned by tests/server/timerLifecycle.test.ts.
 *
 * TWO INDEPENDENT CLOCKS, and they are not redundant:
 *   the FIXED-DELAY auto-collect timer, armed at launch for the analyst's chosen wait, and
 *   the STATUS POLLER, which every ~30s asks Velociraptor what the hunt is actually doing.
 * The poller is what makes a hunt stopped or deleted in the Velociraptor GUI collect promptly
 * instead of waiting out a 4-hour delay — and, because it is resumed from disk at startup, it also
 * self-heals the fixed-delay timer that a restart destroyed.
 *
 * `collectingNow` IS THE AUTHORITY ON WHAT IS RUNNING, not the persisted status. A status of
 * "collecting" on disk only means SOME process once started a collect; if that process died
 * mid-collect the status stays "collecting" forever, and honouring it would brick every later
 * "Collect now" for that hunt, permanently and silently. So in-flight state is in memory by design.
 *
 * COALESCE, NEVER DROP (#195). A collect re-reads the hunt's COMPLETE current result set, so N
 * requests arriving mid-collect all want the same thing — they collapse into exactly one follow-up
 * pass. But that pass must happen: this used to be a bare "already collecting → return", so a
 * second collect arriving in the tail of the first was discarded behind a `202 {accepted:true}`,
 * and the hunt's resultRows froze at the previous value forever. It read as flake; it was a drop.
 */
import type { CaseStore } from "../storage/caseStore.js";
import type { AppOptions } from "./appOptions.js";
import type { ImportBase } from "../routes/context.js";
import type { AiControl } from "../analysis/aiControl.js";
import { type VeloHuntJob } from "../analysis/veloHuntStore.js";
import {
  pollHuntStatusOnce,
  isHuntStoppedEarly,
  type HuntPollDeps,
} from "../integrations/velociraptor/huntStatusPoller.js";
import type { HuntUpload } from "../integrations/velociraptor/velociraptorApi.js";
import { parseVelociraptorJson } from "../analysis/velociraptorImport.js";
import { applySeverityFloor } from "../analysis/severityFloor.js";
import { diffTimeline, addedForensicEvents } from "../analysis/timelineDiff.js";
import { diffIocs } from "../analysis/iocsDiff.js";
import {
  recordDeploy,
  fillOutcome,
  HUNT_OUTCOME_MAX_DEFAULT,
  type HuntDeployInput,
} from "../analysis/huntOutcomes.js";
import {
  buildHuntRunSnapshot,
  diffHuntRuns,
  findHuntRunRecord,
  upsertHuntRunRecord,
  type HuntRunDiff,
} from "../analysis/huntRunDiff.js";
import type { InvestigationState, ForensicEvent } from "../analysis/stateTypes.js";
import { logLine } from "../logging/serverLogger.js";

export interface VeloHuntsDeps {
  store: CaseStore;
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
  pushImportCheckpoint: (caseId: string, beforeState: InvestigationState, label: string) => Promise<void>;
  resynthesizeInBackground: (caseId: string) => void;
}

export interface VeloHunts {
  /** Fixed-delay auto-collect timers, keyed by hunt id. The launch route arms them. */
  readonly veloHuntTimers: Map<string, NodeJS.Timeout>;
  /** Start a collect in the background; says synchronously whether it started or was queued. */
  startVeloHuntCollect(caseId: string, huntId: string): "started" | "queued";
  scheduleVeloHuntStatusPoll(caseId: string, huntId: string): void;
  pollVeloHuntStatus(caseId: string, huntId: string): Promise<void>;
  stopVeloHuntStatusPoll(caseId: string, huntId: string): void;
  /** Re-arm status polling for every non-terminal hunt across all cases (server restart). */
  resumeVeloHuntStatusPolls(): Promise<void>;
  /**
   * Record a deployed hunt in the per-case hunting feedback-loop ledger (#157). Never throws.
   * The two ingest paths for hunts the Companion did NOT launch live in
   * composition/veloExternalIngest.ts — see that file for why they are not here.
   */
  recordHuntDeploy(caseId: string, input: HuntDeployInput): Promise<void>;
}

export function createVeloHunts(deps: VeloHuntsDeps): VeloHunts {
  const {
    store,
    options,
    persistEvidence,
    dispatchImport,
    resolveImportKind,
    autoTagImported,
    demoteForensicForCase,
    getControl,
    pushImportCheckpoint,
    resynthesizeInBackground,
  } = deps;

  // In-memory auto-collect timers, keyed by HUNT id (globally unique) so concurrent hunts each get
  // their own. Lost on a server restart BY DESIGN — the jobs are persisted (veloHuntStore), so after a
  // restart the dashboard still shows them and the analyst triggers "Collect now". .unref() so a
  // pending timer never blocks exit.
  const veloHuntTimers = new Map<string, NodeJS.Timeout>();
  // In-flight collects, keyed `caseId huntId`; claimed synchronously before any await, which is what
  // closes the TOCTOU race between the fixed-delay timer, the status poller and a manual "Collect
  // now" all deciding to collect the same hunt at the same moment (VeloHuntStore has no lock/CAS).
  const collectingNow = new Map<string, { rerun: boolean }>();
  const collectKey = (caseId: string, huntId: string): string => `${caseId} ${huntId}`;

  // ── Velociraptor hunt STATUS polling ─────────────────────────────────────────────────────────
  // Keyed `caseId huntId`, self-rescheduling setTimeout (not setInterval, so a slow poll can't
  // overlap itself), .unref()'d so a pending poll never blocks process exit. Interval from
  // DFIR_VELO_HUNT_POLL_S (default 30s, clamped 5-300). Mirrors the live-monitor scheduling.
  const veloStatusTimers = new Map<string, NodeJS.Timeout>();
  const statusKey = (caseId: string, huntId: string): string => `${caseId} ${huntId}`;

  // One status-poll tick: load the job, poll (pure pollHuntStatusOnce), persist + broadcast only on
  // an actual status change, then either reschedule, trigger an immediate collect, or stop. Never
  // throws (pollHuntStatusOnce itself never throws; store I/O failures are best-effort).
  async function pollVeloHuntStatus(caseId: string, huntId: string): Promise<void> {
    const huntStore = options.veloHuntStore;
    const client = options.velociraptorClient;
    if (!huntStore || !client) {
      veloStatusTimers.delete(statusKey(caseId, huntId));
      return;
    }
    let job: VeloHuntJob | null = null;
    try {
      job = await huntStore.get(caseId, huntId);
    } catch (err) {
      logLine(`[velo-hunt-status] failed to load hunt ${huntId} for status poll: ${(err as Error).message}`);
    }
    if (!job) {
      veloStatusTimers.delete(statusKey(caseId, huntId));
      return;
    }

    const pollDeps: HuntPollDeps = { getState: (id) => client.huntStatus(id), log: logLine };
    const outcome = await pollHuntStatusOnce(job, pollDeps);
    if (outcome.job.status !== job.status) {
      try {
        await huntStore.upsert(caseId, outcome.job);
      } catch {
        /* best-effort */
      }
      options.onVeloHunt?.(caseId);
    }

    if (outcome.action === "reschedule") {
      if (veloStatusTimers.has(statusKey(caseId, huntId))) scheduleVeloHuntStatusPoll(caseId, huntId);
    } else if (outcome.action === "collect") {
      veloStatusTimers.delete(statusKey(caseId, huntId));
      startVeloHuntCollect(caseId, huntId); // clears the fixed-delay timer + status poll itself (see below)
    } else {
      veloStatusTimers.delete(statusKey(caseId, huntId));
    }
  }

  // Arm (or re-arm) a hunt's status-poll timer for one interval out. Clears any existing timer first
  // so start is idempotent. Clamped 5s..300s so a bad env value can't busy-loop or stall forever.
  function scheduleVeloHuntStatusPoll(caseId: string, huntId: string): void {
    const key = statusKey(caseId, huntId);
    const existing = veloStatusTimers.get(key);
    if (existing) clearTimeout(existing);
    const seconds = Math.min(300, Math.max(5, Number(process.env.DFIR_VELO_HUNT_POLL_S) || 30));
    const timer = setTimeout(() => {
      void pollVeloHuntStatus(caseId, huntId);
    }, seconds * 1000);
    timer.unref?.();
    veloStatusTimers.set(key, timer);
  }

  function stopVeloHuntStatusPoll(caseId: string, huntId: string): void {
    const key = statusKey(caseId, huntId);
    const timer = veloStatusTimers.get(key);
    if (timer) clearTimeout(timer);
    veloStatusTimers.delete(key);
  }

  // Re-arm status polling for every non-terminal hunt job across all cases (server restart). As a
  // side effect this also self-heals the pre-existing "fixed-delay auto-collect timer is lost on
  // restart" gap: a resumed status poll will detect STOPPED/ARCHIVED on its own and trigger the
  // collect even though the original setTimeout is gone. Best-effort per case.
  async function resumeVeloHuntStatusPolls(): Promise<void> {
    const huntStore = options.veloHuntStore;
    if (!huntStore || !options.velociraptorClient) return;
    let cases: { caseId: string }[] = [];
    try {
      cases = await store.listCases();
    } catch {
      return;
    }
    let resumed = 0;
    for (const c of cases) {
      try {
        for (const job of await huntStore.list(c.caseId)) {
          if (job.status === "running" || job.status === "unreachable") {
            scheduleVeloHuntStatusPoll(c.caseId, job.huntId);
            resumed++;
          }
        }
      } catch {
        /* skip this case */
      }
    }
    if (resumed > 0)
      logLine(
        `[velo-hunt-status] resumed status polling for ${resumed} hunt(s) across ${cases.length} case(s)`,
      );
  }

  // Collect a bundle hunt and import it the SAME way a manual import works. Ingests BOTH the result
  // ROWS (the {"Artifact.Name":[rows]} artifact-map the Velociraptor importer consumes) AND any
  // uploaded JSON reports (e.g. THOR/Hayabusa via Generic.Scanner.ThorZIP) — for those the rows don't
  // matter, the uploaded JSON does; it's detected + dispatched to the right importer. Honors the run's
  // minSeverity floor, records ONE combined import-meta diff, then synthesizes. Never throws (timer).
  //
  // ONE pass. Concurrency is owned by startVeloHuntCollect — call that, not this.
  async function collectVeloHuntOnce(caseId: string, huntId: string): Promise<void> {
    const client = options.velociraptorClient;
    const huntStore = options.veloHuntStore;
    const pipeline = options.pipeline;
    if (!client || !huntStore || !pipeline) return;
    const pending = veloHuntTimers.get(huntId);
    if (pending) {
      clearTimeout(pending);
      veloHuntTimers.delete(huntId);
    }
    stopVeloHuntStatusPoll(caseId, huntId); // an import is starting — it now owns this job's status

    let job = await huntStore.get(caseId, huntId);
    if (!job) return;
    // NOTE: a persisted status of "collecting" is deliberately NOT treated as "in flight" — see the
    // file header. The authority on what is actually running now is `collectingNow`.
    try {
      // A last live check right before collecting: was this hunt stopped/deleted in Velociraptor well
      // before its own scheduled expiry? Checked HERE (not just in the status poller) so every entry
      // point — the poller, the fixed-delay auto-collect timer, and a manual "Collect now" — gets the
      // same signal. Best-effort: a failed check must not block the collect itself.
      let stoppedEarly = job.stoppedEarly === true;
      if (!stoppedEarly) {
        try {
          stoppedEarly = isHuntStoppedEarly(await client.huntStatus(job.huntId), Date.now());
        } catch {
          /* best-effort */
        }
      }
      job = { ...job, status: "collecting", ...(stoppedEarly ? { stoppedEarly: true } : {}) };
      await huntStore.upsert(caseId, job);
      options.onVeloHunt?.(caseId);
      const minSeverity = job.minSeverity;

      // Snapshot the full state BEFORE any import so we record one combined import-meta diff for the
      // whole collection AND can push a single pre-collection undo checkpoint (#76).
      let stateBefore: InvestigationState | null = null;
      if (options.stateStore) {
        try {
          stateBefore = await options.stateStore.load(caseId);
        } catch {
          /* keep null */
        }
      }

      let importedAny = false;
      let lastFile: string | undefined;

      // A bundle flagged superTimelineOnly (the built-in super-timeline-triage) collects raw host
      // artifacts (MFT/USN/Prefetch) whose only purpose is the super-timeline — routing them through the
      // normal Velociraptor importer would flood the forensic timeline + IOC list, defeating the point.
      // So for such a bundle we PARSE the rows (no mergeDelta) and append straight to the super-timeline.
      const bundle =
        job.bundleId && options.artifactBundleStore
          ? await options.artifactBundleStore.get(job.bundleId)
          : null;
      const superOnly = bundle?.superTimelineOnly === true && !!options.superTimelineStore;

      // 1) Result ROWS → the Velociraptor importer (detections + telemetry). Resilient: an artifact
      // whose output is too large to fetch is skipped (logged), not fatal — the rest still import, and
      // its uploaded JSON (if any) is still picked up in step 2.
      // For a suggested fleet hunt the single Custom.Hunt artifact stores rows under named sources
      // (Pivot0…); map them so collect reads `artifact/source` (else 0 rows → false "no evidence", #157).
      const sourcesByArtifact =
        job.sources?.length && job.artifacts.length === 1 ? { [job.artifacts[0]]: job.sources } : undefined;
      const { results: map, skipped } = await client.huntResultsByArtifact(
        job.huntId,
        job.artifacts,
        job.filters,
        sourcesByArtifact,
      );
      if (skipped.length)
        logLine(
          `[velociraptor] hunt ${job.huntId}: skipped ${skipped.length} artifact(s) — ${skipped.map((s) => `${s.name} (${s.error})`).join("; ")} — raise DFIR_VELOCIRAPTOR_COLLECT_MAX_OUTPUT / DFIR_VELOCIRAPTOR_MAX_ROWS if these are oversized`,
        );
      const totalRows = Object.values(map).reduce((n, rows) => n + rows.length, 0);
      // The artifacts that returned NEITHER rows nor an error — not a failure (they simply had nothing
      // to report), but worth distinguishing from `skipped` so "N artifacts collected, M had no findings,
      // K failed to collect" is fully accounted for instead of a bare "+X events" that reads as one artifact.
      const skippedNames = new Set(skipped.map((s) => s.name));
      const emptyArtifacts = job.artifacts.filter((a) => !map[a] && !skippedNames.has(a));
      if (totalRows > 0) {
        const json = JSON.stringify(map);
        const { storedName, importedAt, seq } = await persistEvidence(
          caseId,
          `velo-hunt_${job.huntId}.json`,
          json,
        );
        lastFile = storedName;
        options.onAiStatus?.(caseId, {
          status: "analyzing",
          phase: "extracting",
          at: importedAt,
          detail: `importing Velociraptor hunt ${job.huntId} rows (${Object.keys(map).length} artifact(s), ${totalRows} row(s))`,
        });
        // Deep-link back to the hunt in the Velociraptor GUI: reuse the URL saved on the job when
        // present, else build it from the hunt id. Shared by every event from this hunt, on EITHER
        // path — previously only the super-only branch stamped it, so a normal (forensic-timeline-
        // bound) bundle/hunt collection never carried a veloUrl and the FT's "↗ Velociraptor" link
        // never rendered for its events.
        const jobHuntId = job.huntId; // hoisted so the .map closure below doesn't re-narrow the reassignable `job`
        const veloUrl = job.guiUrl || client.huntGuiUrlFor(jobHuntId);
        if (superOnly) {
          // Parse WITHOUT merging into forensic; append the mapped events to the super-timeline only.
          // The artifact-map carries each row's _Source, so `artifact` is just a filename fallback.
          const artifact = storedName.replace(/^\d+_/, "").replace(/\.(json|jsonl|ndjson|csv)$/i, "");
          // Complete record: don't aggregate rows, lift the 2000-event cap to the super store's cap.
          const parsed = parseVelociraptorJson(json, {
            artifact,
            aggregate: false,
            maxEvents: Number(process.env.DFIR_SUPERTIMELINE_MAX) || 100000,
          });
          const floored = applySeverityFloor(parsed.events, minSeverity); // honor the import floor (no-op when unset) — the forensic path floors via importVelociraptor
          // Id by the HUNT id, not the import `seq` (which increments each collect): re-collecting the
          // same hunt (Collect now / auto-collect after a manual collect) re-parses the SAME rows, and
          // the super-timeline's id-based dedup (dedupeAppend) only drops repeats when the ids are
          // stable. Same rows in the same order → same ids → deduped; a straggler that checks in later
          // gets a higher index and appends. (Forensic imports get this from correlation dedup; the
          // super-only path has no such guard, so the ids must be stable across re-collects.)
          const events: ForensicEvent[] = floored.map((e, i) => ({
            id: `${jobHuntId}-e${i + 1}`,
            timestamp: e.timestamp,
            description: e.description,
            severity: e.severity,
            mitreTechniques: e.mitreTechniques ?? [],
            relatedFindingIds: [],
            sourceScreenshots: [storedName],
            ...(e.artifactName ? { artifactName: e.artifactName } : {}),
            ...(e.message ? { message: e.message } : {}),
            ...(veloUrl ? { veloUrl } : {}),
            sources: e.sources?.length ? e.sources : ["Velociraptor"],
            ...(e.asset ? { asset: e.asset } : {}),
            ...(e.path ? { path: e.path } : {}),
            ...(e.sha256 ? { sha256: e.sha256 } : {}),
            ...(e.md5 ? { md5: e.md5 } : {}),
          }));
          await options.superTimelineStore!.append(caseId, events);
          options.onSuperTimeline?.(caseId); // live dashboards refresh as super-only events stream in
          await autoTagImported(caseId, events);
          importedAny = true; // report success even though nothing hit the forensic timeline
        } else {
          await pipeline.importVelociraptor(caseId, json, {
            label: storedName,
            idPrefix: `${seq}`,
            importedAt,
            minSeverity,
            veloUrl,
          });
          importedAny = true;
        }
      }

      // 2) Uploaded JSON reports (e.g. THOR/Hayabusa) → detect + dispatch. Best-effort: a wrong upload
      // VQL for the server version must not break the rows import (set DFIR_VELOCIRAPTOR_UPLOAD_VQL).
      let uploads: HuntUpload[] = [];
      try {
        uploads = await client.huntUploads(job.huntId);
      } catch (e) {
        logLine(
          `[velociraptor] hunt uploads read failed (override DFIR_VELOCIRAPTOR_UPLOAD_VQL?): ${(e as Error).message}`,
        );
      }
      for (const up of uploads) {
        const upKind = resolveImportKind(up.name, up.content); // honor custom importers like /import + /push
        if (upKind === "unknown") continue;
        if (superOnly) {
          // Super-only bundles route to the super-timeline; the upload path (THOR/Hayabusa JSON) only has
          // a forensic-merge importer (dispatchImport), so ingesting it would leak into the forensic
          // timeline and break the super-only invariant. Skip it and tell the analyst to collect
          // upload-based artifacts via a normal bundle. (The shipped super-timeline-triage bundle has no
          // upload artifacts; this guards custom/edited super-only bundles.)
          logLine(
            `[velociraptor] super-only bundle: skipping uploaded ${upKind} report ${up.name} (upload-based artifacts aren't ingested for super-only bundles — collect them via a normal bundle)`,
          );
          continue;
        }
        if ((upKind === "csv" || upKind === "log") && !(await getControl(caseId)).enabled) continue; // AI-dependent, AI off
        try {
          const { storedName, importedAt, seq } = await persistEvidence(caseId, up.name, up.content);
          lastFile = storedName;
          options.onAiStatus?.(caseId, {
            status: "analyzing",
            phase: "extracting",
            at: importedAt,
            detail: `importing uploaded ${upKind} report ${up.name}`,
          });
          await dispatchImport(upKind, caseId, up.content, {
            label: storedName,
            idPrefix: `${seq}`,
            importedAt,
            minSeverity,
          });
          importedAny = true;
        } catch (e) {
          logLine(`[velociraptor] upload import failed (${up.name}): ${(e as Error).message}`);
        }
      }
      options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });

      // 3) One combined import-meta diff (so the dashboard's "📥 last import / +N" banner lights up).
      let addedEvents = 0;
      let addedIocs = 0;
      if (importedAny && options.stateStore && stateBefore) {
        try {
          const imported = await options.stateStore.load(caseId);
          // Dual-write the hunt's new events into the super-timeline FIRST (superset of everything
          // imported, Info telemetry included); resolve the FULL events from the imported (pre-demote)
          // state since the diff is lossy.
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
          // Demote sub-threshold events out of forensic (kept in super), then compute the import-meta
          // diff + checkpoint decision on the POST-demote state so "+N events" counts only graded signal.
          const s = await demoteForensicForCase(caseId);
          const diff = diffTimeline(stateBefore.forensicTimeline, s.forensicTimeline);
          const iocsDiff = diffIocs(stateBefore.iocs, s.iocs);
          addedEvents = diff.added.length;
          addedIocs = iocsDiff.added.length;
          if (options.importMetaStore) {
            await options.importMetaStore.record(caseId, {
              kind: "velociraptor",
              file: lastFile ?? `velo-hunt_${job.huntId}.json`,
              diff,
              iocsDiff,
            });
            options.onImportMeta?.(caseId);
          }
          // #76: snapshot the pre-collect state for undo when the hunt actually added data.
          if (diff.added.length || diff.removed.length || iocsDiff.added.length || iocsDiff.removed.length) {
            await pushImportCheckpoint(
              caseId,
              stateBefore,
              `velociraptor (${lastFile ?? `hunt ${job.huntId}`})`,
            );
          }
        } catch {
          /* non-fatal */
        }
      }

      // #157 feedback loop: fill this hunt's outcome (by huntId) — for a bundle hunt OR a deployed
      // suggested hunt. Done regardless of importedAny so a hunt that ran and found nothing is recorded
      // as a miss (the loop must know it ran empty so it isn't re-proposed as productive). Best-effort.
      if (options.huntOutcomeStore) {
        try {
          const cur = await options.huntOutcomeStore.load(caseId);
          // #80: run-to-run diff — only meaningful for a fingerprinted (non-bundle) hunt, and only
          // computed when this collect belongs to a DIFFERENT huntId than the fingerprint's last
          // recorded run (a genuine re-deploy, not just pulling stragglers off the same running hunt).
          let runDiff: HuntRunDiff | undefined;
          const fp = cur.find((o) => o.huntId === huntId)?.vqlFingerprint || ""; // `huntId` (param) === job.huntId, and stays non-null inside this closure (job is a reassignable `let`)
          if (fp && options.huntRunSnapshotStore) {
            try {
              const records = await options.huntRunSnapshotStore.load(caseId);
              const prevRecord = findHuntRunRecord(records, fp);
              const snapshot = buildHuntRunSnapshot(map);
              // A run-diff is only SURFACED for a genuinely new run — no prior snapshot, or a different
              // huntId (a real re-deploy). A same-huntId re-collect is just stragglers checking into the
              // SAME running hunt, so it produces no diff of its own.
              const isNewRun = !prevRecord || prevRecord.huntId !== job.huntId;
              if (isNewRun) runDiff = diffHuntRuns(prevRecord?.snapshot, snapshot);
              // But ALWAYS advance the stored baseline to this collect's full result set — including
              // same-huntId re-collects — so the NEXT run diffs against the COMPLETE previous run rather
              // than its first partial collect (which would otherwise falsely report later-arriving rows
              // as "new since last run").
              const next = upsertHuntRunRecord(records, {
                vqlFingerprint: fp,
                huntId: job.huntId,
                capturedAt: new Date().toISOString(),
                snapshot,
              });
              await options.huntRunSnapshotStore.save(caseId, next);
            } catch (e) {
              logLine(`[hunt-run-diff] snapshot failed for hunt ${job.huntId}: ${(e as Error).message}`);
            }
          }
          // resultRows = the rows the hunt RETURNED (what the analyst sees); addedEvents = new-to-case
          // after dedup. Showing both stops "+1 event" reading as wrong next to a 10-row result table.
          await options.huntOutcomeStore.save(
            caseId,
            fillOutcome(cur, job.huntId, {
              resultRows: totalRows,
              addedEvents,
              addedIocs,
              collectedAt: new Date().toISOString(),
              runDiff,
            }),
          );
        } catch (e) {
          logLine(`[hunt-outcomes] fill failed for hunt ${job.huntId}: ${(e as Error).message}`);
        }
      }

      job = {
        ...job,
        status: "imported",
        importedAt: new Date().toISOString(),
        importFile: lastFile,
        addedEvents,
        addedIocs,
        error: undefined,
        skippedArtifacts: skipped.length ? skipped : undefined,
        emptyArtifacts: emptyArtifacts.length ? emptyArtifacts : undefined,
      };
      await huntStore.upsert(caseId, job);
      options.onVeloHunt?.(caseId);
      if (importedAny) resynthesizeInBackground(caseId);
    } catch (err) {
      try {
        const cur = await huntStore.get(caseId, huntId);
        if (cur) await huntStore.upsert(caseId, { ...cur, status: "error", error: (err as Error).message });
      } catch {
        /* ignore */
      }
      options.onVeloHunt?.(caseId);
      options.onAiStatus?.(caseId, {
        status: "error",
        at: new Date().toISOString(),
        detail: `Velociraptor hunt collect failed: ${(err as Error).message}`,
      });
    }
  }

  // Start a collect for one hunt, in the background, and say synchronously what it decided:
  //   "started" — this call owns a fresh collect pass.
  //   "queued"  — a collect was already in flight; ONE more pass will run when it finishes.
  // Either way the request is honored, which is what the 202 on the collect route promises. See the
  // file header for why dropping the second request instead was a real, silent bug (#195).
  function startVeloHuntCollect(caseId: string, huntId: string): "started" | "queued" {
    const key = collectKey(caseId, huntId);
    const inFlight = collectingNow.get(key);
    if (inFlight) {
      inFlight.rerun = true;
      return "queued";
    }

    const entry = { rerun: false };
    collectingNow.set(key, entry);
    void (async () => {
      try {
        // Re-check `rerun` AFTER each pass: requests that landed during the pass are served by one
        // more pass (they'd all read the same complete result set, so they collapse into one).
        // A pass that throws (only the hunt-store read outside its own try can) is logged and does
        // NOT cancel a queued rerun — the point of the queue is that a request always gets a pass.
        do {
          entry.rerun = false;
          try {
            await collectVeloHuntOnce(caseId, huntId);
          } catch (err) {
            logLine(`[velociraptor] collect pass failed for hunt ${huntId}: ${(err as Error).message}`);
          }
        } while (entry.rerun);
      } finally {
        collectingNow.delete(key);
      }
    })();
    return "started";
  }

  // Record a deployed hunt in the per-case hunting feedback loop ledger (#157). Best-effort + never
  // throws — an outcome-recording failure must not break a deploy. Stamps the time here so huntOutcomes
  // stays time-free. Re-deploying the same huntId upserts (recordDeploy dedups by id).
  async function recordHuntDeploy(caseId: string, input: HuntDeployInput): Promise<void> {
    if (!options.huntOutcomeStore) return;
    try {
      const max = Number(process.env.DFIR_HUNT_OUTCOME_MAX) || HUNT_OUTCOME_MAX_DEFAULT;
      const cur = await options.huntOutcomeStore.load(caseId);
      await options.huntOutcomeStore.save(caseId, recordDeploy(cur, input, max));
    } catch (e) {
      logLine(`[hunt-outcomes] record deploy failed: ${(e as Error).message}`);
    }
  }

  return {
    veloHuntTimers,
    startVeloHuntCollect,
    scheduleVeloHuntStatusPoll,
    pollVeloHuntStatus,
    stopVeloHuntStatusPoll,
    resumeVeloHuntStatusPolls,
    recordHuntDeploy,
  };
}
