import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import type { Severity } from "./stateTypes.js";
import type { HuntTarget, SkippedArtifact } from "../integrations/velociraptor/velociraptorApi.js";

// The per-case record of Velociraptor BUNDLE hunts: which bundle was launched, the returned hunt id,
// when results should be collected, and the outcome once they are. Persisted to a side file
// (`state/velo-hunt.json`) so a server restart (the project's #1 gotcha) doesn't strand a hunt — the
// dashboard still shows it and the analyst can "Collect now". NOT part of InvestigationState.
// MULTIPLE concurrent jobs per case are supported (a list keyed by huntId) — starting a second hunt
// while a first is still running no longer drops the first.

export type VeloHuntStatus = "running" | "collecting" | "imported" | "error" | "deleted" | "unreachable";

/**
 * Where a collect actually is while `status` is "collecting" (#770).
 *
 * "collecting" covers three very different waits, and the card used to render the same badge and no
 * text for all of them — so a normal queue wait looked identical to a hang. Reported, never inferred:
 *
 *   fetching  — reading result rows out of Velociraptor. Network-bound, no case writes yet.
 *   queued    — the rows are in hand and the collect is waiting for the case's import slot, i.e. for
 *               ANOTHER import to finish. Nothing is wrong; the analyst simply cannot tell without it.
 *   importing — holding the slot and writing. The long one on a large case.
 */
export type VeloCollectPhase = "fetching" | "queued" | "importing";

export interface VeloHuntJob {
  bundleId: string;
  // Set when this job was launched for a specific DwellWindow (the "Dwell-Time Triage" bundle
  // requires one). Bookkeeping only — VeloHuntStore itself is NOT in SNAPSHOT_STATE_FILES (it's
  // live-server-tied/transient); the durable window definition lives in DwellWindowStore.
  dwellWindowId?: string;
  bundleName: string;
  artifacts: string[];
  sources?: string[]; // named sources for a single-artifact fleet-hunt (Companion launchHunt → Pivot0…); collect reads `artifact/source`
  huntId: string;
  guiUrl?: string;
  launchedAt: string; // ISO
  waitMinutes: number;
  collectAt: string; // ISO — launchedAt + waitMinutes; when the auto-collect fires
  status: VeloHuntStatus;
  // Set while `status` is "collecting", cleared on the way out of it. A job that says "collecting"
  // with no phase was written by an older build, or stranded by a server that died mid-collect — the
  // persisted status is NOT authority on what is running (see composition/veloHunts.ts's header).
  collectPhase?: VeloCollectPhase;
  collectRows?: number; // rows this collect fetched from Velociraptor; known once the fetch finishes
  target?: HuntTarget;
  minSeverity?: Severity; // optional import floor chosen at run time (keeps low-value items out)
  timeoutSeconds?: number; // optional per-collection timeout used for this hunt (Velociraptor default 600s)
  expirySeconds?: number; // relative hunt expiry used at launch (seconds); default one hour
  filters?: Record<string, string>; // per-artifact VQL WHERE filters snapshotted from the bundle (applied at collect)
  superTimelineOnly?: boolean; // super-timeline-only routing, snapshotted from the bundle at launch
  // The COLLECTION window this hunt was launched with, when the analyst scoped it. Forensically load-
  // bearing: it tells a later reader that silence outside these bounds is a collection boundary, not an
  // absence of activity. `end` is absent for a relative preset (the hunt keeps collecting forward).
  timeScope?: {
    start: string; // ISO
    end?: string; // ISO
    scopedArtifacts: number; // how many artifacts actually received the window
    totalArtifacts: number; // how many were launched
    // true = the server reported no parameter metadata for this bundle's artifacts (the catalog fetch
    // failed or came back empty), so the bounded/unbounded split above could NOT be verified — it may
    // understate what actually got scoped. Distinguishes "this bundle genuinely has no date-parameterized
    // artifacts" (degraded: false, benign) from "we don't actually know" (degraded: true, a real gap).
    degraded: boolean;
  };
  error?: string;
  // Set at collect time when Velociraptor reported this hunt terminal (STOPPED/ARCHIVED) well before
  // its own scheduled expiry — a strong signal an analyst stopped or deleted it in Velociraptor rather
  // than it running to natural completion (see isHuntStoppedEarly). Lets the UI say so instead of the
  // generic "no new results collected yet — collect again later", which is misleading for a hunt that
  // will never produce anything again.
  stoppedEarly?: boolean;
  importedAt?: string; // ISO — when results were collected + imported
  importFile?: string; // stored evidence filename
  addedEvents?: number;
  addedIocs?: number;
  // Per-artifact collection accounting from the last collect, so "N artifacts, +X events" doesn't read
  // as "only one artifact collected" when the rest simply had nothing to report vs. actually failed.
  skippedArtifacts?: SkippedArtifact[]; // fetch FAILED (oversized/timeout/error) — see the reason
  emptyArtifacts?: string[]; // fetched cleanly, zero rows — nothing to report, not an error
  truncatedArtifacts?: TruncatedArtifact[]; // fetched PARTIALLY — the read hit the row cap, findings missing
}

/**
 * A hunt job as the DASHBOARD receives it: the persisted record plus one thing the record cannot say.
 *
 * `collectActive` is the answer to "is a collect actually running for this hunt RIGHT NOW", and it
 * comes from the live in-flight map in composition/veloHunts.ts, never from the file. A persisted
 * status of "collecting" only means some process once started one; a server that died mid-collect
 * leaves it set forever, so reading the file as proof of activity makes the card assert work that
 * stopped hours ago. Present only for a job whose status IS "collecting" — it means nothing otherwise.
 */
export interface VeloHuntJobView extends VeloHuntJob {
  collectActive?: boolean;
}

/**
 * An artifact whose read hit the collection row cap. The third collect outcome beside skipped (the
 * fetch failed) and empty (nothing to report), and the one that used to be invisible: the read
 * succeeded, its rows imported, and nothing told the analyst the artifact had more to say.
 *
 * THOR is why this exists. Its log opens with ~1000 lines of module init and per-file progress and
 * only then reports what it found, so the old 1000-row dashboard cap ended a real scan mid-run — the
 * 40 warnings it had counted never left the server, and the collect reported success.
 */
export interface TruncatedArtifact {
  name: string;
  kept: number; // rows imported
  total: number; // rows the read returned before the cap (kept + 1 once the cap bit)
}

/**
 * The operator-facing warnings for one collect: the artifacts that FAILED to fetch, and the ones that
 * fetched only PARTIALLY. Both name the knob that lifts them, and the truncation half is the one worth
 * having — a failed fetch is loud, a truncated one looks exactly like a clean success.
 */
export function collectWarnings(
  huntId: string,
  skipped: readonly SkippedArtifact[],
  cut: readonly TruncatedArtifact[],
): string[] {
  const out: string[] = [];
  if (skipped.length)
    out.push(
      `[velociraptor] hunt ${huntId}: skipped ${skipped.length} artifact(s) — ` +
        `${skipped.map((s) => `${s.name} (${s.error})`).join("; ")} — raise ` +
        `DFIR_VELOCIRAPTOR_COLLECT_MAX_OUTPUT / DFIR_VELOCIRAPTOR_COLLECT_MAX_ROWS if these are oversized`,
    );
  if (cut.length)
    out.push(
      `[velociraptor] hunt ${huntId}: ${cut.length} artifact(s) hit the collection row cap — ` +
        `${cut.map((t) => `${t.name} (kept ${t.kept})`).join("; ")}. Findings BEYOND the cap were never ` +
        `read; raise DFIR_VELOCIRAPTOR_COLLECT_MAX_ROWS and collect again.`,
    );
  return out;
}

/**
 * Does this hunt's results route into the super-timeline ONLY, never the forensic timeline?
 *
 * Read from the JOB, because a bundle stays editable while its hunt is still running. The flag used
 * to be read back off the bundle store at collect time, so any mid-flight change to the bundle —
 * an edit that did not re-send superTimelineOnly, or deleting a custom bundle outright — silently
 * re-routed the collect and dumped raw MFT/USN/Prefetch rows into the forensic timeline and the IOC
 * list, which is the exact flood the flag exists to prevent.
 *
 * `bundleFlag` is the fallback for jobs launched before the job carried the field: without it, an
 * in-flight super-only hunt would flood on the first collect after an upgrade.
 */
export function superOnlyHunt(job: VeloHuntJob, bundleFlag: boolean | undefined): boolean {
  return (job.superTimelineOnly ?? bundleFlag) === true;
}

// Cap retained jobs per case (newest first) so the side file stays small — old terminal jobs drop off.
const MAX_JOBS = 12;

// Serializes a case's list->modify->save section on the hunt-job file (follow-up to #682). Two
// hunts launched together both read the same list and the second save drops the first, so a hunt
// that IS running on the fleet has no record here — the analyst cannot see or collect it.
const veloHuntLock = new StateLock();

export class VeloHuntStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "velo-hunt.json");
  }

  // All tracked bundle hunts for the case, newest first. Back-compat: an older single-object file
  // (one job per case) is read as a one-element list.
  async list(caseId: string): Promise<VeloHuntJob[]> {
    try {
      const parsed = JSON.parse(await readFile(this.path(caseId), "utf8")) as unknown;
      if (Array.isArray(parsed)) return parsed as VeloHuntJob[];
      if (parsed && typeof parsed === "object" && typeof (parsed as VeloHuntJob).huntId === "string")
        return [parsed as VeloHuntJob];
      return [];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async get(caseId: string, huntId: string): Promise<VeloHuntJob | null> {
    return (await this.list(caseId)).find((j) => j.huntId === huntId) ?? null;
  }

  // Add a new job (prepended) or update an existing one IN PLACE (matched by huntId), capping history.
  upsert(caseId: string, job: VeloHuntJob): Promise<VeloHuntJob> {
    return veloHuntLock.runExclusive(caseId, async () => {
      const jobs = await this.list(caseId);
      const idx = jobs.findIndex((j) => j.huntId === job.huntId);
      const next = idx >= 0 ? jobs.map((j, i) => (i === idx ? job : j)) : [job, ...jobs].slice(0, MAX_JOBS);
      await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
      return job;
    });
  }
}
