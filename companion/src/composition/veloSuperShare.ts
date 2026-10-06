// The super-only import of one hunt artifact, and the fair share of the hunt's super-timeline cap
// (#1982). Extracted from veloHunts.ts, which sits at the 800-line file-size limit.
//
// A super-only hunt (the built-in Super-Timeline Triage) shares ONE DFIR_SUPERTIMELINE_MAX across all
// of its artifacts. It used to be spent first-come in bundle order: Windows.NTFS.MFT is entry 1, a
// full MFT read is as large as the cap, so USN and every artifact after MFT got nothing — and the
// collection inventory then called them "in the archive only", sending the analyst to search the
// archive for rows that were never added. The cap is now split by row count before the loop, smallest
// first: each artifact gets what it needs, up to an equal share of what is left. An artifact the
// split cut is recorded on the job, so the inventory and the hunt card can say so.

import type { BulkImportSink } from "../analysis/ingest/velociraptorBulk.js";
import { runVelociraptorBulk, bulkPathApplies } from "../analysis/ingest/velociraptorBulk.js";
import { parseVelociraptorJson } from "../analysis/velociraptorImport.js";
import { applySeverityFloor } from "../analysis/severityFloor.js";
import type { ForensicEvent, Severity } from "../analysis/stateTypes.js";
import type { SuperTimelineStore, SuperEviction } from "../analysis/superTimelineStore.js";
import type { SuperCappedArtifact } from "../analysis/veloHuntStore.js";
import { getServerLogger, logLine } from "../logging/serverLogger.js";

export const DEFAULT_SUPERTIMELINE_MAX = 100000;

/** The case-wide super-timeline cap, which one super-only hunt also uses as its budget. */
export function superTimelineCap(env: NodeJS.ProcessEnv = process.env): number {
  return Number(env.DFIR_SUPERTIMELINE_MAX) || DEFAULT_SUPERTIMELINE_MAX;
}

/**
 * Water-fill `cap` across artifacts by row count, smallest first: each gets min(its rows, an equal
 * share of what is left). Returned in INPUT order. No share exceeds its rows; the sum never exceeds
 * the cap. Rows stand in for events: a row that maps to two events still counts once, so the share is
 * an upper bound on events, never an overrun.
 */
export function superTimelineShares(rows: readonly number[], cap: number): number[] {
  const order = rows.map((r, i) => ({ r: Math.max(0, Math.floor(r) || 0), i })).sort((a, b) => a.r - b.r);
  const shares = new Array<number>(rows.length).fill(0);
  let left = Math.max(0, Math.floor(cap) || 0);
  order.forEach(({ r, i }, k) => {
    const share = Math.min(r, Math.floor(left / (order.length - k)));
    shares[i] = share;
    left -= share;
  });
  return shares;
}

export interface SuperShareLedger {
  /** The event limit for the artifact at `index`. Call once per artifact, in loop order. */
  limit(index: number): number;
  /** Charge what the artifact actually added, so slack it left goes to a later artifact. */
  charge(added: number): void;
}

/**
 * The per-artifact limit in LOOP order: what is left of the cap minus the shares reserved for the
 * artifacts not read yet. An artifact read first can never eat a later one's share; a share an
 * earlier artifact did not use (severity floor, dedup) goes to a later one, never past the cap.
 */
export function createSuperShareLedger(rows: readonly number[], cap: number): SuperShareLedger {
  const shares = superTimelineShares(rows, cap);
  let remaining = cap;
  let reserved = shares.reduce((a, b) => a + b, 0);
  return {
    limit(index) {
      reserved -= shares[index] ?? 0;
      return Math.max(0, remaining - reserved);
    },
    charge(added) {
      remaining -= Math.max(0, added);
    },
  };
}

export interface SuperOnlyDeps {
  bulkImportSink?: BulkImportSink;
  superTimelineStore: SuperTimelineStore;
  onSuperTimeline?: (caseId: string) => void;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<void>;
}

export interface SuperOnlyArtifact {
  caseId: string;
  huntId: string;
  name: string;
  json: string;
  rows: number;
  storedName: string;
  importedAt: string;
  minSeverity?: Severity;
  veloUrl?: string;
  partly?: string;
  /** This artifact's limit from the share ledger. */
  limit: number;
  /** The hunt's DFIR_SUPERTIMELINE_MAX, for the record. */
  cap: number;
}

export interface SuperOnlyResult {
  added: number;
  evicted?: SuperEviction;
  imported: boolean;
  /** Set when the share cut this artifact: kept/total rows, for the job and the inventory. */
  capped?: SuperCappedArtifact;
}

/**
 * Append one artifact's rows to the super-timeline ONLY (never the forensic timeline), up to its
 * share. The rows are already stored as evidence, so a cut loses nothing from the chain of custody.
 */
export async function importSuperOnlyArtifact(
  deps: SuperOnlyDeps,
  a: SuperOnlyArtifact,
): Promise<SuperOnlyResult> {
  const capped =
    a.limit < a.rows ? { name: a.name, kept: Math.max(0, a.limit), total: a.rows, cap: a.cap } : undefined;
  if (capped)
    logLine(
      `[velociraptor] hunt ${a.huntId}: ${a.name} — ${capped.kept} of ${a.rows} rows in the super-timeline; the shared cap (${a.cap}) was used up, the rest is stored as evidence only (raise DFIR_SUPERTIMELINE_MAX and collect again)`,
    );
  if (a.limit <= 0) return { added: 0, imported: false, capped };
  if (bulkPathApplies(deps.bulkImportSink, a.json)) {
    // A large artifact takes the batched driver (#1439): the same mapping, one batch at a time,
    // stopped at this artifact's share (#1982).
    const res = await runVelociraptorBulk(
      deps.bulkImportSink,
      a.caseId,
      a.json,
      {
        label: a.storedName,
        idPrefix: `${a.huntId}-${a.name}`,
        importedAt: a.importedAt,
        velociraptor: { artifact: a.name, partlyReadArtifact: a.partly },
        minSeverity: a.minSeverity,
        veloUrl: a.veloUrl,
        superMaxEvents: a.limit,
      },
      "super-only",
    );
    return res
      ? { added: res.superAppended, evicted: res.superEvicted, imported: true, capped }
      : { added: 0, imported: false, capped };
  }
  // Parse WITHOUT merging into forensic. Complete record: no aggregation, and the event cap is this
  // artifact's share, not the 2000-event forensic default.
  const parsed = parseVelociraptorJson(a.json, {
    artifact: a.name,
    aggregate: false,
    maxEvents: a.limit,
    partlyReadArtifact: a.partly,
  });
  const floored = applySeverityFloor(parsed.events, a.minSeverity); // the forensic path floors via importVelociraptor
  // Id by the HUNT id + ARTIFACT NAME: unique across artifacts and STABLE across re-collects — same
  // rows in the same order → same ids → deduped; a straggler that checks in later appends.
  const events: ForensicEvent[] = floored.map((e, i) => ({
    id: `${a.huntId}-${a.name}-e${i + 1}`,
    timestamp: e.timestamp,
    description: e.description,
    severity: e.severity,
    mitreTechniques: e.mitreTechniques ?? [],
    relatedFindingIds: [],
    sourceScreenshots: [a.storedName],
    ...(e.artifactName ? { artifactName: e.artifactName } : {}),
    ...(e.message ? { message: e.message } : {}),
    ...(a.veloUrl ? { veloUrl: a.veloUrl } : {}),
    ...(e.partlyReadArtifact ? { partlyReadArtifact: e.partlyReadArtifact } : {}),
    sources: e.sources?.length ? e.sources : ["Velociraptor"],
    ...(e.asset ? { asset: e.asset } : {}),
    ...(e.path ? { path: e.path } : {}),
    ...(e.sha256 ? { sha256: e.sha256 } : {}),
    ...(e.md5 ? { md5: e.md5 } : {}),
  }));
  const appended = await deps.superTimelineStore.appendReporting(a.caseId, events);
  getServerLogger().info(
    `[import] ${a.caseId} ${a.storedName}: done — super +${appended.retained} (super-only)`,
    { caseId: a.caseId },
  );
  deps.onSuperTimeline?.(a.caseId); // live dashboards refresh as super-only events stream in
  await deps.autoTagImported(a.caseId, events);
  return { added: appended.retained, evicted: appended.evicted, imported: true, capped };
}
