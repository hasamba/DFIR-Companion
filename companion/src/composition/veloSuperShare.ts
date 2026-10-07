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
//
// The split is in ROWS, the cut is measured in mapped EVENTS. Rows are the only count known before
// the loop: an event count needs the mapping, and mapping a full MFT twice (once to count) doubles
// the slowest step of the collect. So a row-based share is the allocation, the ledger charges the
// events each artifact actually offered (slack flows on), and whether an artifact lost anything is
// decided from its own mapping result, in events — a row of MFT can map to up to eight.

import { createHash } from "node:crypto";
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
  /** Charge the events the artifact offered, so slack it left goes to a later artifact. */
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
  /** Read-scope tag (#1993): a re-read that keeps different rows must not reuse the old ids. */
  scopeTag?: string;
}

/**
 * Short id tag for how a capped read chose its rows (#1993). Empty for a plain read, so existing ids
 * and plain re-collects are unchanged; a window hashes its bounds; newest-first is "nw".
 */
export function scopeTagOf(
  rec: { name?: string; windowStart?: string; windowEnd?: string; order?: string } | undefined,
): string {
  if (rec?.order === "newest") return "nw";
  if (!rec?.windowStart && !rec?.windowEnd) return "";
  const bounds = `${rec.windowStart ?? ""}|${rec.windowEnd ?? ""}`;
  return createHash("sha256").update(bounds).digest("hex").slice(0, 8);
}

export interface SuperOnlyResult {
  /** New rows the super-timeline retained (a re-collect's dedup makes this 0). */
  added: number;
  /** Mapped events offered to the super-timeline: written, or already there from an earlier collect. */
  offered: number;
  evicted?: SuperEviction;
  imported: boolean;
  /** Set when the share cut this artifact's mapped events, for the job and the inventory. */
  capped?: SuperCappedArtifact;
}

/**
 * The cut, decided AFTER mapping (#1982 review): one MFT row maps to up to eight events, so a limit
 * equal to the row count can still lose most of an artifact. Counted in mapped events — offered vs
 * produced — never the allocated limit, and never as retained rows.
 */
function cutRecord(a: SuperOnlyArtifact, mapped: number, offered: number): SuperCappedArtifact | undefined {
  if (offered >= mapped) return undefined;
  logLine(
    `[velociraptor] hunt ${a.huntId}: ${a.name} — ${offered} of ${mapped} mapped events (from ${a.rows} rows) in the super-timeline; the shared cap (${a.cap}) was used up, the rest is stored as evidence only (raise DFIR_SUPERTIMELINE_MAX and collect again)`,
  );
  return { name: a.name, kept: offered, total: mapped, rows: a.rows, cap: a.cap };
}

/**
 * Append one artifact's rows to the super-timeline ONLY (never the forensic timeline), up to its
 * share. The rows are already stored as evidence, so a cut loses nothing from the chain of custody.
 * A share of zero still maps the artifact, so its record can say how much was lost.
 */
export async function importSuperOnlyArtifact(
  deps: SuperOnlyDeps,
  a: SuperOnlyArtifact,
): Promise<SuperOnlyResult> {
  const limit = Math.max(0, a.limit);
  const idBase = `${a.huntId}-${a.name}${a.scopeTag ? `~${a.scopeTag}` : ""}`;
  if (bulkPathApplies(deps.bulkImportSink, a.json)) {
    // A large artifact takes the batched driver (#1439): the same mapping, one batch at a time,
    // stopped at this artifact's share (#1982). `events` counts every mapped event after the floor,
    // and the driver offers the first `limit` of them.
    const res = await runVelociraptorBulk(
      deps.bulkImportSink,
      a.caseId,
      a.json,
      {
        label: a.storedName,
        idPrefix: idBase,
        importedAt: a.importedAt,
        velociraptor: { artifact: a.name, partlyReadArtifact: a.partly },
        minSeverity: a.minSeverity,
        veloUrl: a.veloUrl,
        superMaxEvents: limit,
      },
      "super-only",
    );
    if (!res) return { added: 0, offered: 0, imported: false };
    const offered = Math.min(limit, res.events);
    return {
      added: res.superAppended,
      offered,
      evicted: res.superEvicted,
      imported: true,
      capped: cutRecord(a, res.events, offered),
    };
  }
  // Parse WITHOUT merging into forensic. Complete record: no aggregation and no event cap here, so
  // the cut below can count what was lost; the parse path only sees inputs under the bulk threshold.
  const parsed = parseVelociraptorJson(a.json, {
    artifact: a.name,
    aggregate: false,
    maxEvents: Number.MAX_SAFE_INTEGER,
    partlyReadArtifact: a.partly,
  });
  const mapped = applySeverityFloor(parsed.events, a.minSeverity); // the forensic path floors via importVelociraptor
  const floored = mapped.slice(0, limit);
  const capped = cutRecord(a, mapped.length, floored.length);
  if (!floored.length) return { added: 0, offered: 0, imported: false, capped };
  // Id by the HUNT id + ARTIFACT NAME: unique across artifacts and STABLE across re-collects — same
  // rows in the same order → same ids → deduped; a straggler that checks in later appends.
  const events: ForensicEvent[] = floored.map((e, i) => ({
    id: `${idBase}-e${i + 1}`,
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
  return {
    added: appended.retained,
    offered: events.length,
    evicted: appended.evicted,
    imported: true,
    capped,
  };
}
