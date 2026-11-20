import { createHash } from "node:crypto";
import { huntFieldsOf } from "./huntArtifactFields.js";
import { buildHuntEntries, HUNT_ENTRY_PREFIX, rankGrades, type HuntGrade } from "./huntEntries.js";
import { huntCoverageFromJobs, type HuntCoverage } from "./huntFraming.js";
import { loadHuntJobsSafe, type HuntFramingStores } from "./huntFramingLoad.js";
import { gradeRarity } from "./huntGrade.js";
import { mergeGrades } from "./huntGradeBaseline.js";
import { buildHostKeyIndex, resolveHostKey, stableHostKey } from "./huntHostKey.js";
import { recordObservations, type HuntInventory, type InventoryObservation } from "./huntInventory.js";
import { GRADES_KEPT, type HuntInventoryStore } from "./huntInventoryStore.js";
import { raritySettingsFromEnv } from "./huntRarity.js";
import { isHuntType, type IncidentType } from "./incidentTypes.js";
import type { ForensicRow } from "./forensicRows.js";
import type { ForensicEvent, InvestigationState } from "./stateTypes.js";

/**
 * Hunt grading at the import seam (#2670). For a case in hunt mode only:
 *   1. record this import's own rows into the hunt inventory (host counts per program) — the rows are
 *      still here, Info included, because this runs BEFORE demote;
 *   2. grade the whole inventory (rarity here; baseline, policy, new-since-last-hunt and downloads
 *      through `extraGrades`, phase 5) against the coverage the hunts recorded;
 *   3. write ONE grouped entry per graded item into the forensic timeline, update the ones whose
 *      wording changed, and remove the summaries that no longer apply.
 *
 * It never reads the super-timeline and starts no AI. It never changes an imported row: detections
 * keep their own grade. An analyst-promoted summary is never removed.
 */
export interface HuntSettleStateStore {
  loadOverview(caseId: string): Promise<InvestigationState>;
  appendForensicEvents(caseId: string, events: readonly ForensicEvent[]): Promise<number>;
  forensicRowsById(caseId: string, ids: readonly string[]): Promise<ForensicRow[]>;
  updateForensicRows(caseId: string, rows: readonly ForensicRow[]): Promise<unknown>;
  deleteForensicRows(caseId: string, rowIds: readonly number[]): Promise<number>;
}

export interface ExtraGrades {
  grades: HuntGrade[];
  /** Item keys the baseline approves: they lose rare / new bumps (mergeGrades). */
  approved?: string[];
  /** Readable labels of the approved items, for the AI's hunt framing ("Approved by client"). */
  approvedLabels?: string[];
  /** Folded into the graded signature, so a baseline change re-grades. */
  signature: string;
  baselineVersion?: number;
}

export interface HuntSettleDeps extends HuntFramingStores {
  stateStore: HuntSettleStateStore;
  inventoryStore: HuntInventoryStore;
  serverSetId?: (caseId: string) => string | undefined;
  env?: NodeJS.ProcessEnv;
  now?: () => string;
  /** Phase 5: baseline / policy / new / download grades for this inventory. */
  extraGrades?: (input: {
    caseId: string;
    inventory: HuntInventory;
    coverage: HuntCoverage;
    answered: ReadonlySet<string>;
    /** The baseline version this case is pinned to; absent on its first grading. */
    pinnedVersion?: number;
    /** Re-grade with the CURRENT baseline (the analyst-pressed action), not the pinned one. */
    useCurrent: boolean;
  }) => Promise<ExtraGrades>;
}

export interface HuntSettleResult {
  changed: number;
  entries: number;
}

function observations(
  added: readonly ForensicEvent[],
  index: ReturnType<typeof buildHostKeyIndex>,
  renames: InvestigationState["hostRenames"],
): InventoryObservation[] {
  const out: InventoryObservation[] = [];
  for (const e of added) {
    if (e.id.startsWith(HUNT_ENTRY_PREFIX)) continue;
    const fields = huntFieldsOf(e);
    const host = fields ? resolveHostKey(index, fields.host, renames ?? []) : null;
    if (fields && host) out.push({ fields, host, at: e.timestamp });
  }
  return out;
}

const sameEntry = (a: ForensicEvent, b: ForensicEvent): boolean =>
  a.description === b.description && a.severity === b.severity && a.timestamp === b.timestamp;

/** Write the wanted summaries, update changed ones, remove stale ones (never an analyst-promoted one). */
export async function syncHuntEntries(
  store: HuntSettleStateStore,
  caseId: string,
  wanted: readonly ForensicEvent[],
  previousIds: readonly string[],
): Promise<number> {
  const wantedIds = new Set(wanted.map((e) => e.id));
  const rows = await store.forensicRowsById(caseId, [...new Set([...previousIds, ...wantedIds])]);
  const byId = new Map(rows.map((r) => [r.event.id, r]));
  const append = wanted.filter((e) => !byId.has(e.id));
  const update: ForensicRow[] = [];
  for (const e of wanted) {
    const cur = byId.get(e.id);
    if (cur && !sameEntry(cur.event, e)) update.push({ ...cur, event: { ...cur.event, ...e } });
  }
  const stale = rows.filter((r) => !wantedIds.has(r.event.id) && !r.event.promotedAt).map((r) => r.rowId);
  if (append.length) await store.appendForensicEvents(caseId, append);
  if (update.length) await store.updateForensicRows(caseId, update);
  if (stale.length) await store.deleteForensicRows(caseId, stale);
  return append.length + update.length + stale.length;
}

async function loadType(deps: HuntSettleDeps, caseId: string): Promise<IncidentType | null> {
  return (await deps.incidentTypeStore?.loadType(caseId).catch(() => null)) ?? null;
}

/** Grade one case at the seam. Returns 0 changes outside hunt mode. */
export async function huntSettle(
  deps: HuntSettleDeps,
  caseId: string,
  added: readonly ForensicEvent[],
  opts: { useCurrentBaseline?: boolean; replaceInventory?: HuntInventory } = {},
): Promise<HuntSettleResult> {
  if (!isHuntType(await loadType(deps, caseId))) return { changed: 0, entries: 0 };
  const now = (deps.now ?? (() => new Date().toISOString()))();
  const jobs = await loadHuntJobsSafe(deps, caseId);
  const server = deps.serverSetId?.(caseId) ?? "";
  const index = buildHostKeyIndex(jobs, server);
  const renames = (await deps.stateStore.loadOverview(caseId)).hostRenames;
  const obs = observations(added, index, renames);
  const coverage = huntCoverageFromJobs(jobs);
  const answered = new Set(
    coverage.known ? coverage.answeredHosts.map((h) => stableHostKey(server, h.clientId)) : [],
  );
  const rarity = raritySettingsFromEnv(deps.env);
  let result: HuntSettleResult = { changed: 0, entries: 0 };
  await deps.inventoryStore.update(caseId, async (rec) => {
    const inventory = recordObservations(opts.replaceInventory ?? rec.inventory, obs, now);
    const extra = deps.extraGrades
      ? await deps.extraGrades({
          caseId,
          inventory,
          coverage,
          answered,
          useCurrent: opts.useCurrentBaseline === true,
          ...(rec.baselineVersion !== undefined ? { pinnedVersion: rec.baselineVersion } : {}),
        })
      : null;
    const signature = createHash("sha1")
      .update(JSON.stringify([coverage, rarity, extra?.signature ?? "", Object.keys(inventory.items).length]))
      .digest("hex");
    if (!obs.length && !opts.replaceInventory && signature === rec.gradedSignature) {
      result = { changed: 0, entries: rec.entryIds.length };
      return rec;
    }
    const grades = mergeGrades(
      [...gradeRarity({ inventory, coverage, answered, rarity }), ...(extra?.grades ?? [])],
      new Set(extra?.approved ?? []),
    );
    const wanted = buildHuntEntries(grades, now);
    const changed = await syncHuntEntries(deps.stateStore, caseId, wanted, rec.entryIds);
    result = { changed, entries: wanted.length };
    return {
      inventory,
      entryIds: wanted.map((e) => e.id),
      grades: rankGrades(grades).slice(0, GRADES_KEPT),
      approvedLabels: (extra?.approvedLabels ?? []).slice(0, GRADES_KEPT),
      gradedSignature: signature,
      ...(extra?.baselineVersion !== undefined ? { baselineVersion: extra.baselineVersion } : {}),
    };
  });
  return result;
}
