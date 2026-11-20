import { huntCoverageFromJobs } from "./huntFraming.js";
import { loadHuntJobsSafe, type HuntFramingStores } from "./huntFramingLoad.js";
import { isHuntType } from "./incidentTypes.js";
import {
  reportItemOf,
  type HuntReportComparison,
  type HuntReportData,
  type HuntReportPending,
} from "./huntReport.js";
import type { HuntInventoryRecord } from "./huntInventoryStore.js";

/**
 * Assembles the Threat hunt summary's data for one case (#2670). null when the case is not in hunt
 * mode — the report section then says so. Reads only the case's own hunt records; earlier-hunt data
 * (the comparison) is added by the caller only for cases the reader may open.
 */
export interface HuntReportStores extends Omit<HuntFramingStores, "huntInventoryStore"> {
  huntInventoryStore?: { load(caseId: string): Promise<HuntInventoryRecord> };
  huntClientLinkStore?: { load(caseId: string): Promise<{ clientId: string } | null> };
  clientProfileStore?: { get(id: string): Promise<{ name: string } | null> };
  /** The last comparable hunt for the case's client (composition/huntBaselineGrades.ts). */
  previousHunt?: (caseId: string) => Promise<{ at: string; itemKeys: ReadonlySet<string> } | null>;
  /** Items still waiting for the client, with their age across hunts (composition). */
  pending?: (caseId: string) => Promise<HuntReportPending[]>;
}

export async function loadHuntReportData(
  stores: HuntReportStores,
  caseId: string,
): Promise<HuntReportData | null> {
  const type = (await stores.incidentTypeStore?.loadType(caseId).catch(() => null)) ?? null;
  if (!isHuntType(type)) return null;
  const jobs = await loadHuntJobsSafe(stores, caseId);
  const rec = await stores.huntInventoryStore?.load(caseId).catch(() => null);
  const link = await stores.huntClientLinkStore?.load(caseId).catch(() => null);
  const profile = link ? await stores.clientProfileStore?.get(link.clientId).catch(() => null) : null;
  return {
    ...(profile ? { clientName: profile.name } : {}),
    coverage: huntCoverageFromJobs(jobs),
    hunts: jobs.map((j) => ({
      huntId: j.huntId,
      bundleName: j.bundleName,
      launchedAt: j.launchedAt,
      status: j.status,
    })),
    items: (rec?.grades ?? []).map(reportItemOf),
    ...(rec?.baselineVersion !== undefined ? { baselineVersion: rec.baselineVersion } : {}),
    pending: (await stores.pending?.(caseId).catch(() => [])) ?? [],
    comparison: await comparisonOf(stores, caseId, rec),
  };
}

async function comparisonOf(
  stores: HuntReportStores,
  caseId: string,
  rec: HuntInventoryRecord | null | undefined,
): Promise<HuntReportComparison | null> {
  const prev = await stores.previousHunt?.(caseId).catch(() => null);
  if (!prev || !rec) return null;
  const now = new Set(Object.keys(rec.inventory.items));
  return {
    previousCaseId: "",
    previousAt: prev.at,
    newItems: rec.grades.filter((g) => g.kind === "new").length,
    goneItems: [...prev.itemKeys].filter((k) => !now.has(k)).length,
  };
}
