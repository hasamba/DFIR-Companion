import { huntCoverageFromJobs } from "./huntFraming.js";
import { loadHuntJobsSafe, type HuntFramingStores } from "./huntFramingLoad.js";
import { isHuntType } from "./incidentTypes.js";
import { reportItemOf, type HuntReportData } from "./huntReport.js";
import type { HuntInventoryRecord } from "./huntInventoryStore.js";

/**
 * Assembles the Threat hunt summary's data for one case (#2670). null when the case is not in hunt
 * mode — the report section then says so. Reads only the case's own hunt records; earlier-hunt data
 * (the comparison) is added by the caller only for cases the reader may open.
 */
export interface HuntReportStores extends HuntFramingStores {
  huntInventoryStore?: { load(caseId: string): Promise<HuntInventoryRecord> };
}

export async function loadHuntReportData(
  stores: HuntReportStores,
  caseId: string,
): Promise<HuntReportData | null> {
  const type = (await stores.incidentTypeStore?.loadType(caseId).catch(() => null)) ?? null;
  if (!isHuntType(type)) return null;
  const jobs = await loadHuntJobsSafe(stores, caseId);
  const rec = await stores.huntInventoryStore?.load(caseId).catch(() => null);
  return {
    coverage: huntCoverageFromJobs(jobs),
    hunts: jobs.map((j) => ({
      huntId: j.huntId,
      bundleName: j.bundleName,
      launchedAt: j.launchedAt,
      status: j.status,
    })),
    items: (rec?.grades ?? []).map(reportItemOf),
    ...(rec?.baselineVersion !== undefined ? { baselineVersion: rec.baselineVersion } : {}),
    pending: [],
    comparison: null,
  };
}
