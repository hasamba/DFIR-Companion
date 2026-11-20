import type { IncidentType } from "./incidentTypes.js";
import { isHuntType } from "./incidentTypes.js";
import { huntCoverageFromJobs, renderHuntFramingBlock } from "./huntFraming.js";
import type { VeloHuntJob } from "./veloHuntStore.js";

/**
 * Loads the hunt framing for one case (#2670): whether the case is in hunt mode, and the HUNT MODE
 * block with its coverage line. Shared by synthesis and Watson so both read the same words.
 * Fail-soft: an unreadable hunt record means "coverage unknown", never a failed AI call.
 */
export interface HuntFramingStores {
  incidentTypeStore?: { loadType(caseId: string): Promise<IncidentType | null> };
  veloHuntStore?: { list(caseId: string): Promise<VeloHuntJob[]> };
}

export interface HuntFraming {
  hunt: boolean;
  /** "" outside hunt mode. */
  block: string;
}

export async function loadHuntJobsSafe(stores: HuntFramingStores, caseId: string): Promise<VeloHuntJob[]> {
  try {
    return (await stores.veloHuntStore?.list(caseId)) ?? [];
  } catch {
    return [];
  }
}

export async function loadHuntFramingFor(
  stores: HuntFramingStores,
  caseId: string,
  type?: IncidentType | null,
): Promise<HuntFraming> {
  const resolved =
    type !== undefined
      ? type
      : ((await stores.incidentTypeStore?.loadType(caseId).catch(() => null)) ?? null);
  if (!isHuntType(resolved)) return { hunt: false, block: "" };
  const coverage = huntCoverageFromJobs(await loadHuntJobsSafe(stores, caseId));
  return { hunt: true, block: renderHuntFramingBlock(coverage) };
}
