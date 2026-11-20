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
  /** The hunt inventory record: the labels of the items the client's baseline approves. */
  huntInventoryStore?: { load(caseId: string): Promise<{ approvedLabels: string[] }> };
}

/** At most this many approved items are named to the model; the rest are counted. */
export const APPROVED_LISTED = 40;

/**
 * "Approved by client" travels into the AI's view (#2670): the approved programs are named so the model
 * ranks expected use low and only unusual use (new host, odd path, odd time) as an anomaly. Program and
 * path labels only — never the client's name, notes or audit text.
 */
export function renderApprovedBlock(labels: readonly string[]): string {
  if (!labels.length) return "";
  const shown = labels.slice(0, APPROVED_LISTED);
  const more = labels.length - shown.length;
  return (
    `APPROVED BY CLIENT (the client's reviewed baseline; a detection on these still stands): ${shown.join("; ")}` +
    `${more > 0 ? ` (+${more} more)` : ""}\n\n`
  );
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
  const approved = (await stores.huntInventoryStore?.load(caseId).catch(() => null))?.approvedLabels ?? [];
  return { hunt: true, block: renderHuntFramingBlock(coverage) + renderApprovedBlock(approved) };
}
