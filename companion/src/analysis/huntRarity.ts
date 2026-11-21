import type { HuntCoverage } from "./huntFraming.js";
import type { InventoryItem } from "./huntInventory.js";

/**
 * Host rarity (#2670, decision D2). An item is RARE when, among the hosts that cleanly answered:
 *   - at least `minHosts` hosts answered (default 20) — on a 5-host client everything looks rare;
 *   - and it is on at most `maxPct` percent of them (default 5);
 *   - and on at most `maxHosts` hosts (default 10).
 * Integer maths only (n·100 ≤ pct·M), so a boundary never depends on float rounding.
 *
 * Absence is never assumed from incomplete coverage: with unknown coverage nothing is graded rare.
 * A partial artifact collection (cut short, unread source list, failed fetch) blocks rarity only for
 * the items that artifact reported (#2732): their host count is a lower bound. An item whose artifacts
 * are not all known (stored before they were recorded, a row naming none, the list capped) is not
 * graded while any artifact is partial. Items from complete artifacts keep their grading.
 */
export interface RaritySettings {
  minHosts: number;
  maxPct: number;
  maxHosts: number;
}

export const DEFAULT_RARITY: RaritySettings = { minHosts: 20, maxPct: 5, maxHosts: 10 };

function intSetting(raw: string | undefined, fallback: number, min: number, max: number): number {
  const n = Number(raw);
  return Number.isInteger(n) && n >= min && n <= max ? n : fallback;
}

/** DFIR_HUNT_RARE_MIN_HOSTS / _MAX_PCT / _MAX_HOSTS, read per call so a Settings change applies at once. */
export function raritySettingsFromEnv(env: NodeJS.ProcessEnv = process.env): RaritySettings {
  return {
    minHosts: intSetting(env.DFIR_HUNT_RARE_MIN_HOSTS, DEFAULT_RARITY.minHosts, 1, 1_000_000),
    maxPct: intSetting(env.DFIR_HUNT_RARE_MAX_PCT, DEFAULT_RARITY.maxPct, 1, 100),
    maxHosts: intSetting(env.DFIR_HUNT_RARE_MAX_HOSTS, DEFAULT_RARITY.maxHosts, 1, 1_000_000),
  };
}

/** Why rarity grading is off for this coverage, or null when it may grade. */
export function rarityBlocked(c: HuntCoverage, s: RaritySettings): string | null {
  if (!c.known) return "coverage unknown";
  if (c.answered < s.minHosts) return `only ${c.answered} host(s) answered (rarity needs ${s.minHosts})`;
  return null;
}

/** `Windows.X/Source` → `windows.x`: a job names the artifact, a row may name its source too. */
const artifactBase = (name: string): string => name.split("/")[0].trim().toLowerCase();

/**
 * Did a partial artifact report this item — or, while any artifact is partial, one the hunts did not
 * name (a row's own `_Source`/`Source` column can differ from the job's artifact) or none at all?
 * Fails closed: only an item whose every artifact is a collected, complete one is graded.
 */
export function itemArtifactPartial(
  item: Pick<InventoryItem, "artifacts" | "artifactsIncomplete">,
  coverage: { partialArtifactNames: readonly string[]; collectedArtifactNames: readonly string[] },
): boolean {
  if (!coverage.partialArtifactNames.length) return false;
  if (!item.artifacts?.length || item.artifactsIncomplete) return true;
  const partial = new Set(coverage.partialArtifactNames.map(artifactBase));
  const collected = new Set(coverage.collectedArtifactNames.map(artifactBase));
  return item.artifacts.some((a) => partial.has(artifactBase(a)) || !collected.has(artifactBase(a)));
}

/** Is an item on `n` of `answered` answering hosts rare? Pure integer test. */
export function isRare(n: number, answered: number, s: RaritySettings): boolean {
  if (n < 1 || answered < s.minHosts) return false;
  return n * 100 <= s.maxPct * answered && n <= s.maxHosts;
}
