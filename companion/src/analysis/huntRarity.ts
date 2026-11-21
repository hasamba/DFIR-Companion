import type { HuntCoverage } from "./huntFraming.js";
import type { InventoryFamily, InventoryItem } from "./huntInventory.js";

/**
 * Host rarity (#2670, decision D2). An item is RARE when, among the hosts that cleanly answered:
 *   - at least `minHosts` hosts answered (default 20) — on a 5-host client everything looks rare;
 *   - and it is on at most `maxPct` percent of them (default 5);
 *   - and on at most `maxHosts` hosts (default 10).
 * Integer maths only (n·100 ≤ pct·M), so a boundary never depends on float rounding.
 *
 * Absence is never assumed from incomplete coverage: with unknown coverage nothing is graded rare.
 * A partial artifact collection (cut short, unread source list, failed fetch) blocks rarity for every
 * item of a kind that artifact could report (#2732), not only the items it did report: the rows it
 * lost may belong to an item another, complete artifact reported (Prefetch and Amcache share one
 * program item), so that item's host count is a lower bound too. An artifact whose name is not one
 * of the known hunt artifacts could report any kind, so it blocks every item. An item whose artifacts
 * are not all known (stored before they were recorded, a row naming none, the list capped) is not
 * graded while any artifact is partial. Items of kinds no partial artifact reports keep their grading.
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

const ALL_FAMILIES: readonly InventoryFamily[] = ["program", "installed", "autorun", "download"];

/**
 * The item kinds an artifact's rows can become, by its name (the importer's artifact fast paths and
 * huntArtifactFields' evidence labels). Amcache is one artifact with two sources: present files
 * (program) and installed programs. An unknown name could be anything: every kind.
 */
const ARTIFACT_FAMILIES: readonly { re: RegExp; families: readonly InventoryFamily[] }[] = [
  { re: /amcache/, families: ["program", "installed"] },
  { re: /browserdownload|evidence.*download|zone\.?identifier/, families: ["download"] },
  { re: /startup|autorun|taskscheduler|services|persistencesniper/, families: ["autorun"] },
  { re: /prefetch|userassist|appcompatcache|shimcache/, families: ["program"] },
];

/** The kinds a (base-named) artifact could report; every kind when the name is not recognised. */
export function artifactFamilies(name: string): readonly InventoryFamily[] {
  const base = artifactBase(name);
  return ARTIFACT_FAMILIES.find((a) => a.re.test(base))?.families ?? ALL_FAMILIES;
}

/**
 * Could a partial artifact have reported this item (it reports items of this kind, #2732) — or did
 * one the hunts did not name report it (a row's own `_Source`/`Source` column can differ from the
 * job's artifact), or none at all, while any artifact is partial?
 * Fails closed: only an item whose every artifact is a collected, complete one is graded.
 */
export function itemArtifactPartial(
  item: Pick<InventoryItem, "family" | "artifacts" | "artifactsIncomplete">,
  coverage: { partialArtifactNames: readonly string[]; collectedArtifactNames: readonly string[] },
): boolean {
  if (!coverage.partialArtifactNames.length) return false;
  if (coverage.partialArtifactNames.some((a) => artifactFamilies(a).includes(item.family))) return true;
  if (!item.artifacts?.length || item.artifactsIncomplete) return true;
  const partial = new Set(coverage.partialArtifactNames.map(artifactBase));
  const collected = new Set(coverage.collectedArtifactNames.map(artifactBase));
  return item.artifacts.some((a) => partial.has(artifactBase(a)) || !collected.has(artifactBase(a)));
}

/**
 * Must rarity skip this item? A partial artifact could have reported it, or its host list overflowed
 * the cap (#2750: a capped merge drops host identities, so the retained count is only a lower bound).
 */
export function itemRarityUnsafe(
  item: Pick<InventoryItem, "family" | "artifacts" | "artifactsIncomplete" | "hostOverflow">,
  coverage: { partialArtifactNames: readonly string[]; collectedArtifactNames: readonly string[] },
): boolean {
  return (item.hostOverflow ?? 0) > 0 || itemArtifactPartial(item, coverage);
}

/** Is an item on `n` of `answered` answering hosts rare? Pure integer test. */
export function isRare(n: number, answered: number, s: RaritySettings): boolean {
  if (n < 1 || answered < s.minHosts) return false;
  return n * 100 <= s.maxPct * answered && n <= s.maxHosts;
}
