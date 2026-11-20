import type { HuntCoverage } from "./huntFraming.js";
import type { HuntGrade } from "./huntEntries.js";
import { answeringHostCount, itemLabel, type HuntInventory, type InventoryItem } from "./huntInventory.js";
import { isRare, rarityBlocked, type RaritySettings } from "./huntRarity.js";
import type { Severity } from "./stateTypes.js";

/**
 * Deterministic hunt grading (#2670): from the inventory recorded at import, which items become a
 * grouped forensic-timeline entry, and why. No AI, no raw-record read. PURE.
 *
 * Phase 3 grades RARITY only; the baseline / policy / "new since last hunt" / download rules join in
 * huntGradeBaseline.ts. Grading never touches a detection's own row: it only ADDS summary entries.
 */
export interface GradeContext {
  inventory: HuntInventory;
  coverage: HuntCoverage;
  /** Stable client keys of the hosts that answered cleanly. */
  answered: ReadonlySet<string>;
  rarity: RaritySettings;
  rareSeverity?: Severity;
}

export const RARE_SEVERITY: Severity = "Medium";

/** Hostnames of an item, answering hosts first, stable order. */
export function itemHosts(item: InventoryItem, answered: ReadonlySet<string>): string[] {
  const entries = Object.entries(item.hosts);
  const first = entries.filter(([k]) => answered.has(k));
  const rest = entries.filter(([k]) => !answered.has(k));
  return [...first, ...rest].map(([, h]) => h.hostname).sort((a, b) => a.localeCompare(b));
}

function rareGrade(item: InventoryItem, ctx: GradeContext, n: number, m: number): HuntGrade {
  const evidence = item.evidence.join("/");
  return {
    itemKey: item.key,
    kind: "rare",
    severity: ctx.rareSeverity ?? RARE_SEVERITY,
    label: itemLabel(item),
    reason: `Rare: on ${n} of ${m} hosts that answered cleanly (rule: at most ${ctx.rarity.maxPct}% and at most ${ctx.rarity.maxHosts} hosts). Evidence: ${evidence}.`,
    hosts: itemHosts(item, ctx.answered),
    ofHosts: m,
    firstSeen: item.firstSeen,
  };
}

/** Rare grades for the whole inventory; [] when coverage does not allow rarity. */
export function gradeRarity(ctx: GradeContext): HuntGrade[] {
  if (rarityBlocked(ctx.coverage, ctx.rarity) || !ctx.coverage.known) return [];
  const m = ctx.coverage.answered;
  const out: HuntGrade[] = [];
  for (const item of Object.values(ctx.inventory.items)) {
    const n = answeringHostCount(item, ctx.answered);
    if (isRare(n, m, ctx.rarity)) out.push(rareGrade(item, ctx, n, m));
  }
  return out;
}
