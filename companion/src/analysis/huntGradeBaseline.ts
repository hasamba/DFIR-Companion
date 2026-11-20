import type { Baseline } from "./clientProfile.js";
import { categoriesOf, domainUnder, urlHost, type DownloadCategories } from "./downloadCategories.js";
import type { HuntGrade } from "./huntEntries.js";
import { itemVerdict } from "./huntApprovalMatch.js";
import { itemHosts } from "./huntGrade.js";
import { itemLabel, type HuntInventory, type InventoryItem } from "./huntInventory.js";
import type { Severity } from "./stateTypes.js";

/**
 * Baseline and policy grading on later hunts (#2670, phase 5). Deterministic, no AI, no raw-record
 * read. PURE. Per inventory item, against the case's PINNED baseline version:
 *   - Not allowed  → a POLICY finding (DFIR_HUNT_POLICY_SEVERITY, default Medium). Labelled policy, not
 *     malicious. Not allowed wins over Approved.
 *   - Approved     → no hunt entry, and it removes the hunt-based bumps (rare / new). It never lowers a
 *     detection: imported rows are never regraded, so a detection on an approved tool still stands.
 *   - New since the last COMPARABLE hunt → only when a host the item is on now was ALSO answered cleanly
 *     in that hunt (absence is never assumed from incomplete coverage), and the item is not approved.
 *   - Downloads: the source URL's domain (subdomains included) against the client's blocked domains and
 *     blocked categories → policy finding; approved sources → nothing; anything else is Unknown, and a
 *     runnable or archive file from it is flagged. A download with no source URL is Unknown too.
 */
export interface PreviousHunt {
  caseId: string;
  at: string;
  itemKeys: ReadonlySet<string>;
  /** Stable keys of the hosts that answered that hunt cleanly. */
  answered: ReadonlySet<string>;
}

export interface BaselineGradeContext {
  inventory: HuntInventory;
  answered: ReadonlySet<string>;
  baseline: Baseline | null;
  baselineVersion?: number;
  previous: PreviousHunt | null;
  categories: DownloadCategories;
  policySeverity: Severity;
  now: string;
}

export interface BaselineGrades {
  grades: HuntGrade[];
  /** Items the baseline approves: no rare / new bump, and the AI is told they are approved. */
  approved: string[];
}

const RUNNABLE =
  /\.(?:exe|msi|msix|appx|scr|com|bat|cmd|ps1|vbs|js|jse|hta|lnk|dll|iso|img|vhdx?|zip|rar|7z|tar|gz|cab)$/i;

const SEVERITIES = new Set<Severity>(["Low", "Medium", "High", "Critical"]);

/** DFIR_HUNT_POLICY_SEVERITY (Low / Medium / High / Critical), default Medium. Never Info: it must reach the timeline. */
export function policySeverityFromEnv(env: NodeJS.ProcessEnv = process.env): Severity {
  const v = (env.DFIR_HUNT_POLICY_SEVERITY ?? "").trim();
  const norm = (v.charAt(0).toUpperCase() + v.slice(1).toLowerCase()) as Severity;
  return SEVERITIES.has(norm) ? norm : "Medium";
}

function grade(
  item: InventoryItem,
  ctx: BaselineGradeContext,
  kind: HuntGrade["kind"],
  severity: Severity,
  reason: string,
): HuntGrade {
  return {
    itemKey: item.key,
    kind,
    severity,
    label: itemLabel(item),
    reason,
    hosts: itemHosts(item, ctx.answered),
    firstSeen: item.firstSeen,
  };
}

function downloadGrade(item: InventoryItem, ctx: BaselineGradeContext): HuntGrade | null {
  const b = ctx.baseline;
  const runnable = RUNNABLE.test(item.program);
  const hosts = item.sourceUrls.map(urlHost).filter((h): h is string => !!h);
  for (const h of hosts) {
    const cats = categoriesOf(h, ctx.categories).filter((c) => b?.blockedCategories.includes(c));
    const blocked = b?.blockedDomains.find((d) => domainUnder(h, d));
    if (blocked || cats.length)
      return grade(
        item,
        ctx,
        "policy",
        ctx.policySeverity,
        `Policy: downloaded from ${h} — ${blocked ? `blocked site ${blocked}` : `blocked category ${cats.join(", ")}`} (category list ${ctx.categories.version}).`,
      );
  }
  if (hosts.length && hosts.every((h) => b?.approvedDomains.some((d) => domainUnder(h, d)))) return null;
  if (!runnable) return null;
  const where = hosts.length
    ? `from ${hosts.join(", ")}, outside the client's approved sources${hosts.some((h) => categoriesOf(h, ctx.categories).length) ? ` (category: ${hosts.flatMap((h) => categoriesOf(h, ctx.categories)).join(", ")})` : " (no known category: Unknown)"}`
    : "with no source URL recorded (Unknown)";
  return grade(item, ctx, "download", "Medium", `Runnable or archive file downloaded ${where}.`);
}

function isNew(item: InventoryItem, ctx: BaselineGradeContext): boolean {
  const p = ctx.previous;
  if (!p || p.itemKeys.has(item.key)) return false;
  return Object.keys(item.hosts).some((k) => p.answered.has(k) && ctx.answered.has(k));
}

export function gradeBaseline(ctx: BaselineGradeContext): BaselineGrades {
  const grades: HuntGrade[] = [];
  const approved: string[] = [];
  const v = ctx.baselineVersion !== undefined ? ` (baseline v${ctx.baselineVersion})` : "";
  for (const item of Object.values(ctx.inventory.items)) {
    const verdict = ctx.baseline
      ? itemVerdict(ctx.baseline, item, ctx.now)
      : { verdict: "unknown" as const, reason: "" };
    if (verdict.verdict === "not-allowed") {
      grades.push(
        grade(
          item,
          ctx,
          "policy",
          ctx.policySeverity,
          `Policy: not allowed by the client${v}. A policy violation, not proof of malicious activity.`,
        ),
      );
      continue;
    }
    if (verdict.verdict === "approved") {
      approved.push(item.key);
      continue;
    }
    const dl = item.family === "download" ? downloadGrade(item, ctx) : null;
    if (dl) grades.push(dl);
    if (isNew(item, ctx))
      grades.push(
        grade(
          item,
          ctx,
          "new",
          "Medium",
          `New: not in the reviewed baseline and not seen in the last comparable hunt (${ctx.previous!.at.slice(0, 10)}) on hosts that answered both.`,
        ),
      );
  }
  return { grades, approved };
}

const PRIORITY: Record<HuntGrade["kind"], number> = { policy: 0, download: 1, new: 2, rare: 3 };

/** One entry per item: policy beats download beats new beats rare; approved items lose rare / new. */
export function mergeGrades(all: readonly HuntGrade[], approved: ReadonlySet<string>): HuntGrade[] {
  const best = new Map<string, HuntGrade>();
  for (const g of all) {
    if (approved.has(g.itemKey) && (g.kind === "rare" || g.kind === "new")) continue;
    const cur = best.get(g.itemKey);
    if (!cur || PRIORITY[g.kind] < PRIORITY[cur.kind]) best.set(g.itemKey, g);
  }
  return [...best.values()];
}
