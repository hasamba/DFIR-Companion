import { createHash } from "node:crypto";
import { baselineAt } from "../analysis/clientProfile.js";
import type { ClientProfileStore } from "../analysis/clientProfileStore.js";
import { loadDownloadCategories } from "../analysis/downloadCategories.js";
import type { HuntClientLinkStore } from "../analysis/huntClientLink.js";
import { huntCoverageFromJobs } from "../analysis/huntFraming.js";
import { gradeBaseline, policySeverityFromEnv, type PreviousHunt } from "../analysis/huntGradeBaseline.js";
import { stableHostKey } from "../analysis/huntHostKey.js";
import { itemLabel } from "../analysis/huntInventory.js";
import type { HuntInventoryStore } from "../analysis/huntInventoryStore.js";
import type { ExtraGrades, HuntSettleDeps } from "../analysis/huntSettle.js";
import type { VeloHuntJob } from "../analysis/veloHuntStore.js";
import { confirmCandidates } from "../analysis/huntConfirmList.js";
import type { HuntReportPending } from "../analysis/huntReport.js";

/**
 * The phase-5 grader's inputs (#2670): the case's client, its PINNED baseline version (or the current
 * one for an analyst-pressed re-grade), and the LAST COMPARABLE hunt for that client — another hunt
 * case linked to the same client that ran an overlapping bundle over mostly the same answering hosts,
 * collected before this one. Only that case's derived inventory (item keys, answering hosts) is read,
 * never its raw record, and nothing of it is written into this case but counts and a date. Only the
 * cases `peerCaseIds` allows are read — never a password-protected one, never one outside this case's
 * audience (composition/huntPeerCases.ts says why it cannot be a per-request filter).
 */
export interface BaselineGradeDeps {
  links: Pick<HuntClientLinkStore, "load">;
  profiles: Pick<ClientProfileStore, "get">;
  inventories: Pick<HuntInventoryStore, "load">;
  huntJobs: (caseId: string) => Promise<VeloHuntJob[]>;
  /** The other cases allowed to feed this case's persisted output (composition/huntPeerCases.ts). */
  peerCaseIds: (caseId: string) => Promise<string[]>;
  serverSetId: (caseId: string) => string | undefined;
  env?: NodeJS.ProcessEnv;
  now?: () => string;
}

const MIN_HOST_OVERLAP = 0.5;

const answeredOf = (jobs: readonly VeloHuntJob[], server: string): Set<string> => {
  const c = huntCoverageFromJobs(jobs);
  return new Set(c.known ? c.answeredHosts.map((h) => stableHostKey(server, h.clientId)) : []);
};

const latest = (jobs: readonly VeloHuntJob[]): string =>
  jobs
    .map((j) => j.launchedAt)
    .sort()
    .at(-1) ?? "";

export async function previousComparableHunt(
  d: BaselineGradeDeps,
  caseId: string,
  clientId: string,
  answered: ReadonlySet<string>,
): Promise<PreviousHunt | null> {
  const mine = await d.huntJobs(caseId);
  const bundles = new Set(mine.map((j) => j.bundleId));
  const myLatest = latest(mine);
  if (!bundles.size || !answered.size) return null;
  let best: PreviousHunt | null = null;
  for (const other of await d.peerCaseIds(caseId)) {
    if (other === caseId || (await d.links.load(other).catch(() => null))?.clientId !== clientId) continue;
    const jobs = await d.huntJobs(other).catch(() => []);
    const at = latest(jobs);
    if (!jobs.some((j) => bundles.has(j.bundleId)) || !at || at >= myLatest) continue;
    const theirs = answeredOf(jobs, d.serverSetId(other) ?? "");
    const overlap = [...answered].filter((k) => theirs.has(k)).length;
    if (overlap < answered.size * MIN_HOST_OVERLAP) continue;
    if (best && best.at >= at) continue;
    const rec = await d.inventories.load(other).catch(() => null);
    if (!rec || !Object.keys(rec.inventory.items).length) continue;
    best = { caseId: other, at, itemKeys: new Set(Object.keys(rec.inventory.items)), answered: theirs };
  }
  return best;
}

export function baselineGradesProvider(d: BaselineGradeDeps): NonNullable<HuntSettleDeps["extraGrades"]> {
  return async (input): Promise<ExtraGrades> => {
    const link = await d.links.load(input.caseId);
    const profile = link ? await d.profiles.get(link.clientId) : null;
    if (!link || !profile) return { grades: [], signature: link ? "missing-profile" : "no-client" };
    const version =
      input.useCurrent || input.pinnedVersion === undefined ? profile.version : input.pinnedVersion;
    const baseline = baselineAt(profile, version) ?? (version === profile.version ? profile.baseline : null);
    const previous = await previousComparableHunt(d, input.caseId, profile.id, input.answered);
    const categories = loadDownloadCategories();
    const policySeverity = policySeverityFromEnv(d.env);
    const r = gradeBaseline({
      inventory: input.inventory,
      answered: input.answered,
      baseline,
      baselineVersion: version,
      previous,
      categories,
      policySeverity,
      now: (d.now ?? (() => new Date().toISOString()))(),
    });
    const signature = createHash("sha1")
      .update(
        JSON.stringify([
          profile.id,
          version,
          baseline ? 1 : 0,
          previous?.caseId,
          previous?.at,
          categories.version,
          policySeverity,
        ]),
      )
      .digest("hex");
    return {
      grades: r.grades,
      approved: r.approved,
      approvedLabels: r.approved
        .map((k) => input.inventory.items[k])
        .filter(Boolean)
        .map(itemLabel),
      signature,
      baselineVersion: version,
    };
  };
}

/** The report's comparison with the last comparable hunt: its date and item keys, or null. */
export function huntComparisonSource(d: BaselineGradeDeps) {
  return async (caseId: string): Promise<{ at: string; itemKeys: ReadonlySet<string> } | null> => {
    const link = await d.links.load(caseId).catch(() => null);
    if (!link) return null;
    const answered = answeredOf(await d.huntJobs(caseId), d.serverSetId(caseId) ?? "");
    const prev = await previousComparableHunt(d, caseId, link.clientId, answered);
    return prev ? { at: prev.at, itemKeys: prev.itemKeys } : null;
  };
}

const PENDING_REPORTED = 200;

/**
 * Items still waiting for the client's answer, with their age across this client's hunts (#2670):
 * an Unknown item never goes quiet — it is listed in every hunt report, with how many hunts it has
 * stayed unconfirmed for, even after it stops being "new". Counts and dates only cross cases.
 */
export function huntPendingSource(d: BaselineGradeDeps) {
  return async (caseId: string): Promise<HuntReportPending[]> => {
    const link = await d.links.load(caseId).catch(() => null);
    const profile = link ? await d.profiles.get(link.clientId).catch(() => null) : null;
    const rec = await d.inventories.load(caseId).catch(() => null);
    if (!profile || !rec) return [];
    const answered = answeredOf(await d.huntJobs(caseId), d.serverSetId(caseId) ?? "");
    const list = confirmCandidates(rec.inventory, profile.baseline, answered, new Date().toISOString());
    const age = new Map<string, { hunts: number; first: string }>();
    for (const other of await d.peerCaseIds(caseId)) {
      if (other === caseId || (await d.links.load(other).catch(() => null))?.clientId !== profile.id)
        continue;
      const inv = (await d.inventories.load(other).catch(() => null))?.inventory;
      for (const c of list) {
        const item = inv?.items[c.key];
        if (!item) continue;
        const cur = age.get(c.key) ?? { hunts: 0, first: c.firstSeen };
        age.set(c.key, {
          hunts: cur.hunts + 1,
          first: item.firstSeen < cur.first ? item.firstSeen : cur.first,
        });
      }
    }
    return list.slice(0, PENDING_REPORTED).map((c) => ({
      label: c.label,
      hostCount: c.hostCount,
      firstSeen: (age.get(c.key)?.first ?? c.firstSeen).slice(0, 10),
      huntsUnconfirmed: 1 + (age.get(c.key)?.hunts ?? 0),
    }));
  };
}
