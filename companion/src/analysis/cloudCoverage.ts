import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";

// Per-upload cloud coverage (#931 item 14, coverage half, part B — #1063): what one CloudTrail /
// GCP / Azure / M365 / Google Workspace upload states about itself — record count, first → last,
// the categories present — kept OUTSIDE the forensic timeline (a side file, read-time only, never
// part of InvestigationState) so this never floods the timeline or the AI context the way one Low
// row per scope per upload would. Absence is never silence: a category the export never carries
// is said as a stated limitation (`cloudCoverageForCase`, read-time, comparing every upload of one
// provider in the case against that provider's documented category list), never inferred as
// "nothing happened" or "not configured".
//
// What one record never says: a caveat of its own (caveats are computed at read time, across every
// upload of a provider in the case — a single upload cannot know what another upload established);
// an effective configuration (a documented category's absence is stated, never explained); a
// record any importer did not itself decode (this store is filled by the SAME parse functions that
// already emit the per-event rows, never a second read of the raw upload).

export const cloudCoverageProviders = ["aws-cloudtrail", "gcp", "azure", "m365", "google-workspace"] as const;
export type CloudCoverageProvider = (typeof cloudCoverageProviders)[number];

export const SCOPES_PER_UPLOAD_MAX = 256;
export const UPLOADS_TRACKED_PER_CASE_MAX = 200;
const SCOPE_VALUE_MAX = 200;
const CATEGORY_NAME_MAX = 120;
const CATEGORIES_PER_SCOPE_MAX = 64;
const RECORD_TYPE_IDS_MAX = 64;

export const cloudCoverageCategorySchema = z.object({
  name: z.string().max(CATEGORY_NAME_MAX),
  count: z.number().int().nonnegative(),
  /** AWS CloudTrail only: Management/Data categories carry a read-only tri-state count. */
  readOnly: z
    .object({
      true: z.number().int().nonnegative(),
      false: z.number().int().nonnegative(),
      unknown: z.number().int().nonnegative(),
    })
    .optional(),
  /** M365 only: the numeric RecordType values folded into this Workload/Operation category, kept as a fact, never used as the category label. */
  recordTypeIds: z.array(z.number().int()).max(RECORD_TYPE_IDS_MAX).optional(),
});
export type CloudCoverageCategory = z.infer<typeof cloudCoverageCategorySchema>;

export const cloudCoverageRecordSchema = z.object({
  provider: z.enum(cloudCoverageProviders),
  scope: z.object({ kind: z.string().max(40), value: z.string().max(SCOPE_VALUE_MAX) }),
  uploadId: z.string().min(1),
  /** Set once, when this upload id is first recorded; never refreshed by a later re-import of the same upload. Drives eviction age. */
  uploadFirstSeenAt: z.string().min(1),
  recordCount: z.number().int().nonnegative(),
  first: z.string(),
  last: z.string(),
  categories: z.array(cloudCoverageCategorySchema).max(CATEGORIES_PER_SCOPE_MAX),
  importedAt: z.string().min(1),
});
export type CloudCoverageRecord = z.infer<typeof cloudCoverageRecordSchema>;
const fileSchema = z.array(cloudCoverageRecordSchema);

/** A record before the store assigns `uploadFirstSeenAt` and `importedAt`. */
export type CloudCoverageDraft = Omit<CloudCoverageRecord, "uploadFirstSeenAt" | "importedAt">;

const groupKey = (provider: string, uploadId: string): string => `${provider}|${uploadId}`;

const lock = new StateLock();

export class CloudCoverageStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "cloud-coverage.json");
  }

  async load(caseId: string): Promise<CloudCoverageRecord[]> {
    try {
      return fileSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  /**
   * Record coverage drafts, grouped internally by `(provider, uploadId)` — a single call may
   * span more than one group (a mixed GCP+Azure upload produces two). Each group replaces any
   * existing records of the SAME upload id in place, preserving that upload's original
   * `uploadFirstSeenAt` rather than resetting its eviction age. A brand-new group, once the case
   * is past the tracked-uploads bound, evicts the single oldest group's ENTIRE record set
   * atomically — never a partial upload left behind, and never triggered by re-importing an
   * upload already tracked.
   */
  async record(
    caseId: string,
    drafts: readonly CloudCoverageDraft[],
    at: string = new Date().toISOString(),
  ): Promise<CloudCoverageRecord[]> {
    return lock.runExclusive(caseId, async () => {
      let next = await this.load(caseId);
      const byGroup = new Map<string, CloudCoverageDraft[]>();
      for (const d of drafts) {
        const k = groupKey(d.provider, d.uploadId);
        (byGroup.get(k) ?? byGroup.set(k, []).get(k)!).push(d);
      }
      for (const [key, groupDrafts] of byGroup) {
        const existingOfThisUpload = next.filter((r) => groupKey(r.provider, r.uploadId) === key);
        const firstSeenAt = existingOfThisUpload.length
          ? existingOfThisUpload.reduce(
              (min, r) => (r.uploadFirstSeenAt < min ? r.uploadFirstSeenAt : min),
              existingOfThisUpload[0].uploadFirstSeenAt,
            )
          : at;
        const capped = groupDrafts.slice(0, SCOPES_PER_UPLOAD_MAX);
        const fresh: CloudCoverageRecord[] = capped.map((d) => ({
          ...d,
          uploadFirstSeenAt: firstSeenAt,
          importedAt: at,
        }));
        // Replace this group's own records; every other group's records are untouched.
        next = [...next.filter((r) => groupKey(r.provider, r.uploadId) !== key), ...fresh];
      }

      // Evict the oldest tracked group(s), atomically, only as far as needed — re-recording an
      // already-tracked group never adds one, so this only fires for a genuinely NEW group.
      while (true) {
        const groups = new Map<string, string>(); // key -> firstSeenAt
        for (const r of next) {
          const k = groupKey(r.provider, r.uploadId);
          if (!groups.has(k)) groups.set(k, r.uploadFirstSeenAt);
        }
        if (groups.size <= UPLOADS_TRACKED_PER_CASE_MAX) break;
        const oldestKey = [...groups.entries()].sort(
          (a, b) => a[1].localeCompare(b[1]) || a[0].localeCompare(b[0]),
        )[0][0];
        next = next.filter((r) => groupKey(r.provider, r.uploadId) !== oldestKey);
      }

      await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
      return next;
    });
  }
}

// ───────────────────────────── read-time summary and caveats ─────────────────────────────

// Documented category universes, for the read-time absence caveat only (never used to grade or
// gate anything at import time). GCP/AWS/Azure lists are the providers' own documented, closed
// sets; M365's Workload values are numerous and not fully enumerable here, so a representative,
// commonly-audited subset is used — the caveat is stated as resting on that subset, never as
// exhaustive. Google Workspace carries no per-application caveat at all (see `renderCoverageCaveats`).
const AWS_DOCUMENTED_CATEGORIES = ["Management", "Data", "Insight"];
const GCP_DOCUMENTED_CATEGORIES = ["activity", "data_access", "system_event", "policy"];
const AZURE_DOCUMENTED_CATEGORIES = [
  "Administrative",
  "Security",
  "ServiceHealth",
  "Alert",
  "Autoscale",
  "Recommendation",
  "Policy",
  "ResourceHealth",
];
/** Not exhaustive — Microsoft documents many more Workload values; this is the commonly-audited subset the caveat checks. */
const M365_DOCUMENTED_WORKLOADS = [
  "Exchange",
  "SharePoint",
  "OneDrive",
  "AzureActiveDirectory",
  "MicrosoftTeams",
  "SecurityComplianceCenter",
];

export interface CloudCoverageItem {
  provider: CloudCoverageProvider;
  scope: { kind: string; value: string };
  uploadId: string;
  recordCount: number;
  first: string;
  last: string;
  categories: CloudCoverageCategory[];
}

export interface CloudCoverageSummary {
  items: CloudCoverageItem[];
  /** One sentence per absent documented category, grouped by provider, in provider order. */
  caveats: string[];
}

/** Deterministic across providers too: provider name asc, then the per-provider scope order. */
function sortItems(items: readonly CloudCoverageItem[]): CloudCoverageItem[] {
  return [...items].sort(
    (a, b) =>
      a.provider.localeCompare(b.provider) ||
      b.recordCount - a.recordCount ||
      a.scope.value.localeCompare(b.scope.value),
  );
}

/** Pure — read-time only. Never stored, so an M365 caveat can compare across every upload of that provider in the case, and multiple absent categories each get their own sentence. */
export function summarizeCloudCoverage(records: readonly CloudCoverageRecord[]): CloudCoverageSummary {
  const items: CloudCoverageItem[] = records.map((r) => ({
    provider: r.provider,
    scope: r.scope,
    uploadId: r.uploadId,
    recordCount: r.recordCount,
    first: r.first,
    last: r.last,
    categories: r.categories,
  }));
  const byProvider = new Map<CloudCoverageProvider, CloudCoverageRecord[]>();
  for (const r of records)
    (byProvider.get(r.provider) ?? byProvider.set(r.provider, []).get(r.provider)!).push(r);

  const caveats: string[] = [];
  const present = (provider: CloudCoverageProvider): Set<string> =>
    new Set((byProvider.get(provider) ?? []).flatMap((r) => r.categories.map((c) => c.name)));

  if (byProvider.has("aws-cloudtrail")) {
    const seen = present("aws-cloudtrail");
    for (const cat of AWS_DOCUMENTED_CATEGORIES)
      if (!seen.has(cat))
        caveats.push(
          `no ${cat}-category records occur in this case's CloudTrail uploads; this does not establish selector configuration or absence of${cat === "Data" ? " data-plane" : ""} activity`,
        );
  }
  if (byProvider.has("gcp")) {
    const seen = present("gcp");
    for (const cat of GCP_DOCUMENTED_CATEGORIES)
      if (!seen.has(cat))
        caveats.push(
          cat === "data_access"
            ? "no data_access-category records occur in this case's GCP uploads; Data Access audit logging may be enabled but simply unused, or not enabled at all — this record set does not distinguish the two"
            : `no ${cat}-category records occur in this case's GCP uploads`,
        );
  }
  if (byProvider.has("azure")) {
    const seen = present("azure");
    for (const cat of AZURE_DOCUMENTED_CATEGORIES)
      if (!seen.has(cat))
        caveats.push(
          `no ${cat}-category records occur in this case's Azure uploads; this does not establish that no ${cat.toLowerCase()}-relevant activity occurred — Azure's own category assignment, not a completeness signal`,
        );
  }
  if (byProvider.has("m365")) {
    const seenWorkloads = new Set(
      (byProvider.get("m365") ?? []).flatMap((r) => r.categories.map((c) => c.name.split("/")[0])),
    );
    for (const wl of M365_DOCUMENTED_WORKLOADS)
      if (!seenWorkloads.has(wl))
        caveats.push(
          `no ${wl}-workload records occur in this case's M365 uploads (of the commonly-audited workloads checked); this does not establish the workload was not audited — only that no such record reached this export`,
        );
  }
  if (byProvider.has("google-workspace"))
    caveats.push("anonymous views are not logged; anonymous edits and downloads are");

  return { items: sortItems(items), caveats };
}

const PROVIDER_LABEL: Record<CloudCoverageProvider, string> = {
  "aws-cloudtrail": "AWS CloudTrail",
  gcp: "GCP",
  azure: "Azure",
  m365: "M365",
  "google-workspace": "Google Workspace",
};

function categoryWords(c: CloudCoverageCategory): string {
  const ro = c.readOnly
    ? ` (read-only ${c.readOnly.true} / mutating ${c.readOnly.false} / unknown ${c.readOnly.unknown})`
    : "";
  return `${c.name} ${c.count.toLocaleString()}${ro}`;
}

function itemWords(item: CloudCoverageItem): string {
  const scope = item.scope.value ? `${item.scope.kind} ${item.scope.value}` : "scope not recorded";
  const range = item.first && item.last ? ` (${item.first.slice(0, 10)} → ${item.last.slice(0, 10)})` : "";
  const cats = item.categories.map(categoryWords).join(", ");
  return `${PROVIDER_LABEL[item.provider]} — ${scope}: ${item.recordCount.toLocaleString()} records${range}. ${cats}.`;
}

/** Bounded rendering for the AI block — a count cap, never token-level trimming (the file convention every other bounded block in promptBlocks.ts already follows). */
export function renderCloudCoverage(summary: CloudCoverageSummary, max: number): string {
  if (max <= 0 || summary.items.length === 0) return "";
  const shown = summary.items.slice(0, max);
  const beyond = summary.items.length - shown.length;
  const lines = shown.map(itemWords);
  if (beyond > 0) lines.push(`+${beyond} further upload${beyond === 1 ? "" : "s"} not shown`);
  return [...lines, ...summary.caveats].join("\n");
}
