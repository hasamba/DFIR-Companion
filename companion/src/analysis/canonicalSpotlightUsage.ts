// The envelope block one mac_apt (ydkhatri) Spotlight store-item row carries (#933 item 10,
// "933.10"): a structural fact about one indexed item's reported usage/download attributes.
// mac_apt flattens every multi-value kMDItem* attribute to a comma-joined string before it ever
// reaches CSV/TSV, so this block treats those fields as flattened text, never re-splits them into
// an array (a legitimately comma-containing value, e.g. a URL query string, would mis-split).
// Never a claim that a file with no usage/download signal was never used, and never a claim that
// retained usage/download metadata means the file still exists. Kept beside canonicalEvent.ts so
// the envelope schema stays within its size bound (mirrors canonicalSqliteRowState.ts's own
// sibling-file pattern, item 8).

import { z } from "zod";

export const spotlightUsageTools = ["mac_apt-spotlight"] as const;
export type SpotlightUsageTool = (typeof spotlightUsageTools)[number];

export const MAX_FIELD_LEN = 300;

export const SPOTLIGHT_USAGE_BASIS =
  "useCount is a pure aggregate integer with no time-of-use information and is never expanded " +
  "into one synthetic event per count; usedDatesRaw is Apple's own day-bucketed usage history, " +
  "already rounded to day granularity by the OS itself, never a list of exact use times; " +
  "dateUpdated is the Spotlight index's own bookkeeping timestamp for when it last recorded this " +
  "item, never a usage or download time; a missing usage/download signal does not establish " +
  "non-use, and retained usage/download metadata does not establish the file still exists -- the " +
  "index can be stale, partial or carrying copied metadata";

export const spotlightUsageBlockSchema = z.object({
  tool: z.enum(spotlightUsageTools),
  itemId: z.string().max(MAX_FIELD_LEN),
  parentId: z.string().max(MAX_FIELD_LEN).optional(),
  displayName: z.string().max(MAX_FIELD_LEN).optional(),
  displayNameSource: z.enum(["kMDItemDisplayName", "_kMDItemFileName", "unavailable"]),
  pathStatus: z.enum(["resolved", "not-exported"]),
  path: z.string().max(MAX_FIELD_LEN).optional(),
  useCount: z.number().int().nonnegative().optional(),
  lastUsedDate: z.string().optional(),
  usedDatesRaw: z.string().max(MAX_FIELD_LEN).optional(),
  downloadedDateRaw: z.string().max(MAX_FIELD_LEN).optional(),
  whereFromsRaw: z.string().max(MAX_FIELD_LEN).optional(),
  dateUpdated: z.string().optional(),
  storeIdentity: z.string().max(MAX_FIELD_LEN),
  storeIdentitySource: z.enum(["upload-label", "unavailable"]),
  reportFingerprint: z.string().length(64),
  mappingVersion: z.literal("mac-spotlight-usage-v1"),
  basis: z.literal(SPOTLIGHT_USAGE_BASIS),
});
export type SpotlightUsageBlock = z.infer<typeof spotlightUsageBlockSchema>;
