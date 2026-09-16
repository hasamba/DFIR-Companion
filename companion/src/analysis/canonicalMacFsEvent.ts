// The envelope block one FSEventsParser (dlcowen/G-C Partners) All_FSEVENTS.tsv row carries
// (#933 item 9, "933.9"): a structural fact about one fsevents record's reported path, type and
// coalesced flags. The real export uses the parser's own reduced R_COLUMNS set (9 fields), not
// its full attribute list — id_hex, filename, mask, dls_version and record_end_offset are not
// present in this artifact and are never fabricated to fill the gap. Timestamps in this format
// are never a claimed event instant: fsevents records carry no per-record clock at all, only a
// monotonic id that FSEventsParser itself brackets against neighboring log file dates to produce
// a day-precision date or date range. Kept beside canonicalEvent.ts so the envelope schema stays
// within its size bound (mirrors canonicalSqliteRowState.ts's own sibling-file pattern, item 8).

import { z } from "zod";

export const macFsEventTools = ["fseventsparser"] as const;
export type MacFsEventTool = (typeof macFsEventTools)[number];

export const MAX_FIELD_LEN = 300;
export const MAX_RECORD_TYPES = 4;
export const MAX_FLAGS = 16;
export const MAX_TOKEN_LEN = 40;

export const MAC_FSEVENT_BASIS =
  "sourceLocation is the parser's own path/label for the fsevents log that produced this record, " +
  "not a volume UUID -- this export format carries no volume identity signal at all; approxDate* " +
  "is day-precision at best, interpolated from neighboring fsevents log timestamps, never a " +
  "claimed event instant; flags/recordTypes may combine multiple bits on one record because " +
  "fsevents itself coalesces closely-spaced changes to one item into one record, which is not " +
  "evidence of one atomic operation; this is one parsed record, never a complete audit trail of " +
  "everything that happened to this path";

export const macFsEventBlockSchema = z.object({
  tool: z.enum(macFsEventTools),
  // The decimal `id` (wd) column, a real uint64 -- kept as a digits-only string, never Number(),
  // since JS numbers silently lose precision above 2^53.
  recordId: z.string().regex(/^\d+$/),
  fullPath: z.string().max(MAX_FIELD_LEN),
  recordTypes: z.array(z.string().max(MAX_TOKEN_LEN)).max(MAX_RECORD_TYPES),
  flags: z.array(z.string().max(MAX_TOKEN_LEN)).max(MAX_FLAGS),
  approxDateRaw: z.string(),
  approxDateStart: z.string(),
  approxDateEnd: z.string(),
  nodeId: z.string().max(MAX_FIELD_LEN).optional(),
  fsUid: z.string().max(MAX_FIELD_LEN).optional(),
  sourceLocation: z.string().max(MAX_FIELD_LEN),
  sourceModifiedTime: z.string(),
  reportFingerprint: z.string().length(64),
  mappingVersion: z.literal("mac-fsevent-v1"),
  basis: z.literal(MAC_FSEVENT_BASIS),
});
export type MacFsEventBlock = z.infer<typeof macFsEventBlockSchema>;
