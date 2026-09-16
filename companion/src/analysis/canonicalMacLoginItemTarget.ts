// The envelope block one macOS Background Task Management login-item record carries (#933 item 8,
// importer half, #1013): a decoded configuration fact about one item's own bookmark target, never
// evidence it executed. Two real, confirmed BTM generations — legacy (macOS <= 12,
// backgrounditems.btm, `version === 2`) and modern (macOS 13+, BackgroundItems-v*.btm,
// `version >= 3`) — schema-verified live against mnrkbys/bgiparser's own parse_btm(). The modern
// generation's per-item field list beyond type/modificationDate/executableModificationDate/sha256
// is NOT independently confirmed against a real captured sample; every other present key is
// carried through as disclosed, unconfirmed rawFields rather than asserted into a guessed schema.

import { z } from "zod";

export const macLoginItemTools = ["bookmark-decoder"] as const;
export type MacLoginItemTool = (typeof macLoginItemTools)[number];

export const MAX_FIELD_LEN = 300;
export const MAX_PATH_DEPTH = 64;
export const MAX_RAW_FIELDS = 32;

export const MAC_LOGIN_ITEM_BASIS =
  "the target path/volume/CNID facts come from decoding the item's own bookmark data, Apple's " +
  "real (reverse-engineered but well-established) CFURL bookmark format; this is a decoded " +
  "CONFIGURATION record, never evidence the target executed, and never a live CFURL resolution " +
  "against the current filesystem -- a bookmark that fails to resolve is disclosed as " +
  'bookmarkDecodeStatus: "malformed", never silently dropped; rawFields entries beyond ' +
  "type/modificationDate/executableModificationDate/sha256 are present in the archive but this " +
  "design's own research did not confirm their exact meaning against a real captured sample -- " +
  "read them as raw disclosure, never as a Hidden/Disabled/agent-vs-daemon distinction until a " +
  "real fixture confirms it";

export const macLoginItemBlockSchema = z.object({
  tool: z.enum(macLoginItemTools),
  sourceFormat: z.enum(["btm-legacy", "btm-modern"]),
  userUuid: z.string().max(MAX_FIELD_LEN).optional(),
  itemType: z.number().int().optional(),
  modificationDate: z.string().optional(),
  executableModificationDate: z.string().optional(),
  sha256: z.string().length(64).optional(),
  rawFields: z.record(z.string().max(60), z.string().max(MAX_FIELD_LEN)).optional(),
  targetPathComponents: z.array(z.string().max(MAX_FIELD_LEN)).max(MAX_PATH_DEPTH).optional(),
  targetCnidPath: z.array(z.string().regex(/^\d+$/)).max(MAX_PATH_DEPTH).optional(),
  volumeName: z.string().max(MAX_FIELD_LEN).optional(),
  volumeUuid: z.string().max(MAX_FIELD_LEN).optional(),
  volumeIsRoot: z.boolean().optional(),
  fileCreationDate: z.string().optional(),
  wasFileReference: z.boolean().optional(),
  displayName: z.string().max(MAX_FIELD_LEN).optional(),
  bookmarkDecodeStatus: z.enum(["decoded", "malformed", "absent"]),
  // True when the TOC chain ended on a magic mismatch rather than a clean nextToc of 0 — at least
  // as consistent with truncation/corruption as with a deliberate terminator, disclosed rather
  // than folded silently into "decoded" (Ollama code review finding).
  bookmarkTocTruncated: z.boolean().optional(),
  targetEvidence: z.literal("stored-bookmark-metadata"),
  reportFingerprint: z.string().length(64),
  mappingVersion: z.literal("mac-login-item-target-v1"),
  basis: z.literal(MAC_LOGIN_ITEM_BASIS),
});
export type MacLoginItemBlock = z.infer<typeof macLoginItemBlockSchema>;
