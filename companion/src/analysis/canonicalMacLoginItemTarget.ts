// The envelope block one macOS Background Task Management login-item record carries (#933 item 8,
// importer half, #1013): a decoded configuration fact about one item's own bookmark target, never
// evidence it executed. Two real, confirmed BTM generations — legacy (macOS <= 12,
// backgrounditems.btm, `version === 2`) and modern (macOS 13+, BackgroundItems-v*.btm,
// `version >= 3`) — schema-verified live against mnrkbys/bgiparser's own parse_btm(). The modern
// generation's per-item field list beyond type/modificationDate/executableModificationDate/sha256
// is NOT independently confirmed against a real captured sample; every other present key is
// carried through as disclosed, unconfirmed rawFields rather than asserted into a guessed schema.
// #1301 adds the two pre-BTM containers under the same block: the LSSharedFileList
// `SessionLoginItems.sfl2` keyed archive (bookmark payloads, shape per mac_apt + macMRU-Parser) and
// the classic `com.apple.loginitems.plist` whose targets are Alias Manager records (layout per
// mac_alias's writer + plistutils). Records from those write mappingVersion v2; BTM records keep v1.

import { z } from "zod";

export const macLoginItemTools = ["bookmark-decoder"] as const;
export type MacLoginItemTool = (typeof macLoginItemTools)[number];

export const MAX_FIELD_LEN = 300;
export const MAX_PATH_DEPTH = 64;
export const MAX_RAW_FIELDS = 32;

export const MAC_LOGIN_ITEM_ALIAS_BASIS =
  "the target name/volume/CNID/date facts come from decoding the item's own classic Alias Manager " +
  "record (versions 2 and 3, per mac_alias's writer and plistutils's samples) as it was written, " +
  "with HFS-style names rendered the way mac_alias renders them (a stored '/' shown as ':'); " +
  "this is a decoded CONFIGURATION record, never evidence the target executed, and never " +
  "a live resolution against the current filesystem -- a record that fails to decode is disclosed " +
  'as bookmarkDecodeStatus: "malformed", never silently dropped; a POSIX path is the path the ' +
  "record stored, and when only a carbon (colon-separated) path or a bare filename exists that is " +
  "what is shown, never a fabricated slash path; unknown tags are disclosed by number only";

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
  sourceFormat: z.enum(["btm-legacy", "btm-modern", "sfl2", "loginitems-plist"]),
  /** The list's own name for the item (`Name`) — sfl2 and the classic plist only. */
  itemName: z.string().max(MAX_FIELD_LEN).optional(),
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
  /** Which decoder produced the target facts (absent on v1 BTM records, which are always bookmarks). */
  targetRecordKind: z.enum(["cfurl-bookmark", "alias-record"]).optional(),
  aliasVersion: z.union([z.literal(2), z.literal(3)]).optional(),
  /** 0 = file, 1 = folder per mac_alias; any other stored value carried raw. */
  aliasKind: z.number().int().optional(),
  targetCnid: z.string().regex(/^\d+$/).optional(),
  folderCnid: z.string().regex(/^\d+$/).optional(),
  volumeCreationDate: z.string().optional(),
  posixMountPoint: z.string().max(MAX_FIELD_LEN).optional(),
  /** Alias tags this codebase does not interpret, by number; tag 20 (nested alias) is never recursed. */
  aliasUnknownTags: z.array(z.number().int()).max(64).optional(),
  targetEvidence: z.enum(["stored-bookmark-metadata", "stored-alias-metadata"]),
  reportFingerprint: z.string().length(64),
  mappingVersion: z.enum(["mac-login-item-target-v1", "mac-login-item-target-v2"]),
  basis: z.union([z.literal(MAC_LOGIN_ITEM_BASIS), z.literal(MAC_LOGIN_ITEM_ALIAS_BASIS)]),
});
export type MacLoginItemBlock = z.infer<typeof macLoginItemBlockSchema>;
