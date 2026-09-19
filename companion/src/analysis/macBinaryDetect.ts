// Byte-native detection for macOS login-item files (#1013, #1301) — the one place this codebase
// currently recognizes a BINARY import kind rather than a text one. Filename is the only reliable
// signal for WHICH artifact this is (a keyed-archive bplist carries no in-content marker
// distinguishing it from any other keyed-archived plist — matches this codebase's own LEAPP
// precedent: "LEAPP TSVs carry no in-content marker; the filename is the only signal"); the real
// `bplist00` magic on the raw bytes is required too, so a mismatched-magic file under a matching
// name is rejected, never coerced. The name gate is also what keeps an MRU `.sfl2`
// (RecentDocuments, FavoriteVolumes, …) out: same container as SessionLoginItems, but not a
// persistence record, and the parser cannot tell them apart by shape.

const BTM_LEGACY_NAME = /backgrounditems\.btm$/i;
const BTM_MODERN_NAME = /BackgroundItems-v\d+\.btm$/i;
const SFL2_SESSION_LOGIN_ITEMS_NAME = /com\.apple\.LSSharedFileList\.SessionLoginItems\.sfl2$/i;
const CLASSIC_LOGINITEMS_PLIST_NAME = /com\.apple\.loginitems\.plist$/i;

export function looksLikeMacBtmFilename(filename: string): boolean {
  return BTM_LEGACY_NAME.test(filename) || BTM_MODERN_NAME.test(filename);
}

/** Every login-item container this codebase decodes: both BTM generations, the sfl2 list, the classic plist. */
export function looksLikeMacLoginItemFilename(filename: string): boolean {
  return (
    looksLikeMacBtmFilename(filename) ||
    SFL2_SESSION_LOGIN_ITEMS_NAME.test(filename) ||
    CLASSIC_LOGINITEMS_PLIST_NAME.test(filename)
  );
}

// A login-item container this codebase KNOWS by name but does not decode (#1360): the v1
// SessionLoginItems.sfl that macOS 10.11–10.12 wrote (custom SFLListItem archive, superseded by the
// .sfl2 dict shape in 10.13). Deliberately a SEPARATE list from the accept gate above: it is only
// consulted to refuse the name honestly on the text path, so the byte-native routes never start
// accepting a file no reader exists for. A v1 reader was declined — the format is end-of-life and
// no real capture exists to build one against.
const SFL_V1_SESSION_LOGIN_ITEMS_NAME = /com\.apple\.LSSharedFileList\.SessionLoginItems\.sfl$/i;

/** Known but not decoded: the v1 `.sfl` list. Never true for a name the accept gate takes. */
export function looksLikeUndecodedMacLoginItemFilename(filename: string): boolean {
  return SFL_V1_SESSION_LOGIN_ITEMS_NAME.test(filename);
}

/** The names the routes quote back when a file does not match. */
export const MAC_LOGIN_ITEM_FILENAMES =
  "backgrounditems.btm, BackgroundItems-v*.btm, com.apple.LSSharedFileList.SessionLoginItems.sfl2 " +
  "or com.apple.loginitems.plist";

export function isBplistMagic(headBytes: Buffer): boolean {
  return headBytes.length >= 8 && headBytes.toString("ascii", 0, 8) === "bplist00";
}

/** The one binary import kind this codebase currently detects — filename plus real magic, both required. */
export function detectBinaryImportKind(filename: string, headBytes: Buffer): "macloginitem" | null {
  if (looksLikeMacLoginItemFilename(filename) && isBplistMagic(headBytes)) return "macloginitem";
  return null;
}
