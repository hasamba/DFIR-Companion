// The MDN regex-escape idiom — ONE copy shared by every module that embeds a raw value in a
// RegExp (anonymize's tokenizer, redactPaths, asset/geo/IOC description matching, the report
// glossary…). The per-module copies were exactly the small-helper duplication class the
// internal-IP and month-table consolidations removed: a future correction must land everywhere
// at once, and several call sites guard security-relevant surfaces.
//
// Safe under the `u` flag: every character escaped here (. * + ? ^ $ { } ( ) | [ ] \) is a
// SyntaxCharacter, i.e. a legal identity escape in Unicode mode, so no escaped value can turn
// into an "Invalid regular expression" when the caller compiles with `u` (see anonymize.ts's
// exactValueRegExp, which relies on this).
export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
