// The card, phone and national-id detectors of the anonymizer. Moved out of anonymize.ts so the
// glued-remnant pass (anonGluedSecret.ts, #3028) can stop at the same matches.

// A detector, not a validator: matches only real card GROUPINGS, plus a bare contiguous run.
// Separators are permitted ONLY at genuine group boundaries — NOT between every digit (an
// earlier version of this pattern allowed a separator after each digit, so two unrelated bare
// numbers sitting next to each other in ordinary forensic text — a PID and a port, an offset
// and a byte count — got silently concatenated into one candidate before the prefix/Luhn
// filters ever ran, e.g. "30001 35174909" -> digits "3000135174909" -> passes both filters).
// Requiring the separator to land on a real 4-4-4-4 / 4-6-5 / 4-4-4-4-3 boundary means two
// adjacent-but-unrelated numbers essentially never happen to have exactly those group widths.
//
// Longest/most-specific alternative FIRST: JS regex alternation is first-match, not
// longest-match, so the 19-digit 4-4-4-4-3 grouping must be tried before the 16-digit 4-4-4-4
// grouping — otherwise a real 19-digit card would match only its first 16 digits (the engine
// finds \b right after the 4th group, since the following char is a separator), leaving the
// trailing "-123" unmasked in cleartext.
export const CARD_RE =
  /\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{3}\b|\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b|\b\d{4}[ -]\d{6}[ -]\d{5}\b|\b\d{13,19}\b/g;

// Three NARROW patterns. A bare run of ten digits is deliberately NOT matched — forensic text is
// full of PIDs, ports, offsets and sequence numbers, and a generic rule would shred it. Every
// pattern demands either a leading + or explicit separators.
//
// The negative lookbehind on PHONE_E164 keeps it off a "+" that CONTINUES a token rather than
// starting a number: module+offset notation in crash dumps/stack traces (kernel32.dll+1245184)
// and SemVer build metadata (1.0.0+20130313144700 — the SemVer spec's own example) both glue a
// bare "+<digits>" suffix directly onto a preceding identifier. A genuine E.164 number is never
// preceded by a letter, digit, dot, underscore or dash — it follows whitespace, line start, or
// punctuation such as a label colon ("Tel:+972...") — so those are the only characters excluded.
export const PHONE_E164 = /(?<![A-Za-z0-9._-])\+\d{7,15}\b/g;
export const PHONE_IL = /\b0(?:5\d|[2-46-9])-?\d{7}\b/g;
export const PHONE_NANP = /\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b/g;

// Exactly nine digits, not adjacent to another digit, a dot, a dash, or an underscore. The
// lookarounds keep this out of longer runs (byte counts, ten-digit unix seconds), dotted version
// strings, AND snake_case identifiers — session_id_123456782, txn_123456782_archived and similar
// underscore-glued session/request/ticket/backup IDs are routine in forensic text, so `_` is
// excluded on BOTH sides for the same reason as `.`/`-`: a systematic false-positive source, not
// a random one. The exclusion is symmetric because an identifier scheme that glues an ID onto a
// preceding label with `_` is just as likely to glue a trailing qualifier on with `_` the same way.
export const NATID_RE = /(?<![\d._-])\d{9}(?![\d._-])/g;
