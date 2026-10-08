// Unicode format / bidirectional-text control characters, owned in one place (#2027).
//
// A bidi control in a file or process name is how an attacker makes `cod.3aka3.scr` display as
// `rcs.3aka3.doc` (MITRE T1036.002). The same character in a description reverses the dashboard
// row and every export it reaches, so a reader must never see it raw: escapeBidiControls() turns
// each one into a visible marker such as `<RLO>`.
//
// Two encodings reach the importers. The real characters — U+202A–U+202E (embeddings, overrides
// and PDF) and U+2066–U+2069 (isolates) — and the MOJIBAKE form, where the character's UTF-8 bytes
// were decoded as Windows-1252 before the log was written: U+202E is E2 80 AE, which reads "â€®".
// That is exactly how it appears in the OTRF APT29 NXLog export. normalizeBidiMojibake() turns the
// three-character sequence back into the character it stood for, and every reader below sees
// through it.

/**
 * Zero-width, line/paragraph separator, bidi embedding/override/isolate and BOM characters — the
 * invisible characters that make two strings that LOOK equal differ, or make a shown value read
 * differently from what it is. The cloud-config readers strip these before showing a token.
 */
export const FORMAT_CHARS = /[\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g;

const BIDI_NAMES: Readonly<Record<string, string>> = {
  "\u202a": "LRE",
  "\u202b": "RLE",
  "\u202c": "PDF",
  "\u202d": "LRO",
  "\u202e": "RLO",
  "\u2066": "LRI",
  "\u2067": "RLI",
  "\u2068": "FSI",
  "\u2069": "PDI",
};
const RLO = "\u202e";
const OVERRIDE_END = new Set(["\u202c", "\u2069"]); // PDF closes the override; PDI closes its isolate too

const BIDI_RE = /[\u202a-\u202e\u2066-\u2069]/g;
const HAS_BIDI = /[\u202a-\u202e\u2066-\u2069]/;
// "â" + the second UTF-8 byte (0x80, as cp1252 "€" or Latin-1 U+0080; 0x81, undefined in cp1252, so
// kept as U+0081 or replaced with U+FFFD) + the third byte as its Latin-1 character. Only the nine
// bidi controls' byte patterns: E2 80 AA–AE and E2 81 A6–A9.
const MOJIBAKE_RE = /\u00e2(?:[\u20ac\u0080]([\u00aa-\u00ae])|[\u0081\ufffd]([\u00a6-\u00a9]))/g;
const HAS_MOJIBAKE = /\u00e2(?:[\u20ac\u0080][\u00aa-\u00ae]|[\u0081\ufffd][\u00a6-\u00a9])/;

// Paired punctuation is drawn mirrored inside a right-to-left run.
const MIRRORED: Readonly<Record<string, string>> = {
  "(": ")",
  ")": "(",
  "[": "]",
  "]": "[",
  "{": "}",
  "}": "{",
  "<": ">",
  ">": "<",
};

/** The string with every bidi control's Windows-1252 mojibake decoded back to the real character. */
export function normalizeBidiMojibake(s: string): string {
  if (!HAS_MOJIBAKE.test(s)) return s;
  return s.replace(MOJIBAKE_RE, (_, low80: string | undefined, low81: string | undefined) =>
    low80
      ? String.fromCharCode(0x2000 | (low80.charCodeAt(0) & 0x3f))
      : String.fromCharCode(0x2040 | (low81!.charCodeAt(0) & 0x3f)),
  );
}

/** Does the string carry a bidi control, in either encoding? */
export function hasBidiControl(s: string | undefined): boolean {
  return !!s && (HAS_BIDI.test(s) || HAS_MOJIBAKE.test(s));
}

/** The short names (`RLO`, `LRI`, …) of the bidi controls in the string, in order of appearance, deduped. */
export function bidiControlsIn(s: string): string[] {
  const names = (normalizeBidiMojibake(s).match(BIDI_RE) ?? []).map((c) => BIDI_NAMES[c]);
  return [...new Set(names)];
}

/** The string with every bidi control (either encoding) shown as a visible `<NAME>` marker. */
export function escapeBidiControls(s: string): string {
  if (!hasBidiControl(s)) return s;
  return normalizeBidiMojibake(s).replace(BIDI_RE, (c) => `<${BIDI_NAMES[c]}>`);
}

/**
 * How the string DISPLAYS. An RLO forces everything after it, up to its PDF (or the end), to be laid
 * out right-to-left — reversed, with paired punctuation mirrored. The other controls change nothing
 * visible on Latin text and are dropped. This covers the masquerade shape; it is not the full
 * Unicode Bidirectional Algorithm.
 */
export function bidiVisual(s: string): string {
  const chars = [...normalizeBidiMojibake(s)];
  let out = "";
  for (let i = 0; i < chars.length; i++) {
    if (chars[i] !== RLO) {
      if (!BIDI_NAMES[chars[i]]) out += chars[i];
      continue;
    }
    let j = i + 1;
    while (j < chars.length && !OVERRIDE_END.has(chars[j])) j++;
    const run = chars.slice(i + 1, j).filter((c) => !BIDI_NAMES[c]);
    out += run
      .reverse()
      .map((c) => MIRRORED[c] ?? c)
      .join("");
    i = j;
  }
  return out;
}
