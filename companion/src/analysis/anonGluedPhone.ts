import type { AnonTokenCategory } from "./anonymize.js";
import type { Crossing } from "./anonTailJoin.js";

// #3077: an address glued after an encoded blob (#3067), a card or another address (#3062) gets its
// token before the IPv4 pass, so #3018's split of a phone number that starts in its numbers never ran,
// and the phone pass cannot read a number cut by a token: the rest of it went out in clear. Before,
// the run was left whole for the phone pass, which masked the number from wherever it started after
// the address's first number. That reading is restored here, just before the phone pass.

/** What the step needs from the anonymizer and the tail joiner. */
export interface GluedPhoneDeps {
  readonly real: (token: string) => string | undefined;
  readonly assign: (category: AnonTokenCategory, raw: string) => string;
  /** Keeps a minted pair out of the saved discoveries (a cut number is never saved, #2995). */
  readonly unsaved: (token: string, value: string) => void;
  readonly crossers: () => readonly RegExp[];
  readonly suppressed: ReadonlySet<string>;
  /** anonTailJoin's readers: a phone number that starts in `seg` and runs into `next`, and its check. */
  readonly crossing: (seg: string, next: string, crossers: readonly RegExp[]) => Crossing | null;
  readonly phoneOk: (c: Crossing, suppressed: ReadonlySet<string>) => boolean;
}

const TOKEN = /ANON_[A-Z]+_\d+/g;
// The dotted numbers a token's value ends in: an address, or one glued to the end of a blob.
const DOTTED_END = /\d+((?:\.\d+)+)$/;
const WORD_BEFORE = /[A-Za-z0-9_]$/;
const NEXT = 32; // how far a phone number after the token is read

/**
 * The token's dotted end a phone number may start in (after the first number), or null. Only a
 * glued reading: a value with something in front of its dotted numbers (a blob), or a token glued
 * to a word or another token. A plain address keeps #3018's rule (anonTailJoin's plainRun).
 */
function gluedSeg(value: string, before: string): string | null {
  const m = DOTTED_END.exec(value);
  if (!m) return null;
  return m.index > 0 || WORD_BEFORE.test(before) ? m[1] : null;
}

/** Each glued address token with a phone number that starts in it: the rest gets a PHONE token. */
export function splitGluedPhones(text: string, d: GluedPhoneDeps): string {
  let out = "";
  let at = 0;
  for (const m of text.matchAll(TOKEN)) {
    if (m.index < at) continue;
    const value = d.real(m[0]);
    const end = m.index + m[0].length;
    const seg = value ? gluedSeg(value, text.slice(Math.max(0, m.index - 1), m.index)) : null;
    const c = seg ? d.crossing(seg, text.slice(end, end + NEXT), d.crossers()) : null;
    if (!c || !d.phoneOk(c, d.suppressed)) continue;
    const tok = d.assign("PHONE", c.value);
    d.unsaved(tok, c.value);
    out += text.slice(at, end) + c.gap + tok;
    at = end + c.len;
  }
  return out + text.slice(at);
}
