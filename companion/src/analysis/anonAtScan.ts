// The account and e-mail patterns (UPN_ACCT in anonUsernames.ts, EMAIL_RE below) open with
// `\b` and a local part of [A-Za-z0-9._%+-] before an "@". A regex engine tries that opening at every
// word boundary and scans the whole run of local-part characters for an "@" each time, so a long run
// (a domain of `sk-` runs or dotted labels, a URL-encoded body, a dashed slug) took time quadratic in
// its length: minutes on a few hundred KB, on every masked call of the case (#3055).
//
// This runs the same regex only where it can match. A match's local part is the run directly before
// one "@" (an "@" is not a local-part character), and what follows the "@" does not depend on where
// the local part starts. So per "@" the leftmost start the regex itself would take is the first word
// boundary in that run (at least `minLocal` characters before the "@"), and ONE sticky attempt there
// decides the "@": if it fails, every later start in the run fails too. Each run and each domain is
// read once, so the scan is linear, and it returns exactly what `text.replace(re, fn)` returns.

import { UPN_ACCT } from "./anonUsernames.js";

// The e-mail pattern, and the same address with 1-3 digits glued after its TLD (`<user>@<domain>0|x`,
// a log field run into the next value) when the digits cannot go on into another local part or an "@"
// (#3050). A TLD never holds a digit, so the digits are not part of the domain.
export const EMAIL_RE =
  /\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+(?:\.[A-Za-z]{2,}|\.xn--[A-Za-z0-9-]+)\b/g;
export const GLUED_EMAIL_RE =
  /\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+\.[A-Za-z]{2,}(?=\d{1,3}(?![A-Za-z0-9._%+@-]))/g;

const LOCAL = /[A-Za-z0-9._%+-]/;
const WORD = /[A-Za-z0-9_]/;

export type AtReplacer = (match: string, offset: number, whole: string) => string;

/** A matcher of a `\b<local part>@…` regex, usable with String.replace like the regex itself. */
export interface AtAnchored {
  [Symbol.replace](text: string, fn: AtReplacer): string;
}

const isWord = (ch: string | undefined) => ch !== undefined && WORD.test(ch);

// The first index in [from, last] where `\b` holds, or -1.
function firstBoundary(text: string, from: number, last: number): number {
  for (let p = from; p <= last; p++) if (isWord(text[p - 1]) !== isWord(text[p])) return p;
  return -1;
}

/**
 * `re` must open with `\b` and a local part of [A-Za-z0-9._%+-] (at least `minLocal` of them) that
 * ends at an "@", like UPN_ACCT and EMAIL_RE; its flags other than g/y are kept.
 */
export function atAnchored(re: RegExp, minLocal: number): AtAnchored {
  const sticky = new RegExp(re.source, re.flags.replace(/[gy]/g, "") + "y");
  return {
    [Symbol.replace](text: string, fn: AtReplacer): string {
      let out = "";
      let cursor = 0; // the end of the last match: the regex resumes its search there
      for (let at = text.indexOf("@", cursor); at !== -1; at = text.indexOf("@", at + 1)) {
        let start = at;
        while (start > cursor && LOCAL.test(text[start - 1])) start--;
        const p = firstBoundary(text, start, at - minLocal);
        if (p < 0) continue;
        sticky.lastIndex = p;
        const m = sticky.exec(text);
        if (!m) continue;
        out += text.slice(cursor, p) + fn(m[0], p, text);
        cursor = p + m[0].length;
        if (cursor > at + 1) at = cursor - 1; // the next "@" lies at or after the match's end
      }
      return out + text.slice(cursor);
    },
  };
}

/** UPN_ACCT (anonUsernames.ts) read by the scanner; its opener is `\b[A-Za-z0-9._%+-]{2,}@`. */
export const UPN_SCAN: AtAnchored = atAnchored(UPN_ACCT, 2);

const EMAIL_SCAN = atAnchored(EMAIL_RE, 1);
const GLUED_SCAN = atAnchored(GLUED_EMAIL_RE, 1);
type Ended = (result: string, value: string, at: number, end: number, text: string) => string;

/**
 * The e-mail pass: `mint(address, glued)` gives each address its replacement. A glued address is
 * spliced through `ended`, so the digit after its token keeps a delimiter. A digit-led local part may
 * be the tail of a card or phone number a later pass masks whole, so it is not read as glued.
 */
export function replaceEmails(
  text: string,
  mint: (m: string, glued: boolean) => string,
  ended: Ended,
): string {
  const out = text.replace(EMAIL_SCAN, (m) => mint(m, false));
  return out.replace(GLUED_SCAN, (m, at, w) =>
    /^\d/.test(m) ? m : ended(mint(m, true), m, at, at + m.length, w),
  );
}
