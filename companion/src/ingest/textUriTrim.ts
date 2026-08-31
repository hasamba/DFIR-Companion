// Where a URI found in free text actually ENDS, shared by every importer that scrapes one.
//
// Its own module for the same reason textDomains.ts is: one copy is the point. A C2 URL must
// become the same indicator whether a Velociraptor script block, a SIEM message, a Cyber Triage row
// or a decoded PowerShell payload carried it. Four scrapers each kept their own copy of this rule,
// and they had already drifted — #744 was filed because two of them disagreed about a destination.
//
// It sits in the PLATFORM layer rather than beside any caller because its callers are not all in
// one analysis domain: deobfuscate.ts is analysis/privacy (tier 1) and the importers are
// analysis/ingest (tier 3). An import may go down a tier or sideways, never up, so no home inside
// analysis/ can serve both. Platform is below every domain, so all four reach it.

// Punctuation that ends a URI written into prose and can never be part of URI syntax. A trailing
// SLASH is absent on purpose: it is part of a bucket prefix or a directory URL, not the sentence.
const PROSE_PUNCTUATION = /[.,;:]/;

// Closers a URI may legally END on, with the opener that makes one structural. A trailing closer
// belongs to the URI when the match opens it and to the sentence when it does not — the difference
// between `http://[2001:db8::1]`, where the bracket is REQUIRED IPv6 authority syntax, and
// `[http://host/a]`, where it is the writer's bracket. Getting this wrong emits a URL that cannot
// be resolved or pivoted on, so it is not a cosmetic trim.
const STRUCTURAL_CLOSERS: ReadonlyArray<readonly [string, string]> = [
  [")", "("],
  ["]", "["],
];

function occurrences(text: string, ch: string): number {
  let n = 0;
  for (const c of text) if (c === ch) n++;
  return n;
}

/**
 * Drop the sentence's punctuation from the end of a matched URI, keeping every character the URI
 * itself needs.
 *
 * Three rules, applied right to left until nothing more comes off:
 *
 *   quote-delimited   `aws s3 cp x 's3://bucket/evidence.'` keeps its dot. An S3 object key may
 *                     legally end in one, and the closing quote says where the value ends — no
 *                     sentence is being punctuated inside it. A URI counts as quote-delimited only
 *                     when the character immediately before it opens a quote AND the character
 *                     immediately after closes the SAME one, so `he said "go to s3://b/x."` still
 *                     strips: there the quote wraps the sentence, not the URI.
 *   structural closer `)` and `]` come off only when the match does not open them. Balanced means
 *                     the URI's own — an IPv6 authority, or a path like `/a(foo)`.
 *   prose punctuation `.` `,` `;` `:` always come off. No URI needs to end in one.
 *
 * `index` is the match's offset in the ORIGINAL text, because the two characters that decide the
 * quote rule sit outside the match — every caller's pattern stops at a quote rather than consuming
 * it.
 */
export function trimSentencePunctuation(match: string, text: string, index: number): string {
  const opener = index > 0 ? text[index - 1] : "";
  const closer = text[index + match.length] ?? "";
  if ((opener === '"' || opener === "'") && closer === opener) return match;

  let out = match;
  for (;;) {
    const last = out.slice(-1);
    if (last === "") break;
    const structural = STRUCTURAL_CLOSERS.find(([close]) => close === last);
    if (structural) {
      const [close, open] = structural;
      // Balanced (or opened more than closed) means the URI needs it. Stop rather than continue:
      // anything to its left is inside the URI too.
      if (occurrences(out, close) <= occurrences(out, open)) break;
      out = out.slice(0, -1);
      continue;
    }
    if (PROSE_PUNCTUATION.test(last)) {
      out = out.slice(0, -1);
      continue;
    }
    break;
  }
  return out;
}
