// Where a URI found in free text actually ENDS, shared by every importer that scrapes one.
//
// Its own module for the same reason textDomains.ts is: one copy is the point. A C2 URL must
// become the same indicator whether a Velociraptor script block, a SIEM message or a Cyber Triage
// row carried it. Three importers each kept their own copy of this rule, and they had already
// drifted — #744 was filed because two of them disagreed about a single destination.

// Punctuation that ends a URI written into prose rather than the URI itself. A trailing SLASH is
// absent from the class on purpose: it is part of a bucket prefix or a directory URL, not the
// sentence. Quotes and angle brackets are absent because every caller's pattern already refuses
// them inside a match, so they can never be the last character to trim.
const TRAILING_SENTENCE_PUNCTUATION = /[.,;:)\]]+$/;

/**
 * Drop the sentence's punctuation from the end of a matched URI — unless a quote proves the
 * punctuation belongs to the URI.
 *
 * `upload to s3://bucket/loot.` ends a sentence, so the period is the writer's, and keeping it
 * stores a destination that is not a usable URI and duplicates the same bucket written without it.
 *
 * `aws s3 cp x 's3://bucket/evidence.'` is the opposite case. An S3 object key may legally end in a
 * dot, and the closing quote says where the value ends — no sentence is being punctuated inside it.
 * Stripping there records a destination the script never used. The URI counts as quote-delimited
 * only when the character immediately before it opens a quote AND the character immediately after
 * it closes the SAME one, so `he said "go to s3://bucket/evidence."` still strips: the quote wraps
 * the sentence, not the URI.
 *
 * `index` is the match's offset in the ORIGINAL text, because the two characters that decide this
 * sit outside the match — every caller's pattern stops at a quote rather than consuming it.
 */
export function trimSentencePunctuation(match: string, text: string, index: number): string {
  const opener = index > 0 ? text[index - 1] : "";
  const closer = text[index + match.length] ?? "";
  if ((opener === '"' || opener === "'") && closer === opener) return match;
  return match.replace(TRAILING_SENTENCE_PUNCTUATION, "");
}
