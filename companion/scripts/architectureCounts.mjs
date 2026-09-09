/**
 * The ARCHITECTURE.md numbers that check-boundaries.mjs derives (issue #907).
 *
 * WHY THIS EXISTS. Three figures in that document are outputs of the boundary scan: the comply/total
 * pair, and the ledger's length wherever the prose quotes it. tests/architecture/moduleMap.test.ts
 * asserts all three against the gate, so they cannot rot — but until now nothing WROTE them, so
 * every PR that added a cross-domain import hand-edited a number it could not know without running
 * the script, and two branches touching the same sentence conflicted on it. The gate already
 * rewrites the ledger it derives; this is the same idea applied to the prose that quotes it.
 *
 * WHY IT IS A SEPARATE MODULE. check-boundaries.mjs executes its whole scan at import time and calls
 * process.exit in most branches, so a test cannot import a function out of it. Pure string in,
 * string out, here, and the writeFileSync stays with the caller.
 *
 * WHY IT ONLY EVER REWRITES. If a sentence is missing the function leaves the document untouched and
 * says so, rather than inserting prose. A doc that lost the sentence has drifted structurally, which
 * is a question for a person; silently writing a new one would hide the drift and let the guard test
 * pass on text nobody wrote.
 */

// Deliberately the same two patterns tests/architecture/moduleMap.test.ts reads the claims with, so
// the writer and the checker cannot disagree about what counts as a claim.
const PAIR = /([\d,]+) of the ([\d,]+) cross-domain file dependencies already comply/;
const VIOLATIONS = /(\d+)(\s+(?:recorded\s+)?(?:file-pair\s+)?violations?)/gi;

// The two claims are formatted DIFFERENTLY, and the difference is load-bearing. The guard test reads
// the pair with `[\d,]+` and the violation count with a bare `\d+`, so a thousands separator is
// required on one and would break the other — `1,039 violations` matches that pattern as "039".
// Group separators here, none below.
const grouped = (n) => n.toLocaleString("en-US");

/**
 * `doc` with every derived figure replaced by this scan's own counts.
 *
 * Returns the new text plus what was found, so the caller can report a document that no longer
 * carries a claim it is supposed to carry.
 */
export function architectureWithCounts(doc, { complying, crossDomain, violations }) {
  const pair = PAIR.test(doc);
  let text = doc.replace(
    PAIR,
    `${grouped(complying)} of the ${grouped(crossDomain)} cross-domain file dependencies already comply`,
  );

  let violationClaims = 0;
  text = text.replace(VIOLATIONS, (_match, _count, tail) => {
    violationClaims += 1;
    return `${violations}${tail}`;
  });

  return { text, changed: text !== doc, pair, violationClaims };
}
