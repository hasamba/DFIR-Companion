/**
 * The ARCHITECTURE.md numbers that check-boundaries.mjs derives (issue #907).
 *
 * WHY THIS EXISTS. The ledger's length is quoted in that document's prose wherever it states a
 * violation count. tests/architecture/moduleMap.test.ts asserts every such claim against the gate,
 * so it cannot rot — but until #907 nothing WROTE it, so every PR that shrank the ledger hand-edited
 * a number. The gate already rewrites the ledger it derives; this is the same idea applied to the
 * prose that quotes it.
 *
 * WHAT IT NO LONGER WRITES (#1368). The "N of the M cross-domain file dependencies already comply"
 * pair was derived and pinned here too, and that pin cost a CI cycle per lost race: both halves
 * move with every import added anywhere in the tree, so any two concurrent PRs regenerated the
 * same sentence to different values and the second to merge went CONFLICTING against the merge
 * result. The violation count only moves when the ledger does — a deliberate, reviewed act — so it
 * stays. The live pair is `check-boundaries.mjs --json`'s output and is not committed anywhere;
 * moduleMap.test.ts fails if the sentence is written back into the prose.
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

// Deliberately the same pattern tests/architecture/moduleMap.test.ts reads the claims with, so the
// writer and the checker cannot disagree about what counts as a claim. A bare `\d+`, never a
// thousands separator: `1,039 violations` would match as "039".
const VIOLATIONS = /(\d+)(\s+(?:recorded\s+)?(?:file-pair\s+)?violations?)/gi;

/**
 * `doc` with every derived figure replaced by this scan's own counts.
 *
 * Returns the new text plus what was found, so the caller can report a document that no longer
 * carries a claim it is supposed to carry.
 */
export function architectureWithCounts(doc, { violations }) {
  let violationClaims = 0;
  const text = doc.replace(VIOLATIONS, (_match, _count, tail) => {
    violationClaims += 1;
    return `${violations}${tail}`;
  });

  return { text, changed: text !== doc, violationClaims };
}
