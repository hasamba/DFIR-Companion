// #1265: every writer of `canonical.network.source.address` that #1184's own cross-importer audit
// (PR #1267), plus this PR's own additional check of siemImport.ts, confirmed genuinely
// edge-observed must stamp `provenance: "edge-observed"` alongside it — a category-based reader
// filter is unsound (exchangeAuditImport.ts/mailboxChain.ts are genuinely edge-observed but share
// `category: "email"` with the one confirmed-forgeable writer, emailImport.ts).
//
// WHAT THIS DOES NOT CATCH — read before trusting a green run here as proof of anything beyond its
// own 15 registered files: this is a fixed ALLOWLIST, not a whole-codebase scan. A brand-new writer
// of `network.source.address` that is never added to SITES below passes silently, exactly like the
// omission it exists to catch would. It is also plain-text, not AST-based: property-shorthand
// (`{ address }`), a computed key, or a write routed through a shared helper outside these 15 files
// are all invisible to it. A whole-codebase, AST-level gate was considered and deliberately
// deferred (see RECOMMENDATION-1265.md's own "Landing scope") to avoid scope creep on top of an
// already-substantial PR — this sweep is a regression pin for the 15 sites audited AS OF #1265,
// not a standing guarantee for every future one. Add a new writer to SITES (stamped) when you
// confirm it edge-observed, and re-read this comment before assuming a green run means more than
// that.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ANALYSIS_DIR = fileURLToPath(new URL("../../src/analysis/", import.meta.url));

/** One entry per real write site. `occurrences` lets a file with more than one site (e.g.
 * cloudActivityImport.ts writes from two different Azure/GCP branches) require every one to be
 * stamped, not just the first. */
const SITES: { file: string; occurrences: number }[] = [
  { file: "awsImport.ts", occurrences: 1 },
  { file: "awsComputeRow.ts", occurrences: 1 },
  { file: "awsLineage.ts", occurrences: 1 },
  { file: "azureStorageLogImport.ts", occurrences: 1 },
  { file: "cloudActivityImport.ts", occurrences: 2 },
  { file: "gcpRow.ts", occurrences: 1 },
  { file: "googleWorkspaceImport.ts", occurrences: 2 },
  { file: "m365Import.ts", occurrences: 1 },
  { file: "entraAuditImport.ts", occurrences: 2 },
  { file: "exchangeAuditImport.ts", occurrences: 1 },
  { file: "mailboxChain.ts", occurrences: 1 },
  { file: "passwordSprayFanout.ts", occurrences: 1 },
  { file: "webChainRows.ts", occurrences: 1 },
  { file: "combinedLogImport.ts", occurrences: 1 },
  { file: "siemImport.ts", occurrences: 1 },
];

/** Every `source: { address: <expr> }` object-literal slice in the file, found by matching
 * balanced braces from each `source: {` so a multi-field literal (address + port + provenance) is
 * captured whole regardless of key order or added fields. */
function sourceLiterals(source: string): string[] {
  const literals: string[] = [];
  const marker = /source:\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = marker.exec(source))) {
    const start = m.index + m[0].length - 1; // position of the opening "{"
    let depth = 0;
    let end = start;
    for (let i = start; i < source.length; i++) {
      if (source[i] === "{") depth++;
      else if (source[i] === "}") {
        depth--;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    const literal = source.slice(start, end + 1);
    if (/\baddress\s*:/.test(literal)) literals.push(literal);
  }
  return literals;
}

describe("network.source.address writers stamp provenance (#1265)", () => {
  for (const { file, occurrences } of SITES) {
    it(`${file} stamps provenance: "edge-observed" at every address write site`, () => {
      const text = readFileSync(path.join(ANALYSIS_DIR, file), "utf8");
      const literals = sourceLiterals(text);
      expect(literals.length).toBe(occurrences);
      for (const literal of literals) {
        expect(literal).toMatch(/provenance:\s*"edge-observed"/);
      }
    });
  }

  it("emailImport.ts does not write canonical.network.source.address at all (#1184's own fix, pinned)", () => {
    const text = readFileSync(path.join(ANALYSIS_DIR, "emailImport.ts"), "utf8");
    expect(sourceLiterals(text)).toEqual([]);
  });
});
