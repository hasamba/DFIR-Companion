import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

// #1599: only four things may start a synthesis.
//
//   1. the analyst turns AI on for the case          → backfill → scheduleSynthesis
//   2. the analyst presses Re-synthesize / /synthesize → POST /cases/:id/synthesize, slash command
//   3. an import finishes while AI is on              → resynthesizeInBackground (every import path)
//   4. the analyst resolves the last duplicate-host pair → resynthesizeInBackground
//
// Screenshot captures count as evidence arriving, like an import (flush → scheduleSynthesis). The
// analysis-run replay re-runs a recorded synthesis on the analyst's request.
//
// Everything else marks the conclusions out of date (ctx.markConclusionsOutOfDate) and the analyst
// decides when to pay. On a lab case the anonymization switch called pipeline.synthesize() directly,
// with no job and no busy check, and ran a second seven-minute synthesis beside the AI-on catch-up.
//
// This test lists every call site outside analysis/ (the pipeline's own internals) and fails on a
// new one. Adding a site is a product decision about when the analyst pays for a run: if it is not
// one of the four triggers above, call markConclusionsOutOfDate instead. If it is, add it here and say
// which trigger it is.

const SRC = join(__dirname, "..", "..", "src");

/** file (relative to src, forward slashes) → number of call sites. */
type Sites = Record<string, number>;

const RESYNTHESIZE_IN_BACKGROUND: Sites = {
  // 3. import completion
  "composition/importIngest.ts": 2,
  "composition/veloExternalIngest.ts": 4,
  "composition/veloHunts.ts": 1,
  "routes/import.ts": 2,
  "routes/importCommit.ts": 1,
  "routes/importRecovery.ts": 1,
  "routes/reportsExport.ts": 1, // IRIS import
  "routes/analysisRuns.ts": 1, // import replay
  // 2. the /synthesize slash command
  "routes/slashCommand.ts": 1,
  // 4. the last duplicate-host pair
  "routes/hostDuplicates.ts": 1,
};

const SCHEDULE_SYNTHESIS: Sites = {
  // 1. AI on (backfill ×2) and screenshot windows analyzed (flush ×1), plus its own busy retry.
  "composition/captureAnalysis.ts": 4,
};

// Direct pipeline.synthesize() calls. Each must sit inside an exclusive `synthesis` job — the one
// busy check every synthesis goes through (see the second test).
const DIRECT_SYNTHESIZE: Sites = {
  "composition/captureAnalysis.ts": 2, // the scheduled run and resynthesizeInBackground's run
  "routes/aiSynthesis.ts": 1, // 2. Re-synthesize
  "routes/analysisRuns.ts": 1, // synthesis replay
};

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return entry.name.endsWith(".ts") ? [path] : [];
  });
}

/** Source without comments, so prose about a call is never counted as one. */
function code(path: string): string {
  return readFileSync(path, "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
}

/** Calls of `name(`, excluding its declaration and type signatures (an argument with a `:`). */
function countCalls(text: string, pattern: RegExp): number {
  let n = 0;
  for (const m of text.matchAll(pattern)) {
    const before = text.slice(Math.max(0, (m.index ?? 0) - 9), m.index);
    if (/function\s*$/.test(before)) continue;
    if (m[1].includes(":")) continue;
    n += 1;
  }
  return n;
}

function scan(pattern: RegExp): Sites {
  const sites: Sites = {};
  for (const file of sourceFiles(SRC)) {
    const rel = relative(SRC, file).split(sep).join("/");
    if (rel.startsWith("analysis/")) continue; // the pipeline's own internals
    const n = countCalls(code(file), pattern);
    if (n > 0) sites[rel] = n;
  }
  return sites;
}

describe("synthesis entry points (#1599)", () => {
  it("resynthesizeInBackground is called only by an allowed trigger", () => {
    expect(scan(/\bresynthesizeInBackground\(([^)]*)\)/g)).toEqual(RESYNTHESIZE_IN_BACKGROUND);
  });

  it("scheduleSynthesis is called only by AI-on and screenshot analysis", () => {
    expect(scan(/\bscheduleSynthesis\(([^)]*)\)/g)).toEqual(SCHEDULE_SYNTHESIS);
  });

  it("pipeline.synthesize is called directly only by Re-synthesize, replay and the two job-wrapped runs", () => {
    expect(scan(/[.!]synthesize\(()/g)).toEqual(DIRECT_SYNTHESIZE);
  });

  it("every direct synthesize() call site registers an exclusive synthesis job — the one busy check", () => {
    for (const rel of Object.keys(DIRECT_SYNTHESIZE)) {
      const text = code(join(SRC, rel));
      expect(text, rel).toMatch(/kind:\s*"synthesis"/);
      expect(text, rel).toMatch(/exclusive:\s*true/);
    }
  });
});
