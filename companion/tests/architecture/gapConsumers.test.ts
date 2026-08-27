import { readFile, readdir } from "node:fs/promises";
import { describe, expect, it } from "vitest";

// Whether a silence is missing data or accounted-for dwell time between two waves of activity is a
// property of the TIMELINE, not an opinion one caller holds. Every surface that shows a gap has to
// show the same answer.
//
// It did not, once. `betweenWaves` was set inside the synthesis merge and nowhere else, so the case
// carried a Medium "dwell interval" finding while the coverage panel, the Markdown report and the
// gap-hypothesis prompt each called that identical window a High complete-silence log-tampering gap
// — three surfaces contradicting the finding written about the same minutes.
//
// The fix was `detectGapsWithWaves`, which detects and marks in one step. This test is what keeps it
// the only door: a new caller reaching for the raw detector gets an unmarked gap and reintroduces the
// contradiction silently, because nothing about an unmarked gap looks wrong on its own.
const ALLOWED = new Set(["analysis/gapDetect.ts", "analysis/activityWaves.ts"]);

async function tsFilesUnder(dir: URL, prefix = ""): Promise<{ rel: string; url: URL }[]> {
  const out: { rel: string; url: URL }[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...(await tsFilesUnder(new URL(`${entry.name}/`, dir), rel)));
    else if (entry.name.endsWith(".ts")) out.push({ rel, url: new URL(entry.name, dir) });
  }
  return out;
}

describe("timeline gap consumers", () => {
  it("route every gap read through detectGapsWithWaves", async () => {
    const src = new URL("../../src/", import.meta.url);
    const files = await tsFilesUnder(src);
    const offenders: string[] = [];
    for (const { rel, url } of files) {
      if (ALLOWED.has(rel)) continue;
      const text = await readFile(url, "utf8");
      // A call, not a mention: the import list and prose comments are fine.
      if (/\bdetectTimelineGaps\s*\(/.test(text)) offenders.push(rel);
    }
    expect(
      offenders,
      "these call detectTimelineGaps directly and will render gaps that contradict the findings; " +
        "use detectGapsWithWaves from analysis/activityWaves.ts instead",
    ).toEqual([]);
  });
});
