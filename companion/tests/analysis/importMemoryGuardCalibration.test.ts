// The import memory guard's per-event figures against the runs they were set from (#2814). Synthetic
// data, a real server child per run, one case per run, the guard off so nothing was refused; peak RSS
// sampled every 200 ms through the import's settle plus a 20 s tail. If a figure is changed, every row
// here must still sit under it — and with the stated margin where one is stated. Left out on purpose,
// because the per-event figures do not cover it: a large file read whole whose kept rows are capped
// (a 100 MB SIEM file kept at 2,000 rows peaked at 1.4 GB). See importMemoryGuard.ts.
import { describe, it, expect } from "vitest";
import {
  IMPORT_RSS_BYTES_PER_EVENT,
  IMPORT_HEAP_BYTES_PER_EVENT,
} from "../../src/analysis/importMemoryGuard.js";

const MB = 1024 ** 2;
const GB = 1024 ** 3;

// [path, forensic events after the import, peak RSS in MB] — completed runs under `npm run dev`'s
// 8 GB heap, plus the issue's own figures. Velociraptor rows are DetectRaptor-Evtx-style (~7.5 KB).
const RSS_RUNS: Array<[string, number, number]> = [
  ["bulk Velociraptor, empty case", 70_000, 5_244],
  ["bulk Velociraptor, long-running server", 120_000, 7_234],
  ["bulk Velociraptor, long-running server", 170_000, 7_834],
  ["SIEM 2k into a large case, long-running server", 174_000, 9_375],
  ["EVTX XML 2k into a large case, long-running server", 176_000, 9_475],
  ["whole-file Velociraptor, empty case", 20_000, 2_401],
  ["whole-file Velociraptor", 40_000, 3_669],
  ["whole-file Velociraptor", 100_000, 5_633],
  ["SIEM, empty case", 35_000, 3_944],
  ["SIEM", 70_000, 6_234],
  ["SIEM", 105_000, 6_443],
  ["EVTX XML, empty case", 35_000, 3_340],
  ["EVTX XML", 70_000, 5_206],
  ["issue: synthetic seed, fresh server", 70_000, 6_800],
  ["issue: synthetic, fresh server", 166_000, 6_600],
];

// [path, forensic events, V8's heap limit (MB) it was seen to complete under] — heap_size_limit, what
// the guard compares with: 948 MB for --max-old-space-size=900, 4,144 MB for =4096.
const HEAP_PASSES: Array<[string, number, number]> = [
  ["SIEM 35k into an empty case", 35_000, 948],
  ["SIEM 50k-row file into a 178k-event case", 180_000, 4_144],
  ["small Velociraptor and SIEM imports into a 176k-event case", 178_000, 4_144],
];

describe("import memory guard calibration (#2814)", () => {
  it.each(RSS_RUNS)("the RSS estimate covers %s at %i events", (_path, events, peakMb) => {
    expect(events * IMPORT_RSS_BYTES_PER_EVENT).toBeGreaterThanOrEqual(peakMb * MB);
  });

  it("stays above the real-world run that was killed (about 145,000 events, 11.4 GB) by at least 1.25x", () => {
    expect(145_000 * IMPORT_RSS_BYTES_PER_EVENT).toBeGreaterThanOrEqual(1.25 * 11.4 * GB);
  });

  it.each(HEAP_PASSES)("the heap estimate covers %s with a 1.25x margin", (_path, events, heapMb) => {
    expect(events * IMPORT_HEAP_BYTES_PER_EVENT).toBeGreaterThanOrEqual(1.25 * heapMb * MB);
  });
});
