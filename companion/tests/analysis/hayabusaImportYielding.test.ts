import { describe, it, expect } from "vitest";
import { parseHayabusaTimeline, parseHayabusaTimelineYielding } from "../../src/analysis/hayabusaImport.js";
import { loopLag } from "./helpers/loopLag.js";

// #2789: a large Hayabusa import parsed and mapped every row in one synchronous block, so /health,
// job polls and close/archive requests hung for tens of seconds. The yielding parse must give the
// synchronous parse's result exactly, and must let timers run while it works.

function row(i: number): Record<string, unknown> {
  return {
    Timestamp: `2024-01-01 10:${String(i % 60).padStart(2, "0")}:00.000 +00:00`,
    Computer: `WS${i % 7}`,
    Channel: "Sec",
    EventID: 4688,
    Level: ["high", "med", "low", "info", "crit"][i % 5],
    RuleTitle: `Rule ${i % 40}`,
    RecordID: i,
    Details: {
      Cmdline: `cmd.exe /c echo ${i} http://example${i % 9}.test/x`,
      Proc: `C:\\Windows\\p${i % 11}.exe`,
      TgtIP: `10.0.${i % 20}.${i % 25}`,
    },
  };
}

const jsonl = (n: number): string => Array.from({ length: n }, (_, i) => JSON.stringify(row(i))).join("\n");

describe("the yielding Hayabusa parse (#2789)", () => {
  it("gives the synchronous parse's result for JSONL, CSV, aggregated and unaggregated", async () => {
    const text = jsonl(400);
    for (const opts of [{}, { aggregate: false }, { minSeverity: "Medium" as const }]) {
      expect(await parseHayabusaTimelineYielding(text, opts)).toEqual(parseHayabusaTimeline(text, opts));
    }
    const csv = [
      "Timestamp,Computer,Channel,EventID,Level,RuleTitle,Details",
      ...Array.from(
        { length: 200 },
        (_, i) =>
          `2024-01-01 10:00:${String(i % 60).padStart(2, "0")}.000 +00:00,WS${i % 3},Sec,4688,high,R${i % 5},"Proc: C:\\a${i % 4}.exe ¦ Cmdline: x ${i}"`,
      ),
    ].join("\n");
    expect(await parseHayabusaTimelineYielding(csv)).toEqual(parseHayabusaTimeline(csv));
    expect(await parseHayabusaTimelineYielding("")).toEqual(parseHayabusaTimeline(""));
  });

  it("lets timers run while it maps a large file", async () => {
    const text = jsonl(6000);
    const sync = await loopLag(async () => {
      parseHayabusaTimeline(text);
    });
    const yielding = await loopLag(() => parseHayabusaTimelineYielding(text));
    // The synchronous parse is one block: the timer cannot fire until it ends.
    expect(sync.ticks).toBeLessThanOrEqual(1);
    // The yielding parse hands the loop a turn about every 25 ms of mapping.
    expect(yielding.ticks).toBeGreaterThanOrEqual(5);
    expect(yielding.maxGapMs).toBeLessThan(Math.max(250, sync.maxGapMs));
  }, 60_000);
});
