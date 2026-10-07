import { describe, it, expect } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";

// The Velociraptor importer and the Hayabusa importer must grade the same level word the same
// way. `emergency` / `emer` is Hayabusa's top level; it once graded Info in the Velociraptor route.

const LEVEL_WORDS = ["emergency", "emer", "critical", "crit", "high", "medium", "med", "low"];

function veloGrade(level: string): string | undefined {
  const row = {
    Timestamp: "2026-09-20T19:29:14Z",
    Computer: "WS-01",
    Level: level,
    Title: "Lab Detection",
    Details: "Proc: C:\\Lab\\tool.exe",
    _Source: "Windows.Hayabusa.Rules",
  };
  return parseVelociraptorJson(JSON.stringify([row])).events[0]?.severity;
}

function hayabusaGrade(level: string): string | undefined {
  const csv = [
    "Timestamp,Computer,Channel,EventID,Level,RuleTitle,Details",
    `2026-09-20 19:29:14.000 +00:00,WS-01,Sec,4688,${level},Lab Detection,Proc: C:\\Lab\\tool.exe`,
  ].join("\n");
  return parseHayabusaTimeline(csv).events[0]?.severity;
}

describe("Velociraptor and Hayabusa routes agree on level words", () => {
  it("grades emergency and emer Critical in the Velociraptor route", () => {
    expect(veloGrade("emergency")).toBe("Critical");
    expect(veloGrade("emer")).toBe("Critical");
  });

  it.each(LEVEL_WORDS)("grades %s the same in both routes", (level) => {
    const h = hayabusaGrade(level);
    expect(h).toBeDefined();
    expect(veloGrade(level)).toBe(h);
  });
});
