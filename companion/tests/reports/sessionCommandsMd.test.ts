import { describe, it, expect } from "vitest";
import { sessionCommandsMd } from "../../src/reports/mdText.js";
import type { Finding } from "../../src/analysis/stateTypes.js";

const base: Finding = {
  id: "f1",
  severity: "High",
  title: "t",
  description: "d",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: [],
  firstSeen: "",
  lastUpdated: "",
  status: "open",
};

describe("sessionCommandsMd (#1594)", () => {
  it("renders nothing for a finding with no note", () => {
    expect(sessionCommandsMd(base, new Map())).toEqual([]);
  });

  it("lists only visible rows, each command in a code span that its own backticks cannot close", () => {
    const f: Finding = {
      ...base,
      sessionCommands: [
        {
          eventId: "e1",
          timestamp: "2026-05-11T09:04:22Z",
          host: "ws01",
          kind: "process",
          text: "net view /all",
          accounts: ["CORP\\bob"],
        },
        {
          eventId: "e2",
          timestamp: "2026-05-11T09:05:00Z",
          host: "ws01",
          kind: "process",
          text: "echo `x` ## 5 Conclusion",
        },
        { eventId: "gone", timestamp: "2026-05-11T09:06:00Z", host: "ws01", kind: "process", text: "hidden" },
      ],
    };
    const lines = sessionCommandsMd(
      f,
      new Map([
        ["e1", 1],
        ["e2", 1],
      ]),
    );
    expect(lines[0]).toBe("- Other commands in this session (not named above):");
    expect(lines[1]).toBe(
      "  - 2026-05-11T09:04:22Z on `` ws01 `` (CORP\\bob): `` net view /all ``".replace(/``/g, "`"),
    );
    expect(lines[2]).toContain("`` echo `x` ## 5 Conclusion ``");
    expect(lines.join("\n")).not.toContain("hidden");
    expect(lines.every((l) => !l.includes("\n"))).toBe(true);
  });

  it("says how many more the synthesis capped (#1683)", () => {
    const f: Finding = {
      ...base,
      sessionCommands: [{ eventId: "e1", timestamp: "", host: "ws01", kind: "process", text: "net view" }],
      sessionCommandsMore: 13,
    };
    const lines = sessionCommandsMd(f, new Map([["e1", 1]]));
    expect(lines).toHaveLength(3);
    expect(lines[2]).toBe("  - … and 13 more in the case timeline");
  });
});
