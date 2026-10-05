import { describe, it, expect } from "vitest";
import { renderCommandLineTag, CMD_TAG_MAX } from "../../src/analysis/commandLineTag.js";
import { renderStructuredTags } from "../../src/analysis/synthEvidence.js";
import { promptDescription } from "../../src/analysis/ai/promptDescription.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1",
    timestamp: p.timestamp ?? "2026-01-01T00:00:00Z",
    description: p.description ?? "x",
    severity: p.severity ?? "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const ARGS =
  "-NoProfile -ExecutionPolicy Bypass -Command Write-Output LAB-SAFE-CANARY irm-1614733393-12-represented";

// The shape of a Chainsaw Sysmon EID 1 row: rule name, Image=, CommandLine= (import already dropped
// the image prefix behind a "…" marker), ParentImage=, ParentCommandLine=, host. ~480 characters.
const CHAINSAW_EID1 =
  "Chainsaw: Sysmon EID 1 Process Creation - Suspicious PowerShell Execution Policy Bypass - " +
  `Image=${PS} - CommandLine=… ${ARGS} - ` +
  "ParentImage=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe - " +
  "ParentCommandLine=… -NoLogo -NonInteractive -File C:\\ProgramData\\lab\\run.ps1 - " +
  `User=LAB\\analyst - ${PS} @ ws01.example.com`;

const eid1 = (p: Partial<ForensicEvent> = {}): ForensicEvent =>
  ev({
    asset: "ws01.example.com",
    processName: "powershell.exe",
    parentName: "powershell.exe",
    path: PS.toLowerCase(),
    commandLine: `"${PS.replace("Windows", "WINDOWS")}" ${ARGS}`,
    description: CHAINSAW_EID1,
    ...p,
  });

describe("renderCommandLineTag (#1951)", () => {
  it("the fixture is long enough that the 240-char render hides the arguments", () => {
    expect(CHAINSAW_EID1.length).toBeGreaterThan(400);
    expect(promptDescription(CHAINSAW_EID1)).not.toContain("-ExecutionPolicy Bypass");
  });

  it("gives a long Chainsaw EID 1 row every argument of its command line", () => {
    const tag = renderCommandLineTag(eid1());
    expect(tag).toBe(`<cmd:${ARGS}>`);
    const line = promptDescription(CHAINSAW_EID1) + renderStructuredTags(eid1());
    for (const arg of ARGS.split(" ")) expect(line).toContain(arg);
  });

  it("returns nothing for a row with no commandLine, so the row renders as today", () => {
    expect(renderCommandLineTag(eid1({ commandLine: undefined }))).toBe("");
    const bare = ev({ asset: "WS07", processName: "powershell.exe", description: CHAINSAW_EID1 });
    expect(renderStructuredTags(bare)).toBe(" <host:WS07> <proc:powershell.exe>");
  });

  it("adds no tag when the description already shows the arguments", () => {
    const short = `Sysmon EID 1 powershell.exe ${ARGS}`;
    expect(short.length).toBeLessThanOrEqual(240);
    expect(renderCommandLineTag(eid1({ description: short }))).toBe("");
  });

  it("adds no tag when the command line is only the image", () => {
    expect(renderCommandLineTag(eid1({ commandLine: `"${PS}"` }))).toBe("");
  });

  it("keeps the head and the tail of a command line longer than the cap", () => {
    const long = `-enc ${"A".repeat(400)} -TailMarker`;
    const tag = renderCommandLineTag(eid1({ commandLine: `${PS} ${long}` }));
    const value = tag.slice("<cmd:".length, -1);
    expect(value.length).toBeLessThanOrEqual(CMD_TAG_MAX);
    expect(value.startsWith("-enc AAAA")).toBe(true);
    expect(value).toContain(" … ");
    expect(value.endsWith("-TailMarker")).toBe(true);
  });

  it("one-lines adversary content and strips angle brackets and control characters", () => {
    const tag = renderCommandLineTag(eid1({ commandLine: `${PS} -c "a>b"\r\n<evil:1>\u0007 \t done` }));
    expect(tag).toBe('<cmd:-c "ab" evil:1 done>');
    expect(tag).not.toMatch(/[\r\n\t\u0000-\u001f]/u);
    expect(tag.split("<").length - 1).toBe(1);
    expect(tag.split(">").length - 1).toBe(1);
  });

  it("drops a bare, case-different leading image path that names the process", () => {
    const tag = renderCommandLineTag(eid1({ commandLine: `${PS.toUpperCase()} ${ARGS}` }));
    expect(tag).toBe(`<cmd:${ARGS}>`);
    expect(tag).not.toContain("…");
  });

  it("drops a leading image path that holds spaces when it repeats e.path", () => {
    const img = "C:\\Program Files\\Lab Tool\\tool.exe";
    const tag = renderCommandLineTag(
      eid1({ processName: "tool.exe", path: img.toLowerCase(), commandLine: `${img} --run now` }),
    );
    expect(tag).toBe("<cmd:--run now>");
  });

  it("keeps a command line whose first word is a different image verbatim", () => {
    const tag = renderCommandLineTag(eid1({ commandLine: "cmd.exe /c whoami /all" }));
    expect(tag).toBe("<cmd:cmd.exe /c whoami /all>");
  });
});
