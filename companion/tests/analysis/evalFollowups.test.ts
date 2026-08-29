// MITRE-mapping follow-ups from the Velociraptor eval: T1189 (drive-by download) and
// T1021.001 (RDP lateral movement). T1567.002 (rclone execution) is covered in prefetchExecution.test.
import { describe, it, expect } from "vitest";
import { gradeMotwDownload } from "../../src/analysis/motwDownload.js";
import { rdpLateralSignal } from "../../src/analysis/rdpLateralDetect.js";

describe("gradeMotwDownload — internet download is drive-by initial access (T1189)", () => {
  it("adds T1189 alongside T1204.002 for an internet-zone runnable", () => {
    const g = gradeMotwDownload("3", "installer.msi");
    expect(g.severity).toBe("Medium");
    expect(g.mitre).toContain("T1189");
    expect(g.mitre).toContain("T1204.002");
  });

  it("keeps only T1204.002 for the Restricted zone (4) — no website-compromise claim", () => {
    const g = gradeMotwDownload("4", "tool.exe");
    expect(g.mitre).toContain("T1204.002");
    expect(g.mitre).not.toContain("T1189");
  });

  it("says nothing about a trusted-zone or non-runnable download", () => {
    expect(gradeMotwDownload("1", "installer.msi").mitre).toEqual([]); // intranet zone
    expect(gradeMotwDownload("3", "notes.txt").mitre).toEqual([]); // not runnable/container
  });
});

describe("rdpLateralSignal — explicit-credential logon to a remote host (T1021.001)", () => {
  const row = (over: Record<string, unknown> = {}) => ({
    EventID: 4648,
    ComputerName: "WS-01",
    TargetServer: "DC-01",
    InitiatingUser: "svc_backup",
    SourceIP: "10.0.0.5",
    ...over,
  });

  it("grades a 4648 to a remote server by a real user Medium + T1021.001", () => {
    const s = rdpLateralSignal("Custom.DFIR.RDPLateralMovementDetection", row());
    expect(s?.severity).toBe("Medium");
    expect(s?.mitre).toEqual(["T1021.001"]);
    expect(s?.note).toMatch(/DC-01/);
  });

  it("ignores the local boot noise (UMFD-0 -> localhost) that dominates the artifact", () => {
    expect(
      rdpLateralSignal(
        "Custom.DFIR.RDPLateralMovementDetection",
        row({ TargetServer: "localhost", InitiatingUser: "UMFD-0" }),
      ),
    ).toBeNull();
  });

  it("ignores a machine-account principal and a target that is the host itself", () => {
    expect(
      rdpLateralSignal("Custom.DFIR.RDPLateralMovementDetection", row({ InitiatingUser: "WS-01$" })),
    ).toBeNull();
    expect(
      rdpLateralSignal("Custom.DFIR.RDPLateralMovementDetection", row({ TargetServer: "WS-01" })),
    ).toBeNull();
  });

  it("only fires for that artifact, and only on EID 4648", () => {
    expect(rdpLateralSignal("Windows.EventLogs.Evtx", row())).toBeNull();
    expect(rdpLateralSignal("Custom.DFIR.RDPLateralMovementDetection", row({ EventID: 4624 }))).toBeNull();
  });
});
