// MITRE-mapping follow-ups from the Velociraptor eval: T1189 (drive-by download) and
// T1021.001 (RDP lateral movement). T1567.002 (rclone execution) is covered in prefetchExecution.test.
import { describe, it, expect } from "vitest";
import { gradeMotwDownload } from "../../src/analysis/motwDownload.js";
import { rdpLateralSignal } from "../../src/analysis/rdpLateralDetect.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

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

  it("reads a native 4648's TargetServerName / SubjectUserName field names too (not only the artifact aliases)", () => {
    const native = {
      EventID: 4648,
      Computer: "WS-01",
      TargetServerName: "DC-01",
      SubjectUserName: "svc_backup",
      IpAddress: "10.0.0.5",
    };
    const s = rdpLateralSignal("Custom.DFIR.RDPLateralMovementDetection", native);
    expect(s?.mitre).toEqual(["T1021.001"]);
  });
});

describe("RDP-lateral artifact — the suppressed boot rows are not re-raised by the overlay/floor", () => {
  it("keeps local UMFD boot 4648 rows at Info through the full parse, and grades a remote one Medium + T1021.001", () => {
    const rows = [
      // local boot noise — must stay Info despite the artifact name ending in 'Detection' and the flat 4648 overlay.
      {
        EventID: 4648,
        ComputerName: "WS-01",
        TargetServer: "localhost",
        TargetAccount: "UMFD-0",
        InitiatingUser: "WS-01$",
      },
      // a real remote pivot.
      {
        EventID: 4648,
        ComputerName: "WS-01",
        TargetServer: "DC-01",
        TargetAccount: "svc",
        InitiatingUser: "svc_backup",
        SourceIP: "10.0.0.9",
      },
    ];
    const r = parseVelociraptorJson(JSON.stringify(rows), {
      artifact: "Custom.DFIR.RDPLateralMovementDetection",
      aggregate: false,
    });
    const remote = r.events.find((e) => (e.description || "").includes("DC-01"));
    const boot = r.events.find(
      (e) => (e.description || "").includes("UMFD-0") || (e.description || "").includes("localhost"),
    );
    expect(remote?.severity).toBe("Medium");
    expect(remote?.mitreTechniques).toContain("T1021.001");
    expect(boot?.severity).toBe("Info"); // NOT re-raised to Medium/T1078
  });
});
