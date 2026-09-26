import { describe, it, expect } from "vitest";
import {
  BUILD_TIME_MARKER,
  buildMarkerKind,
  buildTimeContextBlock,
  buildTimeSupport,
  buildTimeWindows,
  capBuildTimeRows,
  hardAttackerSignal,
  repairBuildTimeRows,
  protectedFromCap,
  renderBuildTimeTag,
} from "../../src/analysis/buildTimeWindow.js";
import { applyToForensicEvent } from "../../src/analysis/tagger.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { HostRenameRecord } from "../../src/analysis/hostRenameRecord.js";

// The rows are modelled on INC-2026-001 (lab scenario 018): one VM provisioned on 2025-12-05 under
// WIN-UK1GV882OK6 with Vagrant/Chocolatey, re-imaged by Packer on 2026-08-26 under WIN-0NNTB2RTNB1,
// finally DESKTOP-16OJFO6. Every row the case holds is filed under the CURRENT name, with the former
// one only in the description — which is why the window matches on the whole rename chain.
const HOST = "DESKTOP-16OJFO6";

const renames: HostRenameRecord[] = [
  {
    formerName: "WIN-UK1GV882OK6",
    currentName: "DESKTOP-16OJFO6",
    until: "2025-12-05T03:11:54.000Z",
    basis: "collector",
  },
  {
    formerName: "WIN-0NNTB2RTNB1",
    currentName: "DESKTOP-16OJFO6",
    until: "2026-08-26T13:49:53.000Z",
    basis: "collector",
  },
];

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: "",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: HOST,
    sources: ["Chainsaw"],
    ...extra,
  };
}

// The 2025-12-05 Vagrant/Chocolatey run, as Chainsaw / DetectRaptor recorded it.
const decemberBuild = (): ForensicEvent[] => [
  ev("d1", "2025-12-05T02:43:39Z", {
    severity: "Low",
    path: "c:\\programdata\\chocolatey\\tools\\7z.exe",
    description: "DetectRaptor Amcache detection: Archive Utilities - 7z.exe",
  }),
  ev("d2", "2025-12-05T02:43:42Z", {
    severity: "High",
    mitreTechniques: ["T1059.001", "T1134.001"],
    description:
      "DetectRaptor Evtx detection: T1059.001-Mimikatz Execution via PowerShell - $type = Add-Type $definition -PassThru (EID 800)",
  }),
  ev("d3", "2025-12-05T02:43:45Z", {
    severity: "Medium",
    description:
      "Chainsaw/Sigma: A Rule Has Been Deleted From The Windows Firewall Exception List (EID 2052) [logged under former hostname WIN-UK1GV882OK6]",
  }),
  ev("d4", "2025-12-05T03:02:24Z", {
    severity: "Medium",
    description:
      "Chainsaw/Sigma: Potential PowerShell Obfuscation Using Alias Cmdlets (EID 4104) - ScriptBlockText=# Copyright 2017-2021 Chocolatey Software, Inc.",
  }),
  ev("d5", "2025-12-05T03:04:31Z", {
    severity: "Medium",
    description:
      'Sigma: Potentially Malicious PwSh (EID 4104) - ScriptBlockText=$name = "packer-69324bbd-78e3-ea09-f941-d37c8d6f2fb9"',
  }),
  ev("d6", "2025-12-05T03:26:42Z", {
    severity: "Critical",
    mitreTechniques: ["T1070.001"],
    description:
      "Chainsaw/Log Tampering: Security Audit Logs Cleared - Windows Security Security audit log cleared (EID 1102) [logged under former hostname WIN-UK1GV882OK6]",
  }),
  ev("d7", "2025-12-05T03:27:07Z", {
    severity: "Medium",
    mitreTechniques: ["T1543.003"],
    path: "\\SystemRoot\\System32\\drivers\\vmusbmouse.sys",
    description:
      "Chainsaw/Service Installation: Suspicious Paths Service Installation (EID 7045) - ServiceName=VMware USB Pointing Device",
  }),
];

// The 2026-08-26 Packer first boot: the machine account makes `vagrant` and runs Autounattend.ps1.
const augustBuild = (): ForensicEvent[] => [
  ev("a1", "2026-08-26T13:50:08Z", {
    severity: "Medium",
    mitreTechniques: ["T1543.003"],
    path: "\\SystemRoot\\System32\\drivers\\e1i68x64.sys",
    description:
      "Chainsaw/Service Installation: Suspicious Paths Service Installation (EID 7045) - ServiceName=Intel(R) PRO/1000 PCI Express Network Connection",
  }),
  ev("a2", "2026-08-26T13:52:13Z", {
    severity: "Medium",
    mitreTechniques: ["T1136.001"],
    description:
      "Chainsaw/Account Tampering: New User Created - Windows Security User account created (EID 4720) - WIN-0NNTB2RTNB1\\vagrant, WORKGROUP\\WIN-0NNTB2RTNB1$",
  }),
  ev("a3", "2026-08-26T13:52:14Z", {
    severity: "High",
    mitreTechniques: ["T1098"],
    description:
      "Chainsaw/Account Tampering: User Added to Local Group - Member added to local security group (EID 4732) - Builtin\\Administrators, WORKGROUP\\WIN-0NNTB2RTNB1$",
  }),
  ev("a4", "2026-08-26T13:53:10Z", {
    severity: "Medium",
    description:
      "Sigma: Potentially Malicious PwSh (EID 4104) - ScriptBlockText=Set-ExecutionPolicy Bypass -Force; C:\\Windows\\Temp\\packer\\Autounattend.ps1",
  }),
];

// The scenario itself: three minutes of Cobalt Strike, nine months after the first build.
const scenario = (): ForensicEvent[] => [
  ev("s1", "2026-09-22T08:32:10Z", {
    severity: "High",
    description: "Cobalt Strike beacon: rundll32.exe connecting to 203.0.113.10:443",
    dstIp: "203.0.113.10",
  }),
  ev("s2", "2026-09-22T08:34:41Z", {
    severity: "Critical",
    description: "LockBit ransom note written",
    path: "C:\\Users\\Public\\HOW-TO-DECRYPT-FILES.txt",
  }),
];

function stateWith(events: ForensicEvent[]): InvestigationState {
  return { ...emptyState("INC-TEST"), forensicTimeline: events, hostRenames: renames };
}

describe("buildMarkerKind", () => {
  it("names the provisioner behind a row", () => {
    const [choco, mimikatz, , chocoScript, packer] = decemberBuild();
    expect(buildMarkerKind(choco)).toBe("chocolatey");
    expect(buildMarkerKind(chocoScript)).toBe("chocolatey");
    expect(buildMarkerKind(packer)).toBe("packer");
    // The false-positive Mimikatz row is NOT a marker: it is capped because of WHERE it sits.
    expect(buildMarkerKind(mimikatz)).toBeNull();
  });

  it("reads the machine account as the subject of an account-management record", () => {
    const [, created] = augustBuild();
    expect(buildMarkerKind(created)).toBe("machine-account provisioning");
  });

  it("does not read a human account creation as provisioning", () => {
    const human = ev("h1", "2026-09-22T08:33:00Z", {
      description:
        "Chainsaw/Account Tampering: New User Created - Windows Security User account created (EID 4720) - DESKTOP-16OJFO6\\svc_backup, DESKTOP-16OJFO6\\Administrator",
    });
    expect(buildMarkerKind(human)).toBeNull();
  });

  it("reads a machine-account subject from the canonical envelope, not only from prose", () => {
    const row = ev("c1", "2026-08-26T13:52:13Z", {
      description: "User account created (EID 4720)",
      canonical: {
        schemaVersion: "1.0.0",
        event: { category: "other", type: "event" },
        subject: { kind: "account", name: "WORKGROUP\\WIN-0NNTB2RTNB1$" },
      },
    } as Partial<ForensicEvent>);
    expect(buildMarkerKind(row)).toBe("machine-account provisioning");
  });
});

describe("buildTimeWindows", () => {
  it("finds both build bursts of the scenario-018 host and leaves the incident alone", () => {
    const events = [...decemberBuild(), ...augustBuild(), ...scenario()];
    const windows = buildTimeWindows(events, renames);
    expect(windows).toHaveLength(2);
    expect(windows[0].host).toBe(HOST);
    expect(Date.parse(windows[0].start)).toBeLessThan(Date.parse("2025-12-05T02:43:39Z"));
    expect(Date.parse(windows[0].end)).toBeGreaterThan(Date.parse("2025-12-05T03:27:07Z"));
    expect(Date.parse(windows[1].start)).toBeLessThan(Date.parse("2026-08-26T13:50:08Z"));
    expect(Date.parse(windows[1].end)).toBeLessThan(Date.parse("2026-09-22T08:32:10Z"));
  });

  it("opens no window when the case never learned a rename", () => {
    expect(buildTimeWindows([...decemberBuild()], [])).toEqual([]);
  });

  it("refuses a lone uncorroborated marker", () => {
    const stray = [
      ev("x1", "2027-01-04T10:00:00Z", {
        severity: "Medium",
        path: "C:\\Windows\\Installer\\msi1234.tmp",
        description: "MSI installer artifact",
      }),
    ];
    expect(buildTimeWindows(stray, renames)).toEqual([]);
  });

  it("drops a window whose burst holds a hard attacker signal", () => {
    const events = [
      ...decemberBuild(),
      ev("d8", "2025-12-05T03:20:00Z", {
        severity: "High",
        description: "Credential store theft: ntdsutil ifm create full c:\\temp\\ntds.dit",
      }),
    ];
    expect(buildTimeWindows(events, renames)).toEqual([]);
  });

  it("does not cover a host outside the rename chain", () => {
    const other = decemberBuild().map((e) => ({ ...e, asset: "FILE-SRV-02" }));
    expect(buildTimeWindows(other, renames)).toEqual([]);
  });
});

describe("capBuildTimeRows", () => {
  it("caps the provisioning-day log clear and the Packer account burst, and keeps the incident graded", () => {
    const { state, changed } = capBuildTimeRows(
      stateWith([...decemberBuild(), ...augustBuild(), ...scenario()]),
    );
    expect(changed).toBeGreaterThan(0);
    const byId = new Map(state.forensicTimeline.map((e) => [e.id, e]));
    expect(byId.get("d6")!.severity).toBe("Low"); // the case's only Critical was a build-day 1102
    expect(byId.get("d6")!.buildTime?.cappedFrom).toBe("Critical");
    expect(byId.get("d6")!.description).toContain(BUILD_TIME_MARKER);
    expect(byId.get("d2")!.severity).toBe("Low"); // the Chocolatey "Mimikatz"
    expect(byId.get("d7")!.severity).toBe("Low"); // the VMware driver service
    expect(byId.get("a3")!.severity).toBe("Low"); // "rogue account added to Administrators"
    expect(byId.get("s1")!.severity).toBe("High");
    expect(byId.get("s1")!.buildTime).toBeUndefined();
    expect(byId.get("s2")!.severity).toBe("Critical");
  });

  it("never raises, and leaves an Info row Info", () => {
    const info = ev("i1", "2025-12-05T03:00:00Z", { description: "RDS session logoff (EID 23)" });
    const { state } = capBuildTimeRows(stateWith([...decemberBuild(), info]));
    const row = state.forensicTimeline.find((e) => e.id === "i1")!;
    expect(row.severity).toBe("Info");
    expect(row.buildTime?.cappedFrom).toBeUndefined();
  });

  it("is idempotent — a second pass changes nothing and adds no second note", () => {
    const first = capBuildTimeRows(stateWith([...decemberBuild(), ...augustBuild()]));
    const second = capBuildTimeRows(first.state);
    expect(second.changed).toBe(0);
    expect(second.state).toBe(first.state);
    const notes = second.state.forensicTimeline.filter(
      (e) => (e.description.match(/\[build-time:/g) ?? []).length > 1,
    );
    expect(notes).toEqual([]);
  });

  it("gives a row its grade back when the window is contradicted", () => {
    const capped = capBuildTimeRows(stateWith([...decemberBuild(), ...augustBuild()]));
    const cleared = capBuildTimeRows({ ...capped.state, hostRenames: [] });
    const byId = new Map(cleared.state.forensicTimeline.map((e) => [e.id, e]));
    expect(byId.get("d6")!.severity).toBe("Critical");
    expect(byId.get("d6")!.buildTime).toBeUndefined();
    expect(byId.get("d6")!.description).not.toContain(BUILD_TIME_MARKER);
  });

  it("keeps an analyst-promoted row inside the window at its own grade", () => {
    const promoted = decemberBuild().map((e) =>
      e.id === "d6" ? { ...e, promotedAt: "2026-09-22T09:00:00Z" } : e,
    );
    const { state } = capBuildTimeRows(stateWith([...promoted, ...augustBuild()]));
    const row = state.forensicTimeline.find((e) => e.id === "d6")!;
    expect(row.severity).toBe("Critical");
    expect(row.buildTime).toBeUndefined();
    expect(protectedFromCap(row)).toBe("promoted row");
    // …and promotion protects that ROW only: it never vetoes the window around it, or the 135
    // second-look-promoted Info rows of the real case would empty every window.
    expect(hardAttackerSignal(row)).toBeNull();
    expect(state.forensicTimeline.find((e) => e.id === "d7")!.severity).toBe("Low");
  });
});

describe("what the readers see", () => {
  it("the tagger cannot raise a capped row back", () => {
    const { state } = capBuildTimeRows(stateWith([...decemberBuild(), ...augustBuild()]));
    const row = state.forensicTimeline.find((e) => e.id === "d2")!;
    const raised = applyToForensicEvent(row, {
      eventId: row.id,
      tags: ["token-manipulation"],
      mitre: ["T1134.001"],
      severity: "High",
      ruleIds: ["privesc_token_manipulation"],
    });
    expect(raised.severity).toBe("Low");
  });

  it("renders a tag the 240-character description clip cannot reach", () => {
    const { state } = capBuildTimeRows(stateWith([...decemberBuild(), ...augustBuild()]));
    const row = state.forensicTimeline.find((e) => e.id === "d5")!;
    expect(renderBuildTimeTag(row)).toMatch(/^<build-time:.+>$/);
    expect(renderBuildTimeTag(scenario()[0])).toBe("");
  });

  it("tells synthesis where the story starts, and not to ask for earlier logs", () => {
    const { state } = capBuildTimeRows(stateWith([...decemberBuild(), ...augustBuild(), ...scenario()]));
    const block = buildTimeContextBlock(state.forensicTimeline, renames);
    expect(block).toContain("BUILD-TIME BASELINE");
    expect(block).toContain("2026-09-22T08:32:10Z");
    expect(block).toMatch(/do not ask for logs from before them/i);
  });

  it("says so plainly when nothing outside the build is graded", () => {
    const { state } = capBuildTimeRows(stateWith([...decemberBuild(), ...augustBuild()]));
    const block = buildTimeContextBlock(state.forensicTimeline, renames);
    expect(block).toMatch(/no post-provisioning activity/i);
  });

  it("costs nothing on a case with no build window", () => {
    expect(buildTimeContextBlock(scenario(), renames)).toBe("");
  });

  it("counts a finding's build-time evidence", () => {
    const { state } = capBuildTimeRows(stateWith([...decemberBuild(), ...augustBuild(), ...scenario()]));
    const byId = new Map(state.forensicTimeline.map((e) => [e.id, e]));
    const allBuild = buildTimeSupport([byId.get("d6")!, byId.get("a3")!]);
    expect(allBuild.allBuild).toBe(true);
    const mixed = buildTimeSupport([byId.get("d2")!, byId.get("s1")!]);
    expect(mixed.allBuild).toBe(false);
    expect(mixed.build).toBe(1);
    expect(mixed.firstOutside).toBe("2026-09-22T08:32:10Z");
  });
});

describe("the adversarial cases a code review found (#1529)", () => {
  it("does not grow the window across repeated settles — the note it writes is not a marker", () => {
    // A row 45 minutes after the last December marker: outside the first window, and it must stay
    // outside however many times the pass runs. Before the fix the capped rows' own
    // "[build-time: packer …]" notes read as packer markers and walked the cluster forward.
    const later = ev("late", "2025-12-05T04:12:00Z", {
      severity: "High",
      description: "Cobalt Strike beacon to 198.51.100.7:443",
    });
    let state = stateWith([...decemberBuild(), ...augustBuild(), later]);
    for (let i = 0; i < 5; i++) state = capBuildTimeRows(state).state;
    const row = state.forensicTimeline.find((e) => e.id === "late")!;
    expect(row.severity).toBe("High");
    expect(row.buildTime).toBeUndefined();
    expect(capBuildTimeRows(state).changed).toBe(0);
  });

  it("does not let another host's rename corroborate a lone marker", () => {
    // One servicing row on FILE-SRV-02, at the very minute DESKTOP-16OJFO6 was renamed.
    const other: HostRenameRecord[] = [
      ...renames,
      {
        formerName: "WIN-9ABCDEF1234",
        currentName: "FILE-SRV-02",
        until: "2027-03-01T00:00:00.000Z",
        basis: "collector",
      },
    ];
    const lone = [
      ev("o1", "2026-08-26T13:50:00Z", {
        severity: "High",
        asset: "FILE-SRV-02",
        path: "C:\\Windows\\Installer\\msi9f21.tmp",
        description: "Installer artifact",
      }),
    ];
    expect(buildTimeWindows(lone, other)).toEqual([]);
  });

  it("ignores an analyst-declared rename as corroboration", () => {
    const declared: HostRenameRecord[] = [
      {
        formerName: "WIN-UK1GV882OK6",
        currentName: HOST,
        until: "2027-05-02T10:00:00.000Z",
        basis: "analyst",
      },
      ...renames,
    ];
    const lone = [
      ev("p1", "2027-05-02T10:01:00Z", {
        severity: "High",
        path: "C:\\Windows\\WinSxS\\amd64_x\\f.dll",
        description: "Servicing artifact",
      }),
    ];
    expect(buildTimeWindows(lone, declared)).toEqual([]);
  });

  it("measures each host against its own provisioning boundary in the context block", () => {
    // FILE-SRV-02 was attacked in January; DESKTOP-16OJFO6 was still being built in August. A
    // single case-wide boundary hid the January row and told the model to start the story later.
    const multi: HostRenameRecord[] = [
      {
        formerName: "WIN-0NNTB2RTNB1",
        currentName: "DESKTOP-16OJFO6",
        until: "2026-08-26T13:49:53.000Z",
        basis: "collector",
      },
      {
        formerName: "WIN-9ABCDEF1234",
        currentName: "FILE-SRV-02",
        until: "2025-06-01T09:00:00.000Z",
        basis: "collector",
      },
    ];
    const attack = ev("f1", "2026-01-15T22:10:00Z", {
      severity: "High",
      asset: "FILE-SRV-02",
      description: "Cobalt Strike beacon to 198.51.100.7:443",
    });
    const { state } = capBuildTimeRows({
      ...stateWith([...decemberBuild(), ...augustBuild(), attack]),
      hostRenames: multi,
    });
    const block = buildTimeContextBlock(state.forensicTimeline, multi);
    expect(block).toContain("2026-01-15T22:10:00Z");
  });
});

// Scenario 022 (#1695): the Vagrant box's interactive account is `vagrant`, so the emulation's own
// rows named the provisioner, and the Windows Update churn of the same hour supplied a second marker
// kind. A 12:33–14:06 "build" window on the run day capped every attack finding at Low.
describe("a user session is not a build (#1695)", () => {
  const RUN = "2026-09-26T13:10";

  // The emulation: the `vagrant` user runs renamed tools out of C:\Users\Public.
  const emulation = (): ForensicEvent[] =>
    Array.from({ length: 10 }, (_, i) =>
      ev(`e${i}`, `${RUN}:${String(40 + i).padStart(2, "0")}Z`, {
        severity: "High",
        path: "C:\\Users\\Public\\BlackSuit15DaySim\\beachhead\\operator.exe",
        description: `Sigma: HackTool - Bloodhound/Sharphound Execution - User: ${HOST}\\vagrant - CurrentDirectory: C:\\Users\\vagrant\\Desktop\\`,
      }),
    );

  // Routine servicing in the same hour: Windows Update and an MSI install.
  const servicing = (): ForensicEvent[] => [
    ev("w1", "2026-09-26T13:03:00Z", {
      severity: "Medium",
      processName: "C:\\Windows\\System32\\wuauclt.exe",
    }),
    ev("w2", "2026-09-26T13:12:00Z", {
      severity: "Medium",
      path: "C:\\Windows\\SoftwareDistribution\\Download\\x.cab",
    }),
    ev("w3", "2026-09-26T13:20:00Z", {
      severity: "Medium",
      processName: "C:\\Windows\\System32\\MoUsoCoreWorker.exe",
    }),
    ev("w4", "2026-09-26T13:30:00Z", { severity: "Medium", path: "C:\\Windows\\Installer\\1a2b3c.msi" }),
    ev("w5", "2026-09-26T13:36:00Z", { severity: "Medium", path: "C:\\Windows\\Installer\\4d5e6f.msi" }),
  ];

  it("does not read a user name or profile path as the Vagrant provisioner", () => {
    expect(buildMarkerKind(ev("u1", RUN, { description: `Logon - User: ${HOST}\\vagrant` }))).toBeNull();
    expect(buildMarkerKind(ev("u2", RUN, { path: "C:\\Users\\vagrant\\Downloads\\tool.exe" }))).toBeNull();
    expect(
      buildMarkerKind(ev("u3", RUN, { path: "C:\\Users\\vagrant\\Downloads\\vagrant-shell.ps1" })),
    ).toBeNull();
  });

  it("still reads what the Vagrant provisioner itself writes", () => {
    expect(buildMarkerKind(ev("v1", RUN, { path: "C:\\vagrant\\provision.ps1" }))).toBe("vagrant");
    expect(buildMarkerKind(ev("v2", RUN, { path: "C:\\tmp\\vagrant-elevated-shell.ps1" }))).toBe("vagrant");
    expect(
      buildMarkerKind(ev("v3", RUN, { commandLine: "powershell -File C:\\tmp\\vagrant-shell.ps1" })),
    ).toBe("vagrant");
  });

  it("does not read a user named packer as the Packer provisioner", () => {
    expect(buildMarkerKind(ev("k1", RUN, { path: "C:\\Users\\packer\\Desktop\\notes.txt" }))).toBeNull();
    expect(buildMarkerKind(ev("k2", RUN, { description: `Logon - User: ${HOST}\\packer` }))).toBeNull();
    expect(buildMarkerKind(ev("k3", RUN, { path: "C:\\Windows\\Temp\\packer\\Autounattend.ps1" }))).toBe(
      "packer",
    );
  });

  it("opens no window over an emulation run by the vagrant user during Windows Update", () => {
    const events = [...emulation(), ...servicing()];
    expect(buildTimeWindows(events, renames)).toEqual([]);
    const { state } = capBuildTimeRows(stateWith(events));
    for (const e of state.forensicTimeline.filter((x) => x.id.startsWith("e"))) {
      expect(e.severity).toBe("High");
      expect(e.buildTime).toBeUndefined();
    }
  });

  it("opens no window from routine servicing alone, even beside the host's own rename", () => {
    const renamedToday: HostRenameRecord[] = [
      ...renames,
      {
        formerName: "WIN-0NNTB2RTNB1",
        currentName: HOST,
        until: "2026-09-26T13:15:00.000Z",
        basis: "collector",
      },
    ];
    expect(buildTimeWindows(servicing(), renamedToday)).toEqual([]);
  });

  it("opens no unbounded window from one provisioner kind plus servicing", () => {
    const lateChoco = [
      ev("c1", "2026-09-26T13:05:00Z", {
        severity: "Medium",
        path: "C:\\ProgramData\\chocolatey\\lib\\git\\tools\\x.ps1",
      }),
      ev("c2", "2026-09-26T13:06:00Z", { severity: "Medium", commandLine: "choco upgrade all -y" }),
      ...servicing(),
    ];
    expect(buildTimeWindows(lateChoco, renames)).toEqual([]);
  });

  it("still opens an unbounded window from two different provisioners, labelled by the provisioner", () => {
    const build = [
      ev("b1", "2027-02-01T10:00:00Z", { path: "C:\\ProgramData\\chocolatey\\tools\\7z.exe" }),
      ev("b2", "2027-02-01T10:05:00Z", { path: "C:\\Windows\\Temp\\packer\\Autounattend.ps1" }),
      ...Array.from({ length: 4 }, (_, i) =>
        ev(`b${3 + i}`, `2027-02-01T10:1${i}:00Z`, {
          path: "C:\\Windows\\SoftwareDistribution\\Download\\y.cab",
        }),
      ),
    ];
    const windows = buildTimeWindows(build, renames);
    expect(windows).toHaveLength(1);
    expect(["chocolatey", "packer"]).toContain(windows[0].marker);
  });
});

// #1698: a row can carry the build-time note without the record, or the record with a grade a merge
// raised. On INC-2026-014 a correlated row kept a capped member's note and lost its record, and the
// synthesis quoted a window that no longer existed. The pass now enforces one rule, whatever produced
// the row: inside a window, one note and nothing above Low; outside every window, no note.
describe("the cap pass repairs a row whose note and record disagree (#1698)", () => {
  const STALE = " [build-time: vagrant, 2026-09-26T12:34Z–13:59Z]";

  it("strips a stray note from a row outside every window and leaves its grade", () => {
    const stray = ev("x1", "2026-09-26T13:03:24Z", { severity: "High", description: `Defender row${STALE}` });
    const { state, changed } = capBuildTimeRows(stateWith([...decemberBuild(), stray]));
    const row = state.forensicTimeline.find((e) => e.id === "x1")!;
    expect(changed).toBeGreaterThan(0);
    expect(row.description).toBe("Defender row");
    expect(row.severity).toBe("High");
    expect(row.buildTime).toBeUndefined();
    expect(capBuildTimeRows(state).changed).toBe(0);
  });

  it("gives a row inside a window exactly one note when it arrived with a stray one", () => {
    const stray = ev("x2", "2025-12-05T03:20:00Z", { severity: "High", description: `firewall row${STALE}` });
    const { state } = capBuildTimeRows(stateWith([...decemberBuild(), stray]));
    const row = state.forensicTimeline.find((e) => e.id === "x2")!;
    expect((row.description.match(/\[build-time:/g) ?? []).length).toBe(1);
    expect(row.description).not.toContain("vagrant");
    expect(row.severity).toBe("Low");
    expect(row.buildTime?.cappedFrom).toBe("High");
    expect(capBuildTimeRows(state).changed).toBe(0);
  });

  it("re-caps a row a merge raised inside its own window, keeping the worse original grade", () => {
    const first = capBuildTimeRows(stateWith([...decemberBuild()]));
    const raised = first.state.forensicTimeline.map((e) =>
      e.id === "d4" ? { ...e, severity: "High" as const } : e,
    );
    const { state } = capBuildTimeRows({ ...first.state, forensicTimeline: raised });
    const row = state.forensicTimeline.find((e) => e.id === "d4")!;
    expect(row.severity).toBe("Low");
    expect(row.buildTime?.cappedFrom).toBe("High"); // was Medium before the merge raised it
    expect((row.description.match(/\[build-time:/g) ?? []).length).toBe(1);
  });

  it("never lowers the recorded original grade when a merge brings a milder one", () => {
    const first = capBuildTimeRows(stateWith([...decemberBuild()]));
    const d6 = first.state.forensicTimeline.find((e) => e.id === "d6")!; // Critical, capped
    const merged = first.state.forensicTimeline.map((e) =>
      e.id === "d6" ? { ...e, severity: "Medium" as const } : e,
    );
    const { state } = capBuildTimeRows({ ...first.state, forensicTimeline: merged });
    expect(d6.buildTime?.cappedFrom).toBe("Critical");
    expect(state.forensicTimeline.find((e) => e.id === "d6")!.buildTime?.cappedFrom).toBe("Critical");
  });

  it("leaves an Info row inside a window Info", () => {
    const info = ev("i2", "2025-12-05T03:00:00Z", { description: `session logoff${STALE}` });
    const { state } = capBuildTimeRows(stateWith([...decemberBuild(), info]));
    expect(state.forensicTimeline.find((e) => e.id === "i2")!.severity).toBe("Info");
  });
});

// Synthesis only repairs (#1698, Codex review): the import seam opened the window while the build's
// Info markers were still in the forensic timeline; synthesis sees what demote kept, so it must never
// conclude that a window is gone.
describe("the synthesis-time repair never lifts a cap (#1698)", () => {
  it("keeps a capped row capped when the markers that opened its window are gone", () => {
    const capped = capBuildTimeRows(stateWith([...decemberBuild()]));
    const markersDemoted = capped.state.forensicTimeline.filter((e) => e.id === "d6");
    const { state, changed } = repairBuildTimeRows({ ...capped.state, forensicTimeline: markersDemoted });
    expect(changed).toBe(0);
    expect(state.forensicTimeline[0].severity).toBe("Low");
    expect(state.forensicTimeline[0].buildTime?.cappedFrom).toBe("Critical");
  });

  it("removes a note that has no record, and leaves the grade", () => {
    const stray = ev("x1", "2026-09-26T13:03:24Z", {
      severity: "High",
      description: "Defender row [build-time: vagrant, 2026-09-26T12:34Z–13:59Z]",
    });
    const { state } = repairBuildTimeRows(stateWith([stray]));
    expect(state.forensicTimeline[0].description).toBe("Defender row");
    expect(state.forensicTimeline[0].severity).toBe("High");
  });

  it("re-caps a recorded row a merge raised, keeping the worse original grade", () => {
    const capped = capBuildTimeRows(stateWith([...decemberBuild()]));
    const raised = capped.state.forensicTimeline.map((e) =>
      e.id === "d4" ? { ...e, severity: "High" as const } : e,
    );
    const { state } = repairBuildTimeRows({ ...capped.state, forensicTimeline: raised });
    const row = state.forensicTimeline.find((e) => e.id === "d4")!;
    expect(row.severity).toBe("Low");
    expect(row.buildTime?.cappedFrom).toBe("High");
    expect(repairBuildTimeRows(state).changed).toBe(0);
  });
});
