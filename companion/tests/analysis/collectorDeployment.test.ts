// The collector's own deployment on the case host is not evidence (#1460). INC-2026-028 finding f31
// (High, T1070.006) was built from three rows that describe the Companion's own Velociraptor client
// arriving: a download from the configured server, the msiexec install, and the Sysmon EID 2 the
// MSI leaves on the installed exe. Every rule here lowers a grade or strips a technique, so each one
// is a place an intruder would like to reach — the negative cases are the important half.
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  annotateCollectorDeployment,
  applyCollectorDeployment,
  configuredCollectorServers,
  isCollectorFootprint,
  isCollectorInstallBinary,
  isCollectorServerDestination,
  isMsiexecCreationTimeChange,
  loadCollectorInfrastructure,
} from "../../src/analysis/collectorDeployment.js";
import { aggregateEvents } from "../../src/analysis/eventAggregate.js";
import type { MappedEvent } from "../../src/analysis/siemImport.js";

const SERVER = "10.20.30.40";
const INSTALL_EXE = "C:\\Program Files\\Velociraptor\\Velociraptor.exe";
const MSIEXEC = "C:\\Windows\\System32\\msiexec.exe";

function ev(over: Partial<MappedEvent>): MappedEvent {
  return {
    timestamp: "2026-03-01T11:29:52Z",
    description: "",
    severity: "Medium",
    mitre: [],
    aggKey: "k",
    sources: ["Sysmon"],
    ...over,
  };
}

// The three f31 rows, in the shape mapWindows renders them.
const download = () =>
  ev({
    description: `Sysmon Network connection (EID 3) - Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe - DestinationIp=${SERVER} - DestinationPort=8000 @ WS01`,
    severity: "High",
    mitre: ["T1105"],
    aggKey: "download",
    dstIp: SERVER,
    port: 8000,
  });
const install = () =>
  ev({
    description: `Sysmon Process created (EID 1) - Image=${MSIEXEC} - CommandLine=/i C:\\Users\\it\\Downloads\\velociraptor-0.72.msi /qn @ WS01`,
    severity: "Medium",
    mitre: ["T1218.007"],
    aggKey: "install",
    processName: "msiexec.exe",
    commandLine: `"${MSIEXEC}" /i C:\\Users\\it\\Downloads\\velociraptor-0.72.msi /qn`,
  });
const timeChange = () =>
  ev({
    description: `Sysmon File creation time changed (timestomp) (EID 2) - Image=${MSIEXEC} - TargetFilename=${INSTALL_EXE} @ WS01`,
    severity: "Medium",
    mitre: ["T1070.006"],
    aggKey: "time-change",
    path: INSTALL_EXE,
  });

afterEach(() => vi.unstubAllEnvs());

describe("configuredCollectorServers — known infrastructure comes from config only", () => {
  it("reads the GUI URL's host", () => {
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", `https://${SERVER}:8889`);
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", "");
    expect(configuredCollectorServers()).toEqual([SERVER]);
  });

  it("reads api_connection_string from the api_client config when the file exists", () => {
    const dir = mkdtempSync(join(tmpdir(), "velo-api-"));
    const file = join(dir, "api_client.yaml");
    writeFileSync(
      file,
      `ca_certificate: |\n  -----BEGIN-----\napi_connection_string: https://velo.example.com:8001\nname: api\n`,
    );
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", "");
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", file);
    expect(configuredCollectorServers()).toEqual(["velo.example.com"]);
  });

  it("is empty with nothing configured, and a missing config file is not an error", () => {
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", "");
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", join(tmpdir(), "does-not-exist", "api.yaml"));
    expect(configuredCollectorServers()).toEqual([]);
  });

  it("lower-cases and de-duplicates a host named by both sources", () => {
    const dir = mkdtempSync(join(tmpdir(), "velo-api-"));
    const file = join(dir, "api_client.yaml");
    writeFileSync(file, `api_connection_string: https://VELO:8001\n`);
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", "https://velo:8889");
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", file);
    expect(configuredCollectorServers()).toEqual(["velo"]);
  });
});

describe("isCollectorServerDestination — only a destination or URL field may name the server", () => {
  const infra = { servers: new Set([SERVER]) };

  it("matches DestinationIp / DestinationHostname / the structured dstIp", () => {
    expect(isCollectorServerDestination(download(), infra)).toBe(true);
    expect(
      isCollectorServerDestination(
        ev({
          description: `Sysmon Network connection (EID 3) - Image=x.exe - DestinationHostname=${SERVER}`,
        }),
        infra,
      ),
    ).toBe(true);
    expect(isCollectorServerDestination(ev({ description: "no fields", dstIp: SERVER }), infra)).toBe(true);
  });

  it("matches the host of a URL in the command line", () => {
    expect(
      isCollectorServerDestination(
        ev({
          description: `Sysmon Process created (EID 1) - Image=C:\\W\\powershell.exe - CommandLine=iwr http://${SERVER}:8000/velociraptor.exe -OutFile v.exe`,
        }),
        infra,
      ),
    ).toBe(true);
  });

  it("does NOT match the address as free text", () => {
    expect(
      isCollectorServerDestination(
        ev({
          description: `Sysmon Process created (EID 1) - Image=x.exe - CommandLine=echo ${SERVER} > note.txt`,
        }),
        infra,
      ),
    ).toBe(false);
    expect(isCollectorServerDestination(ev({ description: `SIEM event: ping from ${SERVER}` }), infra)).toBe(
      false,
    );
  });

  it("does NOT match a different host, or a host that merely contains the server", () => {
    expect(isCollectorServerDestination(ev({ description: "x - DestinationIp=10.20.30.41" }), infra)).toBe(
      false,
    );
    expect(isCollectorServerDestination(ev({ description: "x - DestinationIp=110.20.30.40" }), infra)).toBe(
      false,
    );
  });

  it("is inert with no server configured", () => {
    expect(isCollectorServerDestination(download(), { servers: new Set() })).toBe(false);
  });
});

describe("isCollectorInstallBinary — the install root, never a bare name", () => {
  it("matches msiexec installing a velociraptor MSI", () => {
    expect(isCollectorInstallBinary(install())).toBe(true);
  });

  it("matches the collector exe under its install root", () => {
    expect(
      isCollectorInstallBinary(
        ev({
          description: `Sysmon Process created (EID 1) - Image=${INSTALL_EXE} - CommandLine=service run`,
          processName: "Velociraptor.exe",
        }),
      ),
    ).toBe(true);
    expect(
      isCollectorInstallBinary(
        ev({
          description: `Sysmon Process created (EID 1) - Image=C:\\Program Files (x86)\\Velociraptor\\velociraptor.exe`,
        }),
      ),
    ).toBe(true);
  });

  it("matches the service registration (7045) whose ImagePath is the collector exe, quoted or bare", () => {
    expect(
      isCollectorInstallBinary(
        ev({
          description: `Windows System Service installed (EID 7045) - ServiceName=Velociraptor Service - ImagePath="${INSTALL_EXE}" --config "C:\\Program Files\\Velociraptor\\client.config.yaml" service run - StartType=auto start @ WS01`,
        }),
      ),
    ).toBe(true);
    expect(
      isCollectorInstallBinary(
        ev({
          description: `Windows System Service installed (EID 7045) - ServiceName=Velociraptor - ImagePath=${INSTALL_EXE}`,
        }),
      ),
    ).toBe(true);
  });

  it("does NOT match a 7045 whose ImagePath is outside the root, whatever the service is called", () => {
    expect(
      isCollectorInstallBinary(
        ev({
          description: `Windows System Service installed (EID 7045) - ServiceName=Velociraptor Service - ImagePath="C:\\Users\\Public\\Velociraptor.exe" service run`,
        }),
      ),
    ).toBe(false);
  });

  it("does NOT match velociraptor.exe outside the install root", () => {
    expect(
      isCollectorInstallBinary(
        ev({
          description: `Sysmon Process created (EID 1) - Image=C:\\Users\\Public\\velociraptor.exe - CommandLine=velociraptor.exe -c evil.yaml`,
        }),
      ),
    ).toBe(false);
    expect(
      isCollectorInstallBinary(
        ev({
          description: `Sysmon Process created (EID 1) - Image=C:\\Users\\v\\Velociraptor\\velociraptor.exe`,
        }),
      ),
    ).toBe(false);
  });

  it("does NOT match a non-process row, or msiexec with another MSI, or a traversal path", () => {
    expect(isCollectorInstallBinary(timeChange())).toBe(false);
    expect(
      isCollectorInstallBinary(
        ev({
          description: `Sysmon Process created (EID 1) - Image=${MSIEXEC} - CommandLine=/i C:\\tmp\\other.msi /qn`,
        }),
      ),
    ).toBe(false);
    expect(
      isCollectorInstallBinary(
        ev({
          description: `Sysmon Process created (EID 1) - Image=C:\\Program Files\\Velociraptor\\..\\..\\Users\\v\\velociraptor.exe`,
        }),
      ),
    ).toBe(false);
  });
});

const THOR = "C:\\Program Files\\Velociraptor\\Tools\\tmp1845340523\\thor64-lite.exe";
const LSASS = "C:\\Windows\\System32\\lsass.exe";
// The real-collection shape: THOR, unpacked and run by the client, opening lsass (Sysmon EID 10).
const thorAccess = () =>
  ev({
    description: `Sysmon Process accessed (EID 10) - SourceImage=${THOR} - TargetImage=${LSASS} - GrantedAccess=0x1010 @ DESKTOP-16OJFO6`,
    severity: "High",
    mitre: ["T1003.001"],
    aggKey: "thor-lsass",
    processName: "thor64-lite.exe",
  });

describe("isCollectorFootprint — a tool the client ran out of its install root", () => {
  it("matches THOR opening lsass from the unpacked tool tree (EID 10, SourceImage)", () => {
    expect(isCollectorFootprint(thorAccess())).toBe(true);
  });

  it.each([
    ["EID 1", `Sysmon Process created (EID 1) - Image=${THOR} - CommandLine=thor64-lite.exe --quick`],
    [
      "EID 3",
      `Sysmon Network connection (EID 3) - Image=${THOR} - DestinationIp=203.0.113.9 - DestinationPort=443`,
    ],
    ["EID 11", `Sysmon File created (EID 11) - Image=${THOR} - TargetFilename=C:\\ProgramData\\thor.log`],
    [
      "EID 22",
      `Sysmon DNS query (EID 22) - Image=${INSTALL_EXE} - QueryName=velo.example.com - QueryResults=10.20.30.40`,
    ],
    [
      "4688",
      `Security Process created (EID 4688) - NewProcessName=C:\\Program Files (x86)\\Velociraptor\\Tools\\tmp1\\hayabusa.exe`,
    ],
  ])("matches a %s row whose acting image is under the root", (_label, description) => {
    expect(isCollectorFootprint(ev({ description }))).toBe(true);
  });

  it("the client exe's own process-create takes the install note, not the footprint note", () => {
    const row = ev({
      description: `Sysmon Process created (EID 1) - Image=${INSTALL_EXE} - CommandLine=service run`,
      processName: "Velociraptor.exe",
    });
    applyCollectorDeployment([row]);
    expect(row.severity).toBe("Info");
    expect(row.description).toMatch(/Velociraptor client install\]$/);
    expect(row.description).not.toMatch(/footprint/);
  });

  it("does NOT match the same tool outside the root, or a \\Velociraptor\\ directory elsewhere", () => {
    expect(
      isCollectorFootprint(
        ev({
          description: `Sysmon Process accessed (EID 10) - SourceImage=C:\\Users\\Public\\thor64-lite.exe - TargetImage=${LSASS}`,
        }),
      ),
    ).toBe(false);
    expect(
      isCollectorFootprint(
        ev({
          description: `Sysmon Process accessed (EID 10) - SourceImage=C:\\Users\\v\\Velociraptor\\Tools\\thor64-lite.exe - TargetImage=${LSASS}`,
        }),
      ),
    ).toBe(false);
    expect(
      isCollectorFootprint(
        ev({
          description: `Sysmon Process accessed (EID 10) - SourceImage=C:\\Program Files\\Velociraptor\\..\\..\\Users\\v\\thor64-lite.exe - TargetImage=${LSASS}`,
        }),
      ),
    ).toBe(false);
  });

  it("never reads TargetImage — an intruder opening the collector is not the collector", () => {
    expect(
      isCollectorFootprint(
        ev({
          description: `Sysmon Process accessed (EID 10) - SourceImage=C:\\Users\\Public\\mimikatz.exe - TargetImage=${INSTALL_EXE} - GrantedAccess=0x1fffff`,
        }),
      ),
    ).toBe(false);
  });

  it("does NOT match a non-process-shaped row naming the root", () => {
    expect(
      isCollectorFootprint(
        ev({ description: `Sysmon Registry value set (EID 13) - Image=${THOR} - TargetObject=HKLM\\x` }),
      ),
    ).toBe(false);
  });
});

describe("isMsiexecCreationTimeChange — Sysmon EID 2 written by the system msiexec.exe", () => {
  it("matches the f31 row", () => {
    expect(isMsiexecCreationTimeChange(timeChange())).toBe(true);
  });

  it("matches the SysWOW64 msiexec and Hayabusa's EID rendering", () => {
    expect(
      isMsiexecCreationTimeChange(
        ev({
          description: `Hayabusa: File Creation Time Changed (EID 2 Microsoft-Windows-Sysmon/Operational) - Image=C:\\Windows\\SysWOW64\\msiexec.exe - TargetFilename=C:\\x.exe`,
        }),
      ),
    ).toBe(true);
  });

  it("does NOT match a timestomp from another process, or an msiexec outside System32, or another EID", () => {
    expect(
      isMsiexecCreationTimeChange(
        ev({
          description: `Sysmon File creation time changed (timestomp) (EID 2) - Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe - TargetFilename=C:\\Users\\Public\\svchost.exe`,
        }),
      ),
    ).toBe(false);
    expect(
      isMsiexecCreationTimeChange(
        ev({
          description: `Sysmon File creation time changed (timestomp) (EID 2) - Image=C:\\Users\\Public\\msiexec.exe - TargetFilename=C:\\x.exe`,
        }),
      ),
    ).toBe(false);
    expect(
      isMsiexecCreationTimeChange(
        ev({ description: `Sysmon Process created (EID 1) - Image=${MSIEXEC} - CommandLine=/i x.msi` }),
      ),
    ).toBe(false);
    expect(
      isMsiexecCreationTimeChange(
        ev({ description: `Sysmon Network connection (EID 22) - Image=${MSIEXEC} - DestinationIp=1.2.3.4` }),
      ),
    ).toBe(false);
  });
});

describe("applyCollectorDeployment — the f31 sequence", () => {
  it("grades the download and the install Info, and strips T1070.006 from the msiexec EID 2", () => {
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", `https://${SERVER}:8889`);
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", "");
    const rows = [download(), install(), timeChange()];
    applyCollectorDeployment(rows);

    expect(rows[0].severity).toBe("Info");
    expect(rows[0].description).toMatch(
      / \[DFIR collector deployment — download from the configured Velociraptor server\]$/,
    );
    expect(rows[1].severity).toBe("Info");
    expect(rows[1].description).toMatch(/ \[DFIR collector deployment — Velociraptor client install\]$/);
    // The EID 2 keeps its grade and its row; only the timestomp claim goes.
    expect(rows[2].severity).toBe("Medium");
    expect(rows[2].mitre).not.toContain("T1070.006");
    expect(rows[2].description).toMatch(
      / \[MSI install artifact — creation-time change by msiexec.exe is not timestomping\]$/,
    );
  });

  it("grades THOR's lsass access Info with the footprint note, and leaves the tool in Public alone", () => {
    const rows = [
      thorAccess(),
      ev({
        description: `Sysmon Process accessed (EID 10) - SourceImage=C:\\Users\\Public\\thor64-lite.exe - TargetImage=${LSASS}`,
        severity: "High",
        aggKey: "public-thor",
      }),
    ];
    applyCollectorDeployment(rows);
    expect(rows[0].severity).toBe("Info");
    expect(rows[0].description).toMatch(
      / \[DFIR collector footprint — tool run by the Velociraptor client\]$/,
    );
    expect(rows[1].severity).toBe("High");
    expect(rows[1].description).not.toMatch(/DFIR collector/);
  });

  it("leaves a real timestomp and a masquerading velociraptor.exe alone", () => {
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", `https://${SERVER}:8889`);
    const stomp = ev({
      description: `Sysmon File creation time changed (timestomp) (EID 2) - Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe - TargetFilename=C:\\Users\\Public\\svchost.exe`,
      mitre: ["T1070.006"],
    });
    const masq = ev({
      description: `Sysmon Process created (EID 1) - Image=C:\\Users\\Public\\velociraptor.exe - CommandLine=velociraptor.exe -c evil.yaml`,
      severity: "High",
      mitre: ["T1036.005"],
    });
    const before = [structuredClone(stomp), structuredClone(masq)];
    applyCollectorDeployment([stomp, masq]);
    expect([stomp, masq]).toEqual(before);
  });

  it("with no server configured, the download keeps its grade and the other two rules still run", () => {
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", "");
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", "");
    const rows = [download(), install(), timeChange()];
    applyCollectorDeployment(rows);
    expect(rows[0].severity).toBe("High");
    expect(rows[0].description).not.toMatch(/DFIR collector deployment/);
    expect(rows[1].severity).toBe("Info");
    expect(rows[2].mitre).toEqual([]);
  });

  it("strips T1070.006 but keeps the row's other techniques, and annotates once", () => {
    const row = ev({
      description: timeChange().description,
      mitre: ["T1070.006", "T1036"],
    });
    const infra = loadCollectorInfrastructure();
    annotateCollectorDeployment(row, infra);
    annotateCollectorDeployment(row, infra);
    expect(row.mitre).toEqual(["T1036"]);
    expect(row.description.match(/MSI install artifact/g)).toHaveLength(1);
  });
});

describe("aggregateEvents runs the collector-deployment overlay", () => {
  it("emits the f31 download as Info with the deployment note", () => {
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", `https://${SERVER}:8889`);
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", "");
    const { events } = aggregateEvents([download(), timeChange()]);
    const dl = events.find((e) => /DestinationIp=/.test(e.description))!;
    expect(dl.severity).toBe("Info");
    expect(dl.description).toMatch(
      /\[DFIR collector deployment — download from the configured Velociraptor server\]/,
    );
    const tc = events.find((e) => /\(EID 2\)/.test(e.description))!;
    expect(tc.mitreTechniques).toEqual([]);
    expect(tc.description).toMatch(/MSI install artifact/);
  });

  it("a demoted row falls under a severity floor, so the floor sees the collector grade", () => {
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", `https://${SERVER}:8889`);
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", "");
    const { events } = aggregateEvents([download()], { minSeverity: "Low" });
    expect(events).toHaveLength(0);
  });
});
