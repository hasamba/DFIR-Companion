import { describe, it, expect } from "vitest";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import {
  parseSentinelLinux,
  isSentinelSyslogRow,
  isVmConnectionRow,
} from "../../src/analysis/sentinelLinuxImport.js";

// Synthetic fixtures shaped like Microsoft Sentinel / Log Analytics `Syslog` and `VMConnection`
// table exports (#2098). No tenant, no real host; IPs are from the 192.0.2.0/24 documentation range.
const syslogRow = (msg: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  TenantId: "redacted",
  SourceSystem: "Linux",
  TimeGenerated: "2022-05-11T18:10:21.997Z",
  Computer: "host-a",
  EventTime: "2022-05-11T18:10:21Z",
  Facility: "user",
  HostName: "host-a",
  SeverityLevel: "info",
  HostIP: "192.0.2.5",
  ProcessName: "auoms",
  SyslogMessage: msg,
  Type: "Syslog",
  ...extra,
});
const ndjson = (rows: unknown[]): string => rows.map((r) => JSON.stringify(r)).join("\n");

const auoms = (serial: number, cmd: string): string => {
  const prog = cmd.split(" ")[0];
  return `type=AUOMS_EXECVE audit(1652292621.986:${serial}): SchemaVersion="1" syscall=execve success=yes exit=0 a0=7fcd3bdfb8e0 pid=${serial} user=tomcat uid=1001 comm="${prog}" exe="/usr/bin/${prog}" cmdline="${cmd}" redactors= containerid=`;
};

// Sentinel strips the `;` of the XML entities inside SyslogMessage (`&lt unknown process&gt `).
const sysmonEid1 =
  '<Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="2022-05-11T18:10:21.986000000Z"/><EventRecordID>245800</EventRecordID><Correlation/><Execution ProcessID="1590" ThreadID="1590"/><Channel>Linux-Sysmon/Operational</Channel><Computer>host-a</Computer><Security UserId="0"/></System><EventData><Data Name="RuleName">-</Data><Data Name="UtcTime">2022-05-11 18:10:21.986</Data><Data Name="ProcessGuid">{94325212-f5aa-627b-082b-60e4b9550000}</Data><Data Name="ProcessId">17791</Data><Data Name="Image">/bin/bash</Data><Data Name="CommandLine">bash -c echo &quot hi&quot  | whoami</Data><Data Name="CurrentDirectory">/</Data><Data Name="User">tomcat</Data><Data Name="LogonId">1001</Data><Data Name="ParentProcessId">17790</Data><Data Name="ParentImage">&lt unknown process&gt </Data><Data Name="ParentCommandLine">java</Data><Data Name="ParentUser">tomcat</Data></EventData></Event>';

const vmRow = {
  TimeGenerated: "2022-05-11T18:09:38.868Z",
  Computer: "host-a",
  Direction: "outbound",
  ProcessName: "java",
  SourceIp: "192.0.2.5",
  DestinationIp: "192.0.2.6",
  DestinationPort: 1389,
  Protocol: "tcp",
  RemoteIp: "192.0.2.6",
  BytesSent: 129,
  BytesReceived: 196,
  LinksEstablished: 1,
  LinksTerminated: 1,
  Type: "VMConnection",
};

describe("Sentinel Linux detection (#2098)", () => {
  it("claims a Sentinel Syslog export instead of the generic SIEM importer", () => {
    const text = ndjson([syslogRow(auoms(1, "whoami")), syslogRow(auoms(2, "id"))]);
    expect(detectImportKind("syslog.json", text)).toBe("sentinellinux");
  });
  it("claims a VMConnection export", () => {
    expect(detectImportKind("vmconnection.json", JSON.stringify([vmRow]))).toBe("sentinellinux");
  });
  it("row predicates reject the other table and arbitrary JSON", () => {
    expect(isSentinelSyslogRow(syslogRow("x"))).toBe(true);
    expect(isSentinelSyslogRow(vmRow)).toBe(false);
    expect(isVmConnectionRow(vmRow)).toBe(true);
    expect(isVmConnectionRow(syslogRow("x"))).toBe(false);
    expect(isVmConnectionRow({ ...vmRow, Type: "SomethingElse" })).toBe(false);
  });
});

describe("parseSentinelLinux — AUOMS / auditd SyslogMessage", () => {
  it("routes AUOMS records to the auditd parser: one event per record, command line, host", () => {
    const r = parseSentinelLinux(
      ndjson([syslogRow(auoms(1, "bash -c whoami")), syslogRow(auoms(2, "groups"))]),
    );
    expect(r.total).toBe(2);
    expect(r.events).toHaveLength(2);
    const who = r.events.find((e) => e.description.includes("bash -c whoami"));
    expect(who).toBeDefined();
    expect(who?.description).toContain("Command executed (AUOMS_EXECVE)");
    expect(who?.asset).toBe("host-a"); // the AUOMS line has no node= here: the host comes from the row
    expect(who?.timestamp).toBe("2022-05-11T18:10:21.986Z");
  });

  // A multi-host export: the dominant-host fallback used to put every command on one host.
  const onHost = (msg: string, host: string): Record<string, unknown> =>
    syslogRow(msg, { HostName: host, Computer: host });

  it("keeps each host's commands on that host when serials differ", () => {
    const r = parseSentinelLinux(
      ndjson([
        onHost(auoms(1, "whoami"), "host-a"),
        onHost(auoms(2, "id -u"), "host-a"),
        onHost(auoms(3, "uname -a"), "host-b"),
      ]),
    );
    expect(r.events).toHaveLength(3);
    expect(r.events.find((e) => e.description.includes("uname -a"))?.asset).toBe("host-b");
    expect(r.events.find((e) => e.description.includes("whoami"))?.asset).toBe("host-a");
    expect(r.events.find((e) => e.description.includes("id -u"))?.asset).toBe("host-a");
  });

  it("keeps two hosts' records apart when they share an audit serial", () => {
    const r = parseSentinelLinux(
      ndjson([onHost(auoms(7, "whoami"), "host-a"), onHost(auoms(7, "uname -a"), "host-b")]),
    );
    expect(r.events).toHaveLength(2);
    expect(r.events.find((e) => e.description.includes("whoami"))?.asset).toBe("host-a");
    expect(r.events.find((e) => e.description.includes("uname -a"))?.asset).toBe("host-b");
  });
});

describe("parseSentinelLinux — Linux-Sysmon XML SyslogMessage", () => {
  it("unwraps the XML into the Sysmon parser and repairs the stripped entities", () => {
    const r = parseSentinelLinux(ndjson([syslogRow(sysmonEid1, { ProcessName: "sysmon" })]));
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toMatch(/^Sysmon Process create \(EID 1\)/);
    expect(e.description).toContain("/bin/bash");
    // `&quot hi&quot  |` was `&quot;hi&quot; |` before Sentinel turned each `;` into a space.
    expect(e.description).toContain('bash -c echo "hi" | whoami');
    expect(e.description).toContain("ParentImage=<unknown process>");
    expect(e.description).not.toMatch(/&lt|&gt|&quot/);
    expect(e.asset).toBe("host-a");
  });
});

describe("parseSentinelLinux — plain syslog SyslogMessage", () => {
  it("keeps a plain message as a syslog event at the row's time and host", () => {
    const r = parseSentinelLinux(
      ndjson([
        syslogRow("Accepted password for alice from 192.0.2.9 port 22 ssh2", {
          ProcessName: "sshd",
          Facility: "auth",
        }),
      ]),
    );
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("Accepted password for alice");
    expect(e.timestamp).toBe("2022-05-11T18:10:21.997Z");
    expect(e.asset).toBe("host-a");
  });
});

describe("parseSentinelLinux — VMConnection", () => {
  it("maps a row to a Low network-flow event naming the process, remote endpoint and bytes", () => {
    const r = parseSentinelLinux(JSON.stringify([vmRow]));
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("java");
    expect(e.description).toContain("192.0.2.6:1389");
    expect(e.description).toContain("sent 129");
    expect(e.description).toContain("received 196");
    expect(e.processName).toBe("java");
    expect(e.dstIp).toBe("192.0.2.6");
    expect(e.port).toBe(1389);
    expect(e.asset).toBe("host-a");
    expect(e.timestamp).toBe("2022-05-11T18:09:38.868Z");
    expect(e.canonical?.event.category).toBe("network");
    expect(r.iocs.some((i) => i.type === "ip" && i.value === "192.0.2.6")).toBe(true);
  });
});

describe("parseSentinelLinux — mixed and empty input", () => {
  it("handles every shape in one file and reports the total", () => {
    const text = ndjson([syslogRow(auoms(1, "whoami")), syslogRow(sysmonEid1), vmRow]);
    const r = parseSentinelLinux(text);
    expect(r.total).toBe(3);
    expect(r.events).toHaveLength(3);
    expect(r.hostname).toBe("host-a");
  });
  it("returns an empty result for empty input", () => {
    expect(parseSentinelLinux("").events).toHaveLength(0);
    expect(parseSentinelLinux("").format).toBe("empty");
  });
});
