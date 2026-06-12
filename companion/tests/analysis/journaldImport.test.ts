import { describe, it, expect } from "vitest";
import { parseJournald } from "../../src/analysis/journaldImport.js";

const ndjson = (...o: unknown[]): string => o.map((x) => JSON.stringify(x)).join("\n");

describe("parseJournald — journalctl -o json", () => {
  it("maps an sshd failed-password entry: Medium + T1110, IP IOC, own time", () => {
    const r = parseJournald(ndjson({
      __REALTIME_TIMESTAMP: "1717200000000000", // µs epoch → 2024-06-01T00:00:00Z
      _SOURCE_REALTIME_TIMESTAMP: "1717200000123456",
      PRIORITY: "6", // info — but the message escalates it
      MESSAGE: "Failed password for root from 203.0.113.9 port 51542 ssh2",
      SYSLOG_IDENTIFIER: "sshd",
      _HOSTNAME: "web01",
      _COMM: "sshd",
      _EXE: "/usr/sbin/sshd",
    }));
    expect(r.format).toBe("journald");
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1110");
    expect(e.description).toContain("journald [sshd]:");
    expect(e.description).toContain("@ web01");
    expect(e.asset).toBe("web01");
    expect(e.timestamp).toBe("2024-06-01T00:00:00.123Z"); // prefers _SOURCE_REALTIME (µs → ms)
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("203.0.113.9");
    expect(r.iocs.find((i) => i.type === "file")?.value).toBe("/usr/sbin/sshd");
  });

  it("derives severity from PRIORITY when no keyword bump applies (crit → High)", () => {
    const r = parseJournald(ndjson({
      __REALTIME_TIMESTAMP: "1717200000000000",
      PRIORITY: 2,
      MESSAGE: "I/O error on device sda",
      SYSLOG_IDENTIFIER: "kernel",
      _TRANSPORT: "kernel",
      _HOSTNAME: "web01",
    }));
    expect(r.events[0].severity).toBe("High");
  });

  it("flags useradd as High + T1136.001", () => {
    const e = parseJournald(ndjson({
      __REALTIME_TIMESTAMP: "1717200001000000",
      PRIORITY: "6",
      MESSAGE: "new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash",
      SYSLOG_IDENTIFIER: "useradd",
      _HOSTNAME: "web01",
    })).events[0];
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1136.001");
  });

  it("notes a successful root login (Low + T1078)", () => {
    const e = parseJournald(ndjson({
      __REALTIME_TIMESTAMP: "1717200002000000",
      PRIORITY: "6",
      MESSAGE: "Accepted publickey for root from 10.0.0.5 port 40222 ssh2",
      SYSLOG_IDENTIFIER: "sshd",
      _HOSTNAME: "web01",
    })).events[0];
    expect(e.severity).toBe("Low");
    expect(e.mitreTechniques).toContain("T1078");
  });

  it("renders a MESSAGE byte-array (non-UTF8 line)", () => {
    const bytes = "hi".split("").map((c) => c.charCodeAt(0));
    const e = parseJournald(ndjson({
      __REALTIME_TIMESTAMP: "1717200003000000", PRIORITY: "6", MESSAGE: bytes, _HOSTNAME: "h", _BOOT_ID: "x",
    })).events[0];
    expect(e.description).toContain("hi");
  });

  it("ignores non-journald records", () => {
    const r = parseJournald(ndjson({ event_id: 4624, message: "not journald" }));
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });

  it("aggregates repeated identical brute-force lines", () => {
    const mk = (ts: number, ip: string): unknown => ({
      __REALTIME_TIMESTAMP: `${ts}000000`, PRIORITY: "6",
      MESSAGE: `Failed password for invalid user admin from ${ip} port 22 ssh2`,
      SYSLOG_IDENTIFIER: "sshd", _HOSTNAME: "web01",
    });
    const r = parseJournald(ndjson(mk(1717200000, "203.0.113.9"), mk(1717200001, "203.0.113.9")));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });
});
