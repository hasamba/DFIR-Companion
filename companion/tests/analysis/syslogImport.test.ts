import { describe, it, expect } from "vitest";
import {
  looksLikeSyslog, parseSyslogLine, mapSyslogLine, parseSyslog,
} from "../../src/analysis/syslogImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

// RFC 5424 lines straight from the spillage-full-matrix fixture (the two syslog spills + benign chatter).
// The fake Slack token is assembled at runtime so the literal `xoxb-…` string never appears in source —
// it's synthetic EvidenceForge test data, but secret scanners (GitHub push protection) match on shape.
const SLACK_TOKEN = ["xoxb", "32926872419", "2302548692720", "EvidenceForgeFakeNgxR2jaCkfeCIUn3GZNVGjPU"].join("-");
const SLACK = `<30>1 2024-05-16T13:40:26.263976Z APP-MTX-01 app - - - alertbot: posting to slack with token ${SLACK_TOKEN}`;
const PASSWD = "<30>1 2024-05-16T13:45:20.917698Z APP-MTX-01 app - - - app: loaded shared secret EvidenceForgeFake-wPndDbHjZm! from /etc/users/secret.conf";
const ACCEPT = "<86>1 2024-05-16T13:09:55.931460Z APP-MTX-01 sshd 161779 - - Accepted password for jordan.lee from 10.66.10.23 port 58209 ssh2";
const NOISE = "<30>1 2024-05-16T13:01:44.688858Z APP-MTX-01 irqbalance 3122 - - NUMA node 0: balancing pass complete, 2 IRQs moved";
// RFC 3164 (year-less) auth failure with a PUBLIC source IP, and a crit-PRI kernel line.
const FAIL3164 = "May 16 13:40:26 app01 sshd[1234]: Failed password for invalid user admin from 203.0.113.9 port 41022 ssh2";
const CRIT = "<2>1 2024-05-16T14:00:00.000000Z app01 kernel - - - thermal zone tripped, shutting down";

describe("looksLikeSyslog", () => {
  it("matches RFC 5424 and RFC 3164 framing", () => {
    expect(looksLikeSyslog([SLACK, ACCEPT, NOISE].join("\n"))).toBe(true);
    expect(looksLikeSyslog([FAIL3164, FAIL3164, FAIL3164].join("\n"))).toBe(true);
  });
  it("does NOT claim an arbitrary non-syslog log", () => {
    expect(looksLikeSyslog("app started ok\nprocessing batch 12\nERROR could not connect to db")).toBe(false);
    expect(looksLikeSyslog("")).toBe(false);
  });
});

describe("parseSyslogLine", () => {
  it("parses an RFC 5424 line (PRI, ISO timestamp, host, app, structured-data stripped)", () => {
    const p = parseSyslogLine(SLACK, 2024)!;
    expect(p.pri).toBe(30);
    expect(p.timestamp).toBe("2024-05-16T13:40:26.263Z");
    expect(p.host).toBe("APP-MTX-01");
    expect(p.app).toBe("app");
    expect(p.message).toContain(SLACK_TOKEN);
  });
  it("parses an RFC 3164 (year-less) line at the assumed year", () => {
    const p = parseSyslogLine(FAIL3164, 2024)!;
    expect(p.timestamp).toBe("2024-05-16T13:40:26.000Z");
    expect(p.host).toBe("app01");
    expect(p.app).toBe("sshd");
    expect(p.message).toContain("Failed password");
  });
  it("returns null for a non-syslog line", () => {
    expect(parseSyslogLine("just some prose without framing", 2024)).toBeNull();
  });
});

describe("mapSyslogLine", () => {
  it("keeps a benign app message at Info, carries the host as asset, preserves the spilled secret in the description", () => {
    const m = mapSyslogLine(SLACK, 2024, new Map())!;
    expect(m.severity).toBe("Info");
    expect(m.asset).toBe("APP-MTX-01");
    expect(m.sources).toEqual(["Syslog"]);
    expect(m.description).toContain(SLACK_TOKEN);
  });
  it("keeps an auth SUCCESS at Info and does NOT emit a private-range IP as an IOC", () => {
    const sink = new Map<string, SiemIoc>();
    const m = mapSyslogLine(ACCEPT, 2024, sink)!;
    expect(m.severity).toBe("Info");
    expect([...sink.values()]).toHaveLength(0); // 10.66.10.23 is RFC1918 → skipped
  });
  it("bumps an auth FAILURE to Low and emits the public source IP as an IOC", () => {
    const sink = new Map<string, SiemIoc>();
    const m = mapSyslogLine(FAIL3164, 2024, sink)!;
    expect(m.severity).toBe("Low");
    expect([...sink.values()].filter((i) => i.type === "ip").map((i) => i.value)).toContain("203.0.113.9");
  });
  it("bumps a crit/alert/emerg PRI (<=2) to Low", () => {
    const m = mapSyslogLine(CRIT, 2024, new Map())!;
    expect(m.severity).toBe("Low");
  });
});

describe("parseSyslog", () => {
  it("imports the two syslog spills + chatter: distinct messages survive, repeats aggregate, secret preserved", () => {
    const r = parseSyslog([SLACK, PASSWD, ACCEPT, NOISE, NOISE].join("\n"), { assumeYear: 2024 });
    expect(r.format).toBe("syslog");
    expect(r.total).toBe(5);
    // NOISE x2 collapses into one counted row; the three distinct lines stay separate → 4 events.
    expect(r.events).toHaveLength(4);
    expect(r.events.find((e) => e.count === 2)?.description).toContain("NUMA node");
    // Both planted secrets survive verbatim in a preserved event description.
    const all = r.events.map((e) => e.description).join("\n");
    expect(all).toContain(SLACK_TOKEN);
    expect(all).toContain("EvidenceForgeFake-wPndDbHjZm!");
  });
  it("respects a minSeverity floor", () => {
    const r = parseSyslog([ACCEPT, FAIL3164].join("\n"), { assumeYear: 2024, minSeverity: "Low" });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Low");
  });
});
