import { describe, it, expect } from "vitest";
import { parseAuditdLog } from "../../src/analysis/auditdImport.js";

describe("parseAuditdLog — execution (SYSCALL + EXECVE + PATH + PROCTITLE)", () => {
  // `cat /etc/shadow` — a single logical event spread across five records sharing serial 270.
  const log = [
    'type=SYSCALL msg=audit(1490451217.272:270): arch=c000003e syscall=59 success=yes exit=0 ppid=2270 pid=2271 auid=1000 uid=0 gid=0 tty=pts0 ses=3 comm="cat" exe="/usr/bin/cat" key="exec"',
    'type=EXECVE msg=audit(1490451217.272:270): argc=2 a0="cat" a1="/etc/shadow"',
    "type=PROCTITLE msg=audit(1490451217.272:270): proctitle=636174002F6574632F736861646F77",
    'type=PATH msg=audit(1490451217.272:270): item=0 name="/etc/shadow" inode=12345 dev=08:01 mode=0100640 ouid=0 ogid=0 nametype=NORMAL',
    'type=CWD msg=audit(1490451217.272:270): cwd="/root"',
  ].join("\n");

  it("collapses the five records into one EXECVE event at the audit() epoch", () => {
    const r = parseAuditdLog(log);
    expect(r.format).toBe("auditd");
    expect(r.total).toBe(1);
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("Command executed (EXECVE)");
    expect(e.description).toContain("cat /etc/shadow");
    expect(e.timestamp).toBe("2017-03-25T14:13:37.272Z"); // epoch from msg=audit(secs.millis)
    expect(e.sources).toEqual(["auditd"]);
    expect(e.processName).toBe("cat");
  });

  it("bumps to Medium + T1003.008 because the command reads /etc/shadow", () => {
    const e = parseAuditdLog(log).events[0];
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1059");
    expect(e.mitreTechniques).toContain("T1003.008");
  });

  it("extracts file + process IOCs (exe, watched path, comm)", () => {
    const r = parseAuditdLog(log);
    const files = r.iocs.filter((i) => i.type === "file").map((i) => i.value);
    const procs = r.iocs.filter((i) => i.type === "process").map((i) => i.value);
    expect(files).toContain("/usr/bin/cat");
    expect(files).toContain("/etc/shadow");
    expect(procs).toContain("cat");
  });
});

describe("parseAuditdLog — USER_* records with a nested msg='…' blob", () => {
  it("parses the inner op/acct/addr/res and flags a failed SSH login (T1110)", () => {
    const log =
      "type=USER_LOGIN msg=audit(1490451300.123:300): pid=1027 uid=0 auid=4294967295 ses=4294967295 " +
      "msg='op=login acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=evil.example addr=203.0.113.9 terminal=ssh res=failed'";
    const r = parseAuditdLog(log);
    const e = r.events[0];
    expect(e.description).toContain("User login (USER_LOGIN)");
    expect(e.description).toContain("acct=root");
    expect(e.description).toContain("res=failed");
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1110");
    expect(e.srcIp).toBe("203.0.113.9");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("203.0.113.9");
    expect(r.iocs.find((i) => i.type === "domain")?.value).toBe("evil.example");
  });

  it("maps ADD_USER to High + T1136.001 (account creation persistence)", () => {
    const log =
      "type=ADD_USER msg=audit(1490451400.5:400): pid=1 uid=0 auid=1000 ses=3 " +
      "msg='op=adding-user id=1001 exe=\"/usr/sbin/useradd\" hostname=? addr=? terminal=pts/0 res=success'";
    const e = parseAuditdLog(log).events[0];
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1136.001");
    // The "?" placeholder host/addr must not become an IOC.
    expect(parseAuditdLog(log).iocs.filter((i) => i.type === "ip")).toHaveLength(0);
  });
});

describe("parseAuditdLog — SOCKADDR hex decode", () => {
  it("decodes an AF_INET saddr into the remote IP + port", () => {
    // family=AF_INET(0200) port=80(0050) addr=1.2.3.4(01020304) + padding
    const log = [
      'type=SYSCALL msg=audit(1490451500.0:500): arch=c000003e syscall=42 success=yes comm="curl" exe="/usr/bin/curl"',
      "type=SOCKADDR msg=audit(1490451500.0:500): saddr=02000050010203040000000000000000",
    ].join("\n");
    const r = parseAuditdLog(log);
    const e = r.events[0];
    expect(e.srcIp).toBe("1.2.3.4");
    expect(e.port).toBe(80);
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("1.2.3.4");
  });
});

describe("parseAuditdLog — ausearch separators + interpreted header", () => {
  it("ignores '----' record separators and 'time->' headers", () => {
    const log = [
      "----",
      "time->Sat Mar 25 13:53:37 2017",
      'type=USER_AUTH msg=audit(1490451217.000:600): pid=1 uid=0 msg=\'op=PAM:authentication acct="alice" exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=ssh res=success\'',
      "----",
    ].join("\n");
    const r = parseAuditdLog(log);
    expect(r.format).toBe("auditd");
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toContain("acct=alice");
  });
});

describe("parseAuditdLog — aureport tabular fallback", () => {
  it("keeps numbered aureport rows as Info evidence at their own time", () => {
    const report = [
      "Authentication Report",
      "============================================",
      "# date time acct host term exe success event",
      "============================================",
      "1. 04/01/2024 10:00:00 root 198.51.100.7 ssh /usr/sbin/sshd no 234",
    ].join("\n");
    const r = parseAuditdLog(report);
    expect(r.format).toBe("aureport");
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toContain("aureport:");
    expect(r.events[0].timestamp).toBe("2024-04-01T10:00:00.000Z");
    expect(r.iocs.find((i) => i.type === "ip")?.value).toBe("198.51.100.7");
  });
});

describe("parseAuditdLog — edges", () => {
  it("returns empty for non-audit text", () => {
    const r = parseAuditdLog("just a plain log line\nanother line");
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });

  it("aggregates repeated identical events", () => {
    const mk = (serial: number, ts: number): string =>
      `type=SYSCALL msg=audit(${ts}.000:${serial}): comm="ls" exe="/usr/bin/ls" key="watch"\n` +
      `type=EXECVE msg=audit(${ts}.000:${serial}): argc=1 a0="ls"`;
    const r = parseAuditdLog([mk(1, 1490451000), mk(2, 1490451001)].join("\n"));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });
});
