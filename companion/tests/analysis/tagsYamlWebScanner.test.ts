import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { parseShellHistoryFile } from "../../src/analysis/bashHistoryImport.js";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1964: a web vulnerability scanner (sqlmap, dirsearch, xray, vulmap, WebLogicScan) run from a host
// in the case reached the timeline with no technique and no raised grade, so an Info row never
// reached the AI and a playbook that starts with scanning (T1595.002) could not match. These tests
// run the REAL importers and the SHIPPED ruleset: a scan grades Medium, an exploit mode grades High
// with T1190, and file paths, package installs and the radiology "xray" viewer stay untouched.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);
const BASE = "web_scanner_tool";
const EXPLOIT = "web_scanner_exploit_mode";

type Tagged = { severity: string; ruleIds: string[]; mitre: string[]; tags: string[] };

function apply(mapped: Partial<ForensicEvent>): Tagged {
  const event = {
    ...mapped,
    id: "e1",
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: mapped.mitreTechniques ?? [],
  } as unknown as ForensicEvent;
  const proposal = runTagger([event], RULES).perEvent[0];
  const after = proposal ? applyToForensicEvent(event, proposal) : event;
  return {
    severity: after.severity,
    ruleIds: proposal?.ruleIds ?? [],
    mitre: after.mitreTechniques ?? [],
    tags: proposal?.tags ?? [],
  };
}

function sysmon(commandLine: string): Tagged {
  const mapped = parseSiemExport(
    JSON.stringify([
      {
        "@timestamp": "2026-01-02T03:04:05Z",
        channel: "Microsoft-Windows-Sysmon/Operational",
        computer_name: "H1",
        event_id: 1,
        event_data: { Image: "C:\\Windows\\System32\\cmd.exe", CommandLine: commandLine },
      },
    ]),
  );
  return apply(mapped.events[0]);
}

function bash(cmd: string): Tagged {
  const parsed = parseShellHistoryFile(`${cmd}\n`, { user: "lab" });
  return apply(parsed.events[0]);
}

function hayabusa(cmdline: string): Tagged {
  const row = {
    Timestamp: "2026-09-22 14:37:51.894 +00:00",
    Computer: "WS-01",
    Channel: "Microsoft-Windows-Sysmon/Operational",
    EID: 1,
    Level: "info",
    Title: "Proc Exec",
    RecordID: 1001,
    Details: { Cmdline: cmdline, Proc: "C:\\Python311\\python.exe", PID: 1112 },
  };
  const parsed = parseHayabusaTimeline(JSON.stringify([row]));
  return apply(parsed.events[0]);
}

const SCANS: string[] = [
  '"C:\\Python311\\python.exe" sqlmap.py -u http://203.0.113.5/?id=1 --batch',
  '"C:\\Program Files\\Python311\\python.exe" C:\\tools\\sqlmap\\sqlmap.py -r req.txt',
  "xray_windows_amd64.exe webscan --basic-crawler http://203.0.113.5",
  '"C:\\tools\\xray\\xray.exe" ws --url http://203.0.113.5',
  "xray.exe --config c.yaml webscan --listen 127.0.0.1:7777",
  "xray_windows_amd64.exe servicescan --target 203.0.113.5",
  "python dirsearch.py -u http://203.0.113.5 -e php",
  "python vulmap.py -u http://203.0.113.5",
  "python WeblogicScan.py -u 10.0.0.9 -p 7001",
  "py -3 WeblogicScan.py 10.0.0.9 7001",
];

const EXPLOITS: string[] = [
  '"C:\\Python311\\python.exe" sqlmap.py -u http://203.0.113.5/?id=1 --os-shell',
  "sqlmap.exe --url=http://203.0.113.5 --file-write=a.php --file-dest=C:\\inetpub\\wwwroot\\a.php",
  "python vulmap.py -u http://203.0.113.5 -m exp -a weblogic",
  "python vulmap.py -u http://203.0.113.5 --mode=exp",
];

const SYSMON_NEGATIVES: string[] = [
  "notepad C:\\Users\\a\\Documents\\xray\\notes.txt",
  '"C:\\Program Files\\XRay Viewer\\xray.exe" --open study.dcm',
  '"C:\\Program Files\\Radiology\\xray.exe" ss1.dcm',
  "xray.exe --help",
  'mspaint "C:\\scans\\xray-chest.png"',
  "cmd.exe /c type C:\\logs\\weblogicscan.log",
  "python -m pip download sqlmap --no-deps",
  "git clone https://github.com/sqlmapproject/sqlmap.git",
  "notepad++.exe C:\\tools\\sqlmap\\README.md",
  "findstr /i sqlmap C:\\inetpub\\logs\\u_ex.log",
  "python3 -m http.server 8000",
];

describe("bundled data/tags.yaml — web vulnerability scanners (#1964)", () => {
  it("loads both rules with their grades and techniques", () => {
    const base = RULES.rules.find((r) => r.id === BASE);
    const exploit = RULES.rules.find((r) => r.id === EXPLOIT);
    expect(base?.severity).toBe("Medium");
    expect(base?.mitre).toEqual(["T1595.002"]);
    expect(base?.tags).toEqual(expect.arrayContaining(["web-scanner", "reconnaissance"]));
    expect(exploit?.severity).toBe("High");
    expect(exploit?.mitre).toEqual(expect.arrayContaining(["T1595.002", "T1190"]));
  });

  describe("Sysmon EID 1 command lines", () => {
    it.each(SCANS)("grades a scan Medium with T1595.002: %s", (cmd) => {
      const r = sysmon(cmd);
      expect(r.ruleIds).toContain(BASE);
      expect(r.ruleIds).not.toContain(EXPLOIT);
      expect(r.severity).toBe("Medium");
      expect(r.mitre).toContain("T1595.002");
      expect(r.tags).toContain("web-scanner");
    });

    it.each(EXPLOITS)("grades an exploit mode High with T1190: %s", (cmd) => {
      const r = sysmon(cmd);
      expect(r.ruleIds).toContain(EXPLOIT);
      expect(r.severity).toBe("High");
      expect(r.mitre).toEqual(expect.arrayContaining(["T1595.002", "T1190"]));
    });

    it.each(SYSMON_NEGATIVES)("does not match: %s", (cmd) => {
      const r = sysmon(cmd);
      expect(r.ruleIds).not.toContain(BASE);
      expect(r.ruleIds).not.toContain(EXPLOIT);
    });

    it("needs a token boundary after the exploit flag", () => {
      const r = sysmon("sqlmap -u http://203.0.113.5 --os-shellfoo");
      expect(r.ruleIds).toContain(BASE);
      expect(r.ruleIds).not.toContain(EXPLOIT);
    });
  });

  describe("Hayabusa EID 1 rows", () => {
    it("grades a sqlmap command line Medium with T1595.002", () => {
      const r = hayabusa('"C:\\Python311\\python.exe" sqlmap.py -u http://203.0.113.5/?id=1 --batch');
      expect(r.ruleIds).toContain(BASE);
      expect(r.severity).toBe("Medium");
      expect(r.mitre).toContain("T1595.002");
    });
  });

  describe("bash history rows", () => {
    it.each([
      "sqlmap -u http://203.0.113.5 --batch",
      "cd /opt/dirsearch && python3 dirsearch.py -u http://203.0.113.5",
      "./xray_linux_amd64 webscan --url http://203.0.113.5",
      "python3 WeblogicScan.py 10.0.0.9 7001",
    ])("grades a scan Medium: %s", (cmd) => {
      const r = bash(cmd);
      expect(r.ruleIds).toContain(BASE);
      expect(r.severity).toBe("Medium");
      expect(r.mitre).toContain("T1595.002");
    });

    it.each([
      "sudo sqlmap -u 'http://203.0.113.5/?id=1' --os-shell",
      "proxychains4 python3 vulmap.py -u http://203.0.113.5 -m exp",
    ])("grades an exploit mode High with T1190: %s", (cmd) => {
      const r = bash(cmd);
      expect(r.ruleIds).toContain(EXPLOIT);
      expect(r.severity).toBe("High");
      expect(r.mitre).toEqual(expect.arrayContaining(["T1595.002", "T1190"]));
    });

    it.each([
      "cd /opt/sqlmap",
      "vim vulmap.py",
      "git clone https://github.com/sqlmapproject/sqlmap.git",
      "grep -r sqlmap /var/log/nginx/access.log",
      "cat /opt/sqlmap/README.md",
      "pip install sqlmap",
      "ls ~/xray",
    ])("does not match: %s", (cmd) => {
      const r = bash(cmd);
      expect(r.ruleIds).not.toContain(BASE);
      expect(r.ruleIds).not.toContain(EXPLOIT);
    });
  });
});
