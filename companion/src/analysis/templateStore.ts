import { readFile, readdir, mkdir, unlink } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { atomicWrite } from "../storage/atomicWrite.js";
import { storeFilePath } from "../storage/safeStoreId.js";
import type { Severity, InvestigationQuestion, QuestionStatus, NextStep, StepPriority } from "./stateTypes.js";

export interface TemplateNextStep {
  action: string;
  priority: StepPriority;
  rationale: string;
  pointer: string;
}

export interface CaseTemplate {
  id: string;
  name: string;
  description: string;
  builtIn: boolean;
  recommendedImports: string[];      // e.g. ["chainsaw", "thor", "hayabusa"]
  initialKeyQuestions: string[];     // pre-populated question strings
  initialNextSteps: TemplateNextStep[]; // pre-populated recommended next steps
  severityFloor: Severity | null;    // minimum severity shown initially
  huntPlatforms: string[];           // e.g. ["Velociraptor", "Security Onion"]
}

export const BUILT_IN_TEMPLATES: readonly CaseTemplate[] = [
  {
    id: "ransomware",
    name: "Ransomware",
    description: "Ransomware attack — encryption event, lateral movement, potential double-extortion.",
    builtIn: true,
    recommendedImports: ["chainsaw", "hayabusa", "thor", "velociraptor", "kape"],
    initialKeyQuestions: [
      "What was the initial access vector?",
      "When did encryption begin, and which hosts and shares were affected?",
      "Was data exfiltrated before encryption (double-extortion)?",
      "What ransom note or attacker-left IOC was found?",
      "How did the attacker achieve lateral movement or privilege escalation?",
      "How was persistence established?",
      "Are backups intact and isolated from the network?",
    ],
    initialNextSteps: [
      { priority: "critical", action: "Isolate all affected hosts from the network immediately", rationale: "Prevent further encryption and lateral movement while preserving evidence", pointer: "Network switch ports or EDR isolation console" },
      { priority: "critical", action: "Preserve volatile memory (RAM dump) and disk image of patient zero before any remediation", rationale: "Memory may contain encryption keys, injected attacker tools, and credentials that won't survive a reboot", pointer: "Velociraptor: Windows.Memory.Acquisition / winpmem on patient zero" },
      { priority: "high", action: "Collect Windows event logs (Security.evtx, System.evtx, Sysmon) from all affected hosts", rationale: "Identify initial access, lateral movement (EID 4624/4672/4688), and the encryption process chain", pointer: "KAPE triage or Velociraptor Windows.EventLogs.Evtx collection" },
      { priority: "high", action: "Run Chainsaw/Hayabusa against collected EVTX to surface attacker activity quickly", rationale: "Rapidly triage hundreds of event logs against known-bad Sigma rules", pointer: "chainsaw hunt --sigma rules/ -d evtx/ OR import Hayabusa json-timeline output" },
      { priority: "high", action: "Check for data exfiltration indicators: large outbound transfers, rclone, MEGAsync, cloud sync tools", rationale: "Ransomware groups commonly exfiltrate before encrypting (double extortion) — determines notification obligations", pointer: "Zeek/Suricata logs, proxy logs, DLP alerts, KAPE SRUM network usage" },
      { priority: "medium", action: "Locate the ransom note and any attacker-dropped tools or scripts", rationale: "Ransom note contains wallet address, victim ID, and sometimes C2 URLs useful for threat-intel lookup", pointer: "File system search for .txt/.html ransom notes; THOR scan for attacker tooling" },
      { priority: "medium", action: "Verify backup integrity and confirm backups are isolated from the network", rationale: "Determines recovery path and RTO — ransomware frequently targets backup systems first", pointer: "Backup server access logs, VSS shadow copy status, offline backup verification" },
    ],
    severityFloor: "High",
    huntPlatforms: ["Velociraptor", "Security Onion"],
  },
  {
    id: "bec",
    name: "BEC / Email Compromise",
    description: "Business Email Compromise — account takeover, mail-rule manipulation, wire-fraud.",
    builtIn: true,
    recommendedImports: ["m365", "siem", "chainsaw"],
    initialKeyQuestions: [
      "Which mailboxes were compromised?",
      "How was initial access achieved (phishing, password spray, OAuth grant)?",
      "Were mail-forwarding rules or inbox rules created by the attacker?",
      "Were financial transactions or wire transfers initiated?",
      "What external IP addresses and user-agents accessed the account?",
      "Was MFA present and, if so, how was it bypassed?",
      "What data was accessed or exfiltrated from the mailbox?",
    ],
    initialNextSteps: [
      { priority: "critical", action: "Revoke all active sessions and reset the compromised account's password and MFA", rationale: "Terminates attacker's active access before further damage — session revocation is independent of password reset", pointer: "Entra ID / Azure AD → Revoke sessions, reset MFA methods, reset password" },
      { priority: "critical", action: "Export the Unified Audit Log (UAL) for all affected mailboxes covering the past 90 days", rationale: "Primary evidence source for all mailbox and sign-in activity in Microsoft 365", pointer: "Microsoft Purview compliance portal → Audit search, or Import M365 export into DFIR Companion" },
      { priority: "high", action: "Review and immediately delete any attacker-created inbox rules (forwarding, deletion, move-to-folder)", rationale: "Inbox rules are used to hide replies, delete security alerts, and forward mail to attacker-controlled addresses", pointer: "Exchange Admin Center → mailbox rules, or Get-InboxRule in Exchange Online PowerShell" },
      { priority: "high", action: "Audit OAuth app grants and newly consented applications on the compromised account", rationale: "OAuth app grants survive password resets and provide persistent mailbox access without credentials", pointer: "Entra ID → Enterprise Applications → User consent / Get-AzureADServicePrincipal" },
      { priority: "high", action: "Identify all source IPs and user-agents used during the compromise window and enrich as IOCs", rationale: "Attribute sessions to attacker infrastructure; IPs may resolve to known bulletproof hosting or VPN services", pointer: "UAL OperationName=UserLoggedIn, ClientIPAddress field — import into DFIR Companion for enrichment" },
      { priority: "medium", action: "Notify finance and wire-transfer teams; review sent items and drafts for fraudulent payment requests", rationale: "BEC most commonly culminates in wire fraud — early notification can claw back in-flight transfers", pointer: "Search sent items and drafts for keywords: wire transfer, invoice, payment, bank account change" },
      { priority: "medium", action: "Check for mailbox delegation or Send As / Send on Behalf permissions added during the attack", rationale: "Delegation grants persistent mailbox access that outlasts password resets", pointer: "Get-MailboxPermission / Get-RecipientPermission in Exchange Online PowerShell" },
    ],
    severityFloor: "Medium",
    huntPlatforms: ["Microsoft 365", "Entra ID / Azure AD"],
  },
  {
    id: "insider-threat",
    name: "Insider Threat",
    description: "Malicious or negligent insider — data theft, sabotage, policy violation.",
    builtIn: true,
    recommendedImports: ["siem", "kape", "plaso", "m365", "aws"],
    initialKeyQuestions: [
      "Who is the subject of investigation and what is their role?",
      "What data or systems did the subject access outside their normal scope?",
      "Were large file copies, USB transfers, or cloud uploads observed?",
      "Did the subject access systems after a resignation or termination notice?",
      "Are there signs of data staging or collection before departure?",
      "What communication channels (email, Teams, Slack) were used?",
      "Was account or credentials sharing observed?",
    ],
    initialNextSteps: [
      { priority: "critical", action: "Preserve all relevant logs and evidence before the subject's access is revoked or systems are modified", rationale: "Evidence destruction risk is highest when the subject is still active or aware of the investigation", pointer: "SIEM, DLP, proxy, badge-access, M365 UAL, and endpoint logs — legal hold if applicable" },
      { priority: "high", action: "Pull full DLP and data-loss alerts for the subject's accounts over the investigation window", rationale: "DLP alerts are the primary signal for data staging and exfiltration activity", pointer: "DLP console, Microsoft Purview, CASB (Defender for Cloud Apps) file-activity report" },
      { priority: "high", action: "Collect endpoint forensic triage (KAPE or Plaso) from the subject's workstation", rationale: "Surfaces file access history, USB device connections, recently opened files, and application usage", pointer: "KAPE targets: USB, LNK files, JumpLists, MFT, SRUM network/app usage — import into DFIR Companion" },
      { priority: "high", action: "Pull physical security and badge-access logs for the investigation window", rationale: "After-hours badge swipes or access to restricted areas corroborate or contradict digital activity timestamps", pointer: "Physical security system export; correlate timestamps with endpoint and SIEM activity" },
      { priority: "medium", action: "Review cloud storage activity (OneDrive, Google Drive, Dropbox, Box) for mass-download or bulk-sync events", rationale: "Cloud sync tools are the most common exfiltration channel for insiders due to their low visibility", pointer: "CASB / cloud-proxy logs, Microsoft Defender for Cloud Apps file-activity timeline" },
      { priority: "medium", action: "Examine email for large attachments, forwarding to personal addresses, or unusual recipient domains", rationale: "Email remains a primary insider exfiltration channel, especially for document theft", pointer: "Exchange message trace, UAL MailItemsAccessed and SendAs operations, O365 Defender alerts" },
      { priority: "medium", action: "Establish the subject's normal access baseline for the 3 months before the investigation window", rationale: "Anomalous access is only meaningful relative to a baseline — avoids false positives on legitimate job duties", pointer: "SIEM query: same user, same resource types, prior quarter — document the normal pattern first" },
    ],
    severityFloor: "Medium",
    huntPlatforms: ["Microsoft 365", "Velociraptor", "Elastic SIEM"],
  },
  {
    id: "web-intrusion",
    name: "Web App Intrusion",
    description: "Web application attack — SQL injection, RCE, webshell, server compromise.",
    builtIn: true,
    recommendedImports: ["network", "siem", "chainsaw", "hayabusa"],
    initialKeyQuestions: [
      "What web application or endpoint was targeted?",
      "What was the attack technique (SQLi, RCE, file upload, SSRF)?",
      "Was a webshell or backdoor installed?",
      "What OS commands were executed by the web process?",
      "Did the attacker pivot from the web server to internal systems?",
      "What data was accessed or exfiltrated?",
      "Has the vulnerability been patched or the system isolated?",
    ],
    initialNextSteps: [
      { priority: "critical", action: "Snapshot the compromised web server, then isolate it from the network", rationale: "Preserve evidence before isolation; prevents further exploitation or lateral movement from the server", pointer: "VM snapshot or disk image first, then firewall/EDR isolation — do NOT wipe or rebuild yet" },
      { priority: "critical", action: "Search for webshells across the web root and all upload/temp directories", rationale: "Webshells provide persistent backdoor access and are frequently missed by AV due to obfuscation", pointer: "find /var/www -name '*.php' -newer <install_date> / THOR webshell scan / Velociraptor Windows.Detection.Webshell" },
      { priority: "high", action: "Collect and archive web server access logs (Apache/Nginx/IIS/WAF) for the full attack window", rationale: "Access logs are the primary evidence source: attacker requests, payloads, response codes, and C2 callback patterns", pointer: "/var/log/apache2/access.log, IIS C:\\inetpub\\logs, WAF audit log — import Suricata/Zeek into DFIR Companion" },
      { priority: "high", action: "Review OS process execution logs for suspicious child processes spawned by the web worker", rationale: "RCE and webshell activity appears as the web process (w3wp, httpd, nginx) spawning cmd.exe, bash, or python", pointer: "Sysmon EID 1, Auditd execve, Security EID 4688 filtered by ParentImage=web process" },
      { priority: "high", action: "Run Suricata/Zeek against captured network traffic to identify C2 callbacks and data exfiltration", rationale: "Network evidence confirms exploitation and characterises outbound attacker communication", pointer: "Import network capture or Suricata eve.json into DFIR Companion via the Network importer" },
      { priority: "medium", action: "Identify the exact CVE or vulnerability exploited and confirm patch availability", rationale: "Required for remediation decision and to scope whether other instances of the same application are at risk", pointer: "CVE database, vendor security advisory, WAF rule that fired, PoC code if public" },
      { priority: "medium", action: "Hunt other internet-facing hosts for the same vulnerability or identical webshell hashes", rationale: "Automated scanners mean one exploited host often implies others were hit in the same sweep", pointer: "Velociraptor fleet hash hunt / THOR enterprise scan / WAF log review across all web properties" },
    ],
    severityFloor: "Medium",
    huntPlatforms: ["Security Onion", "Elastic SIEM"],
  },
  {
    id: "general-malware",
    name: "General Malware",
    description: "Malware infection — trojan, RAT, info-stealer, cryptominer, or unknown malware family.",
    builtIn: true,
    recommendedImports: ["thor", "chainsaw", "hayabusa", "velociraptor", "sandbox"],
    initialKeyQuestions: [
      "What malware family or IOC triggered the alert?",
      "What was the infection vector (email attachment, drive-by, USB)?",
      "How many hosts are affected?",
      "What C2 infrastructure (IP/domain/URL) was contacted?",
      "What persistence mechanisms were established?",
      "Was credential theft or lateral movement observed?",
      "Is the malware still active or has the system been cleaned?",
    ],
    initialNextSteps: [
      { priority: "critical", action: "Isolate infected host(s) from the network to stop active C2 communication and lateral movement", rationale: "Live malware with an active C2 channel will download additional payloads, exfiltrate data, and spread laterally", pointer: "EDR isolation console or network switch port shutdown — confirm C2 is severed via Netstat/Velociraptor" },
      { priority: "critical", action: "Capture a full memory dump of the infected host before any remediation or reboot", rationale: "RAM contains decrypted payloads, injected code, in-memory C2 config, and credentials that disappear on reboot", pointer: "Velociraptor: Windows.Memory.Acquisition / winpmem / LiME for Linux" },
      { priority: "high", action: "Submit the malware sample to a sandbox (CAPEv2 or Falcon Sandbox) and import the report", rationale: "Automated sandbox analysis surfaces full behavior, network indicators, dropped files, and MITRE mapping in minutes", pointer: "Collect sample via Velociraptor Windows.System.BinaryInfo, submit, import sandbox JSON into DFIR Companion" },
      { priority: "high", action: "Run THOR or Chainsaw/Hayabusa on the host to find related dropped files, scripts, and registry persistence", rationale: "Determines the full scope of the infection beyond the initial detection alert", pointer: "THOR --intense / Chainsaw hunt --sigma rules/ -d evtx/ — import results into DFIR Companion" },
      { priority: "high", action: "Enrich all IOCs (hashes, IPs, domains, URLs) from the detection against threat intel", rationale: "Identifies the malware family, known C2 infrastructure, and related samples for broader context and attribution", pointer: "Enable VirusTotal + Hunting.ch enrichment in DFIR Companion for this case" },
      { priority: "medium", action: "Hunt the fleet for the same binary hash and C2 IP/domain to determine the scope of infection", rationale: "Malware commonly spreads or is deployed to multiple hosts before the initial detection fires", pointer: "Velociraptor fleet hunt: Windows.Network.Netstat for C2 IP, Windows.Search.FileFinder for binary hash" },
      { priority: "medium", action: "Identify and document all persistence mechanisms for complete and durable remediation", rationale: "Incomplete removal of persistence leads to reinfection after the host is cleaned and reconnected", pointer: "Autoruns, Scheduled Tasks (schtasks), Services, Registry Run keys, WMI subscriptions — KAPE triage" },
    ],
    severityFloor: "High",
    huntPlatforms: ["Velociraptor", "Security Onion"],
  },
];

// Build initial InvestigationQuestion objects from a template's question strings.
// Pinned so synthesis preserves them and can answer them over time.
export function buildInitialQuestions(template: CaseTemplate): InvestigationQuestion[] {
  return template.initialKeyQuestions.map((q) => ({
    id: randomUUID(),
    question: q,
    status: "unknown" as QuestionStatus,
    answer: "",
    pointer: "",
    pinned: true,
  }));
}

// Build initial NextStep objects from a template's recommended next steps.
export function buildInitialNextSteps(template: CaseTemplate): NextStep[] {
  return (template.initialNextSteps ?? []).map((s) => ({
    id: randomUUID(),
    priority: s.priority,
    action: s.action,
    rationale: s.rationale,
    pointer: s.pointer,
  }));
}

export class TemplateStore {
  constructor(private readonly root: string) {}

  // Validates the id and guarantees containment beneath root (#213) — the id reaches here straight
  // from a request body/param, so `../..` must not become a path.
  private path(id: string): string {
    return storeFilePath(this.root, id);
  }

  async list(): Promise<CaseTemplate[]> {
    return [...BUILT_IN_TEMPLATES, ...(await this.listCustom())];
  }

  private async listCustom(): Promise<CaseTemplate[]> {
    let entries: string[];
    try {
      entries = await readdir(this.root);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const templates: CaseTemplate[] = [];
    for (const entry of entries) {
      if (!entry.endsWith(".json")) continue;
      try {
        const raw = JSON.parse(await readFile(join(this.root, entry), "utf8")) as CaseTemplate;
        if (!raw.builtIn) templates.push(raw);
      } catch {
        // skip malformed files
      }
    }
    return templates;
  }

  async get(id: string): Promise<CaseTemplate | null> {
    const builtin = BUILT_IN_TEMPLATES.find((t) => t.id === id);
    if (builtin) return builtin;
    try {
      return JSON.parse(await readFile(this.path(id), "utf8")) as CaseTemplate;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  async save(input: Omit<CaseTemplate, "id" | "builtIn"> & { id?: string }): Promise<CaseTemplate> {
    const template: CaseTemplate = {
      id: input.id && String(input.id).trim() ? String(input.id).trim() : randomUUID(),
      name: String(input.name ?? "").trim(),
      description: String(input.description ?? "").trim(),
      builtIn: false,
      recommendedImports: Array.isArray(input.recommendedImports) ? input.recommendedImports.map(String) : [],
      initialKeyQuestions: Array.isArray(input.initialKeyQuestions) ? input.initialKeyQuestions.map(String) : [],
      initialNextSteps: Array.isArray(input.initialNextSteps) ? input.initialNextSteps : [],
      severityFloor: input.severityFloor ?? null,
      huntPlatforms: Array.isArray(input.huntPlatforms) ? input.huntPlatforms.map(String) : [],
    };
    await mkdir(this.root, { recursive: true });
    await atomicWrite(this.path(template.id), JSON.stringify(template, null, 2));
    return template;
  }

  async delete(id: string): Promise<boolean> {
    if (BUILT_IN_TEMPLATES.some((t) => t.id === id)) {
      throw new Error(`cannot delete built-in template "${id}"`);
    }
    try {
      await unlink(this.path(id));
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw err;
    }
  }
}
