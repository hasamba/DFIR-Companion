import type { InvestigationState } from "../analysis/stateTypes.js";
import type { GlossaryEntry } from "./reportMeta.js";

// A curated dictionary of DFIR / security terms and acronyms. The report's glossary (2.4)
// is auto-derived by scanning the investigation text for these terms, so the analyst gets
// a relevant glossary for free; a human-authored glossary in ReportMeta overrides it.
// Keep entries genuinely glossary-worthy (acronyms, tools, techniques) — not common words.
export const GLOSSARY_DICTIONARY: Record<string, string> = {
  EDR: "Endpoint Detection and Response — endpoint tooling that records and alerts on host activity.",
  XDR: "Extended Detection and Response — correlates detections across endpoint, network and cloud.",
  MDR: "Managed Detection and Response — an outsourced detection-and-response service.",
  SIEM: "Security Information and Event Management — central log aggregation, correlation and alerting.",
  SOC: "Security Operations Center — the team that monitors and responds to security events.",
  DFIR: "Digital Forensics and Incident Response.",
  IOC: "Indicator of Compromise — an observable artifact (hash, IP, domain…) tied to an intrusion.",
  IOA: "Indicator of Attack — a behavioral signal of an attack in progress.",
  TTP: "Tactics, Techniques and Procedures — how an adversary operates.",
  C2: "Command and Control — infrastructure an attacker uses to control compromised hosts.",
  RAT: "Remote Access Trojan — malware giving an attacker remote control of a host.",
  LOLBIN: "Living-Off-the-Land Binary — a legitimate system binary abused for malicious purposes.",
  RDP: "Remote Desktop Protocol — Windows remote graphical session protocol.",
  SMB: "Server Message Block — Windows file/printer sharing protocol, often abused for lateral movement.",
  LSASS: "Local Security Authority Subsystem Service — Windows process holding credentials; a credential-theft target.",
  Mimikatz: "A credential-dumping tool that extracts secrets from LSASS.",
  PsExec: "A Sysinternals remote-execution tool, frequently abused for lateral movement.",
  "Cobalt Strike": "A commercial adversary-emulation framework widely abused by threat actors for C2.",
  "lateral movement": "Techniques an attacker uses to move from one host to others within a network.",
  "privilege escalation": "Gaining higher permissions than initially obtained on a system.",
  persistence: "Techniques that let an attacker retain access across reboots or credential changes.",
  exfiltration: "Unauthorized transfer of data out of the victim environment.",
  beacon: "Periodic callback traffic from a compromised host to C2 infrastructure.",
  ransomware: "Malware that encrypts data and demands payment for decryption.",
  phishing: "Social engineering via fraudulent messages to steal credentials or deliver malware.",
  MFA: "Multi-Factor Authentication.",
  "MITRE ATT&CK": "A knowledge base of adversary tactics and techniques.",
  CVE: "Common Vulnerabilities and Exposures — a public identifier for a known vulnerability.",
  TLP: "Traffic Light Protocol — a sensitivity-labeling scheme for sharing information.",
  PII: "Personally Identifiable Information.",
  WMI: "Windows Management Instrumentation — a management interface often abused for execution and persistence.",
  PowerShell: "A Windows scripting and automation shell commonly used in attacks.",
  LDAP: "Lightweight Directory Access Protocol — directory queries, e.g. against Active Directory.",
  Kerberos: "A Windows/network authentication protocol; targeted by attacks such as Kerberoasting.",
  NTLM: "A legacy Windows authentication protocol; subject to relay and pass-the-hash attacks.",
  "Active Directory": "Microsoft's directory service for Windows domain identity and access.",
  "domain controller": "A server that authenticates users and enforces policy in an Active Directory domain.",
  "scheduled task": "A Windows mechanism to run programs on a schedule, often abused for persistence.",
  prefetch: "A Windows execution artifact recording recently run programs.",
  amcache: "A Windows registry hive recording program-execution metadata.",
  shimcache: "Application Compatibility Cache — a Windows artifact of executed/known binaries.",
  MFT: "Master File Table — the NTFS index of every file on a volume; a key forensic artifact.",
  YARA: "A pattern-matching tool and ruleset for identifying malware.",
  VirusTotal: "An online service aggregating many AV engines and threat intel for files/URLs/IPs.",
  THOR: "Nextron's APT/IOC scanner.",
  Velociraptor: "An open-source endpoint-visibility and DFIR collection tool.",
};

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// All free-text in the investigation a term could plausibly appear in. IOC values (hashes,
// IPs) are excluded — they're not prose and would only cause false matches.
function collectText(state: InvestigationState): string {
  const parts: string[] = [state.lastSummary, state.attackerPath];
  for (const f of state.findings) parts.push(f.title, f.description);
  for (const e of state.forensicTimeline) parts.push(e.description);
  for (const t of state.timeline) parts.push(t.description);
  for (const m of state.mitreTechniques) parts.push(m.id, m.name);
  for (const q of state.keyQuestions) parts.push(q.question, q.answer);
  for (const s of state.nextSteps) parts.push(s.action, s.rationale, s.pointer);
  for (const th of state.openThreads) parts.push(th.description);
  return parts.join("\n");
}

// Derive the glossary: every dictionary term that appears (as a whole token, case-
// insensitively) anywhere in the investigation text, sorted alphabetically.
export function deriveGlossary(state: InvestigationState): GlossaryEntry[] {
  const text = collectText(state);
  const out: GlossaryEntry[] = [];
  for (const [term, explanation] of Object.entries(GLOSSARY_DICTIONARY)) {
    // Reject matches embedded in a larger alphanumeric run (so "MFT" ≠ "MFTX", "C2" ≠ "AC2").
    const re = new RegExp(`(?<![A-Za-z0-9])${escapeRegExp(term)}(?![A-Za-z0-9])`, "i");
    if (re.test(text)) out.push({ term, explanation });
  }
  return out.sort((a, b) => a.term.localeCompare(b.term));
}
