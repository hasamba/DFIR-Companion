// Map a forensic event's MITRE ATT&CK techniques (and, as a fallback, its description) to the
// ATT&CK TACTIC name — which is exactly how DFIR-IRIS names its timeline "event categories".
// The orchestrator resolves the returned name → IRIS event_category_id at runtime via
// /manage/event-categories/list, so an event lands in the right category automatically.
//
// The technique→tactic table is a curated subset covering the techniques THOR / the vision model
// commonly emit in intrusion cases; unknown techniques fall through to the keyword heuristic and
// finally to undefined (→ "Unspecified"). A technique can belong to several tactics; we record one
// forensically-relevant tactic per technique and, when an event has several, pick the
// highest-priority tactic (impact/exfil first) so the category reflects the worst observed stage.

// IRIS event-category names = ATT&CK tactic names (exact spelling matters for the id lookup).
export type IrisTactic =
  | "Initial Access" | "Execution" | "Persistence" | "Privilege Escalation"
  | "Defense Evasion" | "Credential Access" | "Discovery" | "Lateral Movement"
  | "Collection" | "Command and Control" | "Exfiltration" | "Impact";

// Base technique id (sub-techniques are stripped to their parent) → tactic.
const TECHNIQUE_TACTIC: Record<string, IrisTactic> = {
  // Initial Access
  T1566: "Initial Access", T1190: "Initial Access", T1133: "Initial Access", T1078: "Initial Access",
  T1195: "Initial Access", T1199: "Initial Access", T1189: "Initial Access", T1091: "Initial Access", T1200: "Initial Access",
  // Execution
  T1059: "Execution", T1204: "Execution", T1203: "Execution", T1106: "Execution", T1569: "Execution",
  T1047: "Execution", T1129: "Execution", T1559: "Execution", T1610: "Execution", T1648: "Execution",
  // Persistence
  T1547: "Persistence", T1543: "Persistence", T1136: "Persistence", T1505: "Persistence", T1546: "Persistence",
  T1574: "Persistence", T1098: "Persistence", T1137: "Persistence", T1037: "Persistence", T1176: "Persistence",
  T1554: "Persistence", T1053: "Persistence", T1197: "Persistence",
  // Privilege Escalation
  T1548: "Privilege Escalation", T1134: "Privilege Escalation", T1068: "Privilege Escalation",
  T1484: "Privilege Escalation", T1611: "Privilege Escalation",
  // Defense Evasion
  T1070: "Defense Evasion", T1027: "Defense Evasion", T1036: "Defense Evasion", T1112: "Defense Evasion",
  T1562: "Defense Evasion", T1218: "Defense Evasion", T1140: "Defense Evasion", T1497: "Defense Evasion",
  T1480: "Defense Evasion", T1055: "Defense Evasion", T1564: "Defense Evasion", T1222: "Defense Evasion",
  T1127: "Defense Evasion", T1006: "Defense Evasion", T1620: "Defense Evasion", T1535: "Defense Evasion",
  T1207: "Defense Evasion", T1014: "Defense Evasion",
  // Credential Access
  T1003: "Credential Access", T1110: "Credential Access", T1555: "Credential Access", T1552: "Credential Access",
  T1558: "Credential Access", T1556: "Credential Access", T1187: "Credential Access", T1212: "Credential Access",
  T1040: "Credential Access", T1539: "Credential Access", T1649: "Credential Access",
  // Discovery
  T1087: "Discovery", T1083: "Discovery", T1057: "Discovery", T1018: "Discovery", T1082: "Discovery",
  T1016: "Discovery", T1049: "Discovery", T1033: "Discovery", T1007: "Discovery", T1069: "Discovery",
  T1482: "Discovery", T1135: "Discovery", T1046: "Discovery", T1518: "Discovery", T1010: "Discovery",
  T1124: "Discovery", T1201: "Discovery", T1012: "Discovery", T1614: "Discovery",
  // Lateral Movement
  T1021: "Lateral Movement", T1570: "Lateral Movement", T1550: "Lateral Movement", T1563: "Lateral Movement",
  T1080: "Lateral Movement", T1072: "Lateral Movement", T1210: "Lateral Movement", T1534: "Lateral Movement",
  // Collection
  T1005: "Collection", T1114: "Collection", T1056: "Collection", T1560: "Collection", T1113: "Collection",
  T1119: "Collection", T1213: "Collection", T1074: "Collection", T1115: "Collection", T1039: "Collection", T1125: "Collection",
  // Command and Control
  T1071: "Command and Control", T1105: "Command and Control", T1571: "Command and Control", T1572: "Command and Control",
  T1090: "Command and Control", T1219: "Command and Control", T1095: "Command and Control", T1102: "Command and Control",
  T1568: "Command and Control", T1573: "Command and Control", T1104: "Command and Control", T1008: "Command and Control",
  // Exfiltration
  T1041: "Exfiltration", T1048: "Exfiltration", T1567: "Exfiltration", T1029: "Exfiltration", T1020: "Exfiltration",
  T1011: "Exfiltration", T1052: "Exfiltration", T1030: "Exfiltration",
  // Impact
  T1486: "Impact", T1490: "Impact", T1489: "Impact", T1485: "Impact", T1491: "Impact", T1561: "Impact",
  T1499: "Impact", T1498: "Impact", T1531: "Impact", T1496: "Impact", T1565: "Impact", T1657: "Impact",
};

// When an event spans several tactics, the latest/worst stage wins.
const TACTIC_PRIORITY: IrisTactic[] = [
  "Impact", "Exfiltration", "Credential Access", "Lateral Movement", "Privilege Escalation",
  "Persistence", "Collection", "Command and Control", "Initial Access", "Discovery",
  "Defense Evasion", "Execution",
];

// Strong, specific keyword signals for events that carry no ATT&CK id (e.g. many THOR hits).
const KEYWORD_TACTIC: Array<[RegExp, IrisTactic]> = [
  [/\b(ransom\w*|encrypt(ed|ion)? for impact|vssadmin\s+delete|shadow\s*cop(y|ies)\s+delet|inhibit\s+recovery|wbadmin\s+delete)\b/i, "Impact"],
  [/\b(exfiltrat\w+|data\s+staged|rclone|megacmd)\b/i, "Exfiltration"],
  [/\b(mimikatz|lsass|sekurlsa|kerberoast|asreproast|dcsync|ntds\.dit|credential\s+dump\w*|hashdump|wdigest|pass-?the-?(hash|ticket))\b/i, "Credential Access"],
  [/\b(psexec|wmiexec|smbexec|lateral\s+move\w*|remote\s+desktop|\brdp\b|winrm|\bwmic\b\s+\/node|pass-?the-?)\b/i, "Lateral Movement"],
  [/\b(uac\s*bypass|fodhelper|token\s+manipulation|sedebugprivilege|getsystem|named\s+pipe\s+impersonat)\b/i, "Privilege Escalation"],
  [/\b(run\s*key|currentversion\\run|scheduled\s+task|schtasks|new-?service|sc\s+create|webshell|web\s+shell|autorun|wmi\s+event\s+subscription)\b/i, "Persistence"],
  [/\b(defender\s+tamper\w*|disable\s+(defender|antivirus|amsi)|amsi\s+bypass|clear(ed)?\s+event\s+log|wevtutil\s+cl|obfuscat\w+|process\s+(injection|hollow\w*)|rundll32|mshta|regsvr32)\b/i, "Defense Evasion"],
  [/\b(c2|c&c|command\s+and\s+control|beacon\w*|cobalt\s*strike|reverse\s+shell|ingress\s+tool\s+transfer)\b/i, "Command and Control"],
  [/\b(phish\w+|spear-?phish\w*|malicious\s+(attachment|link)|drive-?by|exploit\s+public)\b/i, "Initial Access"],
  [/\b(bloodhound|sharphound|adfind|net\s+(group|user|view)|nltest|whoami\s+\/|domain\s+trust|reconnaissance)\b/i, "Discovery"],
  [/\b(powershell|cmd\.exe|wscript|cscript|\bwmi\b|invoke-expression|iex\s*\(|encodedcommand)\b/i, "Execution"],
];

// A handful of techniques span several ATT&CK tactics, and the single home recorded in
// TECHNIQUE_TACTIC is the wrong stage for a whole class of events. The worst offender is T1078
// (Valid Accounts): ATT&CK lists it under Initial Access / Persistence / Priv-Esc / Defense Evasion,
// and we pin it to Initial Access — but an explicit-credential or remote-service logon REUSING
// existing credentials (EID 4648, SSH/RDP/WinRM, psexec/wmiexec, pass-the-hash) is operationally
// LATERAL MOVEMENT, not first entry. Without this refinement those internal host-to-host logons pile
// into the Initial Access lane and contradict a synthesis that (correctly) calls the entry vector
// unknown. When an event's description matches a rule below, that tactic overrides the table default
// FOR THAT TECHNIQUE. Description-free callers are unaffected (the regex tests against "").
const CONTEXT_REFINEMENT: Record<string, ReadonlyArray<readonly [RegExp, IrisTactic]>> = {
  T1078: [
    [/\b(explicit credentials|eid\s*4648|remote desktop|rdp|winrm|psexec|wmiexec|pass-?the-?(?:hash|ticket)|accepted\s+(?:password|publickey)|ssh\s+login)\b/i, "Lateral Movement"],
  ],
};

function baseTechnique(id: string): string {
  const m = /T\d{4}/i.exec(id);
  return m ? m[0].toUpperCase() : id.toUpperCase();
}

// The tactic a single technique resolves to, letting a description-keyed refinement override the
// table default for multi-tactic techniques (e.g. T1078 → Lateral Movement on a remote logon).
function tacticForTechnique(technique: string, description: string): IrisTactic | undefined {
  const base = baseTechnique(technique);
  const refinements = CONTEXT_REFINEMENT[base];
  if (refinements) for (const [re, tac] of refinements) if (re.test(description)) return tac;
  return TECHNIQUE_TACTIC[base];
}

// The IRIS event-category name for an event, or undefined when nothing matches (→ "Unspecified").
export function tacticForTechniques(techniques: readonly string[], description = ""): IrisTactic | undefined {
  const found = new Set<IrisTactic>();
  for (const t of techniques) {
    const tac = tacticForTechnique(t, description);
    if (tac) found.add(tac);
  }
  if (found.size > 0) return TACTIC_PRIORITY.find((t) => found.has(t));
  for (const [re, tac] of KEYWORD_TACTIC) if (re.test(description)) return tac;
  return undefined;
}
