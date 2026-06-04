// Canonical MITRE ATT&CK links (https://attack.mitre.org). A technique id like "T1059" or a
// sub-technique "T1059.001" maps to its technique page; tactic NAMES (as the synthesis / IRIS
// categories use them) map to their tactic page. Used by the dashboard, the report, and the
// IRIS export so every MITRE reference is a working link.

const TECHNIQUE_RE = /^T(\d{4})(?:\.(\d{3}))?$/;

// URL for a technique / sub-technique id, or null when the string isn't a valid id.
export function attackTechniqueUrl(id: string): string | null {
  const m = TECHNIQUE_RE.exec(id.trim().toUpperCase());
  if (!m) return null;
  return m[2]
    ? `https://attack.mitre.org/techniques/T${m[1]}/${m[2]}/`
    : `https://attack.mitre.org/techniques/T${m[1]}/`;
}

// ATT&CK tactic name (lowercased) → tactic id, for linking the tactic pages.
export const ATTACK_TACTIC_IDS: Readonly<Record<string, string>> = {
  reconnaissance: "TA0043", "resource development": "TA0042", "initial access": "TA0001",
  execution: "TA0002", persistence: "TA0003", "privilege escalation": "TA0004",
  "defense evasion": "TA0005", "credential access": "TA0006", discovery: "TA0007",
  "lateral movement": "TA0008", collection: "TA0009", exfiltration: "TA0010",
  "command and control": "TA0011", impact: "TA0040",
};

export function attackTacticUrl(name: string): string | null {
  const id = ATTACK_TACTIC_IDS[name.trim().toLowerCase()];
  return id ? `https://attack.mitre.org/tactics/${id}/` : null;
}

// Render a technique id as a Markdown link, falling back to plain text for an unrecognized id.
export function attackTechniqueMd(id: string): string {
  const url = attackTechniqueUrl(id);
  return url ? `[${id}](${url})` : id;
}
