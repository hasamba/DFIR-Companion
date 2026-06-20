# Step 3 — Review Findings & MITRE ATT&CK

**Findings** are AI-synthesised conclusions — the "so what" layer on top of the raw timeline. Each finding groups related events, assigns severity, maps to ATT&CK, and links back to the specific events that support it.

## Read the findings panel

The **Findings** panel (right side of the dashboard) shows 10 findings for this case. Look for:

| Finding | Severity | What to notice |
|---------|----------|----------------|
| Active Cobalt Strike C2 Beacon | **Critical** | Links to beacon events + C2 IOCs |
| Domain Admin Credentials Compromised via Mimikatz | **Critical** | Confidence %, related events |
| PsExec Lateral Movement to DC01 | **High** | Multiple corroborating sources |
| Ransomware Payload Deployed and Blocked | **High** | The save — EDR stopped it |

## Explore the MITRE ATT&CK panel

Scroll down to the **MITRE ATT&CK** section. You'll see the techniques identified across the case plotted by tactic (Initial Access → Execution → Persistence → Lateral Movement → Exfiltration).

Notable techniques in this case:
- **T1071.001** — C2 over HTTP/HTTPS
- **T1003.001** — LSASS credential dumping (Mimikatz)
- **T1021.002** — SMB/Windows Admin Shares (PsExec)
- **T1486** — Data encrypted for impact (ransomware attempt)

## Try the analyst tools

- **Tags** — Click the tag icon on any finding to mark it `confirmed-malicious`, `key-evidence`, or `false-positive`
- **Comments** — Click the comment icon to read the pre-loaded analyst notes (e.g. "DKIM analysis confirmed spoofed sender domain")
- **Scope** — The scope is set to May 14–23. Try adjusting it to see how findings change

---

When you've reviewed the findings and MITRE mapping, move on.
