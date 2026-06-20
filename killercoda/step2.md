# Step 2 — Explore the Forensic Timeline

The **Forensic Timeline** is the core of the investigation — a chronological list of every event extracted from every imported tool, deduplicated and correlated across sources.

## Walk the attack chain

The demo case covers **May 15–22, 2026**. Scroll from the top and look for these phases:

1. **May 15 — Initial Access & Beacon**
   Look for the Cobalt Strike beacon check-in from `WORKSTATION-04` to `185.220.101.47`. The event should show `sources: [CrowdStrike, Suricata]` — two independent tools corroborating the same activity.

2. **May 16–17 — Lateral Movement**
   Find the `PsExec` execution events spreading to `DC01` and `FILE-SERVER-01`. Look for `PSEXESVC` service installation events from the Chainsaw import.

3. **May 18 — Credential Dumping**
   Find the Mimikatz `sekurlsa::logonpasswords` event. Check the process chain — what spawned it?

4. **May 21 — Data Staging**
   Find the `rar.exe` archiving events — 47 GB of financial data compressed before exfiltration.

5. **May 22 — Ransomware Blocked**
   Find the EDR block on `ransom_payload.exe`. This is where the attack was stopped.

## Use the filters

- **Severity filter** — click the coloured severity chips above the timeline to show only Critical/High events
- **Source filter** — use the source dropdown to show only events from a specific tool (e.g. just Chainsaw, or just Suricata)
- **Search** — type a hostname, IP, or keyword to filter events

## Check event details

Click any event row to expand it. You'll see:
- Exact timestamp from the original artifact
- Source tool(s) that observed it
- Asset (affected host) and user
- Related IOCs and findings

---

When you've traced the attack from beacon to ransomware block, move to the next step.
