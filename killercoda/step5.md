# Step 5 — Trace the Attacker Path

The **Evidence Chain** and **Adversary Hints** panels show the causal graph of the attack — not just a list of events, but *how* they connect.

## Evidence Chain panel

The evidence chain derives causal links from the structured fields in forensic events:
- **Process spawns** — parent → child process relationships
- **Lateral movement** — same credential or hash seen on multiple hosts
- **File lineage** — a file written then executed
- **Network flows** — outbound connections to C2

Look for the chain running: `spearphish email → macro execution → Cobalt Strike → PsExec → Mimikatz → rar.exe → ransomware attempt`

## Adversary Hints panel

The **Adversary Hints** panel scores the case's identified ATT&CK techniques against known MITRE Groups — purely offline, no AI, no network. This is hypothesis fuel, not attribution.

For this case you should see matches suggesting **FIN7** and **Lazarus Group** based on technique overlap. The panel shows:
- Group name and description
- How many of their known techniques appear in this case
- The specific overlapping techniques

> **Important caveat shown in the UI:** a 4-technique overlap with a group that uses 12 total (focused actor) reads very differently than a 4-technique overlap with one that uses 150 (diffuse).

## Attack Phases panel

The **Attack Phases** section groups the timeline into temporal bursts separated by quiet periods. This case shows distinct phases:
1. Initial access & beacon establishment (May 15)
2. Reconnaissance & lateral movement (May 16–17)
3. Credential harvesting & data staging (May 18–21)
4. Ransomware attempt (May 22)

## Try the API

```
curl -s "http://localhost:4773/cases/demo/evidence-graph" | python3 -m json.tool | head -40
```{{exec}}

```
curl -s "http://localhost:4773/cases/demo/adversary-hints" | python3 -m json.tool
```{{exec}}

---

When you've traced the attacker path, click **Continue** to finish.
