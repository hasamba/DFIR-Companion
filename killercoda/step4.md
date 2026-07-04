# Step 4 — Investigate IOCs & Threat Intel

The **IOCs panel** lists every observed indicator extracted from the forensic evidence — IPs, domains, file hashes, process names, URLs, CVEs. In a real case these would be sent to your threat intel providers; in this demo they carry pre-populated results.

## Browse the IOC list

The demo case has **17 IOCs**. Find these key ones:

| Indicator | Type | What the intel says |
|-----------|------|---------------------|
| `185.220.101.47` | IP | AbuseIPDB: 97% confidence malicious — known Cobalt Strike C2 |
| `cobaltkit.xyz` | Domain | ThreatFox: Cobalt Strike C2, first seen 2026-04-12 |
| `a3f8c2d...` (Mimikatz hash) | Hash | VirusTotal: 64/72 engines detect as HackTool.Mimikatz |
| `ransom_payload.exe` | Hash | VirusTotal: 71/72 — BlackCat/ALPHV ransomware |

## Check the source badges

Each IOC shows **⊕ N sources** — how many independent tools observed it. Click the badge to see which tools saw it and in what context. A C2 IP seen by both Suricata (network) and the EDR (process) is stronger evidence than one seen by only one source.

## False-positive markers

Three IOCs are pre-marked **false positive** (the internal DNS server and WSUS server IPs). In a real case you'd mark known-good internal infrastructure so it doesn't pollute synthesis or the report.

## Try querying from the terminal

You can also query the IOCs via the API:

```
curl -s "http://localhost:4773/cases/demo/iocs" | python3 -m json.tool | head -60
```{{exec}}

---

When you've explored the IOCs and their threat intel verdicts, move to the final step.
