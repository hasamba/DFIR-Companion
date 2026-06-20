# You've completed the DFIR Companion walkthrough

You investigated a full BEC + ransomware-precursor incident — from the initial Cobalt Strike beacon through lateral movement, credential dumping, data staging, and the blocked ransomware deployment.

## What you used

- **Forensic timeline** — correlated events from Chainsaw, CrowdStrike, Suricata, and the EDR
- **AI-synthesised findings** — 10 conclusions mapped to MITRE ATT&CK
- **Threat intel enrichment** — pre-enriched IOCs from VirusTotal, AbuseIPDB, ThreatFox
- **Evidence chain** — causal graph tracing the attack path
- **Adversary hints** — offline ATT&CK group overlap scoring

## Try it on your own evidence

DFIR Companion runs locally on your machine:

```bash
# Via Docker
docker run -d -p 4773:4773 -v $(pwd)/cases:/data/cases ghcr.io/hasamba/dfir-companion:latest

# Or from source (Node 20+)
git clone https://github.com/hasamba/DFIR-Companion.git
cd DFIR-Companion/companion && npm ci && npm run build
node dist/server.js
```

Then open **http://localhost:4773/dashboard** and import your own artifacts — Velociraptor exports, Chainsaw results, THOR JSON, Hayabusa timelines, SIEM exports, memory forensics, or network logs.

## Learn more

- [GitHub — hasamba/DFIR-Companion](https://github.com/hasamba/DFIR-Companion)
- [Full importer list and configuration](https://github.com/hasamba/DFIR-Companion/blob/master/companion/README.md)

*This environment will be cleaned up automatically when you close the session.*
