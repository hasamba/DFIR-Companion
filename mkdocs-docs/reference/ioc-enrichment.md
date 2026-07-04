# IOC Enrichment

## How It Works

The IOC panel's enrichment system checks indicators against external and internal threat-intel services.

!!! warning "OPSEC: nothing is sent externally until you opt in"
    Go to **Settings → Enrichment** and enable sources for this case. The list starts empty — local-only providers (MISP, YETI, OpenCTI) are enabled by default; external SaaS providers require explicit per-case opt-in.

---

## Available Enrichment Providers

### External (opt-in per case)

| Provider | What it checks | Key required |
|----------|----------------|--------------|
| VirusTotal | Hashes, IPs, domains, URLs | Yes (`DFIR_VT_KEY`) |
| AbuseIPDB | IP addresses | Yes (`DFIR_ABUSEIPDB_KEY`) |
| Hunting.ch (abuse.ch) | MalwareBazaar + ThreatFox + URLhaus + YARAify | Yes (`DFIR_HUNTINGCH_KEY`) |
| CrowdStrike Falcon Intel | Hashes, IPs, domains, URLs via Indicators + MalQuery | Yes (`DFIR_CROWDSTRIKE_CLIENT_ID` / `_SECRET`) |
| Shodan | IP host lookup (open ports, services, CVEs) | Yes (`DFIR_SHODAN_KEY`) |
| CIRCL hashlookup | File hashes (NSRL-derived, free) | No |

### Local (no OPSEC concern by default)

| Provider | What it checks | Setup |
|----------|----------------|-------|
| MISP | All IOC types | Self-hosted instance + key (`DFIR_MISP_URL` / `_KEY`) |
| YETI | All IOC types | Self-hosted instance + key (`DFIR_YETI_URL` / `_KEY`) |
| OpenCTI | All IOC types | Self-hosted instance + key (`DFIR_OPENCTI_URL` / `_KEY`) |
| RockyRaccoon | Parent→child chain validation | Self-hosted (`DFIR_ROCKYRACCOON_URL`) |

### IP Infrastructure (Informational — no reputation verdict)

| Provider | Information | Key required |
|----------|-------------|--------------|
| Reverse DNS | PTR hostnames for IPs | No |
| WHOIS/RDAP | Netblock, ASN, country, abuse contact | No |
| GeoIP | Country, city, ASN, org (ipinfo.io) | No |
| Shodan | Hosted domains, ports, CVEs | Yes (reuses Shodan key) |

---

## IOC Whitelist

Add known-good patterns in **Settings → IOC Whitelist**:

- **CIDR** — for internal IP ranges (e.g. `10.0.0.0/8`)
- **Exact** — specific hashes or values
- **Regex** — patterns (length-bounded to prevent ReDoS)

Any IOC matching a whitelist rule is **automatically marked false-positive on import** and excluded from enrichment and synthesis.

!!! tip
    Add your internal CIDR ranges to the whitelist early. It cuts false-positive IOC noise significantly.

---

## NSRL Known-Good Hashes

Upload or point to an NSRL (NIST National Software Reference Library) hash list in **Settings → NSRL**. File hashes in the NSRL are automatically marked as known-good software on import.

For large NSRL RDS databases (hundreds of millions of hashes), point to the SQLite `.db` file instead of importing — it queries on demand without loading into memory. Requires Node 22.5+.

!!! note
    NSRL is "known software", not strictly "known-good" — some RDS sets include hacktools. A known hash can still be malicious in context. Treat the auto-false-positive marking as noise reduction, not a verdict.
