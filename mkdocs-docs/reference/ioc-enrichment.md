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

## When a verdict applies

A provider's verdict is **current reputation**: what the provider says today, measured when it
last looked. It is not evidence about the time of the case — an address is reassigned, a domain
changes hands, a certificate is reused. So every verdict now carries the provider's own dated
facts, each of its kind, against the case time:

- **VirusTotal** — the latest scan the verdict comes from (*verdict measured by the latest scan
  on 2026-04-30 — 1,827 days after the case time (2021-04-29)*); for a file or URL, the date it
  was first submitted to VirusTotal (*a submission date, not when the file or URL came to
  exist*); for an IP or domain, when its record was last updated (*not an observation*).
- **AbuseIPDB** — the report window the lookup covered (`maxAgeInDays`, 90 by default), where
  the case time falls relative to it, the latest report and the count. A clean answer over the
  window *says nothing about earlier dates*.
- Every other provider is **undated**: *the provider reports no dates; the lookup ran on …, N
  days after the case time*.

The **case time** is the earliest dated timeline event the indicator was extracted from
(authoritative when the importer linked it; *the approximately matching event* when it was
matched by value). An indicator with no dated event says so — its "first seen" is the import
time, never a sighting. The words appear on the AI's threat-intel verdict lines, in the IOC CSV
`enrichment` column, in the risk factors (*current reputation, measured …*), and on the dashboard
badge as a visible chip (`scan 2026-04-30`, `window 2026-01-31→2026-05-01`) with the full facts
on hover. The risk score itself is unchanged. Nothing says "was malicious at the time".

**Not yet covered:** MISP, OpenCTI and Hunting.ch dates; keeping a provider's earlier assertion
when a re-check replaces it; expired or revoked assertions; a rule-retirement review. Each has
its own semantics and is tracked as a spec.

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
