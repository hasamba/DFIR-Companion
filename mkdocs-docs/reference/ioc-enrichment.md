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
- **MISP** — one assertion per attribute (its uuid is the record): `first_seen` / `last_seen`
  as *observed by the provider 2026-01-01 → 2026-01-15* (an observation interval, kept per
  attribute, never one span across attributes), the record's `timestamp` as *record created or
  last edited … (not an observation)*, the event's `date` as *the event's stated date … (as
  recorded, not an observation)*, and `publish_timestamp` as *published …*. The lookup asks for
  deleted attributes too and reads every page (up to 6,400 attributes; a read cut at the bound is
  **incomplete** and concludes nothing about absence); 32 attributes are listed, the rest counted.
- **OpenCTI** — one assertion per linked **indicator** (its id is the record): `valid_from` /
  `valid_until` as *valid from … until …* (STIX validity — *the assertion's validity ended* when
  it has), `revoked`, its score, and `created` as *object created … (creation, not publication,
  not an observation)*. The observable search is paged until the exact value is found; a bound
  reached first is an incomplete search, never a miss.
- **Hunting.ch** — per backend: ThreatFox `first_seen` / `last_seen` (*observed by the
  provider*) with the rule *ThreatFox removes IOCs older than six months from its API; a miss is
  not a withdrawal*; URLhaus `date_added` as *added to the provider's dataset on … (a dataset
  date, not when the infrastructure came to exist)* and `last_online` only when reported; a
  host's `firstseen`; a payload's `firstseen` / `lastseen`; a nested URL list cut by the API's
  own limit is said as *truncated*. Every backend reports its own outcome — a backend that errors
  is neither "no hit" nor cached as checked.
- Every other provider is **undated**: *the provider reports no dates; the lookup ran on …, N
  days after the case time*.

The **case time** is the earliest dated timeline event the indicator was extracted from
(authoritative when the importer linked it; *the approximately matching event* when it was
matched by value). An indicator with no dated event says so — its "first seen" is the import
time, never a sighting. The words appear on the AI's threat-intel verdict lines, in the IOC CSV
`enrichment` column, in the risk factors (*current reputation, measured …*), and on the dashboard
badge as a visible chip (`scan 2026-04-30`, `window 2026-01-31→2026-05-01`) with the full facts
on hover. The risk score itself is unchanged. Nothing says "was malicious at the time".

## Assertions over time

A provider's answer is an **assertion** with a stable identity — the provider, the source and
the provider's own record id (a MISP attribute uuid, an OpenCTI indicator id, a ThreatFox ioc
id, a URLhaus url id; the indicator value under that source when the provider names none).
A re-check used to replace the previous hit, and a miss dropped it; now:

- A fresh assertion supersedes the one with the **same identity** — never one with the same
  verdict. A successful check that does not return a known assertion marks it *not returned on
  the check at …; kept as history — a miss is not a withdrawal*. A provider (or one backend of a
  fan-out provider) that **errors** keeps its last-known assertions (*last known; the provider
  errored on the last check*) and is retried on the next run, even when it never had a hit. A
  check that read an **incomplete** result (a pagination bound) concludes nothing about absence.
- **Expired and revoked are marked, never erased.** An OpenCTI indicator past `valid_until` reads
  *validity ended 2026-06-02 (before now); kept as history*; an OpenCTI `revoked` indicator or a
  MISP `deleted` attribute reads *revoked by the provider; kept as history*. Expiry is judged at
  the moment of use — an export a week after the check sees the week.
- **History** — every material change (verdict, score, tags, dates, validity, revocation, status)
  appends a dated record to the IOC's assertion history; identical consecutive checks coalesce
  into first / last checked and a count; 256 records are kept per assertion (the first, the newest
  32 and a compacted count past that). A reassigned address whose reputation flipped keeps both
  states.
- **Three views.** *Latest*: the newest state of each assertion from a successful check.
  *Actionable*: the latest, and live now — what the **block-list**, the **STIX bundle** and
  **finding corroboration** read; a revoked, expired, not-returned, errored or pre-tracking
  assertion never reaches a blocked address, a STIX verdict or a "corroborated by intel" mark.
  *Last known*: every assertion whatever its state, labelled — what the **report** and the IOC
  CSV print. An IOC whose intel assertions are all non-actionable asserts no indicator →
  attack-pattern relationship in the STIX bundle (a finding's own techniques stay in the report).
- **Hits recorded before assertion tracking** read as *recorded before assertion tracking;
  re-check to make it actionable*: last-known and labelled, never actionable. A case enriched
  before this version loses its intel corroboration until its IOCs are re-checked — run a forced
  re-check once.
- A provider's **provenance is not established** by any of this: the envelope of facts is the
  provider's statement, read and dated, never verified.

## Intel retirement review

The **Intel Retirement Review** panel (and the report section of the same name, off by default in
existing templates) lists every finding whose intel corroboration rested on assertions that are
now all expired, revoked, not returned, errored or pre-tracking — each with the assertions
named, the labels above, and what else corroborates the finding (tools, hosts, graph, KEV). It is
a list to **review**, never an action: **Keep** and **Retire** record the analyst's decision (with
a note) in the case and on the investigation log, and change nothing else — no severity, no
status, no deployed detection, and no erasure of the evidence a rule produced. A recorded
*retire* additionally stops the STIX bundle asserting that finding's intel-derived relationships
and labels it in the report; the finding itself is closed or dismissed only through its own
controls. `GET /cases/:id/intel-retirement` returns the review; `POST
/cases/:id/intel-retirement/:findingId` with `{ "decision": "retire" | "keep", "note": "…" }`
records it.

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
