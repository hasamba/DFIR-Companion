// CISA Known Exploited Vulnerabilities (KEV) catalog integration — issue #99.
//
// The KEV catalog lists CVEs that CISA has confirmed are actively exploited in the wild.
// When a CVE is found in the forensic timeline (e.g. an exploitation event or SIEM alert)
// or in a customer's exposed services (Shodan), matching it against KEV grounds the analysis:
// a KEV match is a HIGHLY PROBABLE initial access vector, not just a theoretical risk. The
// model is told explicitly so it can flag the exact CVE, product, and required patch.
//
// Pure logic only (CVE extraction, catalog parsing, matching, digest building) — no I/O.
// Persistence in kevStore.ts. Integration points:
//  • synthSelect.ts: KEV digest prepended to the synthesis context so the AI reasons about it.
//  • reports/markdown.ts: §4.5.1 CISA KEV correlation subsection.
//  • server.ts: /kev/* routes + Settings → KEV panel.

export interface KevEntry {
  cveID: string;                       // "CVE-2024-38094" — normalised to upper-case
  vendorProject: string;               // "Microsoft"
  product: string;                     // "SharePoint Server"
  vulnerabilityName: string;           // short title
  dateAdded: string;                   // ISO date added to KEV, e.g. "2024-10-22"
  shortDescription: string;
  requiredAction: string;              // the patch / workaround instruction
  dueDate: string;                     // CISA due date for federal agencies
  knownRansomwareCampaignUse: string;  // "Known" | "Unknown"
  notes?: string;                      // reference URLs (space/semicolon separated)
}

// Keyed by normalised (upper-cased) CVE id so lookups are O(1).
export type KevCatalog = Map<string, KevEntry>;

// CVE-yyyy-nnnn(n+): year 1999–2099, 4+ digit sequence. New regex per call so exec() is safe.
// 1999|(20\d{2}) captures 1999 and 2000–2099; the trailing hyphen anchors the year boundary so
// CVE-2100-… does not false-match as CVE-210x-….
function cveRegex(): RegExp {
  return /CVE-(1999|20\d{2})-\d{4,}/gi;
}

// Extract all CVE ids mentioned in a text string. Returns them upper-cased and deduplicated.
export function extractCveIds(text: string): string[] {
  if (!text) return [];
  const found = new Set<string>();
  const re = cveRegex();
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) found.add(m[0].toUpperCase());
  return [...found];
}

// Parse the CISA KEV JSON feed (or a local copy) into a list of entries. Tolerant:
// missing/extra fields are silently ignored; malformed/non-CVE entries are skipped.
// Accepts either the full feed object ({ vulnerabilities: [...] }) or a bare array.
export function parseKevJson(json: unknown): KevEntry[] {
  if (typeof json !== "object" || json === null) return [];
  const vulns: unknown[] = Array.isArray(json)
    ? json
    : Array.isArray((json as Record<string, unknown>).vulnerabilities)
      ? (json as Record<string, unknown>).vulnerabilities as unknown[]
      : [];

  const out: KevEntry[] = [];
  for (const v of vulns) {
    if (typeof v !== "object" || v === null) continue;
    const r = v as Record<string, unknown>;
    const cveID = String(r.cveID ?? "").trim().toUpperCase();
    if (!/^CVE-(1999|20\d{2})-\d{4,}$/.test(cveID)) continue;
    out.push({
      cveID,
      vendorProject: String(r.vendorProject ?? ""),
      product: String(r.product ?? ""),
      vulnerabilityName: String(r.vulnerabilityName ?? ""),
      dateAdded: String(r.dateAdded ?? ""),
      shortDescription: String(r.shortDescription ?? ""),
      requiredAction: String(r.requiredAction ?? ""),
      dueDate: String(r.dueDate ?? ""),
      knownRansomwareCampaignUse: String(r.knownRansomwareCampaignUse ?? "Unknown"),
      notes: r.notes !== undefined ? String(r.notes) : undefined,
    });
  }
  return out;
}

// Build an O(1) lookup map from a parsed entry list.
export function buildKevCatalog(entries: KevEntry[]): KevCatalog {
  const map: KevCatalog = new Map();
  for (const e of entries) map.set(e.cveID, e);
  return map;
}

// Look up CVE ids against the catalog. Returns matched entries in input order.
export function matchKevEntries(cveIds: readonly string[], catalog: KevCatalog): KevEntry[] {
  if (!catalog.size) return [];
  const out: KevEntry[] = [];
  const seen = new Set<string>();
  for (const id of cveIds) {
    const key = id.toUpperCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const entry = catalog.get(key);
    if (entry) out.push(entry);
  }
  return out;
}

// Build a compact KEV digest block for the synthesis prompt. Returned string is empty when
// there are no matches (costs no tokens on a case with no exploited CVEs).
export function buildKevDigest(matches: KevEntry[]): string {
  if (!matches.length) return "";
  const lines = matches.map((e) => {
    const ransomNote = e.knownRansomwareCampaignUse === "Known" ? " [RANSOMWARE CAMPAIGN]" : "";
    return `- ${e.cveID} (${e.vendorProject} ${e.product})${ransomNote} — ${e.vulnerabilityName}. Patch: ${e.requiredAction}`;
  });
  return `KEV-MATCHED CVEs (CISA Known Exploited Vulnerabilities — actively exploited in the wild):\n${lines.join("\n")}\n\n`;
}
