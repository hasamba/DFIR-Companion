// Free-text IOC extraction for a Velociraptor row.
//
// Its own module because analysis/velociraptorImport.ts is frozen by the file-size ledger (#384).
//
// `genericIocs` only fires on structured keys, so an indicator that lives INSIDE a matched command
// `Line`, a collected file `Content`, a YARA `HitString` or a PowerShell script block — very often
// the exact thing the rule fired on — is otherwise missed entirely.
import { addIoc, cleanIp, str, getCI, type SiemIoc } from "./siemImport.js";
import { extractDomains } from "./textDomains.js";

const TEXT_URL = /\bhttps?:\/\/[^\s"'<>)\]}]+/gi;
// Octet-bounded, so a "10.0.22000" version string is not read as an address.
const TEXT_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const TEXT_HASH = /\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi;

// URLs, IPv4, SHA256/SHA1/MD5 hashes, and domains. The domain pass is the newest: a collected
// script block names its C2 by name at least as often as by address, and until `extractDomains`
// ran here those names were simply lost (#648).
export function scrapeText(text: string, sink: Map<string, SiemIoc>): void {
  if (!text) return;
  for (const m of text.matchAll(TEXT_URL)) addIoc(sink, "url", m[0].replace(/[.,;:)\]]+$/, "").slice(0, 300));
  for (const m of text.matchAll(TEXT_IPV4)) {
    const ip = cleanIp(m[0]);
    if (ip) addIoc(sink, "ip", ip);
  }
  for (const m of text.matchAll(TEXT_HASH)) addIoc(sink, "hash", m[0].toLowerCase());
  for (const d of extractDomains(text)) addIoc(sink, "domain", d);
}

// The free-text fields that carry a detection's evidence (and its embedded IOCs). `ScriptBlockText`
// is what Velociraptor's own Windows.EventLogs.PowershellScriptblock artifact — the ordinary way to
// collect EID 4104 — puts the script under, as a flat top-level column with no parsed event around
// it. Until it was listed here that row reached no scraper at all and produced zero IOCs (#652).
const EVIDENCE_TEXT_KEYS = [
  "Line",
  "Content",
  "CommandLine",
  "HitString",
  "StringHit",
  "Message",
  "Details",
  "ScriptBlockText",
];
export function scrapeEvidence(row: Record<string, unknown>, sink: Map<string, SiemIoc>): void {
  for (const k of EVIDENCE_TEXT_KEYS) scrapeText(str(getCI(row, k)), sink);
}
