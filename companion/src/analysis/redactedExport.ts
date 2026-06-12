import type { AnonCategory, AnonPolicy } from "./anonymize.js";
import { SECRET_PLACEHOLDER } from "./anonymize.js";
import type { ZipEntry } from "./zipArchive.js";

// Pure logic for the Redacted case export (#54): a shareable ZIP for external parties with internal
// IPs / hosts / usernames / emails / paths tokenized, secrets one-way redacted, screenshot metadata
// stripped + PII text blurred, and AI keys/config excluded. This module owns the deterministic
// pieces (option parsing, the export policy, deep text anonymization, archive layout, and the
// human-readable redaction notes); the I/O orchestration lives in reports/redactedExportBuilder.ts.

const ALL_CATEGORIES: Record<AnonCategory, boolean> = {
  IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true,
};

// The export always uses MAXIMUM redaction, independent of the per-case AI-anonymization toggle:
// every entity category is tokenized and secrets are one-way redacted. The package is meant to
// leave the analyst's machine, so it must never depend on the wire-anonymization setting being on.
export function redactedExportPolicy(): AnonPolicy {
  return { enabled: true, categories: { ...ALL_CATEGORIES }, redactSecrets: true };
}

export interface RedactedExportOptions {
  includeReport: boolean;       // report.md + report.html
  includeCsvs: boolean;         // findings / IOCs / timeline CSVs
  includeStateJson: boolean;    // the full (anonymized) case state JSON
  includeScreenshots: boolean;  // screenshot images
  blurScreenshots: boolean;     // OCR-blur PII text in screenshots (EXIF is always stripped)
}

export const DEFAULT_REDACTED_EXPORT_OPTIONS: RedactedExportOptions = {
  includeReport: true,
  includeCsvs: true,
  includeStateJson: true,
  includeScreenshots: true,
  blurScreenshots: true,
};

// A query-string flag is true unless it is explicitly a falsy token (0/false/no/off). Missing →
// the supplied default. Lets `?screenshots=0&blur=0` opt out while bare params keep the safe default.
function flag(value: unknown, dflt: boolean): boolean {
  if (value === undefined || value === null || value === "") return dflt;
  return !/^(0|false|no|off)$/i.test(String(value).trim());
}

export function resolveRedactedExportOptions(query: Record<string, unknown>): RedactedExportOptions {
  return {
    includeReport: flag(query.report, true),
    includeCsvs: flag(query.csvs, true),
    includeStateJson: flag(query.state, true),
    includeScreenshots: flag(query.screenshots, true),
    blurScreenshots: flag(query.blur, true),
  };
}

// The rendered report artifacts (as strings) produced from the anonymized case state. Mirrors
// what ReportWriter.writeAll persists, but in-memory so the canonical on-disk report (which keeps
// the REAL values) is never touched.
export interface RedactedReportContents {
  markdown: string;
  html: string;
  findingsCsv: string;
  iocsCsv: string;
  timelineCsv: string;
  forensicTimelineCsv: string;
  stateJson: string;
}

/**
 * Deep-walk a value, applying `redact` to every string. The mirror image of the anonymizer's
 * `restoreDeep` — used to tokenize an entire InvestigationState (and report metadata) field by
 * field, so real values are anonymized at their source rather than in serialized JSON text (where
 * a Windows path's escaped backslashes would defeat the path detector). Pure; returns a new value.
 */
export function applyAnonDeep<T>(value: T, redact: (s: string) => string): T {
  if (typeof value === "string") return redact(value) as unknown as T;
  if (Array.isArray(value)) return value.map((v) => applyAnonDeep(v, redact)) as unknown as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = applyAnonDeep(v, redact);
    return out as unknown as T;
  }
  return value;
}

export interface RedactionSummary {
  caseId: string;
  options: RedactedExportOptions;
  screenshotCount: number;      // images included in the package
  screenshotsBlurred: number;   // images where OCR painted at least one box
  screenshotRedactions: number; // total boxes painted across all images
  metadataStripped: number;     // images re-encoded to drop EXIF/GPS/etc.
}

const REPORT_DIR = "report";
const SCREENSHOT_DIR = "screenshots";
const NOTES_FILE = "REDACTION-NOTES.txt";

// Reduce a filename to a safe single archive path segment: strip any directory component and
// collapse path-traversal characters. Defense-in-depth so a screenshot filename can never escape
// the screenshots/ prefix in the ZIP (zip-slip), regardless of how it got onto disk.
export function safeArchiveName(name: string): string {
  const base = name.replace(/^.*[\\/]/, "");
  const cleaned = base.replace(/[\\/]/g, "_").replace(/\.{2,}/g, ".").trim();
  return cleaned.length > 0 ? cleaned : "file";
}

// Config / secret-bearing files that are NEVER placed in the package — documented in the notes so
// the recipient (and the analyst) can see what was deliberately withheld.
export const EXCLUDED_FROM_EXPORT: readonly string[] = [
  ".env / environment variables (AI provider keys, enrichment API keys)",
  "state/ai-control.json (AI model + provider configuration)",
  "state/enrich-control.json (enabled threat-intel providers)",
  "state/anon-control.json, state/anon-entities.json, state/anon-discovered.json",
  "metadata/captures.jsonl, metadata/imports.jsonl (raw capture/import audit logs)",
  "case.json (raw case metadata)",
];

/**
 * Assemble the archive entry list from the anonymized report contents, the redacted screenshots,
 * and the redaction notes — honoring which parts the analyst chose to include. Pure.
 */
export function assembleRedactedEntries(input: {
  contents: RedactedReportContents;
  screenshots: { name: string; data: Buffer }[];
  notes: string;
  options: RedactedExportOptions;
}): ZipEntry[] {
  const enc = (s: string): Buffer => Buffer.from(s, "utf8");
  const entries: ZipEntry[] = [{ path: NOTES_FILE, data: enc(input.notes) }];

  if (input.options.includeReport) {
    entries.push({ path: `${REPORT_DIR}/report.md`, data: enc(input.contents.markdown) });
    entries.push({ path: `${REPORT_DIR}/report.html`, data: enc(input.contents.html) });
  }
  if (input.options.includeCsvs) {
    entries.push({ path: `${REPORT_DIR}/findings.csv`, data: enc(input.contents.findingsCsv) });
    entries.push({ path: `${REPORT_DIR}/iocs.csv`, data: enc(input.contents.iocsCsv) });
    entries.push({ path: `${REPORT_DIR}/timeline.csv`, data: enc(input.contents.timelineCsv) });
    entries.push({ path: `${REPORT_DIR}/forensic-timeline.csv`, data: enc(input.contents.forensicTimelineCsv) });
  }
  if (input.options.includeStateJson) {
    entries.push({ path: `${REPORT_DIR}/state-export.json`, data: enc(input.contents.stateJson) });
  }
  if (input.options.includeScreenshots) {
    for (const shot of input.screenshots) {
      entries.push({ path: `${SCREENSHOT_DIR}/${safeArchiveName(shot.name)}`, data: shot.data });
    }
  }
  return entries;
}

/**
 * Human-readable manifest placed at the root of the package. States exactly what was redacted, the
 * residual-risk caveats (faces and other non-text visual PII are NOT auto-detected), and what was
 * deliberately excluded — so the recipient can trust the package and the analyst can audit it.
 */
export function buildRedactionNotes(summary: RedactionSummary): string {
  const o = summary.options;
  const yn = (b: boolean): string => (b ? "yes" : "no");
  const lines: string[] = [
    "DFIR Companion — Redacted Case Export",
    "=====================================",
    "",
    `Case: ${summary.caseId}`,
    "",
    "This package is a SHAREABLE, REDACTED copy of the case for external parties. It was produced",
    "by the DFIR Companion's redacted-export feature, NOT a raw copy of the case folder.",
    "",
    "What was redacted",
    "-----------------",
    "- Internal/victim indicators in all text (report, CSVs, state JSON) are replaced with",
    "  consistent typed tokens: internal IPv4 (RFC1918/loopback/CGNAT) -> ANON_IP_n, hostnames ->",
    "  ANON_HOST_n, accounts -> ANON_USER_n, internal email/domains -> ANON_EMAIL_n/ANON_DOMAIN_n,",
    "  user profile paths -> ANON_PATH_n. The SAME real value always maps to the SAME token within",
    "  this package, so the narrative still reads coherently.",
    `- Credentials / API keys / tokens are one-way redacted to "${SECRET_PLACEHOLDER}" (NOT reversible).`,
    "- Adversary indicators (public IPs, malware hashes, attacker domains/URLs) are PRESERVED on",
    "  purpose so the threat signal survives — they are not victim PII.",
    "- The token -> real-value mapping is NEVER included; it stays only on the source machine.",
    "",
    "Screenshots",
    "-----------",
    `- Included in this package: ${yn(o.includeScreenshots)}`,
  ];
  if (o.includeScreenshots) {
    lines.push(
      `- Images: ${summary.screenshotCount} (metadata/EXIF stripped from ${summary.metadataStripped}).`,
      `- PII-text blurring (OCR): ${yn(o.blurScreenshots)} — ${summary.screenshotRedactions} region(s)` +
        ` blacked out across ${summary.screenshotsBlurred} image(s).`,
      "- CAVEAT: OCR text-blurring is BEST-EFFORT. Faces and other NON-TEXT visual PII are NOT",
      "  auto-detected, and low-confidence or stylized text may survive. REVIEW every screenshot",
      "  before sharing, or re-export with screenshots excluded if in doubt.",
    );
  }
  lines.push(
    "",
    "What was excluded (never in this package)",
    "-----------------------------------------",
    ...EXCLUDED_FROM_EXPORT.map((f) => `- ${f}`),
    "",
    "Note: if the investigating firm configured a report logo, it is the firm's own branding and is",
    "included in the report AS-IS (not stripped).",
    "",
    "Generated by DFIR Companion. Verify the contents before distribution.",
    "",
  );
  return lines.join("\n");
}

export function redactedExportFilename(caseId: string): string {
  return `case-${caseId}-redacted.zip`;
}
