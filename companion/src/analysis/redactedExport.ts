import { createHash } from "node:crypto";
import type { AnonCategory, AnonPolicy } from "./anonymize.js";
import { SECRET_PLACEHOLDER } from "./anonymize.js";
import type { ZipEntry } from "./zipArchive.js";
import { CUSTODY_MANIFEST_FILENAME, type CustodyManifest } from "./custodyManifest.js";

// Pure logic for the Redacted case export (#54): a shareable ZIP for external parties with internal
// IPs / hosts / usernames / emails / paths tokenized, secrets one-way redacted, screenshot metadata
// stripped + PII text blurred, and AI keys/config excluded. This module owns the deterministic
// pieces (option parsing, the export policy, deep text anonymization, archive layout, and the
// human-readable redaction notes); the I/O orchestration lives in reports/redactedExportBuilder.ts.

const ALL_CATEGORIES: Record<AnonCategory, boolean> = {
  IP: true,
  EMAIL: true,
  USER: true,
  HOST: true,
  DOMAIN: true,
  PATH: true,
  CMD: true,
  REG: true,
  CARD: true,
  PHONE: true,
  NATID: true,
};

// The export always uses MAXIMUM redaction, independent of the per-case AI-anonymization toggle:
// every entity category is tokenized and secrets are one-way redacted. The package is meant to
// leave the analyst's machine, so it must never depend on the wire-anonymization setting being on.
//
// maskPublicIps is FALSE here on purpose. This package is shared with a third party to describe
// an incident; tokenizing the adversary's infrastructure would make it unactionable. The export
// strips the VICTIM's identity, not the attacker's.
export function redactedExportPolicy(): AnonPolicy {
  return { enabled: true, categories: { ...ALL_CATEGORIES }, redactSecrets: true, maskPublicIps: false };
}

export interface RedactedExportOptions {
  includeReport: boolean; // report.md + report.html
  includeCsvs: boolean; // findings / IOCs / timeline CSVs
  includeStateJson: boolean; // the full (anonymized) case state JSON
  includeScreenshots: boolean; // screenshot images
  blurScreenshots: boolean; // OCR-blur PII text in screenshots (EXIF is always stripped)
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
  /**
   * The signed chain-of-custody manifest describing the REDACTED appendix in this package. Absent
   * when the case has no custody store or the writer has no signing secret.
   */
  custodyManifest?: CustodyManifest;
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

/**
 * Fields of a custody record that survive redaction untouched (#362).
 *
 * A SHA-256 is not PII: it reveals nothing about a file's contents, its name, or the host it came
 * from. Tokenizing it leaves an external recipient a chain they cannot check against the evidence
 * they actually hold, which is most of what the appendix is for. `prevHash` goes with it — without
 * it the chain cannot be walked at all in the redacted copy. `seq` is an ordinal and `event` a fixed
 * enum; neither can carry case data, and both are listed here so they survive by DESIGN rather than
 * because the anonymizer's detectors happen not to match them.
 *
 * Everything else is redacted, including fields added later: `artifactPath` carries filenames and
 * case ids, `source` a hostname or page URL, `collectedBy` an analyst's name.
 */
const CUSTODY_PRESERVED_FIELDS: ReadonlySet<string> = new Set(["sha256", "prevHash", "seq", "event"]);

/**
 * Redact custody records for the redacted export, field by field.
 *
 * Deliberately NOT applyAnonDeep over the whole record: the point is that unknown fields are
 * redacted by DEFAULT. A field added to CustodyRecord later leaks only if someone explicitly adds it
 * to the allow-list above, which is the safe direction for a mistake to fall.
 */
export function redactCustodyRecords<T extends object>(
  records: readonly T[],
  redact: (s: string) => string,
): T[] {
  return records.map((record) => {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(record as Record<string, unknown>)) {
      out[key] = CUSTODY_PRESERVED_FIELDS.has(key) ? value : applyAnonDeep(value, redact);
    }
    return out as T;
  });
}

export interface RedactionSummary {
  caseId: string;
  options: RedactedExportOptions;
  screenshotCount: number; // images included in the package
  screenshotsBlurred: number; // images where OCR painted at least one box
  screenshotRedactions: number; // total boxes painted across all images
  metadataStripped: number; // images re-encoded to drop EXIF/GPS/etc.
}

const REPORT_DIR = "report";
const SCREENSHOT_DIR = "screenshots";
const NOTES_FILE = "REDACTION-NOTES.txt";
const MANIFEST_FILE = "export-manifest.json";

// Provenance for the machine-readable manifest (#79). The impure bits (wall-clock time, app
// version) are supplied by the caller so the manifest builder stays pure + deterministic.
export interface ExportManifestMeta {
  caseId: string;
  exportedAt: string; // ISO-8601 UTC, from the orchestrator
  generatedBy: string; // app version, from getAppVersion()
}

export interface ExportManifestFile {
  path: string;
  sha256: string;
  bytes: number;
}

export interface ExportManifest extends ExportManifestMeta {
  files: ExportManifestFile[];
  totalFiles: number;
  totalBytes: number;
}

/**
 * A hashed, machine-readable manifest of the archive's contents (#79) — mirrors the whole-case
 * `archive-manifest.json` (caseExportArchive.ts) so a recipient of the redacted report ZIP can
 * verify each artifact's integrity and enumerate the contents programmatically. Hashes every entry
 * passed in, so it lists every file EXCEPT itself (it is appended after this runs). Pure.
 */
export function buildExportManifest(entries: readonly ZipEntry[], meta: ExportManifestMeta): ExportManifest {
  const files: ExportManifestFile[] = entries.map((e) => ({
    path: e.path,
    sha256: createHash("sha256").update(e.data).digest("hex"),
    bytes: e.data.length,
  }));
  return {
    caseId: meta.caseId,
    exportedAt: meta.exportedAt,
    generatedBy: meta.generatedBy,
    files,
    totalFiles: files.length,
    totalBytes: files.reduce((n, f) => n + f.bytes, 0),
  };
}

// Reduce a filename to a safe single archive path segment: strip any directory component and
// collapse path-traversal characters. Defense-in-depth so a screenshot filename can never escape
// the screenshots/ prefix in the ZIP (zip-slip), regardless of how it got onto disk.
export function safeArchiveName(name: string): string {
  const base = name.replace(/^.*[\\/]/, "");
  const cleaned = base
    .replace(/[\\/]/g, "_")
    .replace(/\.{2,}/g, ".")
    .trim();
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
 * and the redaction notes — honoring which parts the analyst chose to include. A hashed
 * `export-manifest.json` covering every other file is always appended last (#79). Pure.
 */
export function assembleRedactedEntries(input: {
  contents: RedactedReportContents;
  screenshots: { name: string; data: Buffer }[];
  notes: string;
  options: RedactedExportOptions;
  manifest: ExportManifestMeta;
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
    entries.push({
      path: `${REPORT_DIR}/forensic-timeline.csv`,
      data: enc(input.contents.forensicTimelineCsv),
    });
  }
  if (input.options.includeStateJson) {
    entries.push({ path: `${REPORT_DIR}/state-export.json`, data: enc(input.contents.stateJson) });
  }
  if (input.options.includeScreenshots) {
    for (const shot of input.screenshots) {
      entries.push({ path: `${SCREENSHOT_DIR}/${safeArchiveName(shot.name)}`, data: shot.data });
    }
  }
  // The signed custody manifest for the redacted appendix. Placed before the package manifest below
  // so it is enumerated and hashed like every other file in the package.
  if (input.contents.custodyManifest) {
    entries.push({
      path: CUSTODY_MANIFEST_FILENAME,
      data: enc(JSON.stringify(input.contents.custodyManifest, null, 2)),
    });
  }
  // Hashed manifest of every file assembled above, appended LAST so it enumerates the whole package
  // (but not itself). Gives the recipient chain-of-custody verification the human-readable notes can't.
  const manifest = buildExportManifest(entries, input.manifest);
  entries.push({ path: MANIFEST_FILE, data: enc(JSON.stringify(manifest, null, 2)) });
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
    "  ANON_HOST_n, accounts -> ANON_USER_n, internal email/domains -> ANON_EMAIL_n/ANON_DOMAIN_n.",
    "  In a user profile path (C:\\Users\\<name>, /home/<name>) only the username segment is",
    "  tokenized, as ANON_USER_n; the rest of the path stays readable. The SAME real value always",
    "  maps to the SAME token within this package, so the narrative still reads coherently.",
    "- CAVEAT: the ACCOUNT and EMAIL patterns are ASCII-only, so a name in another script — including",
    "  any accented Latin name — is NOT auto-detected (CORP\\<hebrew> is missed; CORP\\jose-with-accent",
    "  matches only its unaccented prefix and leaves a stray character beside the token). Names caught",
    "  by the optional Presidio layer, added by the analyst as custom entities, or appearing in a user",
    "  profile path ARE tokenized in any script. Review this package before sharing if the case",
    "  involves non-ASCII personal names.",
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
    "Integrity",
    "---------",
    "- export-manifest.json lists every file in this package with its SHA-256 and byte count, so a",
    "  recipient can verify nothing was altered in transit and enumerate the contents programmatically.",
    "",
    "Generated by DFIR Companion. Verify the contents before distribution.",
    "",
  );
  return lines.join("\n");
}

export function redactedExportFilename(caseId: string): string {
  return `case-${caseId}-redacted.zip`;
}
