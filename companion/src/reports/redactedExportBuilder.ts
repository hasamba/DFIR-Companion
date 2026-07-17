import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { StateStore } from "../analysis/stateStore.js";
import type { ReportWriter } from "./reportWriter.js";
import type { CustomEntitiesStore } from "../analysis/anonEntities.js";
import type { DiscoveredEntitiesStore } from "../analysis/anonDiscovered.js";
import type { CustomerStore } from "../analysis/customerStore.js";
import { createAnonymizer, deriveKnownEntities, type CustomEntity, type KnownEntities } from "../analysis/anonymize.js";
import { redactScreenshot, type ScreenshotRedactOptions, type ScreenshotRedactResult } from "../analysis/imageRedact.js";
import type { OcrRunner } from "../analysis/ocrRedact.js";
import { createZip } from "../analysis/zipArchive.js";
import { getAppVersion } from "../version.js";
import {
  assembleRedactedEntries,
  buildRedactionNotes,
  redactedExportPolicy,
  type RedactedExportOptions,
  type RedactionSummary,
} from "../analysis/redactedExport.js";

// Orchestrates the redacted case export (#54): builds one anonymizer from the case's full state +
// analyst entity lists, renders an anonymized report, EXIF-strips + PII-blurs the screenshots, and
// zips it all up. The only impure module in the feature — disk reads, sharp, and OCR — so its
// collaborators are injectable and the unit test runs with no real fs/sharp/tesseract.

const IMAGE_EXT = /\.(png|jpe?g|webp|gif)$/i;

export interface RedactedExportDeps {
  store: CaseStore;
  reportWriter: Pick<ReportWriter, "redactedReportContents">;
  stateStore: StateStore;
  customEntities: CustomEntitiesStore;
  discoveredEntities: DiscoveredEntitiesStore;
  // Optional: the victim org's own domains/emails (analyst-entered for the exposure check). These
  // are PII and are merged into the anonymizer's known entities so they're tokenized everywhere.
  customerStore?: CustomerStore;
  ocrRunner: OcrRunner;
  // Injectable for tests; default is the real sharp-backed redactor + fs readers.
  redactImage?: (buf: Buffer, opts: ScreenshotRedactOptions) => Promise<ScreenshotRedactResult>;
  listScreenshots?: (caseId: string) => Promise<string[]>;
  readScreenshot?: (caseId: string, file: string) => Promise<Buffer>;
}

export interface RedactedExportResult {
  zip: Buffer;
  summary: RedactionSummary;
}

export async function buildRedactedExport(
  deps: RedactedExportDeps,
  caseId: string,
  options: RedactedExportOptions,
): Promise<RedactedExportResult> {
  // 1. One anonymizer for the whole package — built from the FULL state (so screenshot OCR can
  //    redact entities that may be out of the report's scope) plus the analyst's entity lists,
  //    mirroring the live AI-anonymization path. A shared instance keeps tokens consistent
  //    (same real value -> same token) across the report text AND the screenshots.
  const full = await deps.stateStore.load(caseId);
  const derived = deriveKnownEntities(full);
  const custom = await deps.customEntities.load(caseId);
  const disc = await deps.discoveredEntities.load(caseId);
  // Victim org targets (analyst-entered) are PII: tokenize their domains everywhere (a bare victim
  // domain in the exposure section is not otherwise in deriveKnownEntities) and their emails too.
  const targets = deps.customerStore ? await deps.customerStore.load(caseId) : { domains: [], emails: [] };
  const targetEmails: CustomEntity[] = targets.emails.map((value) => ({ value, category: "EMAIL" as const }));
  const known: KnownEntities = {
    hosts: derived.hosts,
    accounts: derived.accounts,
    internalDomains: [...derived.internalDomains, ...targets.domains.map((d) => d.toLowerCase())],
    custom: [...custom, ...disc.discovered, ...targetEmails],
    suppressed: disc.suppressed,
  };
  const policy = redactedExportPolicy();
  const anon = createAnonymizer(policy, known);

  // 2. Anonymized report artifacts (filtered state -> anonymized -> rendered to strings). The
  //    ReportWriter walks the state with this same anonymizer before rendering.
  const contents = await deps.reportWriter.redactedReportContents(caseId, (s) => anon.apply(s));

  // 3. Screenshots: strip metadata always, optionally OCR-blur PII text.
  const redactImage = deps.redactImage ?? redactScreenshot;
  const listScreenshots = deps.listScreenshots ?? defaultListScreenshots(deps.store);
  const readScreenshot = deps.readScreenshot ?? defaultReadScreenshot(deps.store);

  const screenshots: { name: string; data: Buffer }[] = [];
  let screenshotsBlurred = 0;
  let screenshotRedactions = 0;
  let metadataStripped = 0;
  if (options.includeScreenshots) {
    for (const file of await listScreenshots(caseId)) {
      const buf = await readScreenshot(caseId, file);
      const result = await redactImage(buf, { policy, known, runner: deps.ocrRunner, blur: options.blurScreenshots });
      screenshots.push({ name: file, data: result.buffer });
      if (result.blurred) screenshotsBlurred++;
      screenshotRedactions += result.redactionCount;
      if (result.metadataStripped) metadataStripped++;
    }
  }

  const summary: RedactionSummary = {
    caseId,
    options,
    screenshotCount: screenshots.length,
    screenshotsBlurred,
    screenshotRedactions,
    metadataStripped,
  };
  const notes = buildRedactionNotes(summary);
  const entries = assembleRedactedEntries({
    contents, screenshots, notes, options,
    // Provenance for the hashed export-manifest.json (#79) — mirrors the whole-case archive manifest.
    manifest: { caseId, exportedAt: new Date().toISOString(), generatedBy: getAppVersion() },
  });
  return { zip: createZip(entries), summary };
}

function defaultListScreenshots(store: CaseStore): (caseId: string) => Promise<string[]> {
  return async (caseId) => {
    try {
      const files = await readdir(store.screenshotsDir(caseId));
      // Image files only, and never a name with a path component (defense-in-depth vs zip-slip).
      return files.filter((f) => IMAGE_EXT.test(f) && !/[\\/]/.test(f) && !f.includes("..")).sort();
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  };
}

function defaultReadScreenshot(store: CaseStore): (caseId: string, file: string) => Promise<Buffer> {
  return (caseId, file) => readFile(join(store.screenshotsDir(caseId), file));
}
