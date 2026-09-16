import { randomUUID, createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { ImportMetadata } from "../types.js";
import { parseCsvRecords } from "./csvImport.js";
import {
  mobileBackupGenerationSchema,
  type MobileBackupGeneration,
  type MobileBackupDomain,
  type CompletenessState,
  type DeviceIdentity,
} from "./canonicalMobileBackupGeneration.js";
import type { GenerationOrder } from "./canonicalCollectionGeneration.js";

// The durable, examiner-attested ledger #1132 exists to build (see RECOMMENDATION-1132.md): one
// row per attested pairing of a "Backup Information" LEAPP export with an "Installed Applications"
// one. Mirrors collectionGenerationStore.ts's own append-only file mechanics (#1108) and
// evidenceAttestationStore.ts's own revoke() shape (a THIRD instance of this codebase's own
// established ledger pattern) — but this ledger's own record() does real, narrow structured
// re-parsing no sibling ledger needs, because #1132's own binding IS the act of naming two
// artifacts together, and that act must verify each artifact is what it claims to be.

const fileSchema = z.object({
  version: z.literal(1),
  generations: z.array(mobileBackupGenerationSchema),
});

// Pinned against iLEAPP's own real, current source (`scripts/artifacts/iTunesBackupInfo.py`,
// re-fetched 2026-09-16 — see RECOMMENDATION-1132.md). An EXACT match is required, not "starts
// with" (Codex code-review-equivalent finding on the design's own first draft) — a renamed or
// reordered column would otherwise silently bind the wrong file.
const BACKUP_INFO_HEADER = ["Property", "Property Value"];
const INSTALLED_APPS_HEADER = [
  "Bundle ID",
  "App Icon",
  "Item Name",
  "Artist Name",
  "Version",
  "Genre",
  "storeCohort Date (as stored)",
  "Downloaded by",
  "Purchase Date",
  "Release Date",
  "Source App",
  "Auto Download",
  "Purchased Redownload",
  "Factory Install",
  "Side Loaded",
  "Game Center Enabled",
  "Game Center Ever Enabled",
  "Messages Extension",
];

const BOM = "﻿";

function normalizeHeaderCell(cell: string): string {
  // Strips a leading UTF-8 BOM (some TSV exporters emit one on the first cell) and trims.
  const stripped = cell.startsWith(BOM) ? cell.slice(BOM.length) : cell;
  return stripped.trim();
}

function headerMatches(actual: readonly string[], expected: readonly string[]): boolean {
  if (actual.length !== expected.length) return false;
  return expected.every((h, i) => normalizeHeaderCell(actual[i] ?? "") === h);
}

export interface BackupInfoPreview {
  deviceIdentity: DeviceIdentity;
  /** Parsed ISO instant, or "" when Last Backup Date was absent/unparseable. */
  capturedAt: string;
}

export interface InstalledAppsPreview {
  appCount: number;
}

// iLEAPP's own real source (`scripts/ilapfuncs.py`, re-verified 2026-09-16) formats a plist
// datetime as `plist_date.strftime("%Y-%m-%d %H:%M:%S")` — no offset, because Apple's own plist
// date type is already UTC and the exporter never re-attaches one. `Date.parse()` on a bare
// "YYYY-MM-DD HH:mm:ss" string is NOT UTC — it is the HOST MACHINE'S OWN LOCAL TIMEZONE (a Codex
// code-review High finding: the same evidence would parse to a different real instant on a server
// in Jerusalem vs. one in UTC vs. one in New York, corrupting forensic chronology and making a
// stored generation's own order depend on where the companion happens to be deployed). Only this
// one exact, unambiguous shape is treated as UTC; anything else is left unparsed rather than
// guessed.
const LEAPP_BARE_DATETIME_RE = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/;

function parseLeappUtcDate(raw: string): string {
  const m = LEAPP_BARE_DATETIME_RE.exec(raw);
  if (!m) return "";
  const [, y, mo, d, h, mi, s] = m;
  const ms = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s));
  if (!Number.isFinite(ms)) return "";
  const asDate = new Date(ms);
  // Date.UTC rolls an impossible calendar date over (e.g. "2026-02-30" becomes March 2) rather
  // than failing — the round-trip check here rejects that instead of silently accepting it.
  if (
    asDate.getUTCFullYear() !== Number(y) ||
    asDate.getUTCMonth() !== Number(mo) - 1 ||
    asDate.getUTCDate() !== Number(d)
  ) {
    return "";
  }
  return asDate.toISOString();
}

/** Re-parses a "Backup Information" export's own raw TSV text — never trusts the generic prose
 * importer, which renders every column as `Header: value` prose and extracts nothing structured.
 * Throws if the header does not exactly match iLEAPP's own real, current shape. */
export function parseBackupInfo(text: string): BackupInfoPreview {
  const rows = [...parseCsvRecords(text, "\t")];
  const header = rows[0] ?? [];
  if (!headerMatches(header, BACKUP_INFO_HEADER)) {
    throw new Error(
      `does not look like an iTunes Backup Information export (expected header "${BACKUP_INFO_HEADER.join(", ")}")`,
    );
  }
  const props = new Map<string, string>();
  for (const row of rows.slice(1)) {
    if (row.length < 2) continue;
    props.set(row[0].trim(), row[1]);
  }
  const serial = (props.get("Serial Number") ?? "").trim();
  const uid = (props.get("Unique Identifier") ?? "").trim();
  const deviceIdentity: DeviceIdentity | null = serial
    ? { kind: "serial-number", value: serial }
    : uid
      ? { kind: "unique-identifier", value: uid }
      : null;
  if (!deviceIdentity) {
    throw new Error("no Serial Number or Unique Identifier property found in this Backup Information export");
  }
  const rawDate = (props.get("Last Backup Date") ?? "").trim();
  const capturedAt = parseLeappUtcDate(rawDate);
  return { deviceIdentity, capturedAt };
}

/** Re-parses an "Installed Applications" export's own raw TSV text into structured facts. Throws
 * if the header does not exactly match iLEAPP's own real, current shape. */
export function parseInstalledApps(text: string): {
  facts: { bundleId: string; itemName: string; version: string }[];
} {
  const rows = [...parseCsvRecords(text, "\t")];
  const header = rows[0] ?? [];
  if (!headerMatches(header, INSTALLED_APPS_HEADER)) {
    throw new Error(
      `does not look like an iTunes Backup - Installed Applications export (expected header "${INSTALLED_APPS_HEADER.join(", ")}")`,
    );
  }
  const facts = [];
  for (const row of rows.slice(1)) {
    const bundleId = (row[0] ?? "").trim();
    if (!bundleId) continue;
    facts.push({ bundleId, itemName: (row[2] ?? "").trim(), version: (row[4] ?? "").trim() });
  }
  return { facts };
}

export interface RecordMobileBackupInput {
  backupInfoImportSeq: number;
  installedAppsImportSeq: number;
  domain: MobileBackupDomain;
  completenessState: CompletenessState;
  filtersApplied?: string[];
  /** Only consulted when Last Backup Date is absent/unparseable — see `dateUnavailableReason`. */
  declaredSequence?: number;
  dateUnavailableReason?: string;
  attestedSameBackup: true;
  checked?: string;
  gaps?: string;
  recordedBy: { id: string; displayName: string };
}

export class MobileBackupGenerationStore {
  constructor(private readonly cases: Pick<CaseStore, "stateDir" | "importsLogPath" | "importsDir">) {}

  private readonly enqueueMap = new Map<string, Promise<unknown>>();

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "mobile-backup-generations.json");
  }

  private enqueue<T>(caseId: string, job: () => Promise<T>): Promise<T> {
    const prior = this.enqueueMap.get(caseId) ?? Promise.resolve();
    const run = prior.then(job, job);
    this.enqueueMap.set(
      caseId,
      run.catch(() => undefined),
    );
    return run;
  }

  async load(caseId: string): Promise<MobileBackupGeneration[]> {
    let raw: string;
    try {
      raw = await readFile(this.path(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    let json: unknown;
    try {
      json = JSON.parse(raw);
    } catch {
      throw new Error(
        `mobile-backup-generations.json for case ${caseId} is not valid JSON; it was left untouched so no generation record is lost`,
      );
    }
    const parsed = fileSchema.safeParse(json);
    if (!parsed.success) {
      throw new Error(
        `mobile-backup-generations.json for case ${caseId} does not match the generation schema and was left untouched: ${parsed.error.message}`,
      );
    }
    return parsed.data.generations;
  }

  async all(caseId: string): Promise<MobileBackupGeneration[]> {
    return this.load(caseId);
  }

  async active(caseId: string): Promise<MobileBackupGeneration[]> {
    return (await this.load(caseId)).filter((g) => !g.revokedAt);
  }

  private async importRow(caseId: string, importSeq: number): Promise<ImportMetadata> {
    let raw: string;
    try {
      raw = await readFile(this.cases.importsLogPath(caseId), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        throw new Error(`case ${caseId} has no imports at all; import sequence ${importSeq} does not exist`);
      }
      throw err;
    }
    const rows: ImportMetadata[] = [];
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      rows.push(JSON.parse(line) as ImportMetadata);
    }
    const matches = rows.filter((r) => r.sequenceNumber === importSeq);
    if (matches.length === 0)
      throw new Error(`import sequence ${importSeq} does not exist in case ${caseId}`);
    if (matches.length > 1) {
      throw new Error(
        `import sequence ${importSeq} is ambiguous in case ${caseId} (${matches.length} matching rows)`,
      );
    }
    return matches[0];
  }

  private async readAttestedRef(
    caseId: string,
    importSeq: number,
  ): Promise<{
    text: string;
    ref: { importSeq: number; artifactHash: string; originalName: string; importedAt: string };
  }> {
    const importRow = await this.importRow(caseId, importSeq);
    // Hash the RAW bytes, never a decoded-then-re-encoded string (#1138): reading as utf8 first
    // and hashing Buffer.from(text, "utf8") silently replaces invalid byte sequences with U+FFFD,
    // so two artifacts differing only in their invalid bytes could hash identically.
    const bytes = await readFile(join(this.cases.importsDir(caseId), importRow.filename));
    const artifactHash = createHash("sha256").update(bytes).digest("hex");
    const text = bytes.toString("utf8");
    return {
      text,
      ref: {
        importSeq,
        artifactHash,
        originalName: importRow.originalName,
        importedAt: importRow.importedAt,
      },
    };
  }

  /**
   * Records one examiner-attested pairing. ALL state-dependent validation — both imports exist
   * and are unambiguous, each re-parses as the artifact type its own reference claims, neither
   * import is already bound to another ACTIVE attestation, and (for a `declared` order) the
   * sequence is unique within its own device cohort — runs inside the queued callback, immediately
   * before the write.
   */
  async record(caseId: string, input: RecordMobileBackupInput): Promise<MobileBackupGeneration> {
    return this.enqueue(caseId, async () => {
      if (input.backupInfoImportSeq === input.installedAppsImportSeq) {
        throw new Error("backupInfoImportSeq and installedAppsImportSeq must name two different imports");
      }

      const backupInfo = await this.readAttestedRef(caseId, input.backupInfoImportSeq);
      const installedApps = await this.readAttestedRef(caseId, input.installedAppsImportSeq);

      const allExisting = await this.load(caseId);
      const activeExisting = allExisting.filter((g) => !g.revokedAt);
      const alreadyBound = activeExisting.find(
        (g) =>
          g.backupInfoRef.importSeq === input.backupInfoImportSeq ||
          g.installedAppsRef.importSeq === input.backupInfoImportSeq ||
          g.backupInfoRef.importSeq === input.installedAppsImportSeq ||
          g.installedAppsRef.importSeq === input.installedAppsImportSeq,
      );
      if (alreadyBound) {
        throw new Error(
          `import sequence ${alreadyBound.backupInfoRef.importSeq === input.backupInfoImportSeq || alreadyBound.backupInfoRef.importSeq === input.installedAppsImportSeq ? input.backupInfoImportSeq : input.installedAppsImportSeq} is already bound to an active generation (${alreadyBound.generationId}); revoke it first`,
        );
      }

      const backupInfoParsed = parseBackupInfo(backupInfo.text);
      const installedAppsParsed = parseInstalledApps(installedApps.text);
      if (installedAppsParsed.facts.length === 0) {
        throw new Error(
          `import sequence ${input.installedAppsImportSeq} in case ${caseId} has no installed-app rows — cannot record this generation`,
        );
      }

      let order: GenerationOrder;
      if (backupInfoParsed.capturedAt) {
        order = { kind: "captured", capturedAt: backupInfoParsed.capturedAt };
      } else {
        if (!input.declaredSequence || !input.dateUnavailableReason) {
          throw new Error(
            "Last Backup Date was absent or unparseable in the backup-info export; declaredSequence and dateUnavailableReason are both required",
          );
        }
        order = { kind: "declared", sequence: input.declaredSequence };
      }

      if (order.kind === "declared") {
        const cohortSequence = order.sequence;
        const collision = activeExisting.some(
          (g) =>
            g.deviceIdentity.kind === backupInfoParsed.deviceIdentity.kind &&
            g.deviceIdentity.value.toLowerCase() === backupInfoParsed.deviceIdentity.value.toLowerCase() &&
            g.domain === input.domain &&
            g.order.kind === "declared" &&
            g.order.sequence === cohortSequence,
        );
        if (collision) {
          throw new Error(
            `declared sequence ${cohortSequence} already exists for this device / domain "${input.domain}"`,
          );
        }
      }

      const generation = mobileBackupGenerationSchema.parse({
        generationId: randomUUID(),
        deviceIdentity: backupInfoParsed.deviceIdentity,
        domain: input.domain,
        completenessState: input.completenessState,
        filtersApplied: input.filtersApplied ?? [],
        order,
        ...(order.kind === "declared" ? { dateUnavailableReason: input.dateUnavailableReason } : {}),
        backupInfoRef: backupInfo.ref,
        installedAppsRef: installedApps.ref,
        attestedSameBackup: input.attestedSameBackup,
        inventory: installedAppsParsed.facts,
        checked: input.checked,
        gaps: input.gaps,
        recordedBy: input.recordedBy,
        recordedAt: new Date().toISOString(),
      });

      const generations = [...allExisting, generation];
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, generations }, null, 2));
      return generation;
    });
  }

  /** Marks one specific generation revoked — a correction appends a NEW generation via record()
   * and separately revokes the mistaken one; history is never rewritten. Mirrors
   * collectionGenerationStore.ts's own revoke() exactly. */
  async revoke(
    caseId: string,
    generationId: string,
    revokedBy: { id: string; displayName: string },
    revokedAt: string,
  ): Promise<MobileBackupGeneration[]> {
    return this.enqueue(caseId, async () => {
      const generations = await this.load(caseId);
      const idx = generations.findIndex((g) => g.generationId === generationId);
      if (idx === -1 || generations[idx].revokedAt) return generations;
      const next = generations.map((g, i) => (i === idx ? { ...g, revokedBy, revokedAt } : g));
      await atomicWrite(this.path(caseId), JSON.stringify({ version: 1, generations: next }, null, 2));
      return next;
    });
  }

  /** Re-reads BOTH of the generation's own referenced artifacts and compares each's CURRENT sha256
   * against the one frozen at record time. */
  async verifyArtifacts(
    caseId: string,
    generationId: string,
  ): Promise<{
    backupInfo: { ok: boolean; reason?: string };
    installedApps: { ok: boolean; reason?: string };
  }> {
    const generation = (await this.load(caseId)).find((g) => g.generationId === generationId);
    if (!generation) {
      const notFound = { ok: false, reason: "generation not found" };
      return { backupInfo: notFound, installedApps: notFound };
    }
    const verifyOne = async (ref: { importSeq: number; artifactHash: string }) => {
      let importRow: ImportMetadata;
      try {
        importRow = await this.importRow(caseId, ref.importSeq);
      } catch (err) {
        return { ok: false, reason: (err as Error).message };
      }
      let bytes: Buffer;
      try {
        bytes = await readFile(join(this.cases.importsDir(caseId), importRow.filename));
      } catch (err) {
        return { ok: false, reason: `stored artifact is missing or unreadable: ${(err as Error).message}` };
      }
      const currentHash = createHash("sha256").update(bytes).digest("hex");
      if (currentHash !== ref.artifactHash) {
        return { ok: false, reason: "stored artifact has changed since this generation was recorded" };
      }
      return { ok: true };
    };
    const [backupInfo, installedApps] = await Promise.all([
      verifyOne(generation.backupInfoRef),
      verifyOne(generation.installedAppsRef),
    ]);
    return { backupInfo, installedApps };
  }
}
