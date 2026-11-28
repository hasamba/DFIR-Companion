// The demo case's evidence: the screenshots and imports its capture/import logs name, and the chain of
// custody that records them (#3022). Split out of seedDemoCase.ts, which is at its size-ledger cap.
//
// Before this, the seeder wrote metadata/captures.jsonl and metadata/imports.jsonl by hand but left
// screenshots/ and imports/ empty and recorded no custody, so the Chain of Custody panel (and the
// report's custody appendix) said "No custody records" on a case that claimed nine artifacts.
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { runInCaseScope } from "../storage/caseIncarnation.js";
import { RECEIVED_PATH_PREFIX, type CustodyRecordInput, type CustodyStore } from "./custody.js";
import { StateLock } from "./stateLock.js";

/** What a seed hands back to its caller. `custody` is what the caller records once the slot closes. */
export interface DemoSeedOutput {
  caseId: string;
  caseDir: string;
  stats: { findings: number; iocs: number; events: number; superTimelineEvents: number };
  custody: CustodyRecordInput[];
}

/** The seed result a route or the CLI reports: no custody inputs, plus why custody failed, if it did. */
export type DemoSeedReport = Omit<DemoSeedOutput, "custody"> & { custodyError?: string };

// Five 320x180 solid-colour lossless WebP images (44 bytes each), generated once with sharp. Fixed
// bytes rather than rendered per seed: the demo-mode reset button is unauthenticated, and fixed bytes
// give hashes a test can pin. Distinct colours, so each screenshot hashes differently.
const DEMO_SCREENSHOTS_WEBP = [
  "UklGRiQAAABXRUJQVlA4TBgAAAAvP8EsAAdQ+MIXvv8BAEX6/58i+p/6/wM=",
  "UklGRiQAAABXRUJQVlA4TBgAAAAvP8EsAAfQlHp0p/8BAEX6/58i+p/6/wM=",
  "UklGRiQAAABXRUJQVlA4TBgAAAAvP8EsAAdQpebUuv8BAEX6/58i+p/6/wM=",
  "UklGRiQAAABXRUJQVlA4TBgAAAAvP8EsAAfQlHqUp/8BAEX6/58i+p/6/wM=",
  "UklGRiQAAABXRUJQVlA4TBgAAAAvP8EsAAfQlHq0p/8BAEX6/58i+p/6/wM=",
].map((b64) => Buffer.from(b64, "base64"));

/** The route the demo's imports are receipted as arriving through (routes/importCaseGuard.ts). */
const DEMO_IMPORT_ROUTE = "import";

/** One capture the demo's captures.jsonl lists (defined in seedDemoCase.ts beside the rest of the story). */
export interface DemoCapture {
  timestamp: string;
  url: string;
  triggerType: string;
  screenshotFile: string;
}

const DEMO_IMPORTS = [
  ["2026-05-22T10:00:00.000Z", "thor-wkstn-jsmith.json", "thor_scan_WKSTN-JSMITH.json", 87],
  ["2026-05-22T10:05:00.000Z", "suricata-eve-may15-22.json", "suricata_eve.json", 312],
  ["2026-05-22T10:10:00.000Z", "crowdstrike-siem-export.json", "cs_siem_export_may22.json", 204],
  ["2026-05-22T10:30:00.000Z", "dc01-evtx-chainsaw.json", "DC01_chainsaw_hunt.json", 143],
] as const;

/** The stored copy of one demo import: a marked placeholder, never parseable as the real export. */
function demoImportText(originalName: string, rows: number): string {
  return (
    JSON.stringify(
      {
        _demo: "Synthetic placeholder stored by the built-in demo case. It is not real evidence.",
        originalName,
        rows,
        note: "The rows this import produced are already in the demo case's timeline.",
      },
      null,
      2,
    ) + "\n"
  );
}

const hashes = (bytes: Buffer) => ({
  sha256: createHash("sha256").update(bytes).digest("hex"),
  sha1: createHash("sha1").update(bytes).digest("hex"),
});

const jsonl = (rows: readonly unknown[]) => rows.map((r) => JSON.stringify(r)).join("\n") + "\n";

/**
 * Write the screenshots and imports the demo's capture and import logs name, then the logs
 * themselves, and return the custody entries those files call for. Called inside the seed slot, so
 * it writes with plain fs like the rest of the seeder; the entries are recorded once the slot closes
 * (see seedDemoWithCustody). Each entry mirrors what the real path records: a screenshot as a
 * `collected` artifact from the browser extension (ingest/captureIngest.ts), an import as a
 * `received` receipt (routes/importReceipt.ts) and then its stored copy, `collected` by the companion.
 */
export async function writeDemoEvidence(
  caseDir: string,
  caseId: string,
  captures: readonly DemoCapture[],
): Promise<CustodyRecordInput[]> {
  const entries: CustodyRecordInput[] = [];
  for (const [i, capture] of captures.entries()) {
    const bytes = DEMO_SCREENSHOTS_WEBP[i];
    const artifactPath = join(caseDir, "screenshots", capture.screenshotFile);
    await writeFile(artifactPath, bytes, { flag: "wx" });
    entries.push({
      artifactPath,
      ...hashes(bytes),
      collectedBy: "browser-extension",
      collectedAt: capture.timestamp,
      source: capture.url,
      trigger: capture.triggerType,
      caseId,
    });
  }
  await writeFile(join(caseDir, "metadata", "captures.jsonl"), jsonl(captures), "utf8");

  const imports = [];
  for (const [i, [importedAt, filename, originalName, rows]] of DEMO_IMPORTS.entries()) {
    const bytes = Buffer.from(demoImportText(originalName, rows), "utf8");
    const artifactPath = join(caseDir, "imports", filename);
    await writeFile(artifactPath, bytes, { flag: "wx" });
    const digest = hashes(bytes);
    const common = { ...digest, collectedAt: importedAt, caseId, collectedBy: "companion" };
    entries.push({
      ...common,
      artifactPath: `${RECEIVED_PATH_PREFIX}${DEMO_IMPORT_ROUTE}/${originalName}@${digest.sha256.slice(0, 12)}`,
      bytes: bytes.byteLength,
      source: originalName,
      trigger: DEMO_IMPORT_ROUTE,
      event: "received",
    });
    entries.push({ ...common, artifactPath, source: "", trigger: "import" });
    // The size of the file actually stored, so the import list never contradicts it.
    imports.push({
      caseId,
      sequenceNumber: i + 1,
      importedAt,
      filename,
      originalName,
      rows,
      bytes: bytes.byteLength,
    });
  }
  await writeFile(join(caseDir, "metadata", "imports.jsonl"), jsonl(imports), "utf8");

  // One chain in time order, as the captures and imports happened. Stable, so a receipt stays ahead of its copy.
  return entries.sort((a, b) => a.collectedAt.localeCompare(b.collectedAt));
}

// Serializes seed + custody append per case, for the two callers in one process that can overlap on
// the same id: the reset route (unauthenticated in demo mode) and the demo-mode reset timer. The
// generation scope below already keeps an overlap from doubling the trail (the earlier seed's late
// append is refused as "replaced"); this lock keeps that from happening at all, so an overlapping
// reset never logs a spurious custody failure.
const demoSeedLock = new StateLock();

/**
 * Seed `caseId` through the store's seed slot, then record the demo's chain of custody.
 *
 * The append cannot happen inside the slot: a reseed holds the case folder closed, and the custody
 * store's guarded write would be refused as "replaced". So it runs right after, scoped to the
 * generation the slot handed out — if a delete, archive or another seed replaced the case in between,
 * the append is refused instead of landing stale records in a successor.
 *
 * A custody failure never fails the seed: the case exists either way, and failing here would leave
 * the caller unable to grant access to it. It is returned as `custodyError` for the caller to log; a
 * force reseed rebuilds the case, custody log included, from scratch.
 */
export async function seedDemoWithCustody(
  store: Pick<CaseStore, "casesRoot" | "withSeedSlot">,
  custody: Pick<CustodyStore, "recordMany"> | undefined,
  caseId: string,
  inSlot: (isNew: boolean, generation: string) => Promise<DemoSeedOutput>,
): Promise<DemoSeedReport> {
  return demoSeedLock.runExclusive(`${store.casesRoot}\0${caseId}`, async () => {
    let generation: string | undefined;
    const { custody: entries, ...report } = await store.withSeedSlot(caseId, (isNew, gen) => {
      generation = gen;
      return inSlot(isNew, gen);
    });
    if (!custody || entries.length === 0) return report;
    try {
      await runInCaseScope(
        store.casesRoot,
        report.caseId,
        () => custody.recordMany(report.caseId, entries),
        generation,
      );
      return report;
    } catch (err) {
      return { ...report, custodyError: (err as Error).message };
    }
  });
}
