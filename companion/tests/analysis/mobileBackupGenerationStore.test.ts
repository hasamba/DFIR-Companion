// #1132: the durable, examiner-attested mobile-backup-pairing ledger. Real fixtures shaped exactly
// like iLEAPP's own real TSV exports (re-verified against `scripts/artifacts/iTunesBackupInfo.py`)
// throughout, so the re-parse-and-validate path in record() is exercised authentically.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MobileBackupGenerationStore,
  parseBackupInfo,
  parseInstalledApps,
} from "../../src/analysis/mobileBackupGenerationStore.js";

let dir = "";
const cases = {
  stateDir: () => dir,
  importsLogPath: () => join(dir, "imports.jsonl"),
  importsDir: () => join(dir, "imports"),
} as unknown as ConstructorParameters<typeof MobileBackupGenerationStore>[0];

const ACTOR = { id: "u1", displayName: "J. Analyst" };

const BACKUP_INFO_TSV = [
  "Property\tProperty Value",
  "Product Name\tiPhone",
  "Device Name\tJ's iPhone",
  "Serial Number\tF2LN12ABCDEF",
  "Unique Identifier\t00008030-000A1B2C3D4E5F6G",
  "Product Version\t17.5",
  "Last Backup Date\t2026-01-12 09:00:00",
].join("\n");

const BACKUP_INFO_NO_DATE_TSV = [
  "Property\tProperty Value",
  "Serial Number\tF2LN12ABCDEF",
  "Product Version\t17.5",
].join("\n");

const BACKUP_INFO_NO_SERIAL_TSV = [
  "Property\tProperty Value",
  "Unique Identifier\t00008030-000A1B2C3D4E5F6G",
  "Last Backup Date\t2026-01-12 09:00:00",
].join("\n");

const INSTALLED_APPS_HEADER =
  "Bundle ID\tApp Icon\tItem Name\tArtist Name\tVersion\tGenre\tstoreCohort Date (as stored)\tDownloaded by\tPurchase Date\tRelease Date\tSource App\tAuto Download\tPurchased Redownload\tFactory Install\tSide Loaded\tGame Center Enabled\tGame Center Ever Enabled\tMessages Extension";

function appRow(bundleId: string, itemName: string, version: string): string {
  return [
    bundleId,
    "",
    itemName,
    "Example Artist",
    version,
    "Utilities",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
  ].join("\t");
}

const INSTALLED_APPS_TSV = [
  INSTALLED_APPS_HEADER,
  appRow("com.example.app", "Example", "1.0"),
  appRow("com.example.other", "Other", "2.0"),
].join("\n");

const EMPTY_INSTALLED_APPS_TSV = [INSTALLED_APPS_HEADER].join("\n");

const WRONG_SHAPE_TSV = "Hostname\tTechnique\nWS-01\tRun Key";

async function seedImport(seq: number, filename: string, text: string): Promise<void> {
  await mkdir(join(dir, "imports"), { recursive: true });
  await writeFile(join(dir, "imports", filename), text, "utf8");
  const line =
    JSON.stringify({
      caseId: "c1",
      sequenceNumber: seq,
      importedAt: "2026-01-12T08:00:00Z",
      filename,
      originalName: filename,
      rows: text.split("\n").length - 1,
      bytes: Buffer.byteLength(text, "utf8"),
    }) + "\n";
  await writeFile(join(dir, "imports.jsonl"), line, { flag: "a" });
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "mobile-backup-generation-"));
});

describe("parseBackupInfo", () => {
  it("extracts device identity (Serial Number preferred) and Last Backup Date", () => {
    const r = parseBackupInfo(BACKUP_INFO_TSV);
    expect(r.deviceIdentity).toEqual({ kind: "serial-number", value: "F2LN12ABCDEF" });
    expect(r.capturedAt).toBe(new Date("2026-01-12 09:00:00").toISOString());
  });

  it("falls back to Unique Identifier when Serial Number is absent", () => {
    const r = parseBackupInfo(BACKUP_INFO_NO_SERIAL_TSV);
    expect(r.deviceIdentity).toEqual({ kind: "unique-identifier", value: "00008030-000A1B2C3D4E5F6G" });
  });

  it("returns an empty capturedAt when Last Backup Date is absent", () => {
    expect(parseBackupInfo(BACKUP_INFO_NO_DATE_TSV).capturedAt).toBe("");
  });

  it("throws on the wrong header shape", () => {
    expect(() => parseBackupInfo(WRONG_SHAPE_TSV)).toThrow(/does not look like/);
  });

  it("throws when neither Serial Number nor Unique Identifier is present", () => {
    expect(() => parseBackupInfo("Property\tProperty Value\nProduct Version\t17.5")).toThrow(
      /Serial Number or Unique Identifier/,
    );
  });
});

describe("parseInstalledApps", () => {
  it("extracts bundleId/itemName/version facts", () => {
    const r = parseInstalledApps(INSTALLED_APPS_TSV);
    expect(r.facts).toEqual([
      { bundleId: "com.example.app", itemName: "Example", version: "1.0" },
      { bundleId: "com.example.other", itemName: "Other", version: "2.0" },
    ]);
  });

  it("throws on the wrong header shape", () => {
    expect(() => parseInstalledApps(WRONG_SHAPE_TSV)).toThrow(/does not look like/);
  });
});

describe("MobileBackupGenerationStore.record", () => {
  it("records an attested pairing, freezing the app inventory and deriving order from Last Backup Date", async () => {
    await seedImport(1, "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    await seedImport(2, "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    const store = new MobileBackupGenerationStore(cases);

    const g = await store.record("c1", {
      backupInfoImportSeq: 1,
      installedAppsImportSeq: 2,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
      recordedBy: ACTOR,
    });

    expect(g.deviceIdentity).toEqual({ kind: "serial-number", value: "F2LN12ABCDEF" });
    expect(g.order).toEqual({ kind: "captured", capturedAt: new Date("2026-01-12 09:00:00").toISOString() });
    expect(g.inventory).toHaveLength(2);
    expect(g.backupInfoRef.importSeq).toBe(1);
    expect(g.installedAppsRef.importSeq).toBe(2);
    expect(g.backupInfoRef.originalName).toBe("0001_backupinfo.tsv");
    expect(g.attestedSameBackup).toBe(true);
    expect(await store.active("c1")).toHaveLength(1);
  });

  it("rejects the same importSeq for both references", async () => {
    await seedImport(1, "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    const store = new MobileBackupGenerationStore(cases);
    await expect(
      store.record("c1", {
        backupInfoImportSeq: 1,
        installedAppsImportSeq: 1,
        domain: "mobile-app-presence",
        completenessState: "complete",
        attestedSameBackup: true,
        recordedBy: ACTOR,
      }),
    ).rejects.toThrow(/two different imports/);
  });

  it("rejects when the backupInfoImportSeq does not actually parse as a Backup Information export", async () => {
    await seedImport(1, "0001_wrong.tsv", INSTALLED_APPS_TSV); // swapped
    await seedImport(2, "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    const store = new MobileBackupGenerationStore(cases);
    await expect(
      store.record("c1", {
        backupInfoImportSeq: 1,
        installedAppsImportSeq: 2,
        domain: "mobile-app-presence",
        completenessState: "complete",
        attestedSameBackup: true,
        recordedBy: ACTOR,
      }),
    ).rejects.toThrow(/does not look like/);
  });

  it("rejects an installed-apps export with zero app rows", async () => {
    await seedImport(1, "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    await seedImport(2, "0002_empty.tsv", EMPTY_INSTALLED_APPS_TSV);
    const store = new MobileBackupGenerationStore(cases);
    await expect(
      store.record("c1", {
        backupInfoImportSeq: 1,
        installedAppsImportSeq: 2,
        domain: "mobile-app-presence",
        completenessState: "complete",
        attestedSameBackup: true,
        recordedBy: ACTOR,
      }),
    ).rejects.toThrow(/no installed-app rows/);
  });

  it("requires declaredSequence + dateUnavailableReason when Last Backup Date is absent", async () => {
    await seedImport(1, "0001_backupinfo.tsv", BACKUP_INFO_NO_DATE_TSV);
    await seedImport(2, "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    const store = new MobileBackupGenerationStore(cases);
    await expect(
      store.record("c1", {
        backupInfoImportSeq: 1,
        installedAppsImportSeq: 2,
        domain: "mobile-app-presence",
        completenessState: "complete",
        attestedSameBackup: true,
        recordedBy: ACTOR,
      }),
    ).rejects.toThrow(/declaredSequence and dateUnavailableReason/);

    const g = await store.record("c1", {
      backupInfoImportSeq: 1,
      installedAppsImportSeq: 2,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
      declaredSequence: 1,
      dateUnavailableReason: "Last Backup Date absent from this export",
      recordedBy: ACTOR,
    });
    expect(g.order).toEqual({ kind: "declared", sequence: 1 });
    expect(g.dateUnavailableReason).toBe("Last Backup Date absent from this export");
  });

  it("enforces one-to-one active use of each import reference", async () => {
    await seedImport(1, "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    await seedImport(2, "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    await seedImport(3, "0003_installedapps2.tsv", INSTALLED_APPS_TSV);
    const store = new MobileBackupGenerationStore(cases);
    await store.record("c1", {
      backupInfoImportSeq: 1,
      installedAppsImportSeq: 2,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
      recordedBy: ACTOR,
    });
    // Re-pairing import #1 (already bound) with a DIFFERENT installed-apps import must fail.
    await expect(
      store.record("c1", {
        backupInfoImportSeq: 1,
        installedAppsImportSeq: 3,
        domain: "mobile-app-presence",
        completenessState: "complete",
        attestedSameBackup: true,
        recordedBy: ACTOR,
      }),
    ).rejects.toThrow(/already bound to an active generation/);
  });

  it("allows re-pairing an import once its prior binding is revoked", async () => {
    await seedImport(1, "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    await seedImport(2, "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    await seedImport(3, "0003_installedapps2.tsv", INSTALLED_APPS_TSV);
    const store = new MobileBackupGenerationStore(cases);
    const first = await store.record("c1", {
      backupInfoImportSeq: 1,
      installedAppsImportSeq: 2,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
      recordedBy: ACTOR,
    });
    await store.revoke("c1", first.generationId, ACTOR, "2026-01-12T11:00:00Z");
    const second = await store.record("c1", {
      backupInfoImportSeq: 1,
      installedAppsImportSeq: 3,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
      recordedBy: ACTOR,
    });
    expect(second.installedAppsRef.importSeq).toBe(3);
    expect(await store.active("c1")).toHaveLength(1);
    expect(await store.all("c1")).toHaveLength(2);
  });
});

describe("MobileBackupGenerationStore.verifyArtifacts", () => {
  it("verifies both artifacts ok, and detects one that changed since recording", async () => {
    await seedImport(1, "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    await seedImport(2, "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    const store = new MobileBackupGenerationStore(cases);
    const g = await store.record("c1", {
      backupInfoImportSeq: 1,
      installedAppsImportSeq: 2,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
      recordedBy: ACTOR,
    });
    const ok = await store.verifyArtifacts("c1", g.generationId);
    expect(ok.backupInfo.ok).toBe(true);
    expect(ok.installedApps.ok).toBe(true);

    await writeFile(
      join(dir, "imports", "0002_installedapps.tsv"),
      INSTALLED_APPS_TSV + "\ntampered",
      "utf8",
    );
    const after = await store.verifyArtifacts("c1", g.generationId);
    expect(after.backupInfo.ok).toBe(true);
    expect(after.installedApps.ok).toBe(false);
  });
});
