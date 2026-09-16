// #1132: the mobile-backup-generation ledger's own routes. End-to-end via a real CaseStore-seeded
// import, plus real iLEAPP-shaped TSV fixtures.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MobileBackupGenerationStore } from "../../src/analysis/mobileBackupGenerationStore.js";
import { createApp } from "../../src/server.js";

const BACKUP_INFO_TSV = [
  "Property\tProperty Value",
  "Serial Number\tF2LN12ABCDEF",
  "Last Backup Date\t2026-01-12 09:00:00",
].join("\n");

const INSTALLED_APPS_HEADER =
  "Bundle ID\tApp Icon\tItem Name\tArtist Name\tVersion\tGenre\tstoreCohort Date (as stored)\tDownloaded by\tPurchase Date\tRelease Date\tSource App\tAuto Download\tPurchased Redownload\tFactory Install\tSide Loaded\tGame Center Enabled\tGame Center Ever Enabled\tMessages Extension";

function appRow(bundleId: string, itemName: string, version: string): string {
  return [
    bundleId,
    "",
    itemName,
    "Artist",
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

const INSTALLED_APPS_TSV = [INSTALLED_APPS_HEADER, appRow("com.example.app", "Example", "1.0")].join("\n");

let app: ReturnType<typeof createApp>;
let store: CaseStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-mobile-backup-generations-"));
  store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(store, {
    stateStore: new StateStore(store),
    mobileBackupGenerationStore: new MobileBackupGenerationStore(store),
  });
});

async function seedImport(caseId: string, filename: string, text: string): Promise<number> {
  const seq = await store.nextImportSeq(caseId);
  await store.saveImport(caseId, filename, text);
  await store.appendImport(caseId, {
    caseId,
    sequenceNumber: seq,
    importedAt: new Date().toISOString(),
    filename,
    originalName: filename,
    rows: text.split("\n").length - 1,
    bytes: Buffer.byteLength(text, "utf8"),
  });
  return seq;
}

describe("/cases/:id/mobile-backup-generations", () => {
  it("returns an empty list for a fresh case", async () => {
    const res = await request(app).get("/cases/c1/mobile-backup-generations");
    expect(res.status).toBe(200);
    expect(res.body.generations).toEqual([]);
  });

  it("returns 501 when the store is not configured", async () => {
    const bareApp = createApp(store, { stateStore: new StateStore(store) });
    const res = await request(bareApp).get("/cases/c1/mobile-backup-generations");
    expect(res.status).toBe(501);
  });

  it("records an attested pairing and reflects it in the list", async () => {
    const backupSeq = await seedImport("c1", "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    const appsSeq = await seedImport("c1", "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    const res = await request(app).post("/cases/c1/mobile-backup-generations").send({
      backupInfoImportSeq: backupSeq,
      installedAppsImportSeq: appsSeq,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
    });
    expect(res.status).toBe(201);
    expect(res.body.generation.inventory).toHaveLength(1);
    expect(res.body.generation.recordedBy).toEqual({ id: "local", displayName: "local" });

    const list = await request(app).get("/cases/c1/mobile-backup-generations");
    expect(list.body.generations).toHaveLength(1);
  });

  it("400s a malformed body instead of 500ing", async () => {
    const res = await request(app).post("/cases/c1/mobile-backup-generations").send({});
    expect(res.status).toBe(400);
  });

  it("400s attestedSameBackup: false rather than silently recording", async () => {
    const backupSeq = await seedImport("c1", "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    const appsSeq = await seedImport("c1", "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    const res = await request(app).post("/cases/c1/mobile-backup-generations").send({
      backupInfoImportSeq: backupSeq,
      installedAppsImportSeq: appsSeq,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: false,
    });
    expect(res.status).toBe(400);
  });

  it("400s a record() rejection (e.g. an importSeq that does not exist) — never a 500", async () => {
    const res = await request(app).post("/cases/c1/mobile-backup-generations").send({
      backupInfoImportSeq: 999,
      installedAppsImportSeq: 998,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
    });
    expect(res.status).toBe(400);
  });

  it("filters by device, case-insensitively", async () => {
    const backupSeq = await seedImport("c1", "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    const appsSeq = await seedImport("c1", "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    await request(app).post("/cases/c1/mobile-backup-generations").send({
      backupInfoImportSeq: backupSeq,
      installedAppsImportSeq: appsSeq,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
    });
    const match = await request(app).get("/cases/c1/mobile-backup-generations?device=f2ln12abcdef");
    expect(match.body.generations).toHaveLength(1);
    const noMatch = await request(app).get("/cases/c1/mobile-backup-generations?device=nope");
    expect(noMatch.body.generations).toHaveLength(0);
  });

  it("revokes a generation", async () => {
    const backupSeq = await seedImport("c1", "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    const appsSeq = await seedImport("c1", "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    const created = await request(app).post("/cases/c1/mobile-backup-generations").send({
      backupInfoImportSeq: backupSeq,
      installedAppsImportSeq: appsSeq,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
    });
    const generationId = created.body.generation.generationId as string;
    const res = await request(app).delete(`/cases/c1/mobile-backup-generations/${generationId}`);
    expect(res.status).toBe(200);
    expect(res.body.generations[0].revokedAt).toBeTruthy();
  });

  it("verifies both artifacts ok", async () => {
    const backupSeq = await seedImport("c1", "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    const appsSeq = await seedImport("c1", "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    const created = await request(app).post("/cases/c1/mobile-backup-generations").send({
      backupInfoImportSeq: backupSeq,
      installedAppsImportSeq: appsSeq,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
    });
    const generationId = created.body.generation.generationId as string;
    const ok = await request(app).get(`/cases/c1/mobile-backup-generations/${generationId}/verify`);
    expect(ok.body).toEqual({ backupInfo: { ok: true }, installedApps: { ok: true } });
  });

  it("compares generations across an adjacent pair", async () => {
    const backupSeq1 = await seedImport("c1", "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    const appsSeq1 = await seedImport("c1", "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    await request(app).post("/cases/c1/mobile-backup-generations").send({
      backupInfoImportSeq: backupSeq1,
      installedAppsImportSeq: appsSeq1,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
    });

    const backupInfo2 = BACKUP_INFO_TSV.replace("2026-01-12 09:00:00", "2026-01-13 09:00:00");
    const backupSeq2 = await seedImport("c1", "0003_backupinfo2.tsv", backupInfo2);
    const appsSeq2 = await seedImport(
      "c1",
      "0004_installedapps2.tsv",
      [INSTALLED_APPS_HEADER, appRow("com.example.app", "Example", "2.0")].join("\n"),
    );
    await request(app).post("/cases/c1/mobile-backup-generations").send({
      backupInfoImportSeq: backupSeq2,
      installedAppsImportSeq: appsSeq2,
      domain: "mobile-app-presence",
      completenessState: "complete",
      attestedSameBackup: true,
    });

    const res = await request(app).get("/cases/c1/mobile-backup-generations/compare");
    expect(res.status).toBe(200);
    expect(res.body.cohorts).toHaveLength(1);
    expect(res.body.cohorts[0].pairs).toHaveLength(1);
    expect(res.body.cohorts[0].pairs[0].changes[0].direction).toBe("changed");
    expect(res.body.truncatedCohorts).toBe(false);
  });

  it("candidate-imports classifies backup-info and installed-apps imports with a preview", async () => {
    const backupSeq = await seedImport("c1", "0001_backupinfo.tsv", BACKUP_INFO_TSV);
    const appsSeq = await seedImport("c1", "0002_installedapps.tsv", INSTALLED_APPS_TSV);
    const res = await request(app).get("/cases/c1/mobile-backup-generations/candidate-imports");
    expect(res.status).toBe(200);
    const byPreview = Object.fromEntries(
      (res.body.candidates as { importSeq: number; looksLike: string | null }[]).map((c) => [
        c.importSeq,
        c.looksLike,
      ]),
    );
    expect(byPreview[backupSeq]).toBe("backup-info");
    expect(byPreview[appsSeq]).toBe("installed-apps");
  });

  it("candidate-imports marks an unrecognized import as looksLike null, never a 500", async () => {
    await seedImport("c1", "0001_other.tsv", "Hostname\tTechnique\nWS-01\tRun Key");
    const res = await request(app).get("/cases/c1/mobile-backup-generations/candidate-imports");
    expect(res.status).toBe(200);
    expect(res.body.candidates[0].looksLike).toBeNull();
  });

  // #1138 code-review fix: a file past the size bound is never read/parsed at all.
  it("candidate-imports never fully reads/parses a file past the size bound", async () => {
    const huge = "Property\tProperty Value\n" + "Serial Number\tX\n".repeat(400_000); // > 5MB
    await seedImport("c1", "0001_huge.tsv", huge);
    const res = await request(app).get("/cases/c1/mobile-backup-generations/candidate-imports");
    expect(res.status).toBe(200);
    expect(res.body.candidates[0].looksLike).toBeNull();
    expect(res.body.candidates[0].preview).toBeNull();
  });

  it("candidate-imports returns an empty list for a fresh case, never a 500", async () => {
    const res = await request(app).get("/cases/c1/mobile-backup-generations/candidate-imports");
    expect(res.status).toBe(200);
    expect(res.body.candidates).toEqual([]);
  });
});
