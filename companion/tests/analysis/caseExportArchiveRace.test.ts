import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm, copyFile, rename } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { exportEncryptedCase } from "../../src/analysis/caseExportArchive.js";
import { readZip } from "../../src/analysis/zipArchive.js";
import { decryptBuffer } from "../../src/analysis/caseEncryption.js";
import { StateStore, INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";

// #2244: the nightly e2e exported the seeded demo case while the dashboard load was still migrating
// its legacy investigation.json into SQLite. The migration does not take the export's state lock,
// so the database can appear at any point of the export. Each test here fixes ONE such point.

// A hook run once the export has made its staging folder — after the walk, before the database
// snapshot — so a test can change the case in exactly that gap. The worker thread does its own I/O
// and is not affected by this mock.
const hooks = vi.hoisted(() => ({ afterStaging: null as null | (() => Promise<unknown>) }));
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    mkdtemp: (async (...args: Parameters<typeof actual.mkdtemp>) => {
      const out = await actual.mkdtemp(...args);
      const hook = hooks.afterStaging;
      hooks.afterStaging = null;
      if (hook) await hook();
      return out;
    }) as typeof actual.mkdtemp,
  };
});

afterEach(() => {
  hooks.afterStaging = null;
  vi.restoreAllMocks();
});

const PASSWORD = "correct horse battery staple";
const DB_REL = `state/${INVESTIGATION_DB_FILENAME}`;

const event = (id: string) => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: `event ${id}`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

/** A case the way seed-demo leaves it: legacy investigation.json, no database yet. */
async function legacyCase(caseId: string): Promise<CaseStore> {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-cear-")));
  await store.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  await mkdir(store.stateDir(caseId), { recursive: true });
  await writeFile(
    join(store.stateDir(caseId), "investigation.json"),
    JSON.stringify({
      caseId,
      findings: [{ id: "f1" }],
      iocs: [{ id: "i1" }],
      forensicTimeline: [event("e1"), event("e2")],
    }),
    "utf8",
  );
  return store;
}

/** The dashboard load that migrates the legacy file into SQLite. */
const migrate = (store: CaseStore, caseId: string) => new StateStore(store).load(caseId);

/** Run `fn` once, between the export's walk and its database snapshot. */
function betweenWalkAndSnapshot(fn: () => Promise<unknown>): void {
  hooks.afterStaging = fn;
}

async function archiveOf(
  archive: Buffer,
): Promise<{ paths: string[]; manifest: { counts: Record<string, number> } }> {
  const entries = readZip(await decryptBuffer(archive, PASSWORD));
  const manifest = entries.find((e) => e.path === "archive-manifest.json");
  return {
    paths: entries.map((e) => e.path),
    manifest: JSON.parse((manifest?.data ?? Buffer.from("{}")).toString("utf8")),
  };
}

describe("exportEncryptedCase — the database changes state during the export (#2244)", () => {
  it("retries when the database is created while it is being snapshotted (the nightly failure)", async () => {
    const store = await legacyCase("RACE-1");
    const request = caseSqliteWorker.request.bind(caseSqliteWorker);
    let migrated = false;
    vi.spyOn(caseSqliteWorker, "request").mockImplementation(async (msg) => {
      // The migration was queued on the writer ahead of the snapshot, so it lands first.
      if ((msg as { op: string }).op === "backupDatabase" && !migrated) {
        migrated = true;
        await migrate(store, "RACE-1");
      }
      return request(msg as never);
    });

    const { paths, manifest } = await archiveOf(await exportEncryptedCase(store, "RACE-1", PASSWORD));
    expect(paths).toContain(DB_REL);
    expect(manifest.counts).toMatchObject({ forensicEvents: 2, findings: 1, iocs: 1 });
  });

  it("archives the database when it is created between the walk and the snapshot", async () => {
    const store = await legacyCase("RACE-2");
    betweenWalkAndSnapshot(() => migrate(store, "RACE-2"));

    const { paths, manifest } = await archiveOf(await exportEncryptedCase(store, "RACE-2", PASSWORD));
    // The snapshot alone is not enough: the manifest counts it, so the archive must carry it.
    expect(paths).toContain(DB_REL);
    expect(manifest.counts).toMatchObject({ forensicEvents: 2, findings: 1, iocs: 1 });
  });

  it("exports without the database when it disappears between the walk and the snapshot", async () => {
    const store = await legacyCase("RACE-3");
    await migrate(store, "RACE-3");
    betweenWalkAndSnapshot(() => rm(join(store.stateDir("RACE-3"), INVESTIGATION_DB_FILENAME)));

    const { paths, manifest } = await archiveOf(await exportEncryptedCase(store, "RACE-3", PASSWORD));
    expect(paths).not.toContain(DB_REL);
    expect(paths).toContain("state/investigation.json");
    expect(manifest.counts).toMatchObject({ forensicEvents: 2, findings: 1, iocs: 1 });
  });

  it("never counts a live database that is not in the archive", async () => {
    const store = await legacyCase("RACE-4");
    const request = caseSqliteWorker.request.bind(caseSqliteWorker);
    const liveDb = join(store.stateDir("RACE-4"), INVESTIGATION_DB_FILENAME);
    // A live database that moved on after the snapshot found none.
    vi.spyOn(caseSqliteWorker, "request").mockImplementation(async (msg) => {
      const m = msg as { op: string; dbPath?: string };
      if (m.op === "entityCounts" && m.dbPath === liveDb)
        return { forensicTimeline: 99, findings: 99, iocs: 99 };
      return request(msg as never);
    });

    const { paths, manifest } = await archiveOf(await exportEncryptedCase(store, "RACE-4", PASSWORD));
    expect(paths).not.toContain(DB_REL);
    expect(manifest.counts).toMatchObject({ forensicEvents: 2, findings: 1, iocs: 1 });
  });

  // Windows refuses to rename over a file another handle holds open (EPERM), and the export holds
  // the database open across the snapshot — so this swap cannot happen there at all.
  it.skipIf(process.platform === "win32")(
    "still refuses when the database is replaced on every attempt",
    async () => {
      const store = await legacyCase("RACE-5");
      await migrate(store, "RACE-5");
      const liveDb = join(store.stateDir("RACE-5"), INVESTIGATION_DB_FILENAME);
      const request = caseSqliteWorker.request.bind(caseSqliteWorker);
      let backups = 0;
      vi.spyOn(caseSqliteWorker, "request").mockImplementation(async (msg) => {
        if ((msg as { op: string }).op === "backupDatabase") {
          backups++;
          // A new inode under the same name, every time.
          await copyFile(liveDb, `${liveDb}.swap`);
          await rename(`${liveDb}.swap`, liveDb);
        }
        return request(msg as never);
      });

      await expect(exportEncryptedCase(store, "RACE-5", PASSWORD)).rejects.toThrow(
        /changed file detected in case directory at "state\/investigation\.sqlite"/,
      );
      expect(backups).toBe(3);
    },
  );
});
