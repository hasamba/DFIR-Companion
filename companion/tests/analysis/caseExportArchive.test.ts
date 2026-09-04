import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, readdir, writeFile, mkdir, symlink, link } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  exportEncryptedCase,
  importEncryptedCase,
  CaseImportConflictError,
  dfircaseFilename,
  attachmentContentDisposition,
} from "../../src/analysis/caseExportArchive.js";
import { createZip, readZip } from "../../src/analysis/zipArchive.js";
import { encryptBuffer, decryptBuffer, DecryptionError } from "../../src/analysis/caseEncryption.js";
import { atomicWrite } from "../../src/storage/atomicWrite.js";
import { createHash, scryptSync, createCipheriv, randomBytes } from "node:crypto";
import { StateStore, INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";

const PASSWORD = "correct horse battery staple";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-cea-"));
  return new CaseStore(root);
}

async function seedCase(store: CaseStore, caseId: string, name = "Case One") {
  await store.createCase({ caseId, name, investigator: "alice", aiProvider: "anthropic" });
  await store.saveScreenshot(caseId, "shot-001.webp", Buffer.from([0x52, 0x49, 0x46, 0x46, 1, 2, 3]));
  await store.appendCapture(caseId, {
    caseId,
    sequenceNumber: 1,
    timestamp: "2026-01-01T00:00:00Z",
    url: "https://example.com",
    tabTitle: "t",
    triggerType: "navigation",
    contentHash: "abc",
    isDuplicate: false,
    screenshotFile: "shot-001.webp",
  });
  await store.saveImport(caseId, "thor-001.json", JSON.stringify({ hits: [] }));
  await store.appendImport(caseId, {
    caseId,
    sequenceNumber: 1,
    importedAt: "2026-01-01T00:00:00Z",
    filename: "thor-001.json",
    originalName: "thor.json",
    rows: 0,
    bytes: 12,
  });
  await mkdir(store.stateDir(caseId), { recursive: true });
  await writeFile(
    join(store.stateDir(caseId), "investigation.json"),
    JSON.stringify({
      caseId,
      findings: [{ id: "f1" }],
      iocs: [{ id: "i1" }],
      forensicTimeline: [{ id: "e1" }, { id: "e2" }],
    }),
    "utf8",
  );
}

describe("exportEncryptedCase", () => {
  it("throws for a case that does not exist", async () => {
    const store = await harness();
    await expect(exportEncryptedCase(store, "ghost", PASSWORD)).rejects.toThrow(/does not exist/);
  });

  it("produces a non-empty encrypted buffer for an existing case", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    expect(archive.length).toBeGreaterThan(0);
  });

  it("rejects an invalid case id instead of reading outside the cases root", async () => {
    const store = await harness();
    await expect(exportEncryptedCase(store, "../../etc", PASSWORD)).rejects.toThrow(/invalid case id/);
  });
});

// The archive must be ONE generation of the case. It used to be a walk of a live directory: the
// database was copied as ordinary bytes (so a concurrent transaction could make the copy unusable)
// and the manifest's entity counts were queried from the LIVE database after those bytes had
// already been captured — describing a case that had since moved on.
describe("exportEncryptedCase — single-generation snapshot (#3)", () => {
  async function entriesOf(archive: Buffer): Promise<Map<string, Buffer>> {
    return new Map(readZip(await decryptBuffer(archive, PASSWORD)).map((e) => [e.path, e.data]));
  }

  async function seedDatabase(store: CaseStore, caseId: string): Promise<void> {
    await store.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(store);
    const state = await stateStore.load(caseId);
    const event = (id: string) => ({
      id,
      timestamp: "2026-01-01T00:00:00Z",
      description: `event ${id}`,
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    });
    state.findings = [{ id: "f1" }, { id: "f2" }] as typeof state.findings;
    state.iocs = [{ id: "i1" }] as typeof state.iocs;
    state.forensicTimeline = [event("e1"), event("e2"), event("e3")] as typeof state.forensicTimeline;
    await stateStore.save(state);
  }

  it("archives a consistent database snapshot that opens on its own", async () => {
    const store = await harness();
    await seedDatabase(store, "SNAP-1");

    const files = await entriesOf(await exportEncryptedCase(store, "SNAP-1", PASSWORD));
    const archived = files.get(`state/${INVESTIGATION_DB_FILENAME}`);
    expect(archived).toBeDefined();

    // A snapshot is a standalone database: written out on its own it must open and read back the
    // same entities. Copied live bytes are what could fail this.
    const loose = join(await mkdtemp(join(tmpdir(), "dfir-snapcheck-")), INVESTIGATION_DB_FILENAME);
    await writeFile(loose, archived as Buffer);
    const counts = await caseSqliteWorker.request<Record<string, number> | null>({
      op: "entityCounts",
      dbPath: loose,
      kinds: ["forensicTimeline", "findings", "iocs"],
    });
    expect(counts).toMatchObject({ forensicTimeline: 3, findings: 2, iocs: 1 });
  });

  it("counts the manifest from the database it archived, not the live one", async () => {
    const store = await harness();
    await seedDatabase(store, "SNAP-2");

    const files = await entriesOf(await exportEncryptedCase(store, "SNAP-2", PASSWORD));
    const manifest = JSON.parse((files.get("archive-manifest.json") as Buffer).toString("utf8"));

    expect(manifest.counts).toMatchObject({ forensicEvents: 3, findings: 2, iocs: 1 });

    // The manifest's checksum for the database must be the checksum of the bytes in the archive —
    // the property a recipient actually verifies.
    const archived = files.get(`state/${INVESTIGATION_DB_FILENAME}`) as Buffer;
    const listed = manifest.files.find(
      (f: { path: string }) => f.path === `state/${INVESTIGATION_DB_FILENAME}`,
    );
    expect(listed.sha256).toBe(createHash("sha256").update(archived).digest("hex"));
    expect(listed.bytes).toBe(archived.length);
  });

  it("runs inside the caller's per-case lock, so app state writes cannot interleave", async () => {
    const store = await harness();
    await seedDatabase(store, "SNAP-3");
    const order: string[] = [];
    const lock = new StateLock();

    const exported = exportEncryptedCase(store, "SNAP-3", PASSWORD, [], {
      runExclusive: (caseId, fn) =>
        lock.runExclusive(caseId, async () => {
          order.push("export:start");
          const out = await fn();
          order.push("export:end");
          return out;
        }),
    });
    const write = lock.runExclusive("SNAP-3", async () => {
      order.push("write");
    });
    await Promise.all([exported, write]);

    // The write waited for the whole export rather than landing in the middle of it.
    expect(order).toEqual(["export:start", "export:end", "write"]);
  });

  it("leaves no staging directory behind, on success or on failure", async () => {
    const store = await harness();
    await seedDatabase(store, "SNAP-4");
    const stagingRoot = join(store.casesRoot, ".export-staging");

    await exportEncryptedCase(store, "SNAP-4", PASSWORD);
    expect(existsSync(stagingRoot) ? await readdir(stagingRoot) : []).toEqual([]);

    // A symlink planted in the case makes the export throw mid-build; the snapshot must still go.
    await symlink("/etc/hostname", join(store.screenshotsDir("SNAP-4"), "loot"));
    await expect(exportEncryptedCase(store, "SNAP-4", PASSWORD)).rejects.toThrow(/symlink/);
    expect(existsSync(stagingRoot) ? await readdir(stagingRoot) : []).toEqual([]);
  });
});

describe("exportEncryptedCase — symlink/hardlink rejection (#247)", () => {
  // #247's own threat model: a symlink screenshots/loot -> /etc/shadow bundled into the export
  // exfiltrates host files to whoever imports the archive. A hardlink achieves the identical
  // outcome and is indistinguishable from a normal file via readdir's Dirent — only lstat's
  // nlink count reveals it. These drive the REAL exportEncryptedCase end to end (not the private
  // walkDir helper in isolation), planting a real symlink/hardlink on disk.

  it("refuses to export a case containing a symlink to a file outside the case directory", async () => {
    const store = await harness();
    await seedCase(store, "INC-SYM");
    const secretFile = join(await mkdtemp(join(tmpdir(), "dfir-cea-secret-")), "shadow.txt");
    await writeFile(secretFile, "TOPSECRET-HOST-FILE-CONTENTS", "utf8");
    await symlink(secretFile, join(store.caseDir("INC-SYM"), "screenshots", "loot"));

    await expect(exportEncryptedCase(store, "INC-SYM", PASSWORD)).rejects.toThrow(/symlink/i);
  });

  it("refuses to export a case containing a hardlink to a file outside the case directory", async () => {
    const store = await harness();
    await seedCase(store, "INC-HARD");
    const secretFile = join(await mkdtemp(join(tmpdir(), "dfir-cea-secret-")), "shadow.txt");
    await writeFile(secretFile, "TOPSECRET-HOST-FILE-CONTENTS", "utf8");
    await link(secretFile, join(store.caseDir("INC-HARD"), "screenshots", "loot"));

    await expect(exportEncryptedCase(store, "INC-HARD", PASSWORD)).rejects.toThrow(/hardlink/i);
  });

  it("still exports a normal case with no symlinks/hardlinks (no regression)", async () => {
    const store = await harness();
    await seedCase(store, "INC-CLEAN");
    const archive = await exportEncryptedCase(store, "INC-CLEAN", PASSWORD);
    expect(archive.length).toBeGreaterThan(0);
  });
});

// POSIX-only: every test in here has to CREATE a file whose name Windows cannot hold, which is
// the whole point of the fix. On windows-latest — where ci.yml's companion-windows job runs this
// suite as a gate — writeFile would refuse the name, or silently create a different one, and the
// export assertions below would describe a case that was never seeded. The rules themselves are
// covered platform-independently by the portableZipSegment tests in zipArchive.test.ts, which are
// pure string functions and run everywhere.
describe.skipIf(process.platform === "win32")("exportEncryptedCase — portable entry paths (#675)", () => {
  // Every name below is a legal file on Linux and an impossible one on Windows, so a case
  // directory can hold it — the drop folder keeps a dropped file's original name forever, under
  // drop/_processed/. Each is also a name importEncryptedCase's own isSafeZipEntryPath rejects,
  // which is what made this more than a Windows-extraction annoyance: the export reported success
  // and produced an archive DFIR Companion could not restore, on any platform.
  const HOSTILE_NAMES = [
    "evidence:2026.evtx", // colon — an NTFS alternate data stream on extraction
    "back\\slash.bin", // backslash — a path separator on Windows
    "trailing.", // Windows strips a trailing dot
    "NUL.txt", // a reserved device name, which resolves to no file at all
    "con",
    "pipe|star*.bin",
    'quote".bin',
    "less<greater>.bin",
    "question?.bin",
    "\x01ctrl.bin", // a control character, which is not a filename anywhere
  ];

  async function seedHostileNames(store: CaseStore, caseId: string, names: string[]) {
    const dir = join(store.caseDir(caseId), "drop", "_processed");
    await mkdir(dir, { recursive: true });
    for (const name of names) await writeFile(join(dir, name), `body of ${name}`, "utf8");
  }

  // The contract this fix rests on: whatever the export packs, the import accepts. Driven end to
  // end rather than asserted against the sanitizer in isolation, so tightening isSafeZipEntryPath
  // without teaching portableZipEntryPath the new rule fails HERE.
  it("re-imports a case whose files carry names Windows cannot hold", async () => {
    const store = await harness();
    await seedCase(store, "INC-PORT");
    await seedHostileNames(store, "INC-PORT", HOSTILE_NAMES);

    const archive = await exportEncryptedCase(store, "INC-PORT", PASSWORD);
    const result = await importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-PORT2" });

    expect(result.meta.caseId).toBe("INC-PORT2");
    const restored = await readdir(join(store.caseDir("INC-PORT2"), "drop", "_processed"));
    expect(restored).toHaveLength(HOSTILE_NAMES.length);
    for (const name of restored) expect(name).toMatch(/^[^<>:"/\\|?*\x00-\x1f]+$/);
  });

  it("records the original path of every renamed entry in the manifest, and no others", async () => {
    const store = await harness();
    await seedCase(store, "INC-PORTM");
    await seedHostileNames(store, "INC-PORTM", ["evidence:2026.evtx"]);

    const archive = await exportEncryptedCase(store, "INC-PORTM", PASSWORD);
    const files = new Map(readZip(await decryptBuffer(archive, PASSWORD)).map((e) => [e.path, e.data]));
    const manifest = JSON.parse((files.get("archive-manifest.json") as Buffer).toString("utf8"));

    const renamed = manifest.files.filter((f: { originalPath?: string }) => f.originalPath);
    expect(renamed).toEqual([
      expect.objectContaining({
        path: "drop/_processed/evidence_2026.evtx",
        originalPath: "drop/_processed/evidence:2026.evtx",
      }),
    ]);
    // The rename is recorded, and the bytes are still the file's own — the entry is renamed, not
    // replaced. Every untouched entry stays free of the field, so its presence means what it says.
    expect(files.get("drop/_processed/evidence_2026.evtx")?.toString("utf8")).toBe(
      "body of evidence:2026.evtx",
    );
    expect(manifest.files.length).toBeGreaterThan(1);
  });

  it("refuses to export when two files would take the same name in the archive", async () => {
    const store = await harness();
    await seedCase(store, "INC-PORTC");
    // Two files the case holds separately, one name once the colon is substituted. Overwriting the
    // first with the second is silent evidence loss, so the export names both files and stops.
    await seedHostileNames(store, "INC-PORTC", ["a:b.bin", "a_b.bin"]);

    await expect(exportEncryptedCase(store, "INC-PORTC", PASSWORD)).rejects.toThrow(
      /would both be named "drop\/_processed\/a_b\.bin"/,
    );
  });

  // The import creates an entry's parent folders with mkdir and then writes the file, so one name
  // wanted as a file by one entry and as a folder by another is as fatal as two files sharing a
  // name — whichever lands first, the second fails with EEXIST, EISDIR or ENOTDIR. Sanitizing
  // creates exactly that shape: the file "x_y" and the folder "x:y" coexist on disk and become one
  // name afterwards. readdir decides which of the two the walk reaches first, so the match below
  // accepts either direction's message — the export has to refuse whichever order it is handed,
  // which is why the check looks for a blocking file AND a blocking folder.
  it("refuses to export when a renamed folder would take a file's name", async () => {
    const store = await harness();
    await seedCase(store, "INC-PORTD");
    const dir = join(store.caseDir("INC-PORTD"), "drop", "_processed");
    await mkdir(join(dir, "x:y"), { recursive: true });
    await writeFile(join(dir, "x_y"), "the file", "utf8");
    await writeFile(join(dir, "x:y", "child.bin"), "inside the folder", "utf8");

    await expect(exportEncryptedCase(store, "INC-PORTD", PASSWORD)).rejects.toThrow(
      /"drop\/_processed\/x_y" to be a folder|needs that same name to be a folder/,
    );
  });

  it("refuses a file and a folder that differ only in case, which Windows cannot restore", async () => {
    const store = await harness();
    await seedCase(store, "INC-PORTE");
    const dir = join(store.caseDir("INC-PORTE"), "drop", "_processed");
    await mkdir(join(dir, "data"), { recursive: true });
    await writeFile(join(dir, "Data"), "the file", "utf8");
    await writeFile(join(dir, "data", "child.bin"), "inside the folder", "utf8");

    await expect(exportEncryptedCase(store, "INC-PORTE", PASSWORD)).rejects.toThrow(/folder|both be named/);
  });
});

// Runs on every platform, Windows included: it seeds no hostile name, and what it guards is that
// the sanitizer stays OFF for a case that needs none of it.
describe("exportEncryptedCase — portable entry paths, ordinary case (#675)", () => {
  it("leaves an ordinary case byte-identical — nothing is renamed that need not be", async () => {
    const store = await harness();
    await seedCase(store, "INC-PORTN");
    const archive = await exportEncryptedCase(store, "INC-PORTN", PASSWORD);
    const manifest = JSON.parse(
      readZip(await decryptBuffer(archive, PASSWORD))
        .find((e) => e.path === "archive-manifest.json")!
        .data.toString("utf8"),
    );
    expect(manifest.files.every((f: { originalPath?: string }) => f.originalPath === undefined)).toBe(true);
  });
});

// Re-wrap a decrypted archive in the v1 container the 0.31.0–0.33.0 writer produced. Nothing in
// production writes v1 any more (#268), so a test that needs one has to build it, and the scrypt
// parameters are spelled out here on purpose: they are an INDEPENDENT statement of what v1 is, so
// this breaks loudly if v1's parameters are ever changed in the module (which would make every
// archive already in an analyst's evidence store unopenable — see caseEncryption.ts).
function encryptAsV1(plain: Buffer, password: string): Buffer {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(password, salt, 32, { N: 1 << 14, r: 8, p: 1, maxmem: 32 * 1024 * 1024 });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([Buffer.from("DFIRCZ01", "utf8"), salt, iv, cipher.getAuthTag(), ciphertext]);
}

describe("importEncryptedCase", () => {
  it("imports under a target id, preserving evidence bytes exactly", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);

    const { meta, counts } = await importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-2" });
    expect(meta.caseId).toBe("INC-2");
    expect(counts).toEqual({ forensicEvents: 2, findings: 1, iocs: 1, captures: 1, imports: 1 });

    // screenshot bytes travelled unchanged
    const original = await readFile(join(store.screenshotsDir("INC-1"), "shot-001.webp"));
    const restored = await readFile(join(store.screenshotsDir("INC-2"), "shot-001.webp"));
    expect(restored.equals(original)).toBe(true);

    // raw import file travelled unchanged
    const originalImport = await readFile(join(store.importsDir("INC-1"), "thor-001.json"));
    const restoredImport = await readFile(join(store.importsDir("INC-2"), "thor-001.json"));
    expect(restoredImport.equals(originalImport)).toBe(true);

    // caseId-bearing files were rewritten to the new id
    const invRestored = JSON.parse(
      await readFile(join(store.stateDir("INC-2"), "investigation.json"), "utf8"),
    );
    expect(invRestored.caseId).toBe("INC-2");
    const capturesRestored = (await readFile(store.capturesLogPath("INC-2"), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    expect(capturesRestored[0].caseId).toBe("INC-2");
    const importsRestored = (await readFile(store.importsLogPath("INC-2"), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    expect(importsRestored[0].caseId).toBe("INC-2");
  });

  it("rewrites investigation.json compact and case.json pretty", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    await importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-2" });

    // investigation.json can be huge; re-inflating it on import would undo StateStore's
    // compact write and push a near-ceiling case back over the ~512 MB load limit.
    const inv = await readFile(join(store.stateDir("INC-2"), "investigation.json"), "utf8");
    expect(inv).not.toContain("\n");
    expect(JSON.parse(inv).caseId).toBe("INC-2");

    // case.json stays pretty — it's small and CaseStore writes it pretty, so compacting it
    // here would only flip formatting until the next save.
    const caseJson = await readFile(join(store.caseDir("INC-2"), "case.json"), "utf8");
    expect(caseJson).toContain("\n  ");
    expect(JSON.parse(caseJson).caseId).toBe("INC-2");
  });

  it("imports under the archive's own id into a fresh store when no target is given", async () => {
    const store1 = await harness();
    await seedCase(store1, "INC-1");
    const archive = await exportEncryptedCase(store1, "INC-1", PASSWORD);

    const store2 = await harness(); // a separate cases root where INC-1 is free
    const { meta } = await importEncryptedCase(store2, archive, PASSWORD);
    expect(meta.caseId).toBe("INC-1");
    expect(await store2.caseExists("INC-1")).toBe(true);
  });

  it("throws CaseImportConflictError when the target case already exists", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    await expect(importEncryptedCase(store, archive, PASSWORD)).rejects.toThrow(CaseImportConflictError);
  });

  // #420: caseExists() is a check, not a claim. Two imports aimed at the same id both passed it and
  // then interleaved their writes into the same destination, producing a case that existed in
  // neither archive — case.json from whichever finished last, evidence files from both. Nothing
  // downstream can detect that, so every analysis and custody record built on it is untrustworthy.
  it("cannot merge two archives into one case when imports race for the same id", async () => {
    const store = await harness();
    await seedCase(store, "SRC-A", "Case A");
    await seedCase(store, "SRC-B", "Case B");
    await store.saveImport("SRC-A", "only-in-a.json", JSON.stringify({ from: "A" }));
    await store.saveImport("SRC-B", "only-in-b.json", JSON.stringify({ from: "B" }));
    const archiveA = await exportEncryptedCase(store, "SRC-A", PASSWORD);
    const archiveB = await exportEncryptedCase(store, "SRC-B", PASSWORD);

    const results = await Promise.allSettled([
      importEncryptedCase(store, archiveA, PASSWORD, { targetCaseId: "TARGET" }),
      importEncryptedCase(store, archiveB, PASSWORD, { targetCaseId: "TARGET" }),
    ]);

    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const loser = results.find((r) => r.status === "rejected");
    expect((loser as PromiseRejectedResult).reason).toBeInstanceOf(CaseImportConflictError);

    // Exactly one archive's evidence is present — never both, never a blend.
    const hasA = existsSync(join(store.importsDir("TARGET"), "only-in-a.json"));
    const hasB = existsSync(join(store.importsDir("TARGET"), "only-in-b.json"));
    expect(hasA).toBe(!hasB);
    // ...and the metadata agrees with the evidence, which is the property that actually broke.
    const meta = await store.getCaseMeta("TARGET");
    expect(meta?.name).toBe(hasA ? "Case A" : "Case B");
  });

  it("leaves no staging directory behind, on the winning or the losing path", async () => {
    const store = await harness();
    await seedCase(store, "SRC-A");
    const archive = await exportEncryptedCase(store, "SRC-A", PASSWORD);
    await importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "OK-1" });
    await expect(importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "OK-1" })).rejects.toThrow(
      CaseImportConflictError,
    );
    await expect(
      importEncryptedCase(store, Buffer.from("not an archive at all"), PASSWORD, { targetCaseId: "OK-2" }),
    ).rejects.toThrow();

    expect(await readdir(join(store.casesRoot, ".import-staging"))).toEqual([]);
  });

  it("keeps the staging directory out of the case list", async () => {
    const store = await harness();
    await seedCase(store, "SRC-A");
    const archive = await exportEncryptedCase(store, "SRC-A", PASSWORD);
    await importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "LISTED" });
    // A half-extracted archive holds a readable case.json, which is exactly what listCases treats
    // as a case — so staging lives a level down, under a dotted directory.
    expect((await store.listCases()).map((m) => m.caseId).sort()).toEqual(["LISTED", "SRC-A"]);
  });

  it("throws DecryptionError on the wrong password", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    await expect(
      importEncryptedCase(store, archive, "totally-wrong-password", { targetCaseId: "INC-2" }),
    ).rejects.toThrow(DecryptionError);
  });

  it("rejects an archive with an unsafe (path-traversal) entry and writes nothing", async () => {
    const store = await harness();
    await seedCase(store, "INC-1"); // gives us a valid case.json to reuse
    const caseJson = await readFile(store.caseMetaPath("INC-1"));
    const malicious = createZip([
      { path: "case.json", data: caseJson },
      { path: "../../evil.txt", data: Buffer.from("pwned") },
    ]);
    const archive = await encryptBuffer(malicious, PASSWORD);

    await expect(importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-EVIL" })).rejects.toThrow(
      /unsafe entry path/,
    );
    expect(await store.caseExists("INC-EVIL")).toBe(false);
  });

  it("throws on an archive missing case.json", async () => {
    const store = await harness();
    const archive = await encryptBuffer(
      createZip([{ path: "state/investigation.json", data: Buffer.from("{}") }]),
      PASSWORD,
    );
    await expect(importEncryptedCase(store, archive, PASSWORD)).rejects.toThrow(/missing case\.json/);
  });

  it("rejects an archive with an entry path containing a colon (NTFS ADS) and writes nothing", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const caseJson = await readFile(store.caseMetaPath("INC-1"));
    const malicious = createZip([
      { path: "case.json", data: caseJson },
      { path: "screenshots/shot.jpg:hidden.exe", data: Buffer.from("pwned") },
    ]);
    const archive = await encryptBuffer(malicious, PASSWORD);

    await expect(importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-ADS" })).rejects.toThrow(
      /unsafe entry path/,
    );
    expect(await store.caseExists("INC-ADS")).toBe(false);
  });

  it("cleanly rejects a corrupted state/investigation.json and leaves no orphaned case directory", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const caseJson = await readFile(store.caseMetaPath("INC-1"));
    const malicious = createZip([
      { path: "case.json", data: caseJson },
      { path: "state/investigation.json", data: Buffer.from("{ not valid json") },
    ]);
    const archive = await encryptBuffer(malicious, PASSWORD);

    await expect(
      importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-CORRUPT" }),
    ).rejects.toThrow(/corrupt state\/investigation\.json/);
    expect(await store.caseExists("INC-CORRUPT")).toBe(false);

    // a corrected re-import (retry) must succeed — no orphaned partial directory blocking it
    const fixed = createZip([
      { path: "case.json", data: caseJson },
      { path: "state/investigation.json", data: Buffer.from("{}") },
    ]);
    const fixedArchive = await encryptBuffer(fixed, PASSWORD);
    const { meta } = await importEncryptedCase(store, fixedArchive, PASSWORD, {
      targetCaseId: "INC-CORRUPT",
    });
    expect(meta.caseId).toBe("INC-CORRUPT");
  });

  it("throws a clean Error when case.json parses but has no caseId field", async () => {
    const store = await harness();
    const archive = await encryptBuffer(
      createZip([{ path: "case.json", data: Buffer.from(JSON.stringify({ name: "no id" })) }]),
      PASSWORD,
    );
    await expect(importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-NOID" })).rejects.toThrow(
      /case\.json missing caseId/,
    );
    expect(await store.caseExists("INC-NOID")).toBe(false);
  });

  // #426: the duplicate check compared raw path strings, but the write loop resolved them with the
  // host platform's rules. On Windows several distinct strings name one file, so the later entry
  // silently overwrote the earlier one — evidence loss with no error. These are checked on every
  // platform: an archive whose entries collide is malformed wherever it is opened, and an import
  // that succeeds on Linux while losing a file on Windows is the harder bug to find.
  describe("path aliases that collide on a Windows destination", () => {
    async function importAliased(paths: string[], targetCaseId: string) {
      const store = await harness();
      await seedCase(store, "INC-1");
      const caseJson = await readFile(store.caseMetaPath("INC-1"));
      const archive = await encryptBuffer(
        createZip([
          { path: "case.json", data: caseJson },
          ...paths.map((path, i) => ({ path, data: Buffer.from(`entry ${i}`) })),
        ]),
        PASSWORD,
      );
      return { store, run: () => importEncryptedCase(store, archive, PASSWORD, { targetCaseId }) };
    }

    it("rejects a backslash alias of a forward-slash path", async () => {
      const { store, run } = await importAliased(["state/a.bin", "state\\a.bin"], "INC-BS");
      await expect(run()).rejects.toThrow(/unsafe entry path/);
      expect(await store.caseExists("INC-BS")).toBe(false);
    });

    it("rejects a case-only alias", async () => {
      const { store, run } = await importAliased(
        ["imports/EVIDENCE.bin", "imports/evidence.bin"],
        "INC-CASE",
      );
      await expect(run()).rejects.toThrow(/same file as/i);
      expect(await store.caseExists("INC-CASE")).toBe(false);
    });

    it("rejects a case-only alias in a DIRECTORY segment", async () => {
      const { store, run } = await importAliased(["Imports/a.bin", "imports/a.bin"], "INC-DIR");
      await expect(run()).rejects.toThrow(/same file as/i);
      expect(await store.caseExists("INC-DIR")).toBe(false);
    });

    it("rejects a trailing-dot or trailing-space name, which Windows strips", async () => {
      for (const [i, alias] of ["imports/notes.", "imports/notes ", "imports/dir./a.bin"].entries()) {
        const { store, run } = await importAliased(["imports/notes", alias], `INC-TRIM${i}`);
        await expect(run()).rejects.toThrow(/unsafe entry path/);
        expect(await store.caseExists(`INC-TRIM${i}`)).toBe(false);
      }
    });

    it("rejects a reserved Windows device name, with or without an extension", async () => {
      for (const [i, reserved] of [
        "imports/CON",
        "imports/nul.txt",
        "LPT1/a.bin",
        "imports/com9.bin",
      ].entries()) {
        const { store, run } = await importAliased([reserved], `INC-DEV${i}`);
        await expect(run()).rejects.toThrow(/unsafe entry path/);
        expect(await store.caseExists(`INC-DEV${i}`)).toBe(false);
      }
    });

    it("still accepts the ordinary paths a real export produces", async () => {
      const { store, run } = await importAliased(
        ["imports/thor-001.json", "screenshots/shot-001.webp", "state/notes.md", "reports/report.md"],
        "INC-OK",
      );
      await expect(run()).resolves.toBeTruthy();
      expect(await store.caseExists("INC-OK")).toBe(true);
    });
  });

  it("rejects an archive with duplicate entry paths", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const caseJson = await readFile(store.caseMetaPath("INC-1"));
    const malicious = createZip([
      { path: "case.json", data: caseJson },
      { path: "state/investigation.json", data: Buffer.from("{}") },
      { path: "state/investigation.json", data: Buffer.from('{"other":true}') },
    ]);
    const archive = await encryptBuffer(malicious, PASSWORD);

    await expect(importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-DUP" })).rejects.toThrow(
      /duplicate entry path/,
    );
    expect(await store.caseExists("INC-DUP")).toBe(false);
  });

  // #672: the import result carries the container version so the caller can tell the analyst the
  // archive was written under the weaker v1 derivation. Nothing re-keys the archive — v1 stays
  // readable forever — the analyst is simply told, so they can re-export and get v2.
  it("reports the container format version of the archive it opened", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);

    const { formatVersion } = await importEncryptedCase(store, archive, PASSWORD, {
      targetCaseId: "INC-2",
    });
    expect(formatVersion).toBe(2);
  });

  it("reports version 1 for an archive written by the pre-#268 writer", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const v1Archive = encryptAsV1(
      await decryptBuffer(await exportEncryptedCase(store, "INC-1", PASSWORD), PASSWORD),
      PASSWORD,
    );

    const { meta, formatVersion } = await importEncryptedCase(store, v1Archive, PASSWORD, {
      targetCaseId: "INC-2",
    });
    expect(formatVersion).toBe(1);
    expect(meta.caseId).toBe("INC-2"); // still imports — the weaker version is read-only, not refused
  });
});

// The export walks the case directory while the rest of the app is still writing to it. Every JSON
// sidecar is saved through atomicWrite, which writes "<target>.<uuid>.tmp" and then renames it over
// the target — so readdir routinely lists a temp file that is gone microseconds later, and the
// per-file lstat came back ENOENT and aborted the whole export with a raw 500. A populated case
// made it near-deterministic (a dashboard load fires a burst of sidecar saves); an empty one almost
// never showed it, which is why it read as content-dependent rather than as the race it is.
describe("exportEncryptedCase — concurrent writes into the case directory", () => {
  it("exports while sidecar saves are in flight", async () => {
    const store = await harness();
    await store.createCase({ caseId: "INC-RACE", name: "Race", investigator: "a", aiProvider: null });
    const stateDir = store.stateDir("INC-RACE");
    await mkdir(stateDir, { recursive: true });

    let writing = true;
    const churn = (async () => {
      let n = 0;
      while (writing) {
        await Promise.all(
          ["notebook", "tags", "scope", "hypotheses", "customer"].map((name) =>
            atomicWrite(join(stateDir, `${name}.json`), JSON.stringify({ n: n++ })),
          ),
        );
      }
    })();

    try {
      // Every attempt must succeed. Before the fix each one failed about two times in three, so six
      // rounds miss a regression roughly once in a thousand runs — and six is as many as this can
      // afford: every export pays caseEncryption's deliberately slow scrypt, and a longer loop
      // starves under the full parallel suite and times out rather than failing honestly.
      for (let i = 0; i < 6; i++) {
        const archive = await exportEncryptedCase(store, "INC-RACE", PASSWORD);
        expect(archive.length).toBeGreaterThan(0);
      }
    } finally {
      writing = false;
      await churn;
    }
  });

  it("keeps atomicWrite's temp files out of the archive", async () => {
    const store = await harness();
    await store.createCase({ caseId: "INC-TMP", name: "Tmp", investigator: "a", aiProvider: null });
    const stateDir = store.stateDir("INC-TMP");
    await mkdir(stateDir, { recursive: true });
    // A temp file left behind by a write that died before its rename. It is not case content, and
    // archiving it would also make the manifest differ run to run.
    await writeFile(join(stateDir, "notebook.json.3f2504e0-4f89-41d3-9a0c-0305e82c3301.tmp"), "{}");

    const entries = readZip(
      await decryptBuffer(await exportEncryptedCase(store, "INC-TMP", PASSWORD), PASSWORD),
    );

    expect(entries.map((e) => e.path).filter((p) => p.endsWith(".tmp"))).toEqual([]);
  });

  it("still archives an analyst's own .tmp evidence", async () => {
    const store = await harness();
    await store.createCase({ caseId: "INC-EVID", name: "Evidence", investigator: "a", aiProvider: null });
    const importsDir = store.importsDir("INC-EVID");
    await mkdir(importsDir, { recursive: true });
    await writeFile(join(importsDir, "payload.tmp"), "MZ evidence bytes");

    const entries = readZip(
      await decryptBuffer(await exportEncryptedCase(store, "INC-EVID", PASSWORD), PASSWORD),
    );

    const evidence = entries.find((e) => e.path === "imports/payload.tmp");
    expect(
      evidence,
      "an imported sample named payload.tmp must not be mistaken for a write temp",
    ).toBeDefined();
    expect(evidence?.data.toString("utf8")).toBe("MZ evidence bytes");
  });
});

describe("dfircaseFilename", () => {
  it("includes the case name when it differs from the id", () => {
    expect(dfircaseFilename("INC-1", "Acme Ransomware")).toBe("INC-1 - Acme Ransomware.dfircase");
  });

  it("falls back to just the caseId when there is no name", () => {
    expect(dfircaseFilename("INC-1", undefined)).toBe("INC-1.dfircase");
    expect(dfircaseFilename("INC-1", null)).toBe("INC-1.dfircase");
    expect(dfircaseFilename("INC-1", "")).toBe("INC-1.dfircase");
    expect(dfircaseFilename("INC-1", "   ")).toBe("INC-1.dfircase");
  });

  it("falls back to just the caseId when the name is identical to it", () => {
    expect(dfircaseFilename("INC-1", "INC-1")).toBe("INC-1.dfircase");
  });

  it("trims surrounding whitespace from the name", () => {
    expect(dfircaseFilename("INC-1", "  Acme Ransomware  ")).toBe("INC-1 - Acme Ransomware.dfircase");
  });

  it("sanitizes filesystem-unsafe characters in the name", () => {
    expect(dfircaseFilename("INC-1", 'Acme: "Ransomware" / Attack <2026>')).toBe(
      "INC-1 - Acme_ _Ransomware_ _ Attack _2026_.dfircase",
    );
  });

  // Non-ASCII is legal in a filename on every platform this ships to, so the name keeps its own
  // characters here — carrying them safely is attachmentContentDisposition's job, not this one's.
  it("keeps non-ASCII characters in the name", () => {
    expect(dfircaseFilename("INC-1", "GlobalTech — BEC")).toBe("INC-1 - GlobalTech — BEC.dfircase");
  });
});

describe("attachmentContentDisposition", () => {
  it("sends a plain ASCII filename as-is", () => {
    expect(attachmentContentDisposition("INC-1 - Case One.dfircase")).toBe(
      'attachment; filename="INC-1 - Case One.dfircase"',
    );
  });

  // Node throws ERR_INVALID_CHAR on any header value holding a character above U+00FF, and clients
  // misread the Latin-1 range, so a name with either has to travel percent-encoded in filename*
  // (RFC 6266/5987) with an ASCII-only filename= left behind for clients that ignore filename*.
  it("adds a percent-encoded filename* when the name is not ASCII", () => {
    const header = attachmentContentDisposition("INC-1 - GlobalTech — BEC.dfircase");
    expect(header).toBe(
      'attachment; filename="INC-1 - GlobalTech _ BEC.dfircase"; ' +
        "filename*=UTF-8''INC-1%20-%20GlobalTech%20%E2%80%94%20BEC.dfircase",
    );
  });

  it("emits only header-safe bytes for any name", () => {
    for (const name of ["ñ.dfircase", "案件.dfircase", "Ω — α.dfircase", "tab\there.dfircase"]) {
      expect(attachmentContentDisposition(name)).toMatch(/^[\x20-\x7e]*$/);
    }
  });

  // encodeURIComponent leaves ' ( ) * unescaped, but RFC 5987's attr-char set excludes them — a
  // quote in particular would end the quoted string early in a client that parses filename* loosely.
  it("percent-encodes the characters encodeURIComponent leaves behind", () => {
    expect(attachmentContentDisposition("a'b(c)d*e—.dfircase")).toContain(
      "filename*=UTF-8''a%27b%28c%29d%2Ae%E2%80%94.dfircase",
    );
  });

  // A quote or backslash surviving into filename= would let a crafted case name inject extra
  // header parameters; both are already stripped upstream, and the header builder re-checks.
  it("never lets a quote or backslash into the ASCII filename", () => {
    expect(attachmentContentDisposition('a"b\\c.dfircase')).toContain('filename="a_b_c.dfircase"');
  });
});
