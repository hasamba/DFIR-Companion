import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { exportEncryptedCase, importEncryptedCase } from "../../src/analysis/caseExportArchive.js";
import { createZip, readZip, type ZipEntry } from "../../src/analysis/zipArchive.js";
import { encryptBuffer, decryptBuffer } from "../../src/analysis/caseEncryption.js";

const PASSWORD = "correct horse battery staple";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-prov-"));
  return new CaseStore(root);
}

async function seedCase(store: CaseStore, caseId: string) {
  await store.createCase({ caseId, name: "Case One", investigator: "alice", aiProvider: "anthropic" });
  await store.saveScreenshot(caseId, "shot-001.webp", Buffer.from([0x52, 0x49, 0x46, 0x46, 1, 2, 3]));
  await mkdir(store.stateDir(caseId), { recursive: true });
  await writeFile(
    join(store.stateDir(caseId), "investigation.json"),
    JSON.stringify({ caseId, findings: [], iocs: [], forensicTimeline: [] }),
    "utf8",
  );
}

/**
 * Open a real archive, let the caller rewrite its entries, and seal it again under the same
 * password. Every tampering test goes through here rather than hand-building a ZIP: the point is an
 * archive that is otherwise completely valid — right container version, right structure, right
 * password — and disagrees with its manifest in exactly one way.
 */
async function reseal(archive: Buffer, mutate: (entries: ZipEntry[]) => ZipEntry[]): Promise<Buffer> {
  const entries = readZip(await decryptBuffer(archive, PASSWORD));
  return await encryptBuffer(createZip(mutate(entries)), PASSWORD);
}

const MANIFEST = "archive-manifest.json";

describe("importEncryptedCase — archive manifest verification", () => {
  it("refuses an archive whose entry bytes disagree with the manifest checksum", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    const tampered = await reseal(archive, (entries) =>
      entries.map((e) =>
        e.path === "screenshots/shot-001.webp" ? { path: e.path, data: Buffer.from("swapped") } : e,
      ),
    );

    await expect(importEncryptedCase(store, tampered, PASSWORD, { targetCaseId: "INC-2" })).rejects.toThrow(
      /manifest checksum mismatch.*screenshots\/shot-001\.webp/,
    );
    expect(await store.caseExists("INC-2")).toBe(false);
  });

  it("refuses an archive missing a file its manifest lists", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    const tampered = await reseal(archive, (entries) =>
      entries.filter((e) => e.path !== "screenshots/shot-001.webp"),
    );

    await expect(importEncryptedCase(store, tampered, PASSWORD, { targetCaseId: "INC-2" })).rejects.toThrow(
      /manifest lists a file the archive does not contain.*screenshots\/shot-001\.webp/,
    );
    expect(await store.caseExists("INC-2")).toBe(false);
  });

  it("refuses an archive carrying a file its manifest does not list", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    const tampered = await reseal(archive, (entries) => [
      ...entries,
      { path: "screenshots/extra.webp", data: Buffer.from("smuggled") },
    ]);

    await expect(importEncryptedCase(store, tampered, PASSWORD, { targetCaseId: "INC-2" })).rejects.toThrow(
      /archive contains a file the manifest does not list.*screenshots\/extra\.webp/,
    );
    expect(await store.caseExists("INC-2")).toBe(false);
  });

  // A manifest that lists one path many times used to cost one SHA-256 of that entry PER ROW.
  // The rows are cheap to write and the entry they point at can be large, so a correctly encrypted
  // archive from any authenticated caller could buy an unbounded run of hashing on the event loop —
  // the exact resource the import route's rate limiting exists to protect. The export never writes
  // a duplicate row, so refusing one costs nothing real.
  it("refuses a manifest that lists the same path twice", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    const tampered = await reseal(archive, (entries) =>
      entries.map((e) => {
        if (e.path !== MANIFEST) return e;
        const manifest = JSON.parse(e.data.toString("utf8"));
        manifest.files = [...manifest.files, manifest.files[0]];
        return { path: e.path, data: Buffer.from(JSON.stringify(manifest), "utf8") };
      }),
    );

    await expect(importEncryptedCase(store, tampered, PASSWORD, { targetCaseId: "INC-2" })).rejects.toThrow(
      /manifest lists .* twice/,
    );
    expect(await store.caseExists("INC-2")).toBe(false);
  });

  it("imports an archive that carries no manifest at all", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    const older = await reseal(archive, (entries) => entries.filter((e) => e.path !== MANIFEST));

    const { meta, provenance } = await importEncryptedCase(store, older, PASSWORD, {
      targetCaseId: "INC-2",
    });
    expect(meta.caseId).toBe("INC-2");
    expect(provenance).toBeNull();
  });

  it("imports an archive whose manifest does not parse", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    const garbled = await reseal(archive, (entries) =>
      entries.map((e) => (e.path === MANIFEST ? { path: e.path, data: Buffer.from("{ not json") } : e)),
    );

    const { meta, provenance } = await importEncryptedCase(store, garbled, PASSWORD, {
      targetCaseId: "INC-2",
    });
    expect(meta.caseId).toBe("INC-2");
    expect(provenance).toBeNull();
  });

  it("imports an untampered archive unchanged", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);

    const { meta } = await importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-2" });
    expect(meta.caseId).toBe("INC-2");
    const original = await readFile(join(store.screenshotsDir("INC-1"), "shot-001.webp"));
    const restored = await readFile(join(store.screenshotsDir("INC-2"), "shot-001.webp"));
    expect(restored.equals(original)).toBe(true);
  });
});

describe("importEncryptedCase — provenance", () => {
  it("returns the source case id, export time and exporting version", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);

    const { provenance } = await importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-2" });
    expect(provenance).not.toBeNull();
    expect(provenance!.sourceCaseId).toBe("INC-1");
    expect(provenance!.exportedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(provenance!.generatedBy).toBeTruthy();
    expect(provenance!.totalFiles).toBeGreaterThan(0);
    expect(provenance!.totalBytes).toBeGreaterThan(0);
  });

  it("keeps the source manifest with the imported case", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    await importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-2" });

    const kept = JSON.parse(await readFile(join(store.metadataDir("INC-2"), "source-manifest.json"), "utf8"));
    expect(kept.caseId).toBe("INC-1");
    expect(Array.isArray(kept.files)).toBe(true);
  });

  it("keeps the manifest of the archive just imported, not one carried inside it", async () => {
    // A case that was itself imported carries the previous source-manifest.json as an ordinary
    // file. Re-exporting and re-importing it must leave the NEWEST provenance on disk, not the one
    // that travelled inside the package.
    const store = await harness();
    await seedCase(store, "INC-1");
    await importEncryptedCase(store, await exportEncryptedCase(store, "INC-1", PASSWORD), PASSWORD, {
      targetCaseId: "INC-2",
    });
    await importEncryptedCase(store, await exportEncryptedCase(store, "INC-2", PASSWORD), PASSWORD, {
      targetCaseId: "INC-3",
    });

    const kept = JSON.parse(await readFile(join(store.metadataDir("INC-3"), "source-manifest.json"), "utf8"));
    expect(kept.caseId).toBe("INC-2");
  });

  it("writes no source manifest when the archive carries none", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    const older = await reseal(archive, (entries) => entries.filter((e) => e.path !== MANIFEST));
    await importEncryptedCase(store, older, PASSWORD, { targetCaseId: "INC-2" });

    await expect(
      readFile(join(store.metadataDir("INC-2"), "source-manifest.json"), "utf8"),
    ).rejects.toThrow();
  });
});
