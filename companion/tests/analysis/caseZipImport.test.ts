import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { archiveCase } from "../../src/analysis/caseArchive.js";
import { createZip, readZip, type ZipEntry } from "../../src/analysis/zipArchive.js";
import { CaseImportConflictError } from "../../src/analysis/caseExportArchive.js";
import { importZipArchiveCase } from "../../src/analysis/caseZipImport.js";

// #1784: the plain ZIP that "Archive to ZIP" writes must come back in through Import case.

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-zipimp-"));
  return new CaseStore(root);
}

async function seedCase(store: CaseStore, caseId: string) {
  await store.createCase({ caseId, name: "Case One", investigator: "alice", aiProvider: null });
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
}

/** Archive a seeded case the way the dashboard's "Archive to ZIP" does, and return the ZIP bytes. */
async function archivedZip(store: CaseStore, caseId = "INC-1"): Promise<Buffer> {
  await seedCase(store, caseId);
  const { archivePath } = await archiveCase(store.casesRoot, caseId, {}, "Case One", store.caseDir(caseId));
  return readFile(archivePath);
}

/** Read the archive, let `edit` change the entry list, and zip it back up. */
function rezip(zip: Buffer, edit: (entries: ZipEntry[]) => ZipEntry[]): Buffer {
  return createZip(edit(readZip(zip)));
}

function manifestOf(entries: ZipEntry[], caseId = "INC-1"): Record<string, unknown> {
  const entry = entries.find((e) => e.path === `${caseId}/archive-manifest.json`);
  return JSON.parse(entry!.data.toString("utf8")) as Record<string, unknown>;
}

function withManifest(entries: ZipEntry[], manifest: unknown, caseId = "INC-1"): ZipEntry[] {
  return entries.map((e) =>
    e.path === `${caseId}/archive-manifest.json`
      ? {
          path: e.path,
          data: Buffer.from(typeof manifest === "string" ? manifest : JSON.stringify(manifest)),
        }
      : e,
  );
}

async function importIntoFresh(zip: Buffer, targetCaseId?: string) {
  const dest = await harness();
  return { dest, result: await importZipArchiveCase(dest, zip, { targetCaseId }) };
}

describe("importZipArchiveCase — round trip", () => {
  it("restores every file byte for byte, verifies the manifest, and lists the case", async () => {
    const src = await harness();
    const zip = await archivedZip(src);
    const { dest, result } = await importIntoFresh(zip);

    expect(result.verified).toBe(true);
    expect(result.sourceCaseId).toBe("INC-1");
    expect(result.meta.caseId).toBe("INC-1");
    expect((await dest.listCases()).map((c) => c.caseId)).toContain("INC-1");

    const shot = await readFile(join(dest.caseDir("INC-1"), "screenshots", "shot-001.webp"));
    expect(shot.equals(await readFile(join(src.caseDir("INC-1"), "screenshots", "shot-001.webp")))).toBe(
      true,
    );
    const imp = await readFile(join(dest.caseDir("INC-1"), "imports", "thor-001.json"));
    expect(imp.equals(await readFile(join(src.caseDir("INC-1"), "imports", "thor-001.json")))).toBe(true);
    // The archive's own manifest is a packaging file, not case content.
    await expect(readFile(join(dest.caseDir("INC-1"), "archive-manifest.json"))).rejects.toThrow();
  });

  it("imports under a new target id and rewrites case.json", async () => {
    const zip = await archivedZip(await harness());
    const { dest, result } = await importIntoFresh(zip, "INC-2");
    expect(result.meta.caseId).toBe("INC-2");
    expect(result.sourceCaseId).toBe("INC-1");
    const caseJson = JSON.parse(await readFile(dest.caseMetaPath("INC-2"), "utf8")) as { caseId: string };
    expect(caseJson.caseId).toBe("INC-2");
  });

  it("refuses an id that already exists with a conflict error", async () => {
    const store = await harness();
    const zip = await archivedZip(store);
    await expect(importZipArchiveCase(store, zip)).rejects.toBeInstanceOf(CaseImportConflictError);
  });

  it("imports an archive with no manifest, but reports it as not verified", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) =>
      entries.filter((e) => !e.path.endsWith("/archive-manifest.json")),
    );
    const { dest, result } = await importIntoFresh(zip);
    expect(result.verified).toBe(false);
    expect(await dest.caseExists("INC-1")).toBe(true);
  });

  it("ignores pure directory entries", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) => [
      { path: "INC-1/", data: Buffer.alloc(0) },
      { path: "INC-1/screenshots/", data: Buffer.alloc(0) },
      ...entries,
    ]);
    const { result } = await importIntoFresh(zip);
    expect(result.verified).toBe(true);
  });
});

describe("importZipArchiveCase — refusals", () => {
  async function expectRejected(zip: Buffer, pattern: RegExp = /not a valid case archive/) {
    const dest = await harness();
    await expect(importZipArchiveCase(dest, zip)).rejects.toThrow(pattern);
    // Nothing published, and nothing left behind that lists as a case.
    expect(await dest.listCases()).toEqual([]);
    const names = await readdir(dest.casesRoot).catch(() => [] as string[]);
    expect(names.filter((n) => !n.startsWith("."))).toEqual([]);
  }

  it("rejects bytes that are not a ZIP at all", async () => {
    await expectRejected(Buffer.from("this is not a zip archive at all, just text"));
  });

  it("rejects a tampered byte", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) =>
      entries.map((e) =>
        e.path === "INC-1/screenshots/shot-001.webp"
          ? { path: e.path, data: Buffer.from([9, 9, 9, 9, 1, 2, 3]) }
          : e,
      ),
    );
    await expectRejected(zip, /checksum|sha256|mismatch/i);
  });

  it("rejects a file whose size differs from the manifest even when the hash is recomputed", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) => {
      const manifest = manifestOf(entries);
      const files = (manifest.files as Array<{ path: string; bytes: number }>).map((f) =>
        f.path === "screenshots/shot-001.webp" ? { ...f, bytes: f.bytes + 1 } : f,
      );
      return withManifest(entries, { ...manifest, files });
    });
    await expectRejected(zip, /size/i);
  });

  it("rejects an extra entry the manifest does not list", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) => [
      ...entries,
      { path: "INC-1/screenshots/planted.webp", data: Buffer.from("x") },
    ]);
    await expectRejected(zip, /does not list/);
  });

  it("rejects an archive missing a listed file", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) =>
      entries.filter((e) => e.path !== "INC-1/imports/thor-001.json"),
    );
    await expectRejected(zip, /does not contain/);
  });

  it("rejects a malformed manifest", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) => withManifest(entries, "{ not json"));
    await expectRejected(zip, /manifest/);
  });

  it("rejects a manifest with no files array", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) =>
      withManifest(entries, { caseId: "INC-1", format: "zip" }),
    );
    await expectRejected(zip, /manifest/);
  });

  it("rejects a manifest row with a malformed sha256", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) => {
      const manifest = manifestOf(entries);
      const files = (manifest.files as Array<Record<string, unknown>>).map((f, i) =>
        i === 0 ? { ...f, sha256: "abc" } : f,
      );
      return withManifest(entries, { ...manifest, files });
    });
    await expectRejected(zip, /manifest/);
  });

  it("rejects a manifest that lists one path twice", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) => {
      const manifest = manifestOf(entries);
      const files = manifest.files as unknown[];
      return withManifest(entries, { ...manifest, files: [...files, files[0]] });
    });
    await expectRejected(zip, /twice|duplicate/i);
  });

  it("rejects a top folder that climbs out of the cases root", async () => {
    const caseJson = Buffer.from(JSON.stringify({ caseId: "x" }));
    await expectRejected(createZip([{ path: "../x/case.json", data: caseJson }]), /unsafe|not a valid/);
  });

  it("rejects entries under two top folders", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) => [
      ...entries,
      { path: "OTHER-1/case.json", data: Buffer.from(JSON.stringify({ caseId: "OTHER-1" })) },
    ]);
    await expectRejected(zip, /one case folder/);
  });

  it("rejects a file at the root of the archive", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) => [
      ...entries,
      { path: "readme.txt", data: Buffer.from("hi") },
    ]);
    await expectRejected(zip, /one case folder/);
  });

  it("rejects a manifest whose caseId differs from the folder", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) =>
      withManifest(entries, { ...manifestOf(entries), caseId: "INC-9" }),
    );
    await expectRejected(zip, /does not match/);
  });

  it("rejects a case.json whose caseId differs from the folder", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) =>
      entries
        .filter((e) => !e.path.endsWith("/archive-manifest.json"))
        .map((e) =>
          e.path === "INC-1/case.json"
            ? { path: e.path, data: Buffer.from(JSON.stringify({ caseId: "INC-9", name: "n" })) }
            : e,
        ),
    );
    await expectRejected(zip, /does not match/);
  });

  // Patch every central-directory record of a createZip archive (offset of the flag / method field).
  function patchCentral(zip: Buffer, offset: number, value: number): Buffer {
    const out = Buffer.from(zip);
    for (let i = 0; i + 4 <= out.length; i++) {
      if (out.readUInt32LE(i) === 0x02014b50) out.writeUInt16LE(value, i + offset);
    }
    return out;
  }

  it("rejects an entry with an unsupported compression method", async () => {
    const zip = createZip([
      { path: "INC-1/case.json", data: Buffer.from(JSON.stringify({ caseId: "INC-1" })) },
    ]);
    await expectRejected(patchCentral(zip, 10, 12));
  });

  it("rejects an encrypted entry", async () => {
    const zip = createZip([
      { path: "INC-1/case.json", data: Buffer.from(JSON.stringify({ caseId: "INC-1" })) },
    ]);
    await expectRejected(patchCentral(zip, 8, 0x0801));
  });

  it("rejects a manifest caseId that is not a string", async () => {
    const zip = rezip(await archivedZip(await harness()), (entries) =>
      withManifest(entries, { ...manifestOf(entries), caseId: 7 }),
    );
    await expectRejected(zip, /manifest/);
  });
});
