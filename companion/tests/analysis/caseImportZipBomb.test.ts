import { describe, it, expect } from "vitest";
import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { importEncryptedCase } from "../../src/analysis/caseExportArchive.js";
import { importZipArchiveCase } from "../../src/analysis/caseZipImport.js";
import { IMPORT_STAGING_DIRNAME } from "../../src/analysis/caseRestore.js";
import { encryptBuffer } from "../../src/analysis/caseEncryption.js";
import {
  buildRawZip,
  deflatedEntry,
  deflatedZeros,
  storedEntry,
  type RawZipEntry,
} from "../helpers/rawZip.js";

// #1828: both whole-case imports (plain ZIP and .dfircase) share one reader. A zip bomb must be
// refused before memory grows, and a refused import must leave nothing staged and no case behind.

const MiB = 1024 * 1024;
const PASSWORD = "correct horse battery staple";

async function harness(): Promise<CaseStore> {
  return new CaseStore(await mkdtemp(join(tmpdir(), "dfir-zipbomb-")));
}

function caseJson(caseId: string): Buffer {
  return Buffer.from(JSON.stringify({ caseId, name: "Bomb", investigator: "alice" }));
}

async function expectNothingLeft(store: CaseStore): Promise<void> {
  expect(await store.listCases()).toEqual([]);
  const staged = await readdir(join(store.casesRoot, IMPORT_STAGING_DIRNAME)).catch(() => [] as string[]);
  expect(staged).toEqual([]);
}

/** The lying-header bomb: declares 1000 bytes, inflates to 256 MiB of zeros. */
async function liarEntry(name: string): Promise<RawZipEntry> {
  const { body, crc } = await deflatedZeros(256 * MiB);
  return { name, body, method: 8, crc, size: 1000 };
}

async function honestBombEntry(name: string): Promise<RawZipEntry> {
  const { body, crc } = await deflatedZeros(64 * MiB);
  return { name, body, method: 8, crc, size: 64 * MiB };
}

describe("plain ZIP case import — zip bombs", () => {
  it("refuses a high-ratio entry from the central directory, stages nothing", async () => {
    const zip = buildRawZip([
      deflatedEntry("INC-1/case.json", caseJson("INC-1")),
      await honestBombEntry("INC-1/imports/big.bin"),
    ]);
    const store = await harness();
    await expect(importZipArchiveCase(store, zip)).rejects.toThrow(/not a valid case archive: .*zip bomb/);
    await expectNothingLeft(store);
  });

  it("stops a lying header mid-stream, without the bomb reaching memory, and removes the staging", async () => {
    const zip = buildRawZip([
      deflatedEntry("INC-1/case.json", caseJson("INC-1")),
      await liarEntry("INC-1/imports/liar.bin"),
    ]);
    const store = await harness();
    const before = process.memoryUsage().arrayBuffers;
    await expect(importZipArchiveCase(store, zip)).rejects.toThrow(
      /inflates past the size its header declares/,
    );
    expect(process.memoryUsage().arrayBuffers - before).toBeLessThan(32 * MiB);
    await expectNothingLeft(store);
  });

  it("imports a normal archive with stored and deflated entries", async () => {
    const zip = buildRawZip([
      deflatedEntry("INC-2/case.json", caseJson("INC-2")),
      storedEntry("INC-2/screenshots/shot.webp", Buffer.from([0x52, 0x49, 0x46, 0x46, 9, 9])),
      deflatedEntry(
        "INC-2/metadata/captures.jsonl",
        Buffer.from('{"caseId":"INC-2","n":1}\n\n{"caseId":"INC-2","n":2}\n'),
      ),
    ]);
    const store = await harness();
    const result = await importZipArchiveCase(store, zip, { targetCaseId: "INC-9" });
    expect(result.meta.caseId).toBe("INC-9");
    expect(result.counts.captures).toBe(2);
    const shot = await readFile(join(store.caseDir("INC-9"), "screenshots", "shot.webp"));
    expect([...shot]).toEqual([0x52, 0x49, 0x46, 0x46, 9, 9]);
    // The JSONL rewrite streams line by line and keeps the one-record-per-line shape.
    const captures = await readFile(join(store.caseDir("INC-9"), "metadata", "captures.jsonl"), "utf8");
    expect(captures).toBe('{"caseId":"INC-9","n":1}\n{"caseId":"INC-9","n":2}\n');
    expect(await readdir(join(store.casesRoot, IMPORT_STAGING_DIRNAME))).toEqual([]);
  });

  it("refuses a file that shares its name with a folder another entry needs", async () => {
    const zip = buildRawZip([
      deflatedEntry("INC-3/case.json", caseJson("INC-3")),
      deflatedEntry("INC-3/imports/a", Buffer.from("file")),
      deflatedEntry("INC-3/imports/A/b.txt", Buffer.from("nested")),
    ]);
    const store = await harness();
    await expect(importZipArchiveCase(store, zip)).rejects.toThrow(/also a folder/);
    await expectNothingLeft(store);
  });

  it("refuses a second archive-manifest.json", async () => {
    const manifest = Buffer.from(JSON.stringify({ caseId: "INC-4", files: [] }));
    const zip = buildRawZip([
      deflatedEntry("INC-4/case.json", caseJson("INC-4")),
      deflatedEntry("INC-4/archive-manifest.json", manifest),
      deflatedEntry("INC-4/archive-manifest.json", manifest),
    ]);
    const store = await harness();
    await expect(importZipArchiveCase(store, zip)).rejects.toThrow(/more than one archive-manifest\.json/);
    await expectNothingLeft(store);
  });
});

describe(".dfircase import — zip bombs inside the decrypted package", () => {
  it("refuses a high-ratio entry, stages nothing", async () => {
    const zip = buildRawZip([
      deflatedEntry("case.json", caseJson("INC-5")),
      await honestBombEntry("imports/big.bin"),
    ]);
    const store = await harness();
    await expect(importEncryptedCase(store, await encryptBuffer(zip, PASSWORD), PASSWORD)).rejects.toThrow(
      /zip bomb/,
    );
    await expectNothingLeft(store);
  });

  it("stops a lying header mid-stream and removes the staging", async () => {
    const zip = buildRawZip([
      deflatedEntry("case.json", caseJson("INC-6")),
      await liarEntry("imports/liar.bin"),
    ]);
    const store = await harness();
    await expect(importEncryptedCase(store, await encryptBuffer(zip, PASSWORD), PASSWORD)).rejects.toThrow(
      /inflates past the size its header declares/,
    );
    await expectNothingLeft(store);
  });

  it("refuses an archive entry that aliases the provenance file the importer writes", async () => {
    const files = [{ path: "metadata/Source-Manifest.json", data: Buffer.from("{}") }];
    const manifest = {
      caseId: "INC-7",
      exportedAt: "",
      generatedBy: "",
      files: files.map((f) => ({ path: f.path, sha256: "", bytes: 2 })),
    };
    const { createHash } = await import("node:crypto");
    manifest.files[0].sha256 = createHash("sha256").update(files[0].data).digest("hex");
    const zip = buildRawZip([
      deflatedEntry("case.json", caseJson("INC-7")),
      deflatedEntry(files[0].path, files[0].data),
      deflatedEntry("archive-manifest.json", Buffer.from(JSON.stringify(manifest))),
    ]);
    const store = await harness();
    await expect(importEncryptedCase(store, await encryptBuffer(zip, PASSWORD), PASSWORD)).rejects.toThrow(
      /same file as "metadata\/source-manifest\.json"/,
    );
    await expectNothingLeft(store);
  });
});
