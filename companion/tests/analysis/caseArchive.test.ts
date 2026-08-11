import { describe, it, expect } from "vitest";
import { archiveCase, buildZip, zipArchiveFilename } from "../../src/analysis/caseArchive.js";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdtemp, mkdir, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";

// ── ZIP structure helpers ───────────────────────────────────────────────────

function readLe32(buf: Buffer, off: number): number {
  return buf.readUInt32LE(off);
}

function findEocd(buf: Buffer): number | null {
  for (let i = buf.length - 22; i >= 0; i--) {
    if (readLe32(buf, i) === 0x06054b50) return i;
  }
  return null;
}

describe("buildZip", () => {
  it("produces a buffer with a valid local file header signature", () => {
    const zip = buildZip([{ name: "hello.txt", data: Buffer.from("hello") }]);
    expect(readLe32(zip, 0)).toBe(0x04034b50); // local file header sig
  });

  it("ends with a valid end-of-central-directory record", () => {
    const zip = buildZip([{ name: "a.txt", data: Buffer.from("abc") }]);
    const eocdOffset = findEocd(zip);
    expect(eocdOffset).not.toBeNull();
    expect(readLe32(zip, eocdOffset!)).toBe(0x06054b50);
  });

  it("records the correct entry count in the EOCD", () => {
    const zip = buildZip([
      { name: "a.txt", data: Buffer.from("a") },
      { name: "b.txt", data: Buffer.from("b") },
      { name: "c.txt", data: Buffer.from("c") },
    ]);
    const eocdOffset = findEocd(zip);
    expect(eocdOffset).not.toBeNull();
    // bytes 8-9: total entries on disk; bytes 10-11: total entries
    const count = zip.readUInt16LE(eocdOffset! + 8);
    expect(count).toBe(3);
  });

  it("produces a non-empty buffer for a non-empty input", () => {
    const zip = buildZip([{ name: "data.json", data: Buffer.from('{"key":"value"}') }]);
    expect(zip.length).toBeGreaterThan(30);
  });

  it("handles empty file data without throwing", () => {
    expect(() => buildZip([{ name: "empty.txt", data: Buffer.alloc(0) }])).not.toThrow();
  });

  it("encodes UTF-8 filenames (non-ASCII)", () => {
    const zip = buildZip([{ name: "état/événement.log", data: Buffer.from("data") }]);
    expect(zip.length).toBeGreaterThan(0);
    const eocdOffset = findEocd(zip);
    expect(eocdOffset).not.toBeNull();
  });
});

describe("archiveCase", () => {
  function makeFs(files: Record<string, string>): {
    scanFiles: (dir: string) => Promise<string[]>;
    readFile: (path: string) => Promise<Buffer>;
    writeFile: (path: string, data: Buffer) => Promise<void>;
    written: { path: string; data: Buffer } | null;
  } {
    let written: { path: string; data: Buffer } | null = null;
    return {
      scanFiles: async (_dir: string) => Object.keys(files),
      readFile: async (absPath: string) => {
        // archiveCase builds absPath via path.join (backslashes on Windows);
        // the files map is keyed with forward-slash relative paths — normalize
        // before matching so the mock is path-separator agnostic.
        const normalized = absPath.replaceAll("\\", "/");
        const rel = Object.keys(files).find((k) => normalized.endsWith(k));
        if (!rel) throw new Error(`file not found: ${absPath}`);
        return Buffer.from(files[rel], "utf8");
      },
      writeFile: async (path: string, data: Buffer) => {
        written = { path, data };
      },
      get written() {
        return written;
      },
    };
  }

  it("names the archive '<caseId> (no password).zip' when no case name is given", async () => {
    const fs = makeFs({ "case.json": '{"caseId":"c1"}' });
    const result = await archiveCase("/cases", "c1", fs);
    expect(result.archivePath).toBe(join("/cases", "c1 (no password).zip"));
  });

  it("names the archive '<caseId> - <name> (no password).zip' when a case name is given", async () => {
    const fs = makeFs({ "case.json": '{"caseId":"c1"}' });
    const result = await archiveCase("/cases", "c1", fs, "Acme Breach");
    expect(result.archivePath).toBe(join("/cases", "c1 - Acme Breach (no password).zip"));
  });

  it("includes a manifest with the correct caseId and file count", async () => {
    const files = {
      "case.json": '{"caseId":"c1"}',
      "state/investigation.json": "{}",
    };
    const fs = makeFs(files);
    const result = await archiveCase("/cases", "c1", fs);
    // manifest counts original files + the manifest itself
    expect(result.manifest.caseId).toBe("c1");
    expect(result.manifest.format).toBe("zip");
    expect(result.manifest.files).toHaveLength(Object.keys(files).length);
    expect(result.manifest.totalFiles).toBe(Object.keys(files).length);
  });

  it("includes SHA-256 checksums for each file", async () => {
    const fs = makeFs({ "case.json": '{"caseId":"c1"}' });
    const result = await archiveCase("/cases", "c1", fs);
    const entry = result.manifest.files[0];
    expect(entry.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(entry.bytes).toBeGreaterThan(0);
  });

  it("writes a valid ZIP buffer (local file header sig present)", async () => {
    const fs = makeFs({ "case.json": '{"caseId":"c1"}' });
    await archiveCase("/cases", "c1", fs);
    const { data } = fs.written!;
    expect(data).not.toBeNull();
    expect(readLe32(data, 0)).toBe(0x04034b50); // local file header sig
  });

  it("includes archive-manifest.json INSIDE the zip (in the manifest entry list)", async () => {
    const fs = makeFs({ "case.json": "{}" });
    await archiveCase("/cases", "c1", fs);
    // The archive-manifest.json is added to the zip but NOT to the manifest file list
    // (it's generated, not a pre-existing file)
    const zipData = fs.written!.data;
    const zipStr = zipData.toString("binary");
    expect(zipStr).toContain("archive-manifest.json");
  });

  it("totalBytes sums the original file sizes (not manifest)", async () => {
    const files = {
      "case.json": "abc", // 3 bytes
      "state/x.json": "de", // 2 bytes
    };
    const fs = makeFs(files);
    const result = await archiveCase("/cases", "c1", fs);
    expect(result.manifest.totalBytes).toBe(5);
  });

  // These two run against the real filesystem with NO deps injected, because the atomicity lives
  // entirely in the DEFAULT write. Passing deps.writeFile replaces the code under test with the
  // fixture, so such a test asserts nothing about archiveCase at all.
  describe("default write (real fs) is atomic", () => {
    async function realCaseDir(): Promise<string> {
      const dir = await mkdtemp(join(tmpdir(), "dfir-archive-atomic-"));
      await mkdir(join(dir, "c1"), { recursive: true });
      await writeFile(join(dir, "c1", "case.json"), '{"caseId":"c1"}');
      return dir;
    }

    it("lands a complete archive and leaves no temp file behind", async () => {
      const dir = await realCaseDir();
      try {
        const result = await archiveCase(dir, "c1");
        const written = await readFile(result.archivePath);
        expect(written.subarray(0, 2).toString("latin1")).toBe("PK"); // a real ZIP, not a stub
        expect(findEocd(written)).not.toBeNull(); // complete, not truncated
        expect((await readdir(dir)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    // The crash-mid-write property itself can't be observed in-process; what CAN be is the
    // cleanup branch the atomic write adds, which is where a temp file becomes permanent litter
    // sitting next to the case.
    it("a failed rename leaves neither a partial archive at the target nor a temp file", async () => {
      const dir = await realCaseDir();
      try {
        // A non-empty DIRECTORY at the target path makes rename() fail after the temp file exists.
        const archivePath = join(dir, zipArchiveFilename("c1", null));
        await mkdir(archivePath, { recursive: true });
        await writeFile(join(archivePath, "blocker"), "x");

        await expect(archiveCase(dir, "c1")).rejects.toThrow();

        // The target is still the untouched directory — no truncated ZIP replaced it — and the
        // temp file was cleaned up rather than left as litter next to the case.
        expect((await stat(archivePath)).isDirectory()).toBe(true);
        expect((await readdir(dir)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });
  });
});

describe("zipArchiveFilename", () => {
  it("uses just the caseId when there's no distinct name", () => {
    expect(zipArchiveFilename("c1", undefined)).toBe("c1 (no password).zip");
    expect(zipArchiveFilename("c1", "c1")).toBe("c1 (no password).zip");
    expect(zipArchiveFilename("c1", "")).toBe("c1 (no password).zip");
  });

  it("includes the case name when distinct from the id", () => {
    expect(zipArchiveFilename("INC-1", "Acme Breach")).toBe("INC-1 - Acme Breach (no password).zip");
  });

  it("strips filesystem-unsafe characters from the name", () => {
    expect(zipArchiveFilename("INC-1", 'Acme: "Breach"/Q4')).toBe(
      "INC-1 - Acme_ _Breach_/Q4 (no password).zip".replace(/[<>:"/\\|?*\x00-\x1f]/g, "_"),
    );
  });
});
