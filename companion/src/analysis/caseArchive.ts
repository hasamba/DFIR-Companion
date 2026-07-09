import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { deflateRawSync } from "node:zlib";

// ── CRC-32 via lookup table ────────────────────────────────────────────────
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (const b of buf) c = (CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8)) >>> 0;
  return (c ^ 0xffffffff) >>> 0;
}

// ── Minimal ZIP writer (DEFLATE, UTF-8 filenames) ─────────────────────────
function le16(buf: Buffer, off: number, v: number): void { buf.writeUInt16LE(v >>> 0, off); }
function le32(buf: Buffer, off: number, v: number): void { buf.writeUInt32LE(v >>> 0, off); }

function dosTime(d: Date): { t: number; dt: number } {
  return {
    t: ((d.getUTCHours() & 0x1f) << 11) | ((d.getUTCMinutes() & 0x3f) << 5) | ((d.getUTCSeconds() >> 1) & 0x1f),
    dt: (((d.getUTCFullYear() - 1980) & 0x7f) << 9) | (((d.getUTCMonth() + 1) & 0x0f) << 5) | (d.getUTCDate() & 0x1f),
  };
}

interface ZipEntry {
  nameBytes: Buffer;
  compressed: Buffer;
  rawLen: number;
  crc: number;
  t: number;
  dt: number;
  localOffset: number;
}

export function buildZip(files: Array<{ name: string; data: Buffer; mtime?: Date }>): Buffer {
  const entries: ZipEntry[] = [];
  const localChunks: Buffer[] = [];
  let offset = 0;

  for (const f of files) {
    const nameBytes = Buffer.from(f.name, "utf8");
    const compressed = deflateRawSync(f.data, { level: 6 });
    const crc = crc32(f.data);
    const { t, dt } = dosTime(f.mtime ?? new Date());

    const lh = Buffer.alloc(30 + nameBytes.length);
    le32(lh, 0, 0x04034b50);      // local file header sig
    le16(lh, 4, 20);               // version needed: 2.0
    le16(lh, 6, 0x800);            // general flags: UTF-8
    le16(lh, 8, 8);                // compression: DEFLATE
    le16(lh, 10, t);
    le16(lh, 12, dt);
    le32(lh, 14, crc);
    le32(lh, 18, compressed.length);
    le32(lh, 22, f.data.length);
    le16(lh, 26, nameBytes.length);
    le16(lh, 28, 0);               // extra field length
    nameBytes.copy(lh, 30);

    entries.push({ nameBytes, compressed, rawLen: f.data.length, crc, t, dt, localOffset: offset });
    localChunks.push(lh, compressed);
    offset += 30 + nameBytes.length + compressed.length;
  }

  // Central directory
  const cdChunks: Buffer[] = [];
  for (const e of entries) {
    const cd = Buffer.alloc(46 + e.nameBytes.length);
    le32(cd, 0, 0x02014b50);       // central dir sig
    le16(cd, 4, 20);               // version made by
    le16(cd, 6, 20);               // version needed
    le16(cd, 8, 0x800);            // UTF-8 flag
    le16(cd, 10, 8);               // DEFLATE
    le16(cd, 12, e.t);
    le16(cd, 14, e.dt);
    le32(cd, 16, e.crc);
    le32(cd, 20, e.compressed.length);
    le32(cd, 24, e.rawLen);
    le16(cd, 28, e.nameBytes.length);
    le16(cd, 30, 0);               // extra field length
    le16(cd, 32, 0);               // file comment length
    le16(cd, 34, 0);               // disk number start
    le16(cd, 36, 0);               // internal attributes
    le32(cd, 38, 0);               // external attributes
    le32(cd, 42, e.localOffset);
    e.nameBytes.copy(cd, 46);
    cdChunks.push(cd);
  }

  const centralDir = Buffer.concat(cdChunks);
  const eocd = Buffer.alloc(22);
  le32(eocd, 0, 0x06054b50);      // end-of-central-dir sig
  le16(eocd, 4, 0);               // disk number
  le16(eocd, 6, 0);               // disk with central dir
  le16(eocd, 8, entries.length);
  le16(eocd, 10, entries.length);
  le32(eocd, 12, centralDir.length);
  le32(eocd, 16, offset);         // central dir offset
  le16(eocd, 20, 0);              // comment length

  return Buffer.concat([...localChunks, centralDir, eocd]);
}

// ── Archive manifest ───────────────────────────────────────────────────────
export interface ArchiveManifest {
  caseId: string;
  archivedAt: string;
  format: "zip";
  files: Array<{ path: string; sha256: string; bytes: number }>;
  totalFiles: number;
  totalBytes: number;
}

export interface ArchiveResult {
  archivePath: string;
  manifest: ArchiveManifest;
}

export interface ArchiveDeps {
  /** Returns relative paths of all files inside the case dir (recursive). */
  scanFiles?: (caseDir: string) => Promise<string[]>;
  readFile?: (absPath: string) => Promise<Buffer>;
  writeFile?: (absPath: string, data: Buffer) => Promise<void>;
}

// Windows-illegal filename characters (also unsafe cross-platform): < > : " / \ | ? * and control
// chars — the caseId itself is always filesystem-safe (see isValidCaseId), but the case name is
// free text an analyst typed in.
const UNSAFE_FILENAME_CHARS = /[<>:"/\\|?*\x00-\x1f]/g;

/**
 * The on-disk filename for a case's plain (unencrypted) ZIP archive:
 * `"<caseId> - <name> (no password).zip"`, or just `"<caseId> (no password).zip"` when the case
 * has no distinct name. The "(no password)" marker keeps it visually unambiguous next to an
 * encrypted `.dfircase` archive of the same case.
 */
export function zipArchiveFilename(caseId: string, name: string | null | undefined): string {
  const trimmed = (name ?? "").trim();
  if (!trimmed || trimmed === caseId) return `${caseId} (no password).zip`;
  return `${caseId} - ${trimmed.replace(UNSAFE_FILENAME_CHARS, "_")} (no password).zip`;
}

// Default recursive file scanner for the real filesystem.
async function defaultScanFiles(dir: string): Promise<string[]> {
  const paths: string[] = [];
  async function walk(abs: string, rel: string): Promise<void> {
    const entries = await readdir(abs, { withFileTypes: true });
    for (const e of entries) {
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        await walk(join(abs, e.name), childRel);
      } else {
        paths.push(childRel);
      }
    }
  }
  await walk(dir, "");
  return paths;
}

/**
 * Create a ZIP archive of the case directory.
 *
 * Writes `<casesRoot>/<zipArchiveFilename(caseId, caseName)>` atomically (write
 * to temp path then caller renames, or write directly when deps.writeFile is
 * provided). The archive includes a `<caseId>/archive-manifest.json` that
 * lists every file with its SHA-256 and byte size so integrity can be
 * verified offline.
 *
 * Safe to call on an active case but intended for closed cases. Never removes
 * the original folder — the caller decides what to do afterward.
 */
export async function archiveCase(
  casesRoot: string,
  caseId: string,
  deps: ArchiveDeps = {},
  caseName?: string,
): Promise<ArchiveResult> {
  const caseDir = join(casesRoot, caseId);
  const archivePath = join(casesRoot, zipArchiveFilename(caseId, caseName));

  const scan = deps.scanFiles ?? defaultScanFiles;
  const read = deps.readFile ?? (async (p: string) => readFile(p));
  const write = deps.writeFile ?? (async (p: string, d: Buffer) => writeFile(p, d));

  const relPaths = await scan(caseDir);

  const zipFiles: Array<{ name: string; data: Buffer }> = [];
  const manifestFiles: Array<{ path: string; sha256: string; bytes: number }> = [];
  let totalBytes = 0;

  for (const rel of relPaths) {
    const data = await read(join(caseDir, rel));
    const sha256 = createHash("sha256").update(data).digest("hex");
    const zipName = `${caseId}/${rel.replace(/\\/g, "/")}`;
    zipFiles.push({ name: zipName, data });
    manifestFiles.push({ path: rel, sha256, bytes: data.length });
    totalBytes += data.length;
  }

  const manifest: ArchiveManifest = {
    caseId,
    archivedAt: new Date().toISOString(),
    format: "zip",
    files: manifestFiles,
    totalFiles: manifestFiles.length,
    totalBytes,
  };

  // Include the manifest inside the archive
  zipFiles.push({
    name: `${caseId}/archive-manifest.json`,
    data: Buffer.from(JSON.stringify(manifest, null, 2), "utf8"),
  });

  const zipData = buildZip(zipFiles);
  await write(archivePath, zipData);

  return { archivePath, manifest };
}
