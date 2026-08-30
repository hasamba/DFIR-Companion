import { deflateRawSync, inflateRawSync } from "node:zlib";
import {
  zipCryptoDecrypt,
  verifyZipCryptoCheckByte,
  parseAesExtra,
  aesDecrypt,
  ZipPasswordError,
  ZipAuthenticationError,
} from "./zipCrypto.js";

// A tiny, dependency-free ZIP writer/reader. The redacted case export (#54) bundles the
// anonymized report + screenshots into one shareable archive; rather than pull in a native
// archiver, we emit a standard ZIP (DEFLATE method) with node:zlib so the logic stays pure and
// unit-testable (createZip → readZip round-trips). Output is deterministic — a fixed DOS
// timestamp is used so the same inputs always produce the same bytes.

export interface ZipEntry {
  /** POSIX-style path within the archive (forward slashes, no leading slash). */
  path: string;
  data: Buffer;
}

// ── Portable entry names ───────────────────────────────────────────────────
//
// A ZIP entry name is written as a filename on extraction, so it has to survive the strictest
// filesystem any recipient uses — which is Windows. A case directory routinely holds names Windows
// refuses: the drop folder keeps a dropped file's original name forever under drop/_processed/, and
// analysts drop files straight out of Windows collections. Extracting such an entry on Windows
// either fails outright or, for a colon, silently writes an NTFS alternate data stream — the file
// disappears from the extracted tree with no error at all.
//
// Only the NAME written into the archive is rewritten here. The path the bytes are read from is a
// separate string and must keep the real on-disk spelling, or the read finds nothing.

// Characters Windows refuses in a filename, plus the control range no platform wants. The forward
// slash is in the set too: inside a single segment it is content, not a separator.
const UNPORTABLE_SEGMENT_CHARS = /[<>:"/\\|?*\x00-\x1f]/g;

// Reserved device names. With or without an extension, CON, NUL, LPT1 and friends do not resolve to
// a file on Windows at all, so an entry named after one cannot be extracted.
const WINDOWS_RESERVED_SEGMENT = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

/**
 * Rewrite one path segment so Windows can create a file with that name.
 *
 * Each substitution keeps the segment's length, so two names that differ before sanitizing usually
 * still differ after. Where they do not, the caller must refuse the archive rather than let one
 * file overwrite the other. An ordinary name comes back unchanged, non-ASCII included — Windows
 * accepts those.
 */
export function portableZipSegment(segment: string): string {
  if (!segment) return "_";
  let out = segment.replace(UNPORTABLE_SEGMENT_CHARS, "_");
  // Windows strips trailing dots and spaces, so "notes." and "notes" resolve to one file. Padding
  // with "_" instead of trimming keeps the two names distinct, which the collision check needs.
  out = out.replace(/[.\s]+$/, (run) => "_".repeat(run.length));
  if (WINDOWS_RESERVED_SEGMENT.test(out)) out = `_${out}`;
  return out;
}

/**
 * Rewrite a whole entry path, segment by segment.
 *
 * Backslashes fold to forward slashes first — a ZIP entry has exactly one path syntax — and empty
 * segments are dropped so a doubled slash does not invent a directory.
 */
export function portableZipEntryPath(path: string): string {
  return path
    .replace(/\\/g, "/")
    .split("/")
    .filter((seg) => seg !== "")
    .map(portableZipSegment)
    .join("/");
}

// CRC-32 (IEEE 802.3) lookup table — the checksum every ZIP entry carries.
const CRC_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = (CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8)) >>> 0;
  return (c ^ 0xffffffff) >>> 0;
}

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const METHOD_DEFLATE = 8;
const METHOD_AES = 99; // WinZip AE-x; the real method lives in the 0x9901 extra field
const FLAG_ENCRYPTED = 0x0001; // general-purpose bit 0
const ZIPCRYPTO_HEADER_LEN = 12;
const VERSION = 20; // 2.0 — the minimum that supports DEFLATE
const FLAG_UTF8 = 0x0800; // general-purpose bit 11: filenames are UTF-8
// Fixed DOS time/date (1980-01-01 00:00:00) → reproducible archives, no Date dependency.
const DOS_TIME = 0;
const DOS_DATE = 0x0021; // (1980-1980)<<9 | 1<<5 | 1

interface PreparedEntry {
  nameBytes: Buffer;
  compressed: Buffer;
  crc: number;
  uncompressedSize: number;
  localOffset: number;
}

/** Build a ZIP archive (DEFLATE-compressed) from the given entries. Pure — never touches disk. */
export function createZip(entries: ZipEntry[]): Buffer {
  const localParts: Buffer[] = [];
  const prepared: PreparedEntry[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.path, "utf8");
    const compressed = deflateRawSync(entry.data);
    const crc = crc32(entry.data);

    const header = Buffer.alloc(30);
    header.writeUInt32LE(SIG_LOCAL, 0);
    header.writeUInt16LE(VERSION, 4);
    header.writeUInt16LE(FLAG_UTF8, 6);
    header.writeUInt16LE(METHOD_DEFLATE, 8);
    header.writeUInt16LE(DOS_TIME, 10);
    header.writeUInt16LE(DOS_DATE, 12);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(compressed.length, 18);
    header.writeUInt32LE(entry.data.length, 22);
    header.writeUInt16LE(nameBytes.length, 26);
    header.writeUInt16LE(0, 28); // extra field length

    prepared.push({ nameBytes, compressed, crc, uncompressedSize: entry.data.length, localOffset: offset });
    localParts.push(header, nameBytes, compressed);
    offset += header.length + nameBytes.length + compressed.length;
    // ZIP32 stores sizes/offsets as 32-bit. Fail loudly rather than silently emit a corrupt archive
    // (this is not a ZIP64 writer). 4 GB is far beyond any realistic redacted-case package.
    if (offset > 0xffffffff || entry.data.length > 0xffffffff) {
      throw new Error("archive too large for ZIP32 (over 4 GB) — exclude screenshots or split the case");
    }
  }

  const centralParts: Buffer[] = [];
  let centralSize = 0;
  for (const p of prepared) {
    const header = Buffer.alloc(46);
    header.writeUInt32LE(SIG_CENTRAL, 0);
    header.writeUInt16LE(VERSION, 4); // version made by
    header.writeUInt16LE(VERSION, 6); // version needed
    header.writeUInt16LE(FLAG_UTF8, 8);
    header.writeUInt16LE(METHOD_DEFLATE, 10);
    header.writeUInt16LE(DOS_TIME, 12);
    header.writeUInt16LE(DOS_DATE, 14);
    header.writeUInt32LE(p.crc, 16);
    header.writeUInt32LE(p.compressed.length, 20);
    header.writeUInt32LE(p.uncompressedSize, 24);
    header.writeUInt16LE(p.nameBytes.length, 28);
    header.writeUInt16LE(0, 30); // extra field length
    header.writeUInt16LE(0, 32); // comment length
    header.writeUInt16LE(0, 34); // disk number start
    header.writeUInt16LE(0, 36); // internal attributes
    header.writeUInt32LE(0, 38); // external attributes
    header.writeUInt32LE(p.localOffset, 42);

    centralParts.push(header, p.nameBytes);
    centralSize += header.length + p.nameBytes.length;
  }

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(SIG_EOCD, 0);
  eocd.writeUInt16LE(0, 4); // this disk number
  eocd.writeUInt16LE(0, 6); // disk with central directory
  eocd.writeUInt16LE(prepared.length, 8); // entries on this disk
  eocd.writeUInt16LE(prepared.length, 10); // total entries
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(offset, 16); // central directory offset
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localParts, ...centralParts, eocd]);
}

// Per-entry and total inflated-size caps to prevent zip bombs (decompression-ratio attacks).
// A crafted .dfircase archive with a single entry that inflates to gigabytes would OOM the
// process before a post-hoc size check ever ran. Enforced via zlib's maxOutputLength, which
// aborts DURING decompression rather than after — see readZip. 512 MB per entry and 2 GB total
// are generous ceilings for a forensic case archive (state JSON + screenshots + imports).
const MAX_ENTRY_INFLATED = 512 * 1024 * 1024;
const MAX_TOTAL_INFLATED = 2 * 1024 * 1024 * 1024;

export interface ReadZipOptions {
  /** Override the per-entry inflated-size cap (default {@link MAX_ENTRY_INFLATED}). Tests only —
   *  production callers should use the default. */
  maxEntryBytes?: number;
  /** Override the total inflated-size cap (default {@link MAX_TOTAL_INFLATED}). Tests only. */
  maxTotalBytes?: number;
  /** Password for encrypted entries. Ignored for unencrypted archives. Never logged or persisted. */
  password?: string;
}

/**
 * Read back the entries of an archive produced by {@link createZip} (DEFLATE or stored). Walks the
 * central directory, inflates each entry, and verifies its CRC-32. Used by tests and any consumer
 * that needs to inspect a built package; not a general-purpose unzip (no ZIP64 / encryption).
 * Throws when an entry's inflated size or the running total would exceed a safety cap — enforced
 * via zlib's maxOutputLength DURING inflation, so a bomb aborts before it's fully in memory, not
 * after (zip-bomb guard).
 */
export function readZip(archive: Buffer, opts: ReadZipOptions = {}): ZipEntry[] {
  const maxEntryBytes = opts.maxEntryBytes ?? MAX_ENTRY_INFLATED;
  const maxTotalBytes = opts.maxTotalBytes ?? MAX_TOTAL_INFLATED;
  // Locate the End Of Central Directory record (scan back from the end; no trailing comment).
  let eocd = -1;
  for (let i = archive.length - 22; i >= 0; i--) {
    if (archive.readUInt32LE(i) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("not a ZIP archive: EOCD not found");

  const total = archive.readUInt16LE(eocd + 10);
  let ptr = archive.readUInt32LE(eocd + 16); // central directory offset
  const entries: ZipEntry[] = [];
  let totalInflated = 0;

  for (let i = 0; i < total; i++) {
    // The offset and entry count come straight from the EOCD, which the uploader controls. Without
    // this bound a crafted value past the end of the buffer surfaces as Node's internal
    // ERR_OUT_OF_RANGE from readUInt32LE (mirrors zipExtract's archiveIsEncrypted guard — and this
    // walk is also reached by caseExportArchive, which never runs that scan first).
    if (ptr + 46 > archive.length) throw new Error("corrupt ZIP: central directory out of bounds");
    if (archive.readUInt32LE(ptr) !== SIG_CENTRAL) throw new Error("corrupt ZIP: bad central header");
    const method = archive.readUInt16LE(ptr + 10);
    const flag = archive.readUInt16LE(ptr + 8);
    const modTime = archive.readUInt16LE(ptr + 12);
    const crc = archive.readUInt32LE(ptr + 16);
    const compSize = archive.readUInt32LE(ptr + 20);
    const nameLen = archive.readUInt16LE(ptr + 28);
    const extraLen = archive.readUInt16LE(ptr + 30);
    const commentLen = archive.readUInt16LE(ptr + 32);
    const localOffset = archive.readUInt32LE(ptr + 42);
    const name = archive.toString("utf8", ptr + 46, ptr + 46 + nameLen);
    const extra = archive.subarray(ptr + 46 + nameLen, ptr + 46 + nameLen + extraLen);

    // Jump to the local header to find the actual data start (its name/extra lengths may differ).
    // The central record's relative-offset field is equally attacker-controlled — bound it the
    // same way before the reads below walk off the end of the buffer.
    if (localOffset + 30 > archive.length) throw new Error("corrupt ZIP: local header out of bounds");
    const localNameLen = archive.readUInt16LE(localOffset + 26);
    const localExtraLen = archive.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    let compressed = archive.subarray(dataStart, dataStart + compSize);
    const encrypted = (flag & FLAG_ENCRYPTED) !== 0;

    // Effective compression method and CRC policy, both of which AES entries override.
    let effectiveMethod = method;
    let verifyCrc = true;

    if (encrypted) {
      const password = opts.password;
      if (password === undefined || password === "") {
        throw new ZipPasswordError(
          `zip entry "${name}" is encrypted — a password is required`,
          "password-required",
        );
      }
      if (method === METHOD_AES) {
        const params = parseAesExtra(extra);
        if (!params) {
          throw new ZipPasswordError(
            `zip entry "${name}" uses AES but has no readable AE header`,
            "unsupported-encryption",
          );
        }
        const { plaintext, macOk } = aesDecrypt(compressed, password, params.strength);
        // Fail closed on the HMAC, for BOTH AE-1 and AE-2. The tag is the only cryptographic
        // integrity control WinZip AES has; the CRC is neither a substitute (CRC-32 is linear and
        // non-cryptographic, and its stored value sits in the central directory the same adversary
        // can rewrite) nor even present for AE-2. This was previously computed and dropped, which
        // left AE-2 entries with no integrity verification of any kind: the cipher is AES-CTR, so
        // flipping a ciphertext bit flips exactly that plaintext bit, and a modified log line, hash
        // or command line was accepted as authentic (#428). params.aeVersion and params.actualMethod
        // come from the archive's own 0x9901 field, so the attacker picks AE-2 and STORED to route
        // around both checks — which is precisely why this one may not be conditional.
        if (!macOk) {
          throw new ZipAuthenticationError(
            `zip entry "${name}" failed AES authentication — the archive was modified after it was ` +
              `created (or, once in 65536, the password is wrong in a way the verifier missed)`,
          );
        }
        compressed = plaintext;
        effectiveMethod = params.actualMethod;
        // AE-2 stores a zero CRC by design, so the usual check would always fail. Skipping it is
        // sound only because the HMAC above ran and passed.
        verifyCrc = params.aeVersion !== 2;
      } else {
        const decrypted = zipCryptoDecrypt(compressed, password);
        if (!verifyZipCryptoCheckByte(decrypted.subarray(0, ZIPCRYPTO_HEADER_LEN), crc, modTime)) {
          throw new ZipPasswordError(`wrong password for zip entry "${name}"`, "wrong-password");
        }
        compressed = decrypted.subarray(ZIPCRYPTO_HEADER_LEN);
      }
    }

    let data: Buffer;
    if (effectiveMethod === METHOD_DEFLATE) {
      // Zip-bomb guard: cap the output DURING decompression via zlib's own maxOutputLength, not
      // after — inflateRawSync() otherwise fully materializes the decompressed output before
      // returning, so a check on the result's length only runs once the damage (allocating/OOMing
      // on a multi-GB buffer from a KB-sized entry) has already happened. maxOutputLength makes
      // the call itself throw ERR_BUFFER_TOO_LARGE once output would exceed the limit, without
      // ever producing more than that. Bounded to whatever's left of the TOTAL budget too, so one
      // entry can't consume the whole cap and leave nothing to detect a multi-entry bomb with.
      const remaining = maxTotalBytes - totalInflated;
      const budget = Math.max(0, Math.min(maxEntryBytes, remaining));
      try {
        data = inflateRawSync(compressed, { maxOutputLength: budget });
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ERR_BUFFER_TOO_LARGE") {
          throw new Error(
            `zip entry "${name}" inflates past the ${budget} byte cap for this archive — possible zip bomb`,
          );
        }
        throw err;
      }
    } else {
      data = Buffer.from(compressed);
    }

    totalInflated += data.length;

    if (verifyCrc && crc32(data) !== crc) throw new Error(`corrupt ZIP: CRC mismatch for ${name}`);
    entries.push({ path: name, data });
    ptr += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}
