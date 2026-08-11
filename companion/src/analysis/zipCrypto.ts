// Decryption primitives for password-protected ZIP entries. Pure functions over buffers — no ZIP
// structure knowledge lives here (see zipArchive.ts for that) and no I/O.
//
// Needed because SO-CRATES can only ever try the password "infected": its upload handler builds the
// password list server-side from the filename, and it extracts through Python's zipfile, which has
// never supported WinZip AES. An analyst-supplied password, or any 7-Zip archive, has to be opened
// here instead.

import { pbkdf2Sync, createCipheriv, createHmac, timingSafeEqual } from "node:crypto";

// The CRC-32 table the cipher's key schedule needs. Rebuilt locally ON PURPOSE rather than imported
// from zipArchive: zipArchive imports THIS module, so importing back would create a cycle whose
// module-init order decides whether the table is populated when the cipher first runs. This module
// stays a leaf with no local imports.
const CRC_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

/**
 * Decrypt a ZipCrypto (legacy PKWARE) entry. Returns the FULL decrypted buffer, including the
 * 12-byte encryption header the caller must strip before inflating. The header's last byte is the
 * password check — see verifyZipCryptoCheckByte.
 */
export function zipCryptoDecrypt(data: Buffer, password: string): Buffer {
  // Three 32-bit keys with fixed PKWARE initial values, advanced one byte at a time.
  let key0 = 0x12345678;
  let key1 = 0x23456789;
  let key2 = 0x34567890;

  const crcUpdate = (c: number, b: number): number => (CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8)) >>> 0;
  const updateKeys = (b: number): void => {
    key0 = crcUpdate(key0, b);
    key1 = (key1 + (key0 & 0xff)) >>> 0;
    key1 = (Math.imul(key1, 134775813) + 1) >>> 0; // imul: the product overflows 2^53 otherwise
    key2 = crcUpdate(key2, key1 >>> 24);
  };

  for (const b of Buffer.from(password, "utf8")) updateKeys(b);

  const out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) {
    const temp = (key2 | 2) & 0xffff;
    const plain = data[i] ^ ((Math.imul(temp, temp ^ 1) >> 8) & 0xff);
    out[i] = plain;
    updateKeys(plain); // the keystream depends on the PLAINTEXT, so update after decrypting
  }
  return out;
}

/**
 * Validate the 12th decrypted header byte against the entry's metadata.
 *
 * The APPNOTE says this byte is the high byte of the CRC-32. But when general-purpose flag bit 3
 * (data descriptor) is set the CRC is not known at write time, so writers substitute the high byte
 * of the DOS mod time — Info-ZIP's `zip -P` does exactly this. Accept EITHER, or correct passwords
 * get rejected. A one-byte check has a 1/256 false-accept rate by design; a wrong password that
 * slips through fails the CRC check downstream.
 */
export function verifyZipCryptoCheckByte(header: Buffer, crc: number, modTime: number): boolean {
  const checkByte = header[11];
  return checkByte === crc >>> 24 || checkByte === ((modTime >> 8) & 0xff);
}

/**
 * Why an encrypted entry could not be opened. Distinguishing these is the difference between
 * "try another password" and "this archive can never be opened here", which is what the analyst
 * actually needs to know.
 *  - wrong-password:          this password is not it; another candidate may still work
 *  - password-required:       encrypted, and no password was supplied at all
 *  - unsupported-encryption:  malformed or unknown AE header; no password will ever work
 */
export type ZipPasswordFailure = "wrong-password" | "unsupported-encryption" | "password-required";

export class ZipPasswordError extends Error {
  constructor(
    message: string,
    readonly reason: ZipPasswordFailure,
  ) {
    super(message);
    this.name = "ZipPasswordError";
  }
}

/**
 * The WinZip-AES HMAC did not match — the entry's ciphertext is not what the archive's author
 * encrypted. Deliberately NOT a ZipPasswordError: the password already cleared the 2-byte
 * verifier, so trying more candidates is pointless, and callers that retry on a password failure
 * (zipExtract) must stop and report this instead.
 *
 * It is also not a generic "corrupt ZIP" error. WinZip AES is AES-CTR, which is bit-for-bit
 * malleable — flipping a ciphertext bit flips exactly that plaintext bit — so a failed tag over
 * evidence means targeted, predictable modification at least as plausibly as it means bit rot.
 * An analyst needs to be able to tell "wrong password" from "this archive was altered".
 */
export class ZipAuthenticationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ZipAuthenticationError";
  }
}

export interface AesParams {
  aeVersion: number; // 1 or 2; AE-2 zeroes the entry CRC, so callers must skip the CRC check
  strength: 1 | 2 | 3; // AES-128 / AES-192 / AES-256
  actualMethod: number; // the real compression method (0 stored, 8 deflate) hidden behind method 99
}

const AES_EXTRA_ID = 0x9901;
const SALT_LEN: Record<number, number> = { 1: 8, 2: 12, 3: 16 };
const KEY_LEN: Record<number, number> = { 1: 16, 2: 24, 3: 32 };
const PW_VERIFY_LEN = 2;
const MAC_LEN = 10; // HMAC-SHA1 truncated to 80 bits
const PBKDF2_ITERATIONS = 1000;

/** Locate and parse the 0x9901 extra field of a method-99 entry. Null when absent or malformed. */
export function parseAesExtra(extra: Buffer): AesParams | null {
  let p = 0;
  while (p + 4 <= extra.length) {
    const id = extra.readUInt16LE(p);
    const size = extra.readUInt16LE(p + 2);
    if (id === AES_EXTRA_ID) {
      if (p + 4 + 7 > extra.length) return null;
      const aeVersion = extra.readUInt16LE(p + 4);
      // p+6..p+7 is the vendor id "AE" — not load-bearing, skipped.
      const strength = extra[p + 8];
      const actualMethod = extra.readUInt16LE(p + 9);
      if (strength !== 1 && strength !== 2 && strength !== 3) return null;
      return { aeVersion, strength, actualMethod };
    }
    p += 4 + size;
  }
  return null;
}

// WinZip AES is AES-CTR with a LITTLE-ENDIAN block counter starting at 1. Node's aes-*-ctr
// increments the IV as a BIG-ENDIAN 128-bit integer, which agrees only on the first block — so we
// generate the keystream ourselves with ECB over an explicit LE counter block. Bounded to 2^32
// blocks (64 GB), far past any realistic entry.
function aesCtrXor(key: Buffer, input: Buffer): Buffer {
  const out = Buffer.alloc(input.length);
  const counter = Buffer.alloc(16);
  const ecb = createCipheriv(`aes-${key.length * 8}-ecb`, key, null);
  ecb.setAutoPadding(false);
  for (let off = 0, block = 1; off < input.length; off += 16, block++) {
    counter.writeUInt32LE(block, 0);
    const keystream = ecb.update(counter);
    const n = Math.min(16, input.length - off);
    for (let i = 0; i < n; i++) out[off + i] = input[off + i] ^ keystream[i];
  }
  return out;
}

/**
 * Decrypt a WinZip AES entry. `data` is the raw entry payload:
 *   salt || 2-byte password verifier || ciphertext || 10-byte HMAC-SHA1
 *
 * Returns the still-COMPRESSED plaintext (inflate it per AesParams.actualMethod) and whether the
 * authentication tag matched. Throws ZipPasswordError("wrong-password") when the verifier fails,
 * which is the cheap check — it runs before any decryption work.
 */
export function aesDecrypt(
  data: Buffer,
  password: string,
  strength: 1 | 2 | 3,
): { plaintext: Buffer; macOk: boolean } {
  const saltLen = SALT_LEN[strength];
  const keyLen = KEY_LEN[strength];
  if (data.length < saltLen + PW_VERIFY_LEN + MAC_LEN) {
    throw new ZipPasswordError("AES entry is truncated", "unsupported-encryption");
  }

  const salt = data.subarray(0, saltLen);
  const verifier = data.subarray(saltLen, saltLen + PW_VERIFY_LEN);
  const ciphertext = data.subarray(saltLen + PW_VERIFY_LEN, data.length - MAC_LEN);
  const mac = data.subarray(data.length - MAC_LEN);

  // One PBKDF2 pass yields the encryption key, the MAC key, and the 2-byte verifier, concatenated.
  const derived = pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, keyLen * 2 + PW_VERIFY_LEN, "sha1");
  const encKey = derived.subarray(0, keyLen);
  const macKey = derived.subarray(keyLen, keyLen * 2);
  const expectedVerifier = derived.subarray(keyLen * 2);

  if (!timingSafeEqual(expectedVerifier, verifier)) {
    throw new ZipPasswordError("wrong password for AES-encrypted entry", "wrong-password");
  }

  const plaintext = aesCtrXor(encKey, ciphertext);
  // The HMAC is computed over the CIPHERTEXT, not the plaintext.
  const computed = createHmac("sha1", macKey).update(ciphertext).digest().subarray(0, MAC_LEN);
  return { plaintext, macOk: timingSafeEqual(computed, mac) };
}
