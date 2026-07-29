// Decryption primitives for password-protected ZIP entries. Pure functions over buffers — no ZIP
// structure knowledge lives here (see zipArchive.ts for that) and no I/O.
//
// Needed because SO-CRATES can only ever try the password "infected": its upload handler builds the
// password list server-side from the filename, and it extracts through Python's zipfile, which has
// never supported WinZip AES. An analyst-supplied password, or any 7-Zip archive, has to be opened
// here instead.

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
    key1 = (Math.imul(key1, 134775813) + 1) >>> 0;   // imul: the product overflows 2^53 otherwise
    key2 = crcUpdate(key2, key1 >>> 24);
  };

  for (const b of Buffer.from(password, "utf8")) updateKeys(b);

  const out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) {
    const temp = (key2 | 2) & 0xffff;
    const plain = data[i] ^ ((Math.imul(temp, temp ^ 1) >> 8) & 0xff);
    out[i] = plain;
    updateKeys(plain);   // the keystream depends on the PLAINTEXT, so update after decrypting
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
  return checkByte === (crc >>> 24) || checkByte === ((modTime >> 8) & 0xff);
}
