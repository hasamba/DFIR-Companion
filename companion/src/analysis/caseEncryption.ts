import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from "node:crypto";

// The .dfircase container format: [8B magic][16B salt][12B IV][16B GCM auth tag][ciphertext].
// AES-256-GCM authenticates the WHOLE archive — a wrong password or any tampering/corruption
// fails loudly (DecryptionError) rather than silently producing garbage. This is app-native
// encryption, not a cross-tool-compatible encrypted ZIP: the container is only openable via
// DFIR Companion's own Import, by design (see the design doc — no new dependency, and the whole
// point of the export is to hand the case to another DFIR Companion instance).
const MAGIC = Buffer.from("DFIRCZ01", "utf8");
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const HEADER_LEN = MAGIC.length + SALT_LEN + IV_LEN + TAG_LEN;

export class DecryptionError extends Error {
  constructor(message = "incorrect password or corrupted archive") {
    super(message);
    this.name = "DecryptionError";
  }
}

function deriveKey(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, KEY_LEN);
}

/** Encrypt `data` under `password`. Each call uses a fresh random salt + IV. */
export function encryptBuffer(data: Buffer, password: string): Buffer {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = deriveKey(password, salt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([MAGIC, salt, iv, tag, ciphertext]);
}

/** Decrypt a container produced by {@link encryptBuffer}. Throws {@link DecryptionError} on a
 * wrong password, corrupted/tampered bytes, or a buffer that isn't a .dfircase container. */
export function decryptBuffer(container: Buffer, password: string): Buffer {
  if (container.length < HEADER_LEN || !container.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new DecryptionError("not a valid .dfircase archive");
  }
  let offset = MAGIC.length;
  const salt = container.subarray(offset, offset + SALT_LEN);
  offset += SALT_LEN;
  const iv = container.subarray(offset, offset + IV_LEN);
  offset += IV_LEN;
  const tag = container.subarray(offset, offset + TAG_LEN);
  offset += TAG_LEN;
  const ciphertext = container.subarray(offset);

  const key = deriveKey(password, salt);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new DecryptionError();
  }
}
