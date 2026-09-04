import { randomBytes, scrypt, createCipheriv, createDecipheriv } from "node:crypto";

// The .dfircase container format: [8B magic][16B salt][12B IV][16B GCM auth tag][ciphertext].
// AES-256-GCM authenticates the WHOLE archive — a wrong password or any tampering/corruption
// fails loudly (DecryptionError) rather than silently producing garbage. This is app-native
// encryption, not a cross-tool-compatible encrypted ZIP: the container is only openable via
// DFIR Companion's own Import, by design (see the design doc — no new dependency, and the whole
// point of the export is to hand the case to another DFIR Companion instance).
//
// The trailing digits of the magic are a FORMAT VERSION, and the version is what selects the
// scrypt parameters below — the header carries no separate KDF field. That makes one rule
// absolute: NEVER change the parameters of an existing version. The key would come out
// different, GCM authentication would fail, and every archive already written under that
// version would be unopenable forever while reporting itself as "incorrect password". Raise the
// cost by adding a version, as v2 did, and keep the old one readable.
const MAGIC_LEN = 8;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const HEADER_LEN = MAGIC_LEN + SALT_LEN + IV_LEN + TAG_LEN;

export class DecryptionError extends Error {
  constructor(message = "incorrect password or corrupted archive") {
    super(message);
    this.name = "DecryptionError";
  }
}

// v1 — shipped in 0.31.0: Node's scryptSync defaults (N=2^14). Too weak for an offline attack on
// a .dfircase file, which an attacker holds with unlimited attempts. Kept READ-ONLY so archives
// already written in this format — including the ones the delete-with-encrypted-archive flow left
// as a case's only remaining copy — still open. Nothing writes v1 any more.
const SCRYPT_V1 = { N: 1 << 14, r: 8, p: 1, maxmem: 32 * 1024 * 1024 } as const;
// v2 — the current writer: N=2^17, OWASP's recommendation for sensitive data at rest (~1s per
// derivation, acceptable for a one-time export/import; maxmem must clear 128*N*r = 128 MiB).
// The interactive case-password lock (casePassword.ts) keeps the weaker default since online
// attempts are rate-limited (issue #244).
const SCRYPT_V2 = { N: 1 << 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 } as const;

type ScryptParams = typeof SCRYPT_V1 | typeof SCRYPT_V2;

const FORMATS: ReadonlyArray<{ version: number; magic: Buffer; scrypt: ScryptParams }> = [
  { version: 1, magic: Buffer.from("DFIRCZ01", "utf8"), scrypt: SCRYPT_V1 },
  { version: 2, magic: Buffer.from("DFIRCZ02", "utf8"), scrypt: SCRYPT_V2 },
];
const CURRENT_FORMAT = FORMATS[FORMATS.length - 1];

/** The container version {@link encryptBuffer} writes. A version is only ever ADDED to raise the
 * KDF cost (see the rule above), so a container whose version is BELOW this one was written under
 * weaker parameters. That is what makes `version < CURRENT_FORMAT_VERSION` a sound weakness test,
 * and it keeps working when a v3 arrives without any caller remembering to update a hardcoded 2. */
export const CURRENT_FORMAT_VERSION = CURRENT_FORMAT.version;

function findFormat(container: Buffer): (typeof FORMATS)[number] | undefined {
  if (container.length < HEADER_LEN) return undefined;
  return FORMATS.find((f) => container.subarray(0, MAGIC_LEN).equals(f.magic));
}

/** The container version of `container`, or undefined if it isn't a .dfircase archive this build
 * reads (garbage, truncated, or written by a NEWER build).
 *
 * Reads the magic only — no password, no derivation — so it is cheap. That is exactly why the
 * import route reports it only AFTER a successful decrypt (#672): an endpoint that answered this
 * question without a password would let an unauthenticated caller sort a pile of archives by which
 * ones are cheapest to crack offline. */
export function readFormatVersion(container: Buffer): number | undefined {
  return findFormat(container)?.version;
}

// Async on purpose: at N=2^17 one derivation is about a second of CPU, and scryptSync spent that
// second on the event loop — every export or import froze every other request, WebSocket update
// and timer for its duration (#862). The callback form runs it on libuv's threadpool instead; the
// parameters and the container bytes are unchanged, so every archive already written still opens.
function scryptAsync(password: string, salt: Buffer, keyLen: number, params: ScryptParams): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keyLen, params, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

function deriveKey(password: string, salt: Buffer, params: ScryptParams): Promise<Buffer> {
  return scryptAsync(password, salt, KEY_LEN, params);
}

/** Encrypt `data` under `password`, in the current container version. Each call uses a fresh
 * random salt + IV. */
export async function encryptBuffer(data: Buffer, password: string): Promise<Buffer> {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = await deriveKey(password, salt, CURRENT_FORMAT.scrypt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([CURRENT_FORMAT.magic, salt, iv, tag, ciphertext]);
}

/** Decrypt a container produced by {@link encryptBuffer}, in ANY version this build still reads.
 * Throws {@link DecryptionError} on a wrong password, corrupted/tampered bytes, or a buffer that
 * isn't a .dfircase container (including one written by a NEWER build — an unknown version is
 * reported as such rather than as a wrong password). */
export async function decryptBuffer(container: Buffer, password: string): Promise<Buffer> {
  const format = findFormat(container);
  if (!format) throw new DecryptionError("not a valid .dfircase archive");
  let offset = MAGIC_LEN;
  const salt = container.subarray(offset, offset + SALT_LEN);
  offset += SALT_LEN;
  const iv = container.subarray(offset, offset + IV_LEN);
  offset += IV_LEN;
  const tag = container.subarray(offset, offset + TAG_LEN);
  offset += TAG_LEN;
  const ciphertext = container.subarray(offset);

  const key = await deriveKey(password, salt, format.scrypt);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new DecryptionError();
  }
}
