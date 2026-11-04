import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

// AES-256-GCM sealed string: `v1:<iv b64>:<tag b64>:<ciphertext b64>`.
const VERSION = "v1";
const HKDF_INFO = "dfir-server-sets-v1";

export function deriveServerSetKey(instanceSecret: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", instanceSecret, Buffer.alloc(0), HKDF_INFO, 32));
}

export function seal(plain: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return [VERSION, iv.toString("base64"), cipher.getAuthTag().toString("base64"), ct.toString("base64")].join(
    ":",
  );
}

export function open(sealed: string, key: Buffer): string {
  const parts = sealed.split(":");
  if (parts.length !== 4 || parts[0] !== VERSION)
    throw new Error("server set secret cannot decrypt: bad format");
  try {
    const [, iv, tag, ct] = parts.map((p) => Buffer.from(p, "base64"));
    // A fixed 16-byte tag: without it GCM accepts a truncated tag, so a forger needs only 4 bytes.
    const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  } catch {
    throw new Error("server set secret cannot decrypt: wrong key or corrupt data");
  }
}
