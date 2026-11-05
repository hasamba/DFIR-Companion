import { hkdfSync } from "node:crypto";
import { open, seal } from "../serverSets/secretBox.js";

// The cloud vault reuses the server sets' AES-256-GCM seal/open, with its own HKDF info string and
// the vault key file — never the instance secret, which a data-folder backup also holds.
const HKDF_INFO = "dfir-cloud-vault-v1";

export function deriveCloudVaultKey(vaultKey: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", vaultKey, Buffer.alloc(0), HKDF_INFO, 32));
}

export function sealSecrets(secrets: object, key: Buffer): string {
  return seal(JSON.stringify(secrets), key);
}

/** The secrets object, or undefined when this key does not open the entry. Never throws. */
export function openSecrets(sealed: string, key: Buffer): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(open(sealed, key)) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}
