import { randomBytes, scrypt as nodeScrypt, timingSafeEqual } from "node:crypto";

const VERSION = "scrypt-v1";
const COST = 16_384;
const BLOCK_SIZE = 8;
const PARALLELISM = 1;
const SALT_BYTES = 16;
const HASH_BYTES = 32;
const MAX_MEMORY = 64 * 1024 * 1024;

export const MIN_LOCAL_PASSWORD_LENGTH = 6;

function scrypt(password: string, salt: Buffer, length: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    nodeScrypt(
      password,
      salt,
      length,
      {
        N: COST,
        r: BLOCK_SIZE,
        p: PARALLELISM,
        maxmem: MAX_MEMORY,
      },
      (err, derived) => {
        if (err) reject(err);
        else resolve(derived);
      },
    );
  });
}

export function validateLocalPassword(password: string): void {
  if (password.length < MIN_LOCAL_PASSWORD_LENGTH) {
    throw new Error(`password must be at least ${MIN_LOCAL_PASSWORD_LENGTH} characters`);
  }
  if (password.length > 1_024) throw new Error("password is too long");
}

export async function hashLocalPassword(password: string): Promise<string> {
  validateLocalPassword(password);
  const salt = randomBytes(SALT_BYTES);
  const derived = await scrypt(password, salt, HASH_BYTES);
  return [
    VERSION,
    String(COST),
    String(BLOCK_SIZE),
    String(PARALLELISM),
    salt.toString("base64url"),
    derived.toString("base64url"),
  ].join("$");
}

export async function verifyLocalPassword(password: string, encoded: string): Promise<boolean> {
  const [version, costText, blockText, parallelText, saltText, hashText, ...rest] = encoded.split("$");
  if (version !== VERSION || rest.length > 0) return false;
  const cost = Number(costText);
  const blockSize = Number(blockText);
  const parallelism = Number(parallelText);
  if (cost !== COST || blockSize !== BLOCK_SIZE || parallelism !== PARALLELISM) return false;
  let salt: Buffer;
  let expected: Buffer;
  try {
    salt = Buffer.from(saltText, "base64url");
    expected = Buffer.from(hashText, "base64url");
  } catch {
    return false;
  }
  if (salt.length !== SALT_BYTES || expected.length !== HASH_BYTES || password.length > 1_024) return false;
  const actual = await scrypt(password, salt, expected.length);
  return timingSafeEqual(actual, expected);
}
