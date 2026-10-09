import { createWriteStream } from "node:fs";
import { unlink, type FileHandle } from "node:fs/promises";
import { createHash } from "node:crypto";
import { pipeline } from "node:stream/promises";

/**
 * Copy the whole open file to `dest`, which must not exist (never overwrite evidence already on
 * disk, #214), hashing it in the same stream pass. One pass matters: server-path imports run to
 * hundreds of megabytes, and a second read for the hash would double the I/O (#2055). A partial
 * copy this call created is removed on failure; an existing `dest` is never touched. The caller
 * owns case-write admission (#1855).
 */
export async function copyHandleHashed(
  handle: FileHandle,
  dest: string,
): Promise<{ bytes: number; sha256: string }> {
  const out = createWriteStream(dest, { flags: "wx" });
  let created = false;
  out.once("open", () => (created = true));
  let bytes = 0;
  const hash = createHash("sha256");
  const src = handle.createReadStream({ start: 0, autoClose: false, highWaterMark: 1 << 20 });
  src.on("data", (chunk) => {
    bytes += chunk.length;
    hash.update(chunk);
  });
  try {
    await pipeline(src, out);
  } catch (err) {
    if (created) await unlink(dest).catch(() => undefined);
    throw err;
  }
  return { bytes, sha256: hash.digest("hex") };
}
