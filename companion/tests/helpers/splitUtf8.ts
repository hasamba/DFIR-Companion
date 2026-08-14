/**
 * A child process that writes ONE multi-byte character across TWO stdout/stderr writes.
 *
 * Every spawn site in src/ accumulates child output as `text += chunk.toString()`. That decodes
 * each chunk INDEPENDENTLY, so a UTF-8 sequence straddling a chunk boundary is decoded as two
 * broken halves and both become U+FFFD. The reader never sees the character, and the byte count
 * changes — enough to make `JSON.parse` throw on a Velociraptor JSONL row and silently drop a piece
 * of evidence, which is the failure this helper exists to reproduce.
 *
 * The obvious reproduction — write 600 KB and let the 64 KB pipe buffer do the splitting — works,
 * but it is slow and it depends on a pipe buffer size that is not part of any contract. Two
 * explicit writes with a timer between them force exactly one boundary, in a payload small enough
 * to compare with `toBe`. The contract under test is the same either way: a chunk boundary is a
 * BYTE boundary and may fall anywhere, including inside a character.
 *
 * The fix these tests drive is `stream.setEncoding("utf8")`, which puts a StringDecoder in front of
 * the stream so an incomplete trailing sequence is held back until the bytes that finish it arrive.
 * Removing that one line from a spawn site fails its test here.
 */
import { chmodSync, writeFileSync } from "node:fs";

/**
 * Cyrillic + CJK + a 4-byte emoji — the character classes that show up in real case data (a
 * username, a file path, a filename) and the ones that break. Deliberately NOT pure ASCII.
 */
export const SPLIT_UTF8_TEXT = "Иван/日本語/🧪";

/**
 * Byte 21 of the 23-byte encoding sits INSIDE the trailing 4-byte emoji (bytes 19-22), so neither
 * half is valid UTF-8 on its own. Asserted at module load: a payload edit that accidentally moved
 * this to a character boundary would leave every test below passing against the broken code.
 */
const SPLIT_AT = 21;

const encoded = Buffer.from(SPLIT_UTF8_TEXT, "utf8");
if (encoded.length !== 23 || (encoded[SPLIT_AT] & 0xc0) !== 0x80) {
  throw new Error(`splitUtf8: byte ${SPLIT_AT} of SPLIT_UTF8_TEXT is not a UTF-8 continuation byte`);
}

/**
 * Node source that writes `before + SPLIT_UTF8_TEXT + after` to `stream` in two raw-byte writes,
 * with a delay between them so they arrive as two separate 'data' events. The split always lands
 * inside SPLIT_UTF8_TEXT's trailing emoji, wherever `before` puts it.
 *
 * `before`/`after` let a caller wrap the payload in whatever shape its reader parses — a JSONL row,
 * a login banner — so the test asserts on what the code actually does with the output.
 */
export function splitUtf8Script(
  opts: { stream?: "stdout" | "stderr"; before?: string; after?: string } = {},
): string {
  const stream = opts.stream ?? "stdout";
  const before = opts.before ?? "";
  const after = opts.after ?? "";
  const splitAt = Buffer.byteLength(before, "utf8") + SPLIT_AT;
  return [
    `const b=Buffer.from(${JSON.stringify(before + SPLIT_UTF8_TEXT + after)},"utf8");`,
    `process.${stream}.write(b.subarray(0,${splitAt}));`,
    `setTimeout(()=>{process.${stream}.write(b.subarray(${splitAt}));},30);`,
  ].join("");
}

/**
 * Wraps a script as an executable `#!/usr/bin/env node` shim, for the spawn sites whose argv is
 * fixed by the caller (`velociraptor query …`, `claude auth login`) and so cannot be pointed at
 * `node -e`. The shim ignores its arguments. POSIX only — the shebang is what makes it executable,
 * so guard the calling test with `it.skipIf(process.platform === "win32")`.
 */
export function writeNodeShim(path: string, script: string): string {
  writeFileSync(path, `#!/usr/bin/env node\n${script}\n`);
  chmodSync(path, 0o755);
  return path;
}

/** Node source that writes `text` in one go — for byte-budget tests that need a known byte count. */
export function writeOnceScript(text: string, stream: "stdout" | "stderr" = "stdout"): string {
  return `process.${stream}.write(Buffer.from(${JSON.stringify(text)},"utf8"));`;
}
