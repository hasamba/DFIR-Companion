import type { FileHandle } from "node:fs/promises";
import { unwrapSource, type SiemImportOptions, type SiemParseResult } from "./siemImport.js";
import { stampSourceArtifactHash } from "./canonicalEvent.js";
import { WindowsEventBuilder } from "./siemBuildProgress.js";
import { hasUtf16Bom, readDecodedText, textLines, STREAMED_TEXT_CHUNK_BYTES } from "./streamedTextFile.js";

type Row = Record<string, unknown>;

/**
 * A SIEM / EDR JSON Lines export (a winlogbeat or filebeat dump) parsed from disk one record at a
 * time (#2823), instead of as one string. The whole-text importer (`parseSiemExport`) held the
 * decoded text, its split lines, every parsed record and every mapped row at once — a 100 MB file
 * kept at 2,000 rows peaked about 0.9 GB above the idle server.
 *
 * The result is the whole-text importer's, exactly:
 * - Only a file `extractRecords` reads as JSON Lines streams. The probe below demands that the first
 *   non-blank line is one whole JSON object and that something follows it, so the text is not one
 *   JSON value and `extractRecords` takes its JSON Lines branch.
 * - Each line is read by that branch's rules: trimmed, blank and malformed lines skipped, an Elastic
 *   `_source` unwrapped, an empty object skipped. Lines split on CR or LF, as `\r\n|\r|\n` does.
 * - The rows go through WindowsEventBuilder with the OS-behaviour rules off: the incremental form of
 *   buildSiemResult (DNS rows held for the two whole-upload passes, every other row aggregated at
 *   once, ordered by its record number).
 * - A file whose JSON Lines branch yields no record at all (`{}` then pretty-printed JSON) returns
 *   null, and the caller parses the stored file whole as before (the concatenated-JSON fallback).
 */

const MAX_FIRST_LINE_CHARS = 64 * 1024 * 1024;

/** One JSON Lines line as `extractRecords` reads it; null when it yields no record. */
export function siemRecordFromLine(line: string): Row | null {
  const l = line.trim();
  if (!l) return null;
  let obj: unknown;
  try {
    obj = JSON.parse(l);
  } catch {
    return null;
  }
  const rec = unwrapSource(obj);
  return rec && Object.keys(rec).length > 0 ? rec : null;
}

// Decoded text read by positional reads on the caller's handle, from `pos`.
async function readText(
  fh: FileHandle,
  decoder: TextDecoder,
  pos: number,
): Promise<{ text: string; bytesRead: number }> {
  const buf = Buffer.allocUnsafe(STREAMED_TEXT_CHUNK_BYTES);
  const { bytesRead } = await fh.read(buf, 0, buf.length, pos);
  return { text: decoder.decode(buf.subarray(0, bytesRead), { stream: bytesRead > 0 }), bytesRead };
}

/**
 * Whether the file the caller holds open is SIEM JSON Lines that streams: UTF-8, its first non-blank
 * line one whole JSON object, and non-whitespace after it (scanned chunk by chunk to the end if need
 * be). Positional reads only, never past the first line plus its whitespace tail.
 */
export async function probeSiemJsonLinesHead(fh: FileHandle): Promise<boolean> {
  if (await hasUtf16Bom(fh)) return false;
  const decoder = new TextDecoder("utf-8");
  const terminator = /[\r\n]/g;
  let pos = 0;
  let pending = ""; // from the start of the line being looked for
  let found = false;
  for (;;) {
    const { text, bytesRead } = await readText(fh, decoder, pos);
    pos += bytesRead;
    terminator.lastIndex = pending.length;
    pending += text;
    if (!found) {
      // Walk the complete lines read so far, skipping blank ones, to the first non-blank one.
      for (let m = terminator.exec(pending); m; m = terminator.exec(pending)) {
        const line = pending.slice(0, m.index).trim();
        pending = pending.slice(m.index + 1);
        terminator.lastIndex = 0;
        if (!line) continue;
        if (!siemRecordFromLine(line)) return false; // so the JSON Lines branch yields a record
        found = true;
        break;
      }
      if (!found) {
        if (!bytesRead || pending.length > MAX_FIRST_LINE_CHARS) return false;
        continue;
      }
    }
    if (/\S/.test(pending)) return true;
    if (!bytesRead) return false;
    pending = "";
  }
}

/**
 * Parse a SIEM JSON Lines file from disk. Null when the JSON Lines branch yields no record — the
 * caller then parses the stored file whole, which takes `extractRecords`' last-resort branch.
 */
export async function parseSiemJsonLinesFile(
  path: string,
  opts: SiemImportOptions = {},
  io: { signal?: AbortSignal; chunkBytes?: number } = {},
): Promise<SiemParseResult | null> {
  const text = readDecodedText(path, io);
  const builder = new WindowsEventBuilder("ndjson", opts, { osBehaviour: false });
  let index = 0;
  for await (const line of textLines(text.chunks)) {
    const rec = siemRecordFromLine(line);
    if (rec) builder.add(rec, index++);
  }
  if (index === 0) return null;
  const parsed = builder.finish();
  return { ...parsed, events: stampSourceArtifactHash(parsed.events, "", text.sourceArtifactHash()) };
}
