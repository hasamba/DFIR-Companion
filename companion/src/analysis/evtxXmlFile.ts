import type { ImportDebugRecorder } from "./importDebug.js";
import type { SiemImportOptions, SiemParseResult } from "./siemImport.js";
import { stampSourceArtifactHash } from "./canonicalEvent.js";
import { parseEventBlock } from "./evtxXmlImport.js";
import { throwIfImportAborted, WindowsEventBuilder } from "./siemBuildProgress.js";
import { readDecodedText } from "./streamedTextFile.js";

/**
 * A Windows Event XML export parsed from disk one `<Event>` block at a time (#2823), instead of as
 * one string. Same blocks, records, builder (OS-behaviour rules on) and hash as `parseEvtxXmlProgress`
 * over the whole decoded text:
 *
 * - Blocks are found with the whole-text regex. The buffer is the text from the end of the last block
 *   (or from the first `<Event` still unclosed), so a block split across chunks is matched as one, and
 *   a match inside the buffer is the match the whole string gives: the lazy body ends at the first
 *   close tag after its open tag, and that tag is in the buffer. The close tag is looked for only in
 *   the newly read text, so an unclosed block is never rescanned chunk after chunk.
 * - The parse-progress total counts `<Event\b` like the whole read: a first pass over the file.
 *   Processing progress is reported once, after the parse, because the rows are processed as they are
 *   read; the numbers are the same, the steps between are fewer.
 */

// The global (`g`) patterns are built per call, never shared: their lastIndex is a cursor, and two
// imports of different cases scan at once with awaits between their steps.
const blockRe = (): RegExp => /<Event\b[^>]*>([\s\S]*?)<\/Event>/gi;
const OPEN_RE = /<Event\b/i;
const closeRe = (): RegExp => /<\/Event>/gi;
const openCountRe = (): RegExp => /<Event\b/gi;
const OPEN_LEN = "<Event".length;
const CLOSE_LEN = "</Event>".length;
const YIELD_EVERY = 250;
const PROGRESS_EVERY = 5000;

type Progress = (done: number, total: number) => void | Promise<void>;

const yieldToServer = (): Promise<void> => new Promise<void>((resolve) => setImmediate(resolve));

/** `<Event\b` occurrences in the file, read in parts: an open tag at a chunk's end waits for the next. */
async function countOpenTags(path: string, signal?: AbortSignal, chunkBytes?: number): Promise<number> {
  const opens = openCountRe();
  let total = 0;
  let carry = "";
  for await (const chunk of readDecodedText(path, { signal, chunkBytes }).chunks) {
    const text = carry + chunk;
    const limit = text.length - OPEN_LEN; // a tag starting at or past here has no boundary char yet
    opens.lastIndex = 0;
    for (let m = opens.exec(text); m && m.index < limit; m = opens.exec(text)) total++;
    carry = text.slice(Math.max(0, limit));
  }
  opens.lastIndex = 0;
  while (opens.exec(carry) !== null) total++;
  return total;
}

// The buffer, past the last block, starts at its first `<Event` — text before it can start no block.
function trimToOpen(buf: string): string {
  const open = OPEN_RE.exec(buf);
  if (open) return open.index ? buf.slice(open.index) : buf;
  return buf.slice(-(OPEN_LEN - 1)); // a partial "<Even" at the end may still become an open tag
}

/** Every `<Event>` block of the file, in order, as the whole-text regex finds them. */
export async function* eventBlocks(chunks: AsyncIterable<string>): AsyncGenerator<string, void, undefined> {
  const blocks = blockRe();
  const closes = closeRe();
  let buf = "";
  for await (const chunk of chunks) {
    const closeFrom = Math.max(0, buf.length - (CLOSE_LEN - 1));
    buf += chunk;
    closes.lastIndex = closeFrom;
    if (!closes.test(buf)) {
      buf = trimToOpen(buf);
      continue;
    }
    blocks.lastIndex = 0;
    let end = 0;
    for (let m = blocks.exec(buf); m; m = blocks.exec(buf)) {
      end = blocks.lastIndex;
      yield m[1];
    }
    buf = trimToOpen(buf.slice(end));
  }
}

export async function parseEvtxXmlFile(
  path: string,
  opts: SiemImportOptions & { debug?: ImportDebugRecorder } = {},
  onParseProgress?: Progress,
  onProcessProgress?: Progress,
  signal?: AbortSignal,
  chunkBytes?: number,
): Promise<SiemParseResult> {
  throwIfImportAborted(signal);
  const total = await countOpenTags(path, signal, chunkBytes);
  const builder = new WindowsEventBuilder("winevent-xml", opts);
  if (total === 0) await onParseProgress?.(0, 0);
  const text = readDecodedText(path, { signal, chunkBytes });
  let scanned = 0;
  let records = 0;
  for await (const block of eventBlocks(text.chunks)) {
    throwIfImportAborted(signal);
    scanned++;
    const record = parseEventBlock(block);
    if (record) builder.add(record, records++);
    if (scanned % PROGRESS_EVERY === 0) await onParseProgress?.(scanned, total);
    if (scanned % YIELD_EVERY === 0) {
      await yieldToServer();
      throwIfImportAborted(signal);
    }
  }
  if (total > 0 && scanned % PROGRESS_EVERY !== 0) await onParseProgress?.(scanned, total);
  throwIfImportAborted(signal);
  if (total > 0) opts.debug?.skipped("no_event_id", scanned - records); // a block with no EventID is not an event
  if (records > 0) await onProcessProgress?.(records, records);
  for (const n of builder.drainHeld()) if (n % YIELD_EVERY === 0) await yieldToServer();
  await yieldToServer();
  throwIfImportAborted(signal);
  for (const n of builder.drainDns()) if (n % YIELD_EVERY === 0) await yieldToServer();
  throwIfImportAborted(signal);
  const parsed = builder.finish();
  return { ...parsed, events: stampSourceArtifactHash(parsed.events, "", text.sourceArtifactHash()) };
}
