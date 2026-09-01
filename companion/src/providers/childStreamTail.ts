/**
 * Bounded capture of a spawned CLI's decoded output, shared by the two provider runners that shell
 * out to a coding agent (claudeRunner.ts and codexRunner.ts).
 *
 * Both read a process whose output is attacker-influenced: the agent runs over forensic evidence,
 * and `--output-format stream-json` / `codex exec --json` emit one event per tool result. A run that
 * loops — or evidence crafted to make it loop — produces output with no natural end, and the obvious
 * `text += chunk` retains all of it until the Node heap gives out.
 *
 * #518 fixed that for the ONE consumer that remembered to pass a cap, leaving the fallback at
 * Infinity for claudeRunner (#762) and at no cap at all for codexRunner (#763). A limit that only
 * engages when a caller opts in is not a limit; the default below is what closes the hole, and a
 * consumer that genuinely needs the whole stream opts OUT with `Infinity`, which reads as deliberate
 * at the call site.
 *
 * What survives is the TAIL. Every consumer of these two runners reads the end: `finalText` and
 * `terminalResult` scan for the LAST `result` event and skip lines that fail to parse, and the
 * stderr readers take a 200-300 character snippet for an error message. Dropping the oldest output
 * therefore costs nothing any of them was going to read, while dropping the newest would cost the
 * answer.
 */

/**
 * Default ceiling for retained stdout, in bytes.
 *
 * Generous rather than tight, because stdout is the RESULT: this is a backstop against a run with no
 * end, not a budget any real run should reach. 64 MB is thousands of stream-json events past the
 * tail that any consumer reads, so no working call site changes behaviour — while an agent looping
 * forever now costs 64 MB instead of the process.
 */
export const DEFAULT_MAX_STDOUT_BYTES = 64 * 1024 * 1024;

/**
 * Default ceiling for retained stderr, in bytes.
 *
 * Diagnostics, not evidence — every consumer takes a short snippet of it for an error message — so
 * this matches the tail budget integrations/childOutput.ts already applies to the same stream for
 * the same reason. stderr is the one nobody watches, which is exactly why it must be bounded: a
 * child that logs endlessly could exhaust the heap through it alone while stdout stayed quiet.
 */
export const DEFAULT_MAX_STDERR_BYTES = 64 * 1024;

/**
 * Accumulates decoded stream chunks under a byte budget, keeping the newest.
 *
 * Chunks are retained as a list rather than one growing string so dropping the oldest does not mean
 * rebuilding the whole buffer on every event. Each chunk's UTF-8 size is kept alongside it, because
 * String.length counts UTF-16 code units and undercounts every non-ASCII character — and non-ASCII
 * is exactly what this output carries (hostnames, filenames, quoted log text), so a byte cap
 * measured in code units would let the buffer run to several times its stated limit.
 *
 * The chunks stay decoded, not raw: the streams are read through `setEncoding("utf8")` so a
 * multi-byte character split across a pipe boundary is reassembled by the stream's own StringDecoder
 * (#515). Joining decoded chunks preserves that; re-decoding per chunk here would undo it.
 */
export class StreamTail {
  private readonly chunks: string[] = [];
  private readonly chunkBytes: number[] = [];
  private bytes = 0;

  /** @param maxBytes retained-byte ceiling. `Infinity` keeps everything. */
  constructor(private readonly maxBytes: number) {}

  /** Bytes currently retained. Exceeds the cap only by the single newest chunk (see push). */
  get byteLength(): number {
    return this.bytes;
  }

  /** Add a chunk, then discard whole older chunks until the retained output is back in budget. */
  push(chunk: string): void {
    this.chunks.push(chunk);
    const size = Buffer.byteLength(chunk, "utf8");
    this.chunkBytes.push(size);
    this.bytes += size;
    // Keep at least the newest chunk, however large it is: a cap must never yield empty output.
    while (this.bytes > this.maxBytes && this.chunks.length > 1) {
      this.chunks.shift();
      this.bytes -= this.chunkBytes.shift()!;
    }
  }

  /** Everything still retained, in arrival order. */
  text(): string {
    return this.chunks.join("");
  }
}
