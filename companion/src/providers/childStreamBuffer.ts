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
 * The two streams keep OPPOSITE ends, because their consumers read opposite ends.
 *
 * stdout keeps the TAIL: `finalText` and `terminalResult` scan for the LAST `result` event and skip
 * lines that fail to parse, so dropping the oldest output costs nothing they were going to read
 * while dropping the newest would cost the answer.
 *
 * stderr keeps BOTH ENDS, because two different readers want two different parts of it and each
 * one-ended cap loses the other's:
 *
 *   - The HEAD is what gets displayed. claudeCode.ts and finalText slice the first 200 characters
 *     into the error they throw, codex.ts the first 300, and codex.ts goes further and reorders the
 *     errors it found so the real cause "isn't pushed past the truncation by that noise". A
 *     tail-drop throws that away and works against a deliberate ordering.
 *   - The TAIL is what gets CLASSIFIED. codex.ts calls classifyKind() over the whole of stderr, and
 *     analysis/ai/retry.ts treats "auth", "rate_limit" and "timeout" as the NON-retryable kinds. A
 *     rate-limit line printed after a flood of progress noise is not merely a nicer message: drop
 *     it and the kind degrades to "transport" or "other", both retryable, so the pipeline runs the
 *     same doomed call again — "tripling how long the analyst waits for the same error", in
 *     retry.ts's own words.
 *
 * So the middle is what goes. Both one-ended versions of this were written and both were wrong;
 * see StreamEnds.
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
 * Default ceiling for the retained stderr HEAD, in bytes — the part a reader slices into an error
 * message. Three orders of magnitude more than the 200-300 characters any of them takes, so no error
 * path changes behaviour.
 */
export const DEFAULT_MAX_STDERR_HEAD_BYTES = 48 * 1024;

/**
 * Default ceiling for the retained stderr TAIL, in bytes — the safety net for an error line printed
 * AFTER a flood of progress output, which classifyKind() must still be able to see. An error line is
 * short, so this is smaller than the head budget.
 */
export const DEFAULT_MAX_STDERR_TAIL_BYTES = 16 * 1024;

/**
 * Total default ceiling for retained stderr, in bytes. stderr is the stream nobody watches, which is
 * exactly why it must be bounded: a child that logs endlessly could exhaust the heap through it
 * alone while stdout stayed quiet. The SIZE matches integrations/childOutput.ts; what is kept within
 * it does not, and deliberately — see the module docblock.
 */
export const DEFAULT_MAX_STDERR_BYTES = DEFAULT_MAX_STDERR_HEAD_BYTES + DEFAULT_MAX_STDERR_TAIL_BYTES;

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

/**
 * Accumulates decoded stream chunks under a byte budget, keeping the oldest — the mirror of
 * StreamTail, for a stream whose readers slice from the front.
 *
 * Once the budget is reached nothing further is retained. Whole chunks are kept rather than a
 * string sliced to the byte, so the cap can never cut a surrogate pair in half; that costs at most
 * one pipe chunk of overshoot, the same allowance StreamTail makes at the other end.
 */
export class StreamHead {
  private readonly chunks: string[] = [];
  private bytes = 0;
  private full = false;

  /** @param maxBytes retained-byte ceiling. `Infinity` keeps everything. */
  constructor(private readonly maxBytes: number) {}

  /** Bytes currently retained. Exceeds the cap only by the single chunk that reached it. */
  get byteLength(): number {
    return this.bytes;
  }

  /** Add a chunk, unless the budget is already met — later output is dropped, not the earlier. */
  push(chunk: string): void {
    if (this.full) return;
    this.chunks.push(chunk);
    this.bytes += Buffer.byteLength(chunk, "utf8");
    if (this.bytes >= this.maxBytes) this.full = true;
  }

  /** Everything still retained, in arrival order. */
  text(): string {
    return this.chunks.join("");
  }
}

/**
 * The marker standing in for the discarded middle.
 *
 * Carries NO DIGITS on purpose. classifyKind() regex-scans the whole retained string, and one of its
 * patterns is /5\d\d/ for a server-error status — a byte count of "512 bytes elided" would match it
 * and reclassify the error. The size that was dropped is not worth that risk; byteLength reports what
 * was kept for anyone who needs a number.
 */
const TRUNCATION_MARKER = "\n[...stderr truncated...]\n";

/**
 * Retains both ends of a stream under two byte budgets, discarding the middle.
 *
 * For a stream with two readers that want opposite ends — one slicing a message off the front, one
 * scanning the whole text for a keyword that may only appear at the back. Either single-ended cap
 * silently costs the other reader what it needed; this costs neither, for the price of a marker
 * where the gap is.
 *
 * The marker appears only when output was ACTUALLY dropped. Emitting it whenever the head filled up
 * would claim a loss that did not happen, and a reader cannot tell a false marker from a real one.
 */
export class StreamEnds {
  private readonly head: StreamHead;
  private readonly tail: StreamTail;
  private seenBytes = 0;

  /**
   * @param maxHeadBytes bytes retained from the front. `Infinity` sends everything to the head.
   * @param maxTailBytes bytes retained from the back, once the head budget is met.
   */
  constructor(maxHeadBytes: number, maxTailBytes: number) {
    this.head = new StreamHead(maxHeadBytes);
    this.tail = new StreamTail(maxTailBytes);
  }

  /** Bytes retained across both ends. Excludes whatever the middle dropped. */
  get byteLength(): number {
    return this.head.byteLength + this.tail.byteLength;
  }

  /** Add a chunk to the head while it has room, otherwise to the rolling tail. */
  push(chunk: string): void {
    this.seenBytes += Buffer.byteLength(chunk, "utf8");
    const before = this.head.byteLength;
    this.head.push(chunk);
    // StreamHead ignores a chunk once it is full, so an unchanged byteLength means the head refused
    // this one and it belongs to the tail. Comparing sizes rather than asking the head whether it is
    // full keeps the "keep the first chunk whole" rule in one place.
    if (this.head.byteLength === before) this.tail.push(chunk);
  }

  /** Both retained ends, with a marker between them if anything was lost. */
  text(): string {
    const head = this.head.text();
    const tail = this.tail.text();
    if (!tail) return head;
    const dropped = this.seenBytes > this.byteLength;
    return dropped ? `${head}${TRUNCATION_MARKER}${tail}` : `${head}${tail}`;
  }
}
