// Bounded capture of a spawned child's stdout and stderr, shared by the two runners that shell out
// to analyst-installed forensic binaries (integrations/tools/toolRunner.ts and
// integrations/velociraptor/velociraptorApi.ts — the latter is the one the former was modelled on,
// and both carried the same two defects).
//
// WHAT WENT WRONG, twice:
//
//   1. Only stdout was capped. stderr was appended to a string with no limit at all until the child
//      exited or the timeout fired, so a malfunctioning or hostile tool could exhaust the Node heap
//      by writing to the stream nobody was watching. A forensic tool is an arbitrary local binary
//      the analyst pointed us at; "it will not do that" is not a property we can assert.
//
//   2. The cap counted JavaScript string length while the option was named maxOutputBytes. A UTF-16
//      code unit is not a byte: multibyte output could exceed the intended limit several times over
//      before the check fired. Decoding per chunk was independently wrong — a multibyte character
//      split across a chunk boundary decodes to replacement characters, quietly corrupting output
//      that an importer then parses.
//
// So: count raw Buffer bytes, hold chunks undecoded, and decode ONCE at the end.

/** Default ceiling for the retained stderr tail. Diagnostics, not evidence — the end is the useful part. */
export const DEFAULT_STDERR_TAIL_BYTES = 64 * 1024;

/**
 * Accumulates a child process's output under an explicit byte budget.
 *
 * stdout is the tool's RESULT, so exceeding its cap is a failure the caller must surface (and kill
 * the child over) — truncating it would hand an importer a silently incomplete artifact.
 *
 * stderr is DIAGNOSTIC, so it is bounded by keeping a rolling tail rather than by failing: a tool
 * that logs verbosely is normal, the tail is what an error message needs, and dropping the older
 * bytes costs nothing an analyst was going to read. It therefore can never be the reason a run dies
 * — but it also can never grow without bound.
 */
export class ChildOutputCollector {
  private readonly stdoutChunks: Buffer[] = [];
  private stderrChunks: Buffer[] = [];
  private stdoutBytes = 0;
  private stderrBytes = 0;

  constructor(
    private readonly maxStdoutBytes: number,
    private readonly stderrTailBytes: number = DEFAULT_STDERR_TAIL_BYTES,
  ) {}

  /** Bytes of stdout captured so far. */
  get stdoutByteLength(): number {
    return this.stdoutBytes;
  }

  /** Bytes of stderr currently retained (never more than the tail budget). */
  get stderrByteLength(): number {
    return this.stderrBytes;
  }

  /**
   * Add a stdout chunk. Returns true when the byte budget is now exceeded, which the caller must
   * treat as fatal — kill the child and reject. The chunk is still retained so a caller that wants
   * to report what it got can.
   */
  pushStdout(chunk: Buffer): boolean {
    this.stdoutChunks.push(chunk);
    this.stdoutBytes += chunk.byteLength;
    return this.stdoutBytes > this.maxStdoutBytes;
  }

  /** Add a stderr chunk, discarding whole older chunks so the retained tail stays within budget. */
  pushStderr(chunk: Buffer): void {
    this.stderrChunks.push(chunk);
    this.stderrBytes += chunk.byteLength;
    // Drop from the FRONT: the tail is the part that explains a failure.
    while (this.stderrChunks.length > 1 && this.stderrBytes > this.stderrTailBytes) {
      const dropped = this.stderrChunks.shift();
      this.stderrBytes -= dropped ? dropped.byteLength : 0;
    }
    // A single chunk larger than the whole budget still has to be cut, or one enormous write
    // defeats the limit on its own.
    if (this.stderrChunks.length === 1 && this.stderrBytes > this.stderrTailBytes) {
      const only = this.stderrChunks[0];
      this.stderrChunks = [only.subarray(only.byteLength - this.stderrTailBytes)];
      this.stderrBytes = this.stderrTailBytes;
    }
  }

  /**
   * Decode both streams. Done once, on the concatenated bytes, so a multibyte character split
   * across chunk boundaries survives intact.
   */
  text(): { stdout: string; stderr: string } {
    return {
      stdout: Buffer.concat(this.stdoutChunks).toString("utf8"),
      stderr: Buffer.concat(this.stderrChunks).toString("utf8"),
    };
  }
}
