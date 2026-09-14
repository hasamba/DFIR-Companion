// The envelope block a memory run-envelope row carries (#933 item 12, second half — #1016): what
// the uploader's run envelope STATES about one Volatility run (the command, the plugin, the exit
// status, the digests of the stdout it embeds and of the image), and the verdict read from those
// statements alone. `basis` says what every reader must keep: the envelope is uploader-supplied
// and unsigned — it is a statement about the run, not evidence of it; and an empty result speaks
// only for the pages the dump holds.
// Kept beside canonicalEvent.ts so the envelope schema stays within its size bound.

import { z } from "zod";

export const memoryRunVerdictSchema = z.object({
  kind: z.enum([
    "completed-no-rows",
    "completed-with-rows",
    "did-not-complete-validation",
    "did-not-complete-page-error",
    "did-not-complete-exit",
    "volatility-2",
    "indeterminate",
    "unbound",
  ]),
  words: z.string(),
  /** The rows the embedded export holds, when it was read. */
  rows: z.number().int().nonnegative().optional(),
  /** The requirement line the verdict cites, neutralised, when there is one. */
  requirement: z.string().optional(),
  /** True when the run exited 0 while stderr carried a traceback — exit 0 wins, the traceback is shown. */
  tracebackOnSuccess: z.boolean().optional(),
  /** The dump-type qualification from a crashinfo run of the SAME image in the same bundle, when one applies. */
  dumpQualification: z.string().optional(),
});

export const memoryRunBlockSchema = z.object({
  envelopeVersion: z.number().int().positive(),
  plugin: z.string(),
  command: z.string(),
  exitStatus: z.number().int(),
  /** `sha256:` digests; the stdout digest is computed over the embedded bytes (base64) or text (UTF-8), as `stdoutEncoding` says. */
  stdoutSha256: z.string(),
  stdoutEncoding: z.enum(["bytes", "text-utf8", "none"]),
  /** The digest the envelope STATED, when it stated one; equal to `stdoutSha256` when the run is bound. */
  statedStdoutSha256: z.string().optional(),
  imageSha256: z.string(),
  volatilityVersion: z.string().optional(),
  symbols: z.string().optional(),
  renderer: z.string().optional(),
  startedAt: z.string().optional(),
  endedAt: z.string().optional(),
  /** Whether the envelope's statements were applied to the embedded export. */
  bound: z.boolean(),
  verdict: memoryRunVerdictSchema,
  /** The stderr lines the verdict rests on, neutralised and bounded. */
  stderrLines: z.array(z.string()),
  basis: z.literal(
    "an uploader-supplied, unsigned run envelope; its statements are read, not verified; an empty result speaks only for the pages the dump holds",
  ),
});

export type MemoryRunBlock = z.infer<typeof memoryRunBlockSchema>;
export type MemoryRunVerdict = z.infer<typeof memoryRunVerdictSchema>;
