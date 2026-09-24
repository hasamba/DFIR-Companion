import type { ImportContext } from "../ingest/importContext.js";
import type { ExtractionContext } from "./extraction.js";
import type { SynthesisContext } from "./synthesis.js";

// Moved out of pipeline.ts (#1588) to keep that file under its size limit; pipeline.ts is the only
// reader.

/** The argument list of an importer, minus the ImportContext it takes first (#384). Every import method in pipeline.ts is a one-line delegation to src/analysis/ingest/ — deriving the parameters rather than restating them means the two cannot drift: change an importer's signature and the delegation stops compiling, which a hand-copied signature would not have. */
export type ImporterArgs<F> = F extends (ctx: ImportContext, ...args: infer R) => unknown ? R : never;
/** The same trick for the AI extraction calls, which take an ExtractionContext first (#418). */
export type AiExtractionArgs<F> = F extends (ctx: ExtractionContext, ...args: infer R) => unknown ? R : never;
/** Ditto for the calls that take the widest context of all — synthesis and its two consumers. */
export type AiArgs<F> = F extends (ctx: SynthesisContext, ...args: infer R) => unknown ? R : never;
