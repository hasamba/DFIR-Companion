import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { TagOutcome } from "../analysis/gradeMark.js";
import { importTagger, regradeHeldTagger, type ImportTaggerDeps } from "../routes/routeSettleDeps.js";

/**
 * The two taggers every import site that createApp wires is handed (lifted out of server.ts, #2918):
 *
 *   - `autoTagImported` — automatic tagging of an import's new events, after they are dual-written
 *     into the super-timeline: the content tagger (Timesketch tagger analyzer, ported; TAGGER_AUTO-
 *     gated — analysis/taggerAuto.ts) and the cloud collector's own calls (#2487). Best effort and
 *     non-fatal. routes/routeSettleDeps.ts binds the same one for the route imports.
 *   - `tagHeld` — the held tagger for rows marked "held" (a Watson paste's rows another settle met,
 *     #2909): tags only, and the raises it would make are queued as Watson held-rows cards (#2918).
 *     The streamed-ingest and drop-folder settles get it here, as the route imports get it from
 *     routeSettleDeps, so a held row they meet is graded there instead of waiting for a route import
 *     or a restart.
 */
export interface ImportTaggers {
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
  tagHeld: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
}

export function createImportTaggers(deps: ImportTaggerDeps): ImportTaggers {
  return { autoTagImported: importTagger(deps), tagHeld: regradeHeldTagger(deps) };
}
