import { z } from "zod";
import { CONTROL_DISPOSITIONS } from "./stateTypes.js";

// The typed block a Defender Operational record carries on its envelope (#930 item 1 part B —
// #964). Part A (#968) put the disposition first in the LABEL and the primary file in
// `file.path`; the pass that links a Defender action to a later start of the same file must not
// read prose, and must see EVERY flagged resource, not the primary alone — a second archive member
// that later starts is the same evidence as the first. So the decode's own facts sit here, as the
// importer read them: the disposition (from the action and its result, never the event id), the
// threat, the Detection ID when the record has one, and the bounded resource list with how many
// the record listed. `fillCanonicalGaps` keeps the block when a higher-severity duplicate (a
// Hayabusa Sigma hit over the same record) becomes the merged primary (#965).
export const defenderBlockSchema = z.object({
  disposition: z.enum(CONTROL_DISPOSITIONS),
  threat: z.string(),
  detectionId: z.string().optional(),
  eventType: z.enum(["detection", "action"]),
  /** Every file resource the record listed, in order, bounded — the member form `C:\a.zip->x.exe` kept. */
  resources: z.array(z.string()),
  container: z.string().optional(),
  /** How many file resources the record listed; more than `resources.length` when the list was clipped. */
  resourcesTotal: z.number().int().nonnegative(),
  /** The detected file's digest when THIS record carries one (an export that includes it). Never from another row. */
  sha256: z.string().optional(),
});

export type DefenderBlock = z.infer<typeof defenderBlockSchema>;
