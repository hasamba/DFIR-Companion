import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import { canonicalHostName } from "./hostAlias.js";

// Pairs the analyst has judged to be genuinely DIFFERENT machines, so the merge gate stops asking
// about them. This is the only piece of the gate that is persisted: the pending list itself is
// derived on read (findNearDuplicates minus these), and a MERGE needs no record here because a
// merged pair resolves to one canonical name and stops being a near-duplicate on its own.
//
// Corruption degrades to "no dismissals" rather than throwing. That direction is deliberate: the
// failure mode is re-asking about a pair the analyst already dismissed, which is a nuisance. The
// opposite default would silently un-gate a case, which is the thing this feature exists to prevent.

const dismissalSchema = z.object({
  canonical: z.string(),
  other: z.string(),
  dismissedAt: z.string(),
  dismissedBy: z.string(),
});

const dismissalsSchema = z.array(dismissalSchema).catch([]);

export type HostDuplicateDismissal = z.infer<typeof dismissalSchema>;

// Order matters: "a" folded into "a.corp" is a different statement than the reverse, and the pair
// findNearDuplicates emits always puts the FQDN in `canonical`.
export function dismissalKey(canonical: string, other: string): string {
  return `${canonicalHostName(canonical)}|${canonicalHostName(other)}`;
}

// Serializes a case's load->modify->save section on host-duplicate-dismissals.json (follow-up to
// #682). Losing one of these re-arms the merge gate on a pair an analyst already judged to be two
// genuinely different machines, and the gate blocks synthesis — so the lost write does not merely
// forget a decision, it stalls the case until somebody makes the same call again. MODULE-level: the
// app builds this store twice (runtimeStores.ts and aiProviders.ts).
const hostDuplicateLock = new StateLock();

export class HostDuplicateDismissalStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "host-duplicate-dismissals.json");
  }

  async load(caseId: string): Promise<HostDuplicateDismissal[]> {
    try {
      return dismissalsSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      return []; // malformed → treat as no dismissals (see the note above)
    }
  }

  // Idempotent: re-dismissing a pair keeps the FIRST decision, so the recorded timestamp and
  // analyst stay the ones who actually made the call.
  append(caseId: string, d: HostDuplicateDismissal): Promise<HostDuplicateDismissal[]> {
    return hostDuplicateLock.runExclusive(caseId, async () => {
      const existing = await this.load(caseId);
      const normalized: HostDuplicateDismissal = {
        ...d,
        canonical: canonicalHostName(d.canonical),
        other: canonicalHostName(d.other),
      };
      const key = dismissalKey(normalized.canonical, normalized.other);
      if (existing.some((e) => dismissalKey(e.canonical, e.other) === key)) return existing;
      const next = [...existing, normalized];
      await atomicWrite(this.path(caseId), JSON.stringify(next, null, 2));
      return next;
    });
  }
}
