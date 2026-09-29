import { StateLock } from "./stateLock.js";
import { MAX_CUSTOM_ENTITIES, type CustomEntitiesStore } from "./anonEntities.js";
import type { DiscoveredEntitiesStore } from "./anonDiscovered.js";
import type { PresidioPendingStore } from "./presidioPending.js";
import type { CustomEntity } from "./anonymize.js";

// The analyst's two answers to a Presidio finding (#1822): "Hide from AI" (approve) and "Leave
// visible" (suppress). The stricter choice wins, whatever the order the clicks land in:
//   - Hide always applies, and lifts an earlier "leave visible" veto on the same value.
//   - Leave visible applies only to a value that is still pending and not already hidden.
// Before this, a "Leave visible" from a stale tab (or the bulk "Leave all visible") vetoed a value
// another tab had just hidden, and the anonymizer honoured the veto — the name went to the AI.
//
// MODULE-level lock, keyed by case id, for the same reason as anonDiscovered.ts: every route
// instance must share it, or two requests for one case interleave their read-modify-writes.

export type SuppressRefusal = "not_pending" | "already_hidden";

export type SuppressOutcome =
  | { applied: true; pending: CustomEntity[] }
  | { applied: false; reason: SuppressRefusal; pending: CustomEntity[] };

export type ApproveOutcome =
  | { applied: true; pending: CustomEntity[] }
  | { applied: false; reason: "custom_list_full"; pending: CustomEntity[] };

const decisionLock = new StateLock();

const key = (value: string): string => value.trim().toLowerCase();

export class PresidioDecisions {
  constructor(
    private readonly custom: CustomEntitiesStore,
    private readonly discovered: DiscoveredEntitiesStore,
    private readonly pending: PresidioPendingStore,
  ) {}

  /**
   * Hide from AI. The value goes into the custom list FIRST and the veto is lifted SECOND: the
   * anonymizer lets a custom value win over a veto, so a reader between the two writes still masks
   * it. A full custom list refuses rather than dropping the value silently and reporting success.
   */
  approve(caseId: string, entity: CustomEntity): Promise<ApproveOutcome> {
    return decisionLock.runExclusive(caseId, async () => {
      const k = key(entity.value);
      const existing = await this.custom.load(caseId);
      const present = existing.some((e) => key(e.value) === k);
      if (!present && existing.length >= MAX_CUSTOM_ENTITIES) {
        return { applied: false, reason: "custom_list_full", pending: await this.pending.load(caseId) };
      }
      if (!present) await this.custom.save(caseId, [...existing, entity]);
      await this.discovered.unsuppress(caseId, entity.value);
      const rest = (await this.pending.load(caseId)).filter((e) => key(e.value) !== k);
      await this.pending.save(caseId, rest);
      return { applied: true, pending: rest };
    });
  }

  /** Leave visible — refused for a value that is no longer pending or is already hidden. */
  suppress(caseId: string, value: string): Promise<SuppressOutcome> {
    return decisionLock.runExclusive(caseId, async () => {
      const k = key(value);
      const pending = await this.pending.load(caseId);
      if (!pending.some((e) => key(e.value) === k)) return { applied: false, reason: "not_pending", pending };
      // A pending value can still be hidden: the pipeline writes its findings from a snapshot it
      // read before the analyst's Hide landed. Hidden means the custom list or the auto list.
      const [custom, disc] = await Promise.all([this.custom.load(caseId), this.discovered.load(caseId)]);
      if ([...custom, ...disc.discovered].some((e) => key(e.value) === k)) {
        return { applied: false, reason: "already_hidden", pending };
      }
      await this.discovered.suppress(caseId, value);
      const rest = pending.filter((e) => key(e.value) !== k);
      await this.pending.save(caseId, rest);
      return { applied: true, pending: rest };
    });
  }
}
