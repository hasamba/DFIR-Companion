import { StateLock } from "./stateLock.js";
import { MAX_CUSTOM_ENTITIES, sanitizeCustomEntities, type CustomEntitiesStore } from "./anonEntities.js";
import { anonControlVersion, type AnonControl, type AnonControlStore } from "./anonControl.js";
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

/** A whole-list save from the custom-entity editor (#1839). `stale` changes nothing. */
export type ReplaceCustomOutcome =
  | { applied: true; custom: CustomEntity[]; version: number }
  | { applied: false; reason: "stale"; custom: CustomEntity[]; version: number };

/** A whole-form save of the Anonymization modal's settings (#1839). `stale` changes nothing. */
export type ReplaceControlOutcome =
  | { applied: true; control: AnonControl; previous: AnonControl; version: string }
  | { applied: false; reason: "stale"; control: AnonControl; version: string };

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
    private readonly control?: AnonControlStore,
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
      // Saved even when already present: the save bumps the list's version, so an editor window
      // that loaded the list before this Hide — and may be about to remove the value — is stale (#1839).
      await this.custom.save(caseId, present ? existing : [...existing, entity]);
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

  /**
   * The custom-entity editor's Save (#1839): replace the whole list, but only from the version the
   * editor loaded. Under the same lock as Hide, so a Hide can never land between the check and the
   * write. A stale base answers with the current list and version and writes nothing. A missing
   * base (anything that is not a whole number) counts as stale: fail closed.
   */
  replaceCustom(caseId: string, raw: unknown, baseVersion: unknown): Promise<ReplaceCustomOutcome> {
    return decisionLock.runExclusive(caseId, async () => {
      const current = await this.custom.loadVersioned(caseId);
      if (!Number.isSafeInteger(baseVersion) || baseVersion !== current.version) {
        return { applied: false, reason: "stale", custom: current.entities, version: current.version };
      }
      const entities = sanitizeCustomEntities(raw);
      const version = await this.custom.save(caseId, entities);
      return { applied: true, custom: entities, version };
    });
  }

  /**
   * The Anonymization modal's settings Save (#1839). `build` turns the current control into the
   * next one. With a `baseVersion`, a modal loaded before another window changed the settings is
   * refused, so a stale form cannot turn masking off under a value just hidden. Without one (a
   * partial update that names only the fields it changes) it applies as before.
   */
  replaceControl(
    caseId: string,
    build: (cur: AnonControl) => AnonControl,
    baseVersion: string | undefined,
  ): Promise<ReplaceControlOutcome> {
    const control = this.control;
    if (!control) return Promise.reject(new Error("anonymization control store not wired"));
    return decisionLock.runExclusive(caseId, async () => {
      const cur = await control.load(caseId);
      if (baseVersion !== undefined && baseVersion !== anonControlVersion(cur)) {
        return { applied: false, reason: "stale", control: cur, version: anonControlVersion(cur) };
      }
      const next = build(cur);
      await control.save(caseId, next);
      return { applied: true, control: next, previous: cur, version: anonControlVersion(next) };
    });
  }
}
