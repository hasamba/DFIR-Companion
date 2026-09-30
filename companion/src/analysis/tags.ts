import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { StateLock } from "./stateLock.js";
import { TAGGER_AUTHOR_PREFIX } from "./superTimeline.js";
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { tagPaths } from "./tagsDatabase.js";

// Analyst tags (triage labels) attached to any case entity (a forensic event, finding, IOC,
// key question, asset…), so investigators can hand-label evidence — "confirmed-malicious",
// "false-positive", "needs-review", "key-evidence", "pivot-point", … — independently of the
// AI-assigned severity/MITRE. Kept apart from InvestigationState, so synthesis never wipes them:
// since #1874 in the case database's own `tags` table (worker ops in caseSqliteWorkerTags.ts),
// migrated once from the old per-case side file `state/tags.json`, which is left in place. A tag
// targets `(targetType, targetId)`; the dashboard matches them to rendered entities and shows them
// as inline chips.

export const tagSchema = z.object({
  id: z.string(),
  targetType: z.string(), // "event" | "finding" | "ioc" | "question" | "asset" | …
  targetId: z.string(),
  label: z.string(), // normalized: lowercase, trimmed, internal whitespace → "-"
  author: z.string(),
  createdAt: z.string(),
});

export type Tag = z.infer<typeof tagSchema>;

export interface NewTag {
  targetType: string;
  targetId: string;
  author: string;
  label: string;
}

// A predefined palette of common DFIR triage labels (the dashboard offers these as one-click
// chips; analysts may also type any free-form label). Kept here so server and UI agree on the
// canonical spelling/colour key. NOT enforced — add() accepts any non-empty label.
export const SUGGESTED_TAGS = [
  "confirmed-malicious",
  "false-positive",
  "needs-review",
  "benign-admin",
  "key-evidence",
  "pivot-point",
  "persistence",
  "lateral-movement",
  "c2-comms",
  "exfil",
  "credential-access",
  "initial-access",
] as const;

// Canonicalize a free-form label: lowercase, trim, collapse internal whitespace to hyphens.
// Keeps "Confirmed Malicious", "confirmed-malicious", and "  CONFIRMED   MALICIOUS " equal so
// duplicates don't accumulate and the colour key stays stable.
export function normalizeLabel(label: string): string {
  return String(label).trim().toLowerCase().replace(/\s+/g, "-");
}

// Where an analyst event tag also exempts the raw super-timeline row it names from the cap (#958).
// SuperTimelineStore satisfies this; the store is passed in so tags.ts never imports it.
export interface EventProtectionSink {
  protect(caseId: string, eventId: string): Promise<boolean>;
  unprotect(caseId: string, eventId: string): Promise<void>;
}

// An analyst-authored tag on an event. Tagger tags are automatic and can cover most rows, so they
// never protect; that is what keeps the cap a cap.
function protectsEvent(tag: Pick<Tag, "targetType" | "author">): boolean {
  return tag.targetType === "event" && !tag.author.startsWith(TAGGER_AUTHOR_PREFIX);
}

interface TagPlan {
  fresh: number[]; // input indexes that are new, in input order
  first: Tag | null; // the stored tag for input 0 when it is not new
}

interface TagRemoval {
  removed: Tag | null;
  release: string[]; // analyst event targets no remaining analyst event tag names
}

export class TagsStore {
  // Serializes this case's plan->protect->insert section (#216), so add()'s duplicate check holds:
  // without it, two identical tags arriving together both saw "no duplicate" and both were written.
  // A PRIVATE lock, like HypothesisStore's, so it can never contend with the investigation-state lock.
  private readonly lock = new StateLock();

  constructor(
    private readonly cases: CaseStore,
    private readonly protection?: EventProtectionSink,
  ) {}

  private request<T>(caseId: string, message: Record<string, unknown>): Promise<T> {
    return caseSqliteWorker.request<T>({ ...message, ...tagPaths(this.cases.stateDir(caseId)) });
  }

  // Drop protection for each released target. Runs after the tags are deleted, so a reader never sees
  // a protected row whose tag is already gone.
  private async release(caseId: string, targetIds: readonly string[]): Promise<void> {
    if (!this.protection) return;
    for (const targetId of targetIds) await this.protection.unprotect(caseId, targetId);
  }

  // One read op; the writer is asked to migrate tags.json first only when the database has not yet.
  async load(caseId: string): Promise<Tag[]> {
    const listed = await this.request<Tag[] | { migrate: true }>(caseId, { op: "tagsList" });
    if (Array.isArray(listed)) return listed;
    await this.request<void>(caseId, { op: "tagsEnsure" });
    const again = await this.request<Tag[] | { migrate: true }>(caseId, { op: "tagsList" });
    return Array.isArray(again) ? again : [];
  }

  // Protect BEFORE the tags are inserted: a row that was already evicted reports false and the tag is
  // still kept — most event tags name forensic-timeline events, which are never raw rows. The plan op
  // recorded the analyst event targets as in flight, so a failure here clears that record. Returns the
  // insert's skips: a (target, label) another TagsStore wrote since the plan.
  private async commit(caseId: string, created: Tag[]): Promise<{ index: number; tag: Tag }[]> {
    const guarded = this.protection ? created.filter(protectsEvent) : [];
    try {
      for (const tag of guarded) await this.protection?.protect(caseId, tag.targetId);
      const { skipped } = await this.request<{ skipped: { index: number; tag: Tag }[] }>(caseId, {
        op: "tagsInsert",
        tags: created,
      });
      return skipped;
    } catch (err) {
      if (guarded.length) {
        await this.request<void>(caseId, {
          op: "tagsPendingClear",
          targetIds: guarded.map((t) => t.targetId),
        }).catch(() => undefined);
      }
      throw err;
    }
  }

  // Attach a tag (server-assigned id + createdAt). The label is normalized; author falls back
  // to "anonymous". Idempotent per target: re-adding the same label to the same entity returns
  // the existing tag instead of duplicating it. Throws on an empty label.
  async add(caseId: string, input: NewTag): Promise<Tag> {
    const label = normalizeLabel(input.label);
    if (!label) throw new Error("label is required");
    const targetType = String(input.targetType).trim();
    const targetId = String(input.targetId).trim();
    const author = (input.author || "").trim() || "anonymous";
    return this.lock.runExclusive(caseId, async () => {
      const plan = await this.request<TagPlan>(caseId, {
        op: "tagsPlan",
        inputs: [{ targetType, targetId, label, author }],
        protecting: !!this.protection,
      });
      if (!plan.fresh.length && plan.first) return plan.first;
      const tag: Tag = {
        id: randomUUID(),
        targetType,
        targetId,
        label,
        author,
        createdAt: new Date().toISOString(),
      };
      const skipped = await this.commit(caseId, [tag]);
      return skipped.length ? skipped[0].tag : tag;
    });
  }

  // add() for a batch, in ONE lookup op and ONE insert op (#1874) — the automatic tagger's path. Its
  // cost follows the batch, never the number of tags the case already holds. Same rules as add():
  // normalized labels, one tag per (target, label) with the first author winning, protection for
  // analyst event tags. Every label is checked before anything is written. Returns the tags created,
  // in input order; they share one createdAt, the instant of the batch.
  async addMany(caseId: string, inputs: readonly NewTag[]): Promise<Tag[]> {
    if (inputs.some((input) => !normalizeLabel(input.label))) throw new Error("label is required");
    if (!inputs.length) return [];
    const normalized = inputs.map((input) => ({
      targetType: String(input.targetType).trim(),
      targetId: String(input.targetId).trim(),
      label: normalizeLabel(input.label),
      author: (input.author || "").trim() || "anonymous",
    }));
    return this.lock.runExclusive(caseId, async () => {
      const plan = await this.request<TagPlan>(caseId, {
        op: "tagsPlan",
        inputs: normalized,
        protecting: !!this.protection,
      });
      if (!plan.fresh.length) return [];
      const createdAt = new Date().toISOString();
      const created: Tag[] = plan.fresh.map((i) => ({ id: randomUUID(), ...normalized[i], createdAt }));
      const skipped = new Set((await this.commit(caseId, created)).map((s) => s.index));
      return created.filter((_, i) => !skipped.has(i));
    });
  }

  // Remove one tag by id; returns the removed tag (so callers can inspect its label), or null if
  // no tag with that id existed. Every tag carrying that id goes.
  async remove(caseId: string, tagId: string): Promise<Tag | null> {
    return this.lock.runExclusive(caseId, async () => {
      const { removed, release } = await this.request<TagRemoval>(caseId, { op: "tagsRemove", tagId });
      if (!removed) return null;
      await this.release(caseId, release);
      return removed;
    });
  }

  // Remove the automatic tagger's tags on `targetIds` — the tags a failed bulk import wrote for the
  // rows it then rolled back (#1480). Analyst-authored tags on the same ids are never touched. The
  // caller passes only ids of rows that run inserted, so a stable-id row an earlier run owns keeps
  // its tags. Returns how many were removed.
  async removeTaggerTagsFor(caseId: string, targetIds: readonly string[]): Promise<number> {
    const targets = new Set(targetIds);
    if (!targets.size) return 0;
    // A tag's targetId is a string, so any other value never matched one.
    const ids = [...targets].filter((id): id is string => typeof id === "string");
    return this.lock.runExclusive(caseId, () =>
      this.request<number>(caseId, { op: "tagsRemoveTaggerFor", targetIds: ids }),
    );
  }

  // Remove every tag whose author starts with `prefix`; returns how many were removed. Backs the
  // tagger's "Clear tagger tags" (prefix "tagger:") so a noisy ruleset is fully reversible WITHOUT
  // touching analyst-authored tags.
  async removeByAuthorPrefix(caseId: string, prefix: string): Promise<number> {
    return this.lock.runExclusive(caseId, async () => {
      const { count, release } = await this.request<{ count: number; release: string[] }>(caseId, {
        op: "tagsRemoveByPrefix",
        prefix: String(prefix),
      });
      if (count) await this.release(caseId, release);
      return count;
    });
  }
}
