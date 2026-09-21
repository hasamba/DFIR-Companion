import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import { TAGGER_AUTHOR_PREFIX } from "./superTimeline.js";

// Analyst tags (triage labels) attached to any case entity (a forensic event, finding, IOC,
// key question, asset…), so investigators can hand-label evidence — "confirmed-malicious",
// "false-positive", "needs-review", "key-evidence", "pivot-point", … — independently of the
// AI-assigned severity/MITRE. Kept in a per-case side file (`state/tags.json`) — NOT in
// InvestigationState, so synthesis never wipes them. A tag targets `(targetType, targetId)`;
// the dashboard matches them to rendered entities and shows them as inline chips.

export const tagSchema = z.object({
  id: z.string(),
  targetType: z.string(), // "event" | "finding" | "ioc" | "question" | "asset" | …
  targetId: z.string(),
  label: z.string(), // normalized: lowercase, trimmed, internal whitespace → "-"
  author: z.string(),
  createdAt: z.string(),
});

export type Tag = z.infer<typeof tagSchema>;
const tagsSchema = z.array(tagSchema).catch([]);

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

export class TagsStore {
  // Serializes this case's load->modify->save section (#216). Guards tags.json only — a PRIVATE
  // lock, like HypothesisStore's, so it can never contend with the investigation-state lock.
  // It also makes add()'s duplicate check meaningful: without it, two identical tags arriving
  // together both saw "no duplicate" and both were written.
  private readonly lock = new StateLock();

  constructor(
    private readonly cases: CaseStore,
    private readonly protection?: EventProtectionSink,
  ) {}

  // Drop protection for each target that no analyst event tag names any more. Runs after the
  // tags file is saved, so a reader never sees a protected row whose tag is already gone.
  private async releaseUnreferenced(caseId: string, removed: Tag[], remaining: Tag[]): Promise<void> {
    if (!this.protection) return;
    const stillHeld = new Set(remaining.filter(protectsEvent).map((t) => t.targetId));
    const released = new Set(removed.filter(protectsEvent).map((t) => t.targetId));
    for (const targetId of released) {
      if (!stillHeld.has(targetId)) await this.protection.unprotect(caseId, targetId);
    }
  }

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "tags.json");
  }

  async load(caseId: string): Promise<Tag[]> {
    try {
      return tagsSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async save(caseId: string, tags: Tag[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(tags, null, 2));
  }

  // Attach a tag (server-assigned id + createdAt). The label is normalized; author falls back
  // to "anonymous". Idempotent per target: re-adding the same label to the same entity returns
  // the existing tag instead of duplicating it. Throws on an empty label.
  async add(caseId: string, input: NewTag): Promise<Tag> {
    const label = normalizeLabel(input.label);
    if (!label) throw new Error("label is required");
    const targetType = String(input.targetType).trim();
    const targetId = String(input.targetId).trim();
    return this.lock.runExclusive(caseId, async () => {
      const existingTags = await this.load(caseId);
      const dup = existingTags.find(
        (t) => t.targetType === targetType && t.targetId === targetId && t.label === label,
      );
      if (dup) return dup;
      const tag: Tag = {
        id: randomUUID(),
        targetType,
        targetId,
        label,
        author: (input.author || "").trim() || "anonymous",
        createdAt: new Date().toISOString(),
      };
      // Protect BEFORE the tag is saved: a row that was already evicted reports false and the tag
      // is still kept — most event tags name forensic-timeline events, which are never raw rows.
      if (this.protection && protectsEvent(tag)) await this.protection.protect(caseId, targetId);
      await this.save(caseId, [...existingTags, tag]);
      return tag;
    });
  }

  // Remove one tag by id; returns the removed tag (so callers can inspect its label), or null if
  // no tag with that id existed.
  async remove(caseId: string, tagId: string): Promise<Tag | null> {
    return this.lock.runExclusive(caseId, async () => {
      const tags = await this.load(caseId);
      const removed = tags.find((t) => t.id === tagId) ?? null;
      if (!removed) return null;
      const remaining = tags.filter((t) => t.id !== tagId);
      await this.save(caseId, remaining);
      await this.releaseUnreferenced(caseId, [removed], remaining);
      return removed;
    });
  }

  // Remove the automatic tagger's tags on `targetIds` — the tags a failed bulk import wrote for the
  // rows it then rolled back (#1480). Analyst-authored tags on the same ids are never touched. The
  // caller passes only ids of rows that run inserted, so a stable-id row an earlier run owns keeps
  // its tags. Returns how many were removed; no-op write when nothing matches.
  async removeTaggerTagsFor(caseId: string, targetIds: readonly string[]): Promise<number> {
    const targets = new Set(targetIds);
    if (!targets.size) return 0;
    return this.lock.runExclusive(caseId, async () => {
      const tags = await this.load(caseId);
      const gone = (t: Tag) =>
        t.targetType === "event" && t.author.startsWith(TAGGER_AUTHOR_PREFIX) && targets.has(t.targetId);
      const next = tags.filter((t) => !gone(t));
      const removed = tags.length - next.length;
      if (removed) await this.save(caseId, next);
      return removed;
    });
  }

  // Remove every tag whose author starts with `prefix` in a single load+save; returns how many were
  // removed. Backs the tagger's "Clear tagger tags" (prefix "tagger:") so a noisy ruleset is fully
  // reversible WITHOUT touching analyst-authored tags. No-op write when nothing matches.
  async removeByAuthorPrefix(caseId: string, prefix: string): Promise<number> {
    return this.lock.runExclusive(caseId, async () => {
      const tags = await this.load(caseId);
      const next = tags.filter((t) => !t.author.startsWith(prefix));
      const removed = tags.length - next.length;
      if (removed) {
        await this.save(caseId, next);
        await this.releaseUnreferenced(
          caseId,
          tags.filter((t) => t.author.startsWith(prefix)),
          next,
        );
      }
      return removed;
    });
  }
}
