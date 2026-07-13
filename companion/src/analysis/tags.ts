import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Analyst tags (triage labels) attached to any case entity (a forensic event, finding, IOC,
// key question, asset…), so investigators can hand-label evidence — "confirmed-malicious",
// "false-positive", "needs-review", "key-evidence", "pivot-point", … — independently of the
// AI-assigned severity/MITRE. Kept in a per-case side file (`state/tags.json`) — NOT in
// InvestigationState, so synthesis never wipes them. A tag targets `(targetType, targetId)`;
// the dashboard matches them to rendered entities and shows them as inline chips.

export const tagSchema = z.object({
  id: z.string(),
  targetType: z.string(),       // "event" | "finding" | "ioc" | "question" | "asset" | …
  targetId: z.string(),
  label: z.string(),            // normalized: lowercase, trimmed, internal whitespace → "-"
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

export class TagsStore {
  constructor(private readonly cases: CaseStore) {}

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
    await this.save(caseId, [...existingTags, tag]);
    return tag;
  }

  // Remove one tag by id; returns true if it existed.
  async remove(caseId: string, tagId: string): Promise<boolean> {
    const tags = await this.load(caseId);
    const next = tags.filter((t) => t.id !== tagId);
    if (next.length === tags.length) return false;
    await this.save(caseId, next);
    return true;
  }

  // Remove every tag whose author starts with `prefix` in a single load+save; returns how many were
  // removed. Backs the tagger's "Clear tagger tags" (prefix "tagger:") so a noisy ruleset is fully
  // reversible WITHOUT touching analyst-authored tags. No-op write when nothing matches.
  async removeByAuthorPrefix(caseId: string, prefix: string): Promise<number> {
    const tags = await this.load(caseId);
    const next = tags.filter((t) => !t.author.startsWith(prefix));
    const removed = tags.length - next.length;
    if (removed) await this.save(caseId, next);
    return removed;
  }
}
