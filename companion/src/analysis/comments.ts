import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";

// Investigator comments attached to any case entity (a forensic event, finding, IOC, key
// question, asset…), so investigators can collaborate. Kept in a per-case side file
// (`state/comments.json`) — NOT in InvestigationState, so synthesis never wipes them. A
// comment targets `(targetType, targetId)`; the dashboard matches them to rendered entities.

export const commentSchema = z.object({
  id: z.string(),
  targetType: z.string(),       // "event" | "finding" | "ioc" | "question" | "asset" | …
  targetId: z.string(),
  author: z.string(),
  text: z.string(),
  mentions: z.array(z.string()).catch([]), // @name tokens parsed out of `text` at add-time
  createdAt: z.string(),
});

export type Comment = z.infer<typeof commentSchema>;
const commentsSchema = z.array(commentSchema).catch([]);

// Pull `@name` tokens out of comment text (letters/digits/./_/- , 1-64 chars — matches typical
// investigator handles/usernames). Case-insensitive de-dup, first-seen casing kept, in order of
// appearance so the mention chips read left-to-right the way the analyst typed them.
// The `@` must NOT be preceded by a word/handle character, so email addresses and IOCs
// (`bob@example.com`, `user@host`) — routine in DFIR comments — don't parse as a mention of
// their domain and fire spurious notifications.
// `.`/`-`/`_` are only legal INSIDE the handle: a handle must start AND end alphanumeric, so
// sentence punctuation isn't swallowed ("ping @bob." is a mention of `bob`, not `bob.`). Without
// that, @bob. and @bob de-dup as two different people and the notification names a handle nobody
// has. Keep this in sync with mentionHtml() in dashboard.html.
const MENTION_RE = /(?<![A-Za-z0-9._@-])@([a-zA-Z0-9](?:[a-zA-Z0-9._-]{0,62}[a-zA-Z0-9])?)/g;

export function parseMentions(text: string): string[] {
  const seen = new Set<string>();
  const mentions: string[] = [];
  for (const m of String(text).matchAll(MENTION_RE)) {
    const name = m[1];
    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    mentions.push(name);
  }
  return mentions;
}

export interface NewComment {
  targetType: string;
  targetId: string;
  author: string;
  text: string;
}

export class CommentsStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "comments.json");
  }

  async load(caseId: string): Promise<Comment[]> {
    try {
      return commentsSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async save(caseId: string, comments: Comment[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(comments, null, 2));
  }

  // Append a comment (server-assigned id + createdAt). Author/text are trimmed; author
  // falls back to "anonymous". Returns the stored comment.
  async add(caseId: string, input: NewComment): Promise<Comment> {
    const text = String(input.text).trim();
    const comment: Comment = {
      id: randomUUID(),
      targetType: String(input.targetType).trim(),
      targetId: String(input.targetId).trim(),
      author: (input.author || "").trim() || "anonymous",
      text,
      mentions: parseMentions(text),
      createdAt: new Date().toISOString(),
    };
    await this.save(caseId, [...(await this.load(caseId)), comment]);
    return comment;
  }

  // Remove one comment by id; returns true if it existed.
  async remove(caseId: string, commentId: string): Promise<boolean> {
    const comments = await this.load(caseId);
    const next = comments.filter((c) => c.id !== commentId);
    if (next.length === comments.length) return false;
    await this.save(caseId, next);
    return true;
  }
}
