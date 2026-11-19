import { mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { z } from "zod";
import { StateLock } from "../../analysis/stateLock.js";
import { atomicWrite } from "../../storage/atomicWrite.js";

// #2647: the Telegram mirror's durable state, one GLOBAL JSON file beside the chat bindings
// (notifications/watson-mirror.json) — never under cases/. Older code ignores it, so a rollback is
// safe. An absent entry means mirroring is off for that chat; turning it on again starts fresh (no
// history replay).
//
// Delivery is at-least-once per chat: enqueue (persist) → send → markSent (persist). A crash between
// the send and the mark re-sends one message; nothing is lost. A malformed file reads as empty, so a
// damaged file fails closed: no chat mirrors until someone turns it on again.

export const MIRROR_SENT_MAX = 500;
export const MIRROR_MESSAGE_IDS_MAX = 200;
export const MIRROR_SEEN_MAX = 1000;
/** A held chat collects turn ids; past this many the oldest are dropped (about 100 KB of ids). */
export const MIRROR_PENDING_MAX = 5000;

const retrySchema = z.object({ attempt: z.number().int().nonnegative(), nextAt: z.string() });

const chatSchema = z.object({
  caseId: z.string().min(1),
  chatType: z.string().catch("private"),
  enabledAt: z.string(),
  enabledBy: z.string().catch(""),
  /** The binding's boundAt when mirroring was turned on: a rebind changes it, which stops the mirror. */
  boundAt: z.string().catch(""),
  /** The newest turn id ever enqueued: the scan resumes after it, from the history when it rotated. */
  cursor: z.string().optional().catch(undefined),
  pending: z.array(z.string()).catch([]),
  sent: z.array(z.string()).catch([]),
  messageIds: z.array(z.number()).catch([]),
  held: z.boolean().optional().catch(undefined),
  /** When the last batch went out (the 60 s Auto window). */
  lastBatchAt: z.string().optional().catch(undefined),
  retry: retrySchema.optional().catch(undefined),
});

export type WatsonMirrorChat = z.infer<typeof chatSchema>;
export type WatsonMirrorEntry = WatsonMirrorChat & { chatId: string };

const fileSchema = z.object({
  chats: z.record(z.string(), z.unknown()).catch({}),
  seen: z.array(z.string()).catch([]),
});

interface MirrorFile {
  chats: Record<string, WatsonMirrorChat>;
  seen: string[];
}

const EMPTY: MirrorFile = { chats: {}, seen: [] };

function parseFile(raw: unknown): MirrorFile {
  const f = fileSchema.safeParse(raw);
  if (!f.success) return EMPTY;
  const chats: Record<string, WatsonMirrorChat> = {};
  for (const [id, v] of Object.entries(f.data.chats)) {
    const c = chatSchema.safeParse(v);
    if (c.success) chats[id] = c.data;
  }
  return { chats, seen: f.data.seen };
}

const tail = <T>(list: readonly T[], max: number): T[] => list.slice(Math.max(0, list.length - max));

/** What patch() may change; the queue, sets and identity go through their own methods. */
export type WatsonMirrorPatch = Partial<Pick<WatsonMirrorChat, "held" | "lastBatchAt" | "retry">>;

export class WatsonMirrorStore {
  private readonly lock = new StateLock();

  constructor(readonly file: string) {}

  private async read(): Promise<MirrorFile> {
    let text: string;
    try {
      text = await readFile(this.file, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return EMPTY;
      throw err;
    }
    try {
      return parseFile(JSON.parse(text));
    } catch {
      return EMPTY; // malformed: fail closed
    }
  }

  private async write(f: MirrorFile): Promise<void> {
    await mkdir(dirname(this.file), { recursive: true });
    await atomicWrite(this.file, JSON.stringify(f, null, 2));
  }

  private mutate<T>(fn: (f: MirrorFile) => { next?: MirrorFile; out: T }): Promise<T> {
    return this.lock.runExclusive(this.file, async () => {
      const { next, out } = fn(await this.read());
      if (next) await this.write(next);
      return out;
    });
  }

  /** Change one chat's entry; a chat switched off in the meantime stays off. */
  private updateChat(chatId: string, fn: (c: WatsonMirrorChat) => WatsonMirrorChat): Promise<void> {
    return this.mutate((f) => {
      const cur = f.chats[chatId];
      if (!cur) return { out: undefined };
      return { next: { ...f, chats: { ...f.chats, [chatId]: fn(cur) } }, out: undefined };
    });
  }

  async get(chatId: string): Promise<WatsonMirrorEntry | undefined> {
    const c = (await this.read()).chats[chatId];
    return c ? { ...c, chatId } : undefined;
  }

  async list(): Promise<WatsonMirrorEntry[]> {
    return Object.entries((await this.read()).chats).map(([chatId, c]) => ({ ...c, chatId }));
  }

  async listCase(caseId: string): Promise<WatsonMirrorEntry[]> {
    return (await this.list()).filter((c) => c.caseId === caseId);
  }

  enable(
    chatId: string,
    input: { caseId: string; chatType: string; by: string; boundAt: string; at: string; cursor?: string },
  ): Promise<WatsonMirrorEntry> {
    const entry: WatsonMirrorChat = {
      caseId: input.caseId,
      chatType: input.chatType,
      enabledAt: input.at,
      enabledBy: input.by,
      boundAt: input.boundAt,
      ...(input.cursor ? { cursor: input.cursor } : {}),
      pending: [],
      sent: [],
      messageIds: [],
    };
    return this.mutate((f) => ({
      next: { ...f, chats: { ...f.chats, [chatId]: entry } },
      out: { ...entry, chatId },
    }));
  }

  /** Switch one chat off. Returns the entry it had, or undefined when it was not mirroring. */
  disable(chatId: string): Promise<WatsonMirrorEntry | undefined> {
    return this.mutate((f) => {
      const cur = f.chats[chatId];
      if (!cur) return { out: undefined };
      const chats = { ...f.chats };
      delete chats[chatId];
      return { next: { ...f, chats }, out: { ...cur, chatId } };
    });
  }

  /** Switch off every chat mirroring the case (deleted, or password-protected). */
  disableCase(caseId: string): Promise<WatsonMirrorEntry[]> {
    return this.mutate((f) => {
      const gone = Object.entries(f.chats).filter(([, c]) => c.caseId === caseId);
      if (gone.length === 0) return { out: [] };
      const chats = Object.fromEntries(Object.entries(f.chats).filter(([, c]) => c.caseId !== caseId));
      return { next: { ...f, chats }, out: gone.map(([chatId, c]) => ({ ...c, chatId })) };
    });
  }

  /** Add turn ids in chat order, skipping ones already pending or sent, and move the cursor. */
  enqueue(chatId: string, ids: readonly string[], cursor: string): Promise<void> {
    return this.updateChat(chatId, (c) => {
      const known = new Set([...c.pending, ...c.sent]);
      const fresh = ids.filter((id) => !known.has(id));
      return { ...c, pending: tail([...c.pending, ...fresh], MIRROR_PENDING_MAX), cursor };
    });
  }

  /** The turns went out: off the queue, into the sent set; the Telegram message ids are kept for replies. */
  markSent(chatId: string, ids: readonly string[], messageIds: readonly number[]): Promise<void> {
    return this.updateChat(chatId, (c) => {
      const done = new Set(ids);
      return {
        ...c,
        pending: c.pending.filter((id) => !done.has(id)),
        sent: tail([...c.sent.filter((id) => !done.has(id)), ...ids], MIRROR_SENT_MAX),
        messageIds: tail([...c.messageIds, ...messageIds], MIRROR_MESSAGE_IDS_MAX),
      };
    });
  }

  /** Remember a message the mirror sent that carries no turn (the hold notice, "Mirroring started"). */
  addMessageIds(chatId: string, messageIds: readonly number[]): Promise<void> {
    return this.updateChat(chatId, (c) => ({
      ...c,
      messageIds: tail([...c.messageIds, ...messageIds], MIRROR_MESSAGE_IDS_MAX),
    }));
  }

  patch(chatId: string, p: WatsonMirrorPatch): Promise<void> {
    return this.updateChat(chatId, (c) => {
      const next: WatsonMirrorChat = { ...c, ...p };
      if ("retry" in p && p.retry === undefined) delete next.retry;
      if ("held" in p && !p.held) delete next.held;
      return next;
    });
  }

  /** Inbound dedup by `<chat>:<message_id>`: true the first time, false for a replay. Persisted. */
  markInbound(key: string): Promise<boolean> {
    return this.mutate((f) => {
      if (f.seen.includes(key)) return { out: false };
      return { next: { ...f, seen: tail([...f.seen, key], MIRROR_SEEN_MAX) }, out: true };
    });
  }
}
