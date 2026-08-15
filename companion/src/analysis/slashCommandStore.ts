import { readFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";

// Per-channel case binding store for the war-room slash-command bot (#235). A channel can bind
// to a default case (`/dfir bind <caseId>`) so subsequent commands omit the caseId. Stored in a
// GLOBAL JSON file beside the notification config (a channel-level concern, not per-case) —
// mirrors NotificationConfigStore's location rationale. Returns sensible defaults when absent /
// unreadable. Keyed by `<platform>:<channelId>` so a Slack channel and a Teams channel with the
// same numeric id don't collide.

const bindingSchema = z.object({
  caseId: z.string(),
  boundAt: z.string(),
});

const bindingsFileSchema = z.record(z.string(), bindingSchema).catch({});

export type ChannelBindingMap = Record<string, { caseId: string; boundAt: string }>;

export class SlashCommandChannelStore {
  constructor(private readonly file: string) {}

  async loadAll(): Promise<ChannelBindingMap> {
    try {
      return bindingsFileSchema.parse(JSON.parse(await readFile(this.file, "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw err;
    }
  }

  async get(key: string): Promise<{ caseId: string; boundAt: string } | undefined> {
    return (await this.loadAll())[key];
  }

  // Create the parent directory before writing, exactly as NotificationConfigStore does: this file
  // lives in the notifications/ dir beside cases/, which does not exist until something writes
  // there — so on a fresh install the very first `/dfir bind` is the thing that creates it.
  private async write(map: ChannelBindingMap): Promise<void> {
    const dir = dirname(this.file);
    if (dir) await mkdir(dir, { recursive: true });
    await atomicWrite(this.file, JSON.stringify(map, null, 2));
  }

  async bind(
    key: string,
    caseId: string,
    at: string = new Date().toISOString(),
  ): Promise<{ caseId: string; boundAt: string }> {
    const all = await this.loadAll();
    const next = { ...all, [key]: { caseId, boundAt: at } };
    await this.write(next);
    return next[key];
  }

  async unbind(key: string): Promise<boolean> {
    const all = await this.loadAll();
    if (!(key in all)) return false;
    const next = { ...all };
    delete next[key];
    await this.write(next);
    return true;
  }
}

/** The chat platforms the war-room bot speaks to. */
export type ChatPlatform = "slack" | "teams" | "telegram";

// Build the binding key from the inbound payload's platform + channel id.
export function bindingKey(platform: ChatPlatform, channelId: string): string {
  return `${platform}:${channelId}`;
}

/**
 * The Telegram chats the bot has been bound to, for the notification channel form to OFFER as
 * destinations (#58 follow-up). The operator already told the bot about these with `/dfir bind`,
 * so the Chat ID box can pre-fill instead of sending them to read a JSON file.
 *
 * Offer, never auto-send: a notification carries case content, so the chosen chat is pre-filled
 * into a visible field and still has to be saved — this returns candidates, not a default target.
 * Keys are `<platform>:<channelId>`, and a channel id may itself contain ":" (`@name` handles do
 * not, but nothing guarantees that), so the prefix is sliced off rather than split on.
 */
export function telegramChatsFromBindings(
  map: ChannelBindingMap,
): Array<{ chatId: string; caseId: string; boundAt: string }> {
  const prefix = "telegram:";
  return Object.entries(map)
    .filter(([key]) => key.startsWith(prefix))
    .map(([key, b]) => ({ chatId: key.slice(prefix.length), caseId: b.caseId, boundAt: b.boundAt }))
    .filter((c) => c.chatId !== "")
    .sort((a, b) => a.chatId.localeCompare(b.chatId));
}
