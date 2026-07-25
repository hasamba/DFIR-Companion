import { readFile } from "node:fs/promises";
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

  async bind(key: string, caseId: string, at: string = new Date().toISOString()): Promise<{ caseId: string; boundAt: string }> {
    const all = await this.loadAll();
    const next = { ...all, [key]: { caseId, boundAt: at } };
    await atomicWrite(this.file, JSON.stringify(next, null, 2));
    return next[key];
  }

  async unbind(key: string): Promise<boolean> {
    const all = await this.loadAll();
    if (!(key in all)) return false;
    const next = { ...all };
    delete next[key];
    await atomicWrite(this.file, JSON.stringify(next, null, 2));
    return true;
  }
}

// Build the binding key from the inbound payload's platform + channel id.
export function bindingKey(platform: "slack" | "teams", channelId: string): string {
  return `${platform}:${channelId}`;
}