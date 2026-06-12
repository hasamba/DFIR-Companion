import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { atomicWrite } from "../storage/atomicWrite.js";
import {
  NOTIFICATION_CHANNEL_TYPES,
  SEVERITIES,
  applyChannelPatch,
  type ChannelDraft,
  type NotificationChannel,
  type NotificationEventKind,
} from "./notifications.js";

// Persists the notification channel list. GLOBAL (shared across cases, like IocWhitelistStore /
// TemplateStore / ArtifactBundleStore): Slack/Teams webhooks and the SMTP relay are
// environment-level infrastructure reused across investigations. A single JSON file in its own
// subdir next to `cases/` (a subdir, not a loose sibling, so it stays creatable when
// DFIR_CASES_ROOT is a drive-root child like C:\cases — Windows forbids files in a drive root).
//
// Secrets (webhook URLs, SMTP passwords) live in this file; the GET route redacts them before they
// reach the browser. The list starts empty — notifications are opt-in (OPSEC).

const smtpSchema = z.object({
  host: z.string().catch(""),
  port: z.number().catch(587),
  secure: z.boolean().catch(false),
  username: z.string().optional(),
  password: z.string().optional(),
  from: z.string().catch(""),
  to: z.array(z.string()).catch([]),
  rejectUnauthorized: z.boolean().optional(),
});

const eventsSchema = z.object({
  critical_finding: z.boolean().catch(true),
  playbook_update: z.boolean().catch(true),
  milestone: z.boolean().catch(false),
});

const channelSchema = z.object({
  id: z.string(),
  type: z.enum(NOTIFICATION_CHANNEL_TYPES),
  name: z.string().catch(""),
  enabled: z.boolean().catch(false),
  minSeverity: z.enum(SEVERITIES).catch("High"),
  events: eventsSchema.catch({ critical_finding: true, playbook_update: true, milestone: false } as Record<NotificationEventKind, boolean>),
  webhookUrl: z.string().optional(),
  smtp: smtpSchema.optional(),
  createdAt: z.string().catch(""),
  updatedAt: z.string().catch(""),
});

export class NotificationConfigStore {
  constructor(private readonly file: string) {}

  async load(): Promise<NotificationChannel[]> {
    try {
      const raw = JSON.parse(await readFile(this.file, "utf8")) as unknown;
      if (!Array.isArray(raw)) return [];
      // Re-validate on read so a hand-edited file can't inject a malformed channel into dispatch.
      return raw
        .map((c) => {
          const parsed = channelSchema.safeParse(c);
          return parsed.success ? (parsed.data as NotificationChannel) : null;
        })
        .filter((c): c is NotificationChannel => c !== null);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private async persist(channels: NotificationChannel[]): Promise<void> {
    const dir = dirname(this.file);
    if (dir && !existsSync(dir)) await mkdir(dir, { recursive: true });
    await atomicWrite(this.file, JSON.stringify(channels, null, 2));
  }

  async get(id: string): Promise<NotificationChannel | null> {
    return (await this.load()).find((c) => c.id === id) ?? null;
  }

  // Create a channel from a validated draft (server-assigned id + timestamps).
  async add(draft: ChannelDraft, at: string = new Date().toISOString()): Promise<NotificationChannel> {
    const channels = await this.load();
    const base: NotificationChannel = {
      id: randomUUID(),
      type: draft.type,
      name: draft.name,
      enabled: draft.enabled,
      minSeverity: draft.minSeverity,
      events: draft.events,
      createdAt: at,
      updatedAt: at,
    };
    const channel = applyChannelPatch(base, draft, at);
    await this.persist([...channels, channel]);
    return channel;
  }

  // Update a channel, preserving secrets the edit left blank (applyChannelPatch). Returns null when
  // the id is unknown.
  async update(id: string, draft: ChannelDraft, at: string = new Date().toISOString()): Promise<NotificationChannel | null> {
    const channels = await this.load();
    const idx = channels.findIndex((c) => c.id === id);
    if (idx === -1) return null;
    const next = applyChannelPatch(channels[idx], draft, at);
    const updated = channels.map((c, i) => (i === idx ? next : c));
    await this.persist(updated);
    return next;
  }

  async remove(id: string): Promise<boolean> {
    const channels = await this.load();
    const next = channels.filter((c) => c.id !== id);
    if (next.length === channels.length) return false;
    await this.persist(next);
    return true;
  }
}
