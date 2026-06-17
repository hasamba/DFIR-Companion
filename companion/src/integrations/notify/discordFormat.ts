import type { NotificationEvent } from "../../analysis/notifications.js";
import type { Severity } from "../../analysis/stateTypes.js";

// Pure: a NotificationEvent → a Discord webhook payload. Discord renders rich "embeds" (a coloured
// left stripe + title/description/fields/footer). The embed colour is an INTEGER (0xRRGGBB), unlike
// Slack/Teams which take a hex string. Discord webhooks reply 204 No Content on success (postWebhook
// treats any 2xx as ok). No I/O — unit-tested.

const SEVERITY_COLOR: Record<Severity, number> = {
  Critical: 0xd00000, // red
  High: 0xe8590c,     // orange
  Medium: 0xf1c40f,   // amber
  Low: 0x2d7dd2,      // blue
  Info: 0x868e96,     // grey
};

const SEVERITY_EMOJI: Record<Severity, string> = {
  Critical: "🔴",
  High: "🟠",
  Medium: "🟡",
  Low: "🔵",
  Info: "⚪",
};

export interface DiscordEmbedField {
  name: string;
  value: string;
  inline: boolean;
}

export interface DiscordEmbed {
  title: string;
  description?: string;
  url?: string;
  color: number;
  fields: DiscordEmbedField[];
  footer: { text: string };
  timestamp: string;
}

export interface DiscordPayload {
  embeds: DiscordEmbed[];
}

export function formatDiscord(event: NotificationEvent): DiscordPayload {
  const emoji = SEVERITY_EMOJI[event.severity] ?? "⚪";

  // Render "Key: value" detail lines as embed fields; the rest become the description.
  const fields: DiscordEmbedField[] = [];
  const descLines: string[] = [];
  for (const line of event.lines.filter(Boolean)) {
    const m = /^([A-Za-z][\w .]{0,40}?):\s+(.+)$/.exec(line);
    if (m) fields.push({ name: truncate(m[1], 256), value: truncate(m[2], 1024), inline: m[2].length <= 40 });
    else descLines.push(line);
  }
  fields.push({ name: "Severity", value: event.severity, inline: true });

  const embed: DiscordEmbed = {
    title: truncate(`${emoji} ${event.title}`, 256),
    color: SEVERITY_COLOR[event.severity] ?? 0x868e96,
    ...(descLines.length ? { description: truncate(descLines.join("\n"), 4096) } : {}),
    // A `url` makes the embed title a clickable "Open case" link.
    ...(event.url ? { url: event.url } : {}),
    fields: fields.slice(0, 25), // Discord caps embeds at 25 fields
    footer: { text: truncate(`DFIR Companion · ${event.kind.replace(/_/g, " ")}`, 2048) },
    timestamp: event.at,
  };

  return { embeds: [embed] };
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
