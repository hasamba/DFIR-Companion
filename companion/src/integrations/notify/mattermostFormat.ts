import type { NotificationEvent } from "../../analysis/notifications.js";
import type { Severity } from "../../analysis/stateTypes.js";

// Pure: a NotificationEvent → a Mattermost incoming-webhook payload. Mattermost accepts the
// Slack-COMPATIBLE message format — a top-level markdown `text` plus `attachments` with a coloured
// stripe + fields — but NOT Slack's Block Kit `blocks`, so we build a message attachment rather than
// reusing formatSlack. The headline goes in the top-level `text` (always renders, even where a
// server disables attachments); the coloured attachment carries the detail. No I/O — unit-tested.

const SEVERITY_COLOR: Record<Severity, string> = {
  Critical: "#D00000", // red
  High: "#E8590C",     // orange
  Medium: "#F1C40F",   // amber
  Low: "#2D7DD2",      // blue
  Info: "#868E96",     // grey
};

const SEVERITY_EMOJI: Record<Severity, string> = {
  Critical: "🔴",
  High: "🟠",
  Medium: "🟡",
  Low: "🔵",
  Info: "⚪",
};

export interface MattermostField {
  title: string;
  value: string;
  short: boolean;
}

export interface MattermostAttachment {
  fallback: string;
  color: string;
  text?: string;
  fields: MattermostField[];
  footer: string;
}

export interface MattermostPayload {
  text: string;
  attachments: MattermostAttachment[];
}

export function formatMattermost(event: NotificationEvent): MattermostPayload {
  const emoji = SEVERITY_EMOJI[event.severity] ?? "⚪";
  const headline = `${emoji} ${event.title}`;

  // Render "Key: value" detail lines as fields; the rest become the attachment body text.
  const fields: MattermostField[] = [];
  const textLines: string[] = [];
  for (const line of event.lines.filter(Boolean)) {
    const m = /^([A-Za-z][\w .]{0,40}?):\s+(.+)$/.exec(line);
    if (m) fields.push({ title: m[1], value: m[2], short: m[2].length <= 40 });
    else textLines.push(line);
  }
  fields.push({ title: "Severity", value: event.severity, short: true });

  if (event.url) textLines.push(`[Open case](${event.url})`);

  const attachment: MattermostAttachment = {
    fallback: truncate(headline, 200),
    color: SEVERITY_COLOR[event.severity] ?? "#868E96",
    ...(textLines.length ? { text: truncate(textLines.join("\n\n"), 3000) } : {}),
    fields,
    footer: `DFIR Companion · ${event.kind.replace(/_/g, " ")} · ${event.at}`,
  };

  return { text: `**${truncate(headline, 200)}**`, attachments: [attachment] };
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
