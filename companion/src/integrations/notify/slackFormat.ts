import type { NotificationEvent } from "../../analysis/notifications.js";
import type { Severity } from "../../analysis/stateTypes.js";

// Pure: a NotificationEvent → a Slack incoming-webhook payload. Slack renders Block Kit; we send a
// header + a section with the detail lines, plus a top-level `text` fallback (used in
// notifications/previews and by clients that don't render blocks). No I/O — unit-tested.

const SEVERITY_EMOJI: Record<Severity, string> = {
  Critical: "🔴",
  High: "🟠",
  Medium: "🟡",
  Low: "🔵",
  Info: "⚪",
};

export interface SlackPayload {
  text: string;
  blocks: unknown[];
}

export function formatSlack(event: NotificationEvent): SlackPayload {
  const emoji = SEVERITY_EMOJI[event.severity] ?? "⚪";
  const headline = `${emoji} ${event.title}`;
  const body = event.lines.filter(Boolean).map((l) => `• ${l}`).join("\n");
  const contextText = `DFIR Companion · ${event.kind.replace(/_/g, " ")} · ${event.at}`;

  const blocks: unknown[] = [
    { type: "header", text: { type: "plain_text", text: truncate(headline, 150), emoji: true } },
  ];
  if (body) blocks.push({ type: "section", text: { type: "mrkdwn", text: truncate(body, 2900) } });
  if (event.url) {
    blocks.push({
      type: "actions",
      elements: [{ type: "button", text: { type: "plain_text", text: "Open case" }, url: event.url }],
    });
  }
  blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: contextText }] });

  return { text: `${headline}${body ? `\n${body}` : ""}`, blocks };
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
