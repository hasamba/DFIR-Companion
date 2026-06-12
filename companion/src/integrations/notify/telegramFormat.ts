import type { NotificationEvent } from "../../analysis/notifications.js";
import type { Severity } from "../../analysis/stateTypes.js";

// Pure: a NotificationEvent → a Telegram Bot API sendMessage payload.
// Uses HTML parse_mode so bold/italic/links render natively. No I/O — unit-tested.

const SEVERITY_EMOJI: Record<Severity, string> = {
  Critical: "🔴",
  High: "🟠",
  Medium: "🟡",
  Low: "🔵",
  Info: "⚪",
};

export interface TelegramPayload {
  text: string;
  parse_mode: "HTML";
}

export function formatTelegram(event: NotificationEvent): TelegramPayload {
  const emoji = SEVERITY_EMOJI[event.severity] ?? "⚪";
  const parts: string[] = [`<b>${escHtml(`${emoji} ${event.title}`)}</b>`];

  const details = event.lines.filter(Boolean);
  if (details.length) {
    parts.push("");
    for (const l of details) parts.push(`• ${escHtml(l)}`);
  }

  if (event.url) {
    parts.push("");
    parts.push(`<a href="${escHtml(event.url)}">Open case</a>`);
  }

  parts.push("");
  parts.push(`<i>DFIR Companion · ${escHtml(event.kind.replace(/_/g, " "))} · ${escHtml(event.at)}</i>`);

  return { text: truncate(parts.join("\n"), 4096), parse_mode: "HTML" };
}

function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
