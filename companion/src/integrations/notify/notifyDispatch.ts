import type { FetchFn } from "../../enrichment/provider.js";
import {
  shouldNotify,
  testEvent,
  type NotificationChannel,
  type NotificationChannelType,
  type NotificationEvent,
} from "../../analysis/notifications.js";
import type { NotificationConfigStore } from "../../analysis/notificationStore.js";
import { formatSlack } from "./slackFormat.js";
import { formatTeams } from "./teamsFormat.js";
import { formatTelegram } from "./telegramFormat.js";
import { buildRfc822Message, formatEmail } from "./emailFormat.js";
import { postWebhook } from "./webhookSender.js";
import { sendSmtp, type SmtpConnect } from "./smtpClient.js";

// Routes a NotificationEvent to every channel that wants it (shouldNotify), formats per channel
// type, and sends. Best-effort: a channel failure NEVER throws — it's captured in the per-channel
// result so the dashboard can show "2 sent, 1 failed: <reason>". Injectable transports (fetchFn
// for webhooks, smtpConnect for email) keep it unit-testable with no network.

export interface NotifyTransport {
  fetchFn: FetchFn;
  smtpConnect?: SmtpConnect;     // absent → email channels are skipped with a clear reason
  timeoutMs?: number;
  now?: () => string;
}

export interface ChannelResult {
  channelId: string;
  channel: string;               // display name
  type: NotificationChannelType;
  ok: boolean;
  skipped: boolean;              // filtered out by shouldNotify (not an error)
  error?: string;
}

// Dispatch one event across all channels. Returns a result per channel that MATCHED (skipped ones
// are omitted from the array unless `includeSkipped`).
export async function dispatchEvent(
  channels: readonly NotificationChannel[],
  event: NotificationEvent,
  transport: NotifyTransport,
): Promise<ChannelResult[]> {
  const targets = channels.filter((c) => shouldNotify(c, event));
  return Promise.all(targets.map((c) => sendToChannel(c, event, transport)));
}

async function sendToChannel(
  channel: NotificationChannel,
  event: NotificationEvent,
  transport: NotifyTransport,
): Promise<ChannelResult> {
  const base = { channelId: channel.id, channel: channel.name, type: channel.type, skipped: false };
  try {
    if (channel.type === "slack") {
      if (!channel.webhookUrl) return { ...base, ok: false, error: "no webhook URL configured" };
      const r = await postWebhook(transport.fetchFn, channel.webhookUrl, formatSlack(event), transport.timeoutMs);
      return { ...base, ok: r.ok, ...(r.error ? { error: r.error } : {}) };
    }
    if (channel.type === "teams") {
      if (!channel.webhookUrl) return { ...base, ok: false, error: "no webhook URL configured" };
      const r = await postWebhook(transport.fetchFn, channel.webhookUrl, formatTeams(event), transport.timeoutMs);
      return { ...base, ok: r.ok, ...(r.error ? { error: r.error } : {}) };
    }
    if (channel.type === "telegram") {
      if (!channel.telegram?.botToken) return { ...base, ok: false, error: "no bot token configured" };
      const url = `https://api.telegram.org/bot${channel.telegram.botToken}/sendMessage`;
      const payload = { chat_id: channel.telegram.chatId, ...formatTelegram(event) };
      const r = await postWebhook(transport.fetchFn, url, payload, transport.timeoutMs);
      return { ...base, ok: r.ok, ...(r.error ? { error: r.error } : {}) };
    }
    // email
    if (!channel.smtp) return { ...base, ok: false, error: "no SMTP config" };
    if (!transport.smtpConnect) return { ...base, ok: false, error: "SMTP transport not available on this server" };
    const content = formatEmail(event);
    const raw = buildRfc822Message({
      from: channel.smtp.from,
      to: channel.smtp.to,
      subject: content.subject,
      text: content.text,
      html: content.html,
      date: event.at,
    });
    await sendSmtp(transport.smtpConnect, channel.smtp, raw, { timeoutMs: transport.timeoutMs });
    return { ...base, ok: true };
  } catch (err) {
    return { ...base, ok: false, error: (err as Error).message };
  }
}

// ── Server-facing notifier ───────────────────────────────────────────────────────────────────

export interface NotifierDeps {
  store?: NotificationConfigStore;   // absent → notifier is a no-op (notifications not configured)
  fetchFn: FetchFn;
  smtpConnect?: SmtpConnect;
  timeoutMs?: number;
  log?: (message: string) => void;
}

export interface Notifier {
  // Fire-and-forget from the server's perspective: loads channels, dispatches, logs a summary.
  // Resolves with the per-channel results (also returned by the test route).
  dispatch(event: NotificationEvent): Promise<ChannelResult[]>;
  // Send a test notification to one channel (by id) or all channels.
  test(channelId: string | undefined, at: string): Promise<ChannelResult[]>;
}

export function createNotifier(deps: NotifierDeps): Notifier {
  const transport: NotifyTransport = { fetchFn: deps.fetchFn, smtpConnect: deps.smtpConnect, timeoutMs: deps.timeoutMs };

  async function dispatch(event: NotificationEvent): Promise<ChannelResult[]> {
    if (!deps.store) return [];
    let channels: NotificationChannel[];
    try {
      channels = await deps.store.load();
    } catch (err) {
      deps.log?.(`[notify] failed to load channels: ${(err as Error).message}`);
      return [];
    }
    if (!channels.length) return [];
    const results = await dispatchEvent(channels, event, transport);
    if (results.length) {
      const sent = results.filter((r) => r.ok).length;
      const failed = results.filter((r) => !r.ok);
      deps.log?.(
        `[notify] ${event.kind} "${event.title}" — ${sent}/${results.length} sent` +
          (failed.length ? `; failures: ${failed.map((f) => `${f.channel}: ${f.error}`).join(" | ")}` : ""),
      );
    }
    return results;
  }

  async function test(channelId: string | undefined, at: string): Promise<ChannelResult[]> {
    if (!deps.store) return [];
    const all = await deps.store.load();
    const channels = channelId ? all.filter((c) => c.id === channelId) : all;
    const event = testEvent(at);
    // A test bypasses enable/threshold/kind filters so the analyst can verify a disabled or
    // high-threshold channel directly.
    const results = await Promise.all(channels.map((c) => sendToChannel(c, event, transport)));
    deps.log?.(`[notify] test → ${results.filter((r) => r.ok).length}/${results.length} channel(s) ok`);
    return results;
  }

  return { dispatch, test };
}
