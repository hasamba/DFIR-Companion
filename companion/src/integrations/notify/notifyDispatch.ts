import type { FetchFn } from "../../enrichment/provider.js";
import {
  resolveTelegramBotToken,
  shouldNotify,
  testEvent,
  type NotificationChannel,
  type NotificationChannelType,
  type NotificationEvent,
} from "../../analysis/notifications.js";
import type { NotificationConfigStore } from "../../analysis/notificationStore.js";
import { formatSlack } from "./slackFormat.js";
import { formatTeams } from "./teamsFormat.js";
import { formatMattermost } from "./mattermostFormat.js";
import { formatDiscord } from "./discordFormat.js";
import { formatTelegram } from "./telegramFormat.js";
import { buildRfc822Message, formatEmail } from "./emailFormat.js";
import { postWebhook } from "./webhookSender.js";
import { sendSmtp, type SmtpConnect } from "./smtpClient.js";

// Per-type payload builder for the incoming-webhook channels. They all POST a JSON body to the
// channel's webhookUrl — only the body shape differs (Slack Block Kit, Teams MessageCard,
// Mattermost Slack-compatible attachment, Discord embed). email/telegram use their own transports.
const WEBHOOK_FORMATTERS: Partial<Record<NotificationChannelType, (e: NotificationEvent) => unknown>> = {
  slack: formatSlack,
  teams: formatTeams,
  mattermost: formatMattermost,
  discord: formatDiscord,
};

// Routes a NotificationEvent to every channel that wants it (shouldNotify), formats per channel
// type, and sends. Best-effort: a channel failure NEVER throws — it's captured in the per-channel
// result so the dashboard can show "2 sent, 1 failed: <reason>". Injectable transports (fetchFn
// for webhooks, smtpConnect for email) keep it unit-testable with no network.

export interface NotifyTransport {
  fetchFn: FetchFn;
  smtpConnect?: SmtpConnect; // absent → email channels are skipped with a clear reason
  // The war-room bot's DFIR_TELEGRAM_BOT_TOKEN, injected rather than read here so this module stays
  // env-free. Used by telegram channels that carry no token of their own.
  telegramBotToken?: string;
  // DFIR_TELEGRAM_API_BASE — a self-hosted Bot API or an egress proxy. Applies to EVERY telegram
  // channel, not just token-borrowing ones: it says how to reach Telegram from this box, which is a
  // property of the network rather than of the bot. Posting to api.telegram.org anyway would fail
  // on a closed network, or slip past the proxy the operator put there on purpose.
  telegramApiBase?: string;
  timeoutMs?: number;
  now?: () => string;
}

export interface ChannelResult {
  channelId: string;
  channel: string; // display name
  type: NotificationChannelType;
  ok: boolean;
  skipped: boolean; // filtered out by shouldNotify (not an error)
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
    const formatter = WEBHOOK_FORMATTERS[channel.type];
    if (formatter) {
      if (!channel.webhookUrl) return { ...base, ok: false, error: "no webhook URL configured" };
      const r = await postWebhook(
        transport.fetchFn,
        channel.webhookUrl,
        formatter(event),
        transport.timeoutMs,
      );
      return { ...base, ok: r.ok, ...(r.error ? { error: r.error } : {}) };
    }
    if (channel.type === "telegram") {
      const botToken = resolveTelegramBotToken(channel, transport.telegramBotToken);
      if (!botToken) return { ...base, ok: false, error: "no bot token configured" };
      // The token can now come from the env, so the channel's own transport block is no longer
      // implicitly proven to exist by having one — check the chat ID on its own.
      if (!channel.telegram?.chatId) return { ...base, ok: false, error: "no chat ID configured" };
      // Same default + trailing-slash trim as the war-room poller and slash-command result sender,
      // so one bot is addressed one way everywhere.
      const apiBase = (transport.telegramApiBase ?? "").trim() || "https://api.telegram.org";
      const url = `${apiBase.replace(/\/+$/, "")}/bot${botToken}/sendMessage`;
      const payload = { chat_id: channel.telegram.chatId, ...formatTelegram(event) };
      const r = await postWebhook(transport.fetchFn, url, payload, transport.timeoutMs);
      return { ...base, ok: r.ok, ...(r.error ? { error: r.error } : {}) };
    }
    // email
    if (!channel.smtp) return { ...base, ok: false, error: "no SMTP config" };
    if (!transport.smtpConnect)
      return { ...base, ok: false, error: "SMTP transport not available on this server" };
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
  store?: NotificationConfigStore; // absent → notifier is a no-op (notifications not configured)
  fetchFn: FetchFn;
  smtpConnect?: SmtpConnect;
  // THUNKS, not values: the notifier is built once at startup, so capturing these would pin them to
  // boot-time values. The token is on the /settings/reload allowlist and therefore rotates without a
  // restart; the API base is not, and still needs one — a thunk simply costs nothing and keeps the
  // two read the same way.
  telegramBotToken?: () => string | undefined;
  telegramApiBase?: () => string | undefined;
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
  // Rebuilt per send so the telegram thunks are re-read rather than captured at startup.
  const transportNow = (): NotifyTransport => ({
    fetchFn: deps.fetchFn,
    smtpConnect: deps.smtpConnect,
    telegramBotToken: deps.telegramBotToken?.(),
    telegramApiBase: deps.telegramApiBase?.(),
    timeoutMs: deps.timeoutMs,
  });

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
    const results = await dispatchEvent(channels, event, transportNow());
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
    const transport = transportNow();
    const results = await Promise.all(channels.map((c) => sendToChannel(c, event, transport)));
    deps.log?.(`[notify] test → ${results.filter((r) => r.ok).length}/${results.length} channel(s) ok`);
    return results;
  }

  return { dispatch, test };
}
