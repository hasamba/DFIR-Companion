import type { Logger } from "../logging/logger.js";

// Telegram long-poll transport for the war-room slash-command bot (#235).
//
// The webhook routes need the Companion to be REACHABLE — a tunnel or reverse proxy, a hostname in
// DFIR_ALLOWED_HOSTS, and a setWebhook registration to redo every time that hostname changes. For a
// tool that is meant to run on a locked-down analyst workstation that is a lot of exposure and
// ceremony, so Telegram (alone among the three platforms) offers the other direction: getUpdates.
//
// The Companion calls Telegram and Telegram holds the connection open until an update arrives or
// the timeout expires — so replies stay near-instant without polling in a tight loop, and nothing
// about the machine is reachable from the internet. Same outbound direction the notifier already
// uses.
//
// Telegram refuses getUpdates while a webhook is registered for that bot, and refuses a second
// concurrent poller for the same bot; both surface as HTTP 409 and are reported with the fix
// rather than retried blindly.

export interface TelegramUpdate {
  update_id: number;
  message?: TelegramMessage;
  edited_message?: TelegramMessage;
  channel_post?: TelegramMessage;
}

export interface TelegramMessage {
  chat?: { id?: number | string };
  from?: { id?: number | string };
  text?: string;
  caption?: string;
}

export interface TelegramPollerOptions {
  botToken: string;
  /** Handle one update. Rejections are logged and the loop continues — one bad command must not
   *  stop the bot. */
  onUpdate: (update: TelegramUpdate) => Promise<void>;
  log: Logger;
  apiBase?: string;
  /** How long Telegram holds an idle connection open, in seconds (default 50). */
  pollTimeoutSeconds?: number;
  fetchFn?: typeof fetch;
  /** Injected in tests so backoff doesn't really sleep. */
  sleepFn?: (ms: number) => Promise<void>;
}

const MIN_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 60_000;

export class TelegramPoller {
  private readonly opts: Required<Pick<TelegramPollerOptions, "apiBase" | "pollTimeoutSeconds">> &
    TelegramPollerOptions;
  private readonly fetchFn: typeof fetch;
  private readonly sleepFn: (ms: number) => Promise<void>;
  private stopped = false;
  private controller: AbortController | undefined;
  private loop: Promise<void> | undefined;
  /** Telegram's cursor: the next update_id we have NOT processed. Sending it back is what marks
   *  everything before it as delivered — without it Telegram replays the same commands forever. */
  private offset: number | undefined;
  private backoffMs = MIN_BACKOFF_MS;

  constructor(options: TelegramPollerOptions) {
    // Defaults go AFTER the spread and resolve with ??. Spreading options over a defaults object
    // instead lets an explicitly-passed `apiBase: undefined` overwrite the default with undefined —
    // which is exactly what the caller does when the env override is unset, and it broke every poll
    // with "Cannot read properties of undefined". Tests that simply omit the key never see it.
    this.opts = {
      ...options,
      apiBase: options.apiBase ?? "https://api.telegram.org",
      pollTimeoutSeconds: options.pollTimeoutSeconds ?? 50,
    };
    this.fetchFn = options.fetchFn ?? fetch;
    this.sleepFn = options.sleepFn ?? ((ms) => new Promise((r) => setTimeout(r, ms).unref?.()));
  }

  /** Begin polling. Returns immediately; the loop runs until stop(). */
  start(): void {
    if (this.loop) return;
    this.opts.log.info(`[telegram] long-polling for commands (no inbound URL needed)`);
    this.loop = this.run();
  }

  /** Stop polling and wait for the in-flight request to unwind. */
  async stop(): Promise<void> {
    this.stopped = true;
    this.controller?.abort();
    await this.loop?.catch(() => {});
    this.loop = undefined;
  }

  private async run(): Promise<void> {
    while (!this.stopped) {
      try {
        const updates = await this.getUpdates();
        this.backoffMs = MIN_BACKOFF_MS; // a good round clears any accumulated backoff
        for (const update of updates) {
          if (this.stopped) return;
          // Advance the cursor BEFORE handling: a command that throws must not be redelivered on
          // the next poll, or one malformed message becomes an infinite loop.
          this.offset = update.update_id + 1;
          try {
            await this.opts.onUpdate(update);
          } catch (err) {
            this.opts.log.warn(`[telegram] command failed: ${(err as Error).message}`);
          }
        }
      } catch (err) {
        if (this.stopped) return;
        await this.handleFailure(err as Error);
      }
    }
  }

  private async getUpdates(): Promise<TelegramUpdate[]> {
    this.controller = new AbortController();
    // Give the request longer than Telegram's own hold, so the timeout that fires is theirs.
    const timer = setTimeout(() => this.controller?.abort(), (this.opts.pollTimeoutSeconds + 15) * 1_000);
    timer.unref?.();
    try {
      const url =
        `${this.opts.apiBase.replace(/\/+$/, "")}/bot${this.opts.botToken}/getUpdates` +
        `?timeout=${this.opts.pollTimeoutSeconds}` +
        `&allowed_updates=${encodeURIComponent(JSON.stringify(["message", "channel_post"]))}` +
        (this.offset === undefined ? "" : `&offset=${this.offset}`);
      const res = await this.fetchFn(url, { signal: this.controller.signal });
      const body = (await res.json().catch(() => ({}))) as {
        ok?: boolean;
        result?: TelegramUpdate[];
        description?: string;
      };
      if (!res.ok || body.ok === false) {
        throw new TelegramApiError(res.status, body.description ?? `HTTP ${res.status}`);
      }
      return Array.isArray(body.result) ? body.result : [];
    } finally {
      clearTimeout(timer);
      this.controller = undefined;
    }
  }

  /** Back off after a failed round, saying something actionable for the failures that are
   *  configuration rather than weather. */
  private async handleFailure(err: Error): Promise<void> {
    if (err instanceof TelegramApiError && err.status === 409) {
      // The two ways a bot ends up with a second consumer. Neither resolves by waiting, so say what
      // to do rather than letting an unexplained 409 scroll past every minute.
      this.opts.log.error(
        `[telegram] ${err.message} — a webhook is registered for this bot, or another poller is ` +
          `running. Clear the webhook (deleteWebhook) or stop the other instance; polling and ` +
          `webhooks cannot both be active on one bot.`,
      );
    } else if (err instanceof TelegramApiError && err.status === 401) {
      this.opts.log.error(`[telegram] ${err.message} — DFIR_TELEGRAM_BOT_TOKEN is wrong or revoked.`);
    } else {
      this.opts.log.warn(
        `[telegram] poll failed (${err.message}); retrying in ${Math.round(this.backoffMs / 1000)}s`,
      );
    }
    await this.sleepFn(this.backoffMs);
    this.backoffMs = Math.min(this.backoffMs * 2, MAX_BACKOFF_MS);
  }
}

export class TelegramApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "TelegramApiError";
  }
}

/** Send a chat message through the Bot API. Used for poller replies, where there is no webhook
 *  response to piggyback on. Best-effort: a delivery failure is logged, never thrown at the
 *  command that produced it. */
export async function sendTelegramMessage(input: {
  botToken: string;
  chatId: string;
  text: string;
  apiBase?: string;
  fetchFn?: typeof fetch;
  log: Logger;
}): Promise<void> {
  const base = (input.apiBase ?? "https://api.telegram.org").replace(/\/+$/, "");
  const doFetch = input.fetchFn ?? fetch;
  try {
    const res = await doFetch(`${base}/bot${input.botToken}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: input.chatId, text: input.text }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) input.log.warn(`[telegram] sendMessage returned ${res.status}`);
  } catch (err) {
    input.log.warn(`[telegram] sendMessage failed: ${(err as Error).message}`);
  }
}
