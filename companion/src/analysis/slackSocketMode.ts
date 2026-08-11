import WebSocket from "ws";
import type { Logger } from "../logging/logger.js";

// Slack Socket Mode transport for the war-room slash-command bot (#235). The Slack counterpart to
// Telegram's long polling: the Companion opens an outbound WebSocket to Slack and commands arrive
// down it, so no tunnel, no public hostname, no DFIR_ALLOWED_HOSTS entry, and no Request URL to
// re-register whenever a quick tunnel changes its name.
//
// The handshake: POST apps.connections.open with an app-level token (xapp-…, scope
// connections:write) returns a single-use wss:// URL. Slack then pushes an envelope per command,
// each carrying an envelope_id that MUST be acked — the ack payload is the reply the analyst sees,
// exactly like the HTTP response body. Slack also asks us to reconnect periodically (a `disconnect`
// frame), which is routine rather than an error: it hands out a fresh URL each time.
//
// Note Socket Mode replaces request signing entirely. There is no HTTP request to sign, and the
// app-level token is what authenticates us to Slack — DFIR_SLACK_SIGNING_SECRET is a webhook-mode
// concern and plays no part here.

export interface SlackEnvelope {
  envelope_id?: string;
  type?: string;
  payload?: SlackCommandPayload;
  accepts_response_payload?: boolean;
  reason?: string;
}

export interface SlackCommandPayload {
  command?: string;
  text?: string;
  channel_id?: string;
  user_id?: string;
  response_url?: string;
}

/** The slice of a WebSocket this transport uses, so tests can supply a fake. */
export interface SocketLike {
  on(event: string, cb: (arg?: unknown) => void): void;
  send(data: string): void;
  close(): void;
}

export interface SlackSocketModeOptions {
  appToken: string;
  /** Handle one command. Returns the reply body Slack should show, or undefined to ack silently. */
  onCommand: (payload: SlackCommandPayload) => Promise<unknown>;
  log: Logger;
  apiBase?: string;
  fetchFn?: typeof fetch;
  socketFactory?: (url: string) => SocketLike;
  sleepFn?: (ms: number) => Promise<void>;
}

const MIN_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 60_000;

export class SlackSocketMode {
  private readonly opts: SlackSocketModeOptions;
  private readonly fetchFn: typeof fetch;
  private readonly socketFactory: (url: string) => SocketLike;
  private readonly sleepFn: (ms: number) => Promise<void>;
  private stopped = false;
  private socket: SocketLike | undefined;
  private loop: Promise<void> | undefined;
  private backoffMs = MIN_BACKOFF_MS;
  /** Settles the in-flight pump(). stop() calls this directly rather than waiting for the socket to
   *  emit "close" — a half-open or wedged socket would otherwise hang shutdown indefinitely. */
  private endCurrentSocket: (() => void) | undefined;

  constructor(options: SlackSocketModeOptions) {
    this.opts = options;
    this.fetchFn = options.fetchFn ?? fetch;
    this.socketFactory = options.socketFactory ?? ((url) => new WebSocket(url));
    this.sleepFn = options.sleepFn ?? ((ms) => new Promise((r) => setTimeout(r, ms).unref?.()));
  }

  start(): void {
    if (this.loop) return;
    this.opts.log.info("[slack] socket mode: connecting (no inbound URL needed)");
    this.loop = this.run();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    try {
      this.socket?.close();
    } catch {
      /* already gone */
    }
    this.endCurrentSocket?.(); // don't wait on a "close" event that may never come
    await this.loop?.catch(() => {});
    this.loop = undefined;
  }

  private async run(): Promise<void> {
    while (!this.stopped) {
      try {
        const url = await this.openConnection();
        await this.pump(url); // resolves when Slack asks us to reconnect, or the socket drops
        this.backoffMs = MIN_BACKOFF_MS;
      } catch (err) {
        if (this.stopped) return;
        await this.handleFailure(err as Error);
      }
    }
  }

  /** Trade the app-level token for a single-use wss:// URL. */
  private async openConnection(): Promise<string> {
    const base = (this.opts.apiBase ?? "https://slack.com/api").replace(/\/+$/, "");
    const res = await this.fetchFn(`${base}/apps.connections.open`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.opts.appToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      signal: AbortSignal.timeout(15_000),
    });
    const body = (await res.json().catch(() => ({}))) as { ok?: boolean; url?: string; error?: string };
    if (!body.ok || !body.url) throw new SlackSocketError(body.error ?? `HTTP ${res.status}`);
    return body.url;
  }

  /** Run one socket to completion. Resolves on a clean reconnect request or a drop; rejects only
   *  on a socket-level error, which the caller turns into a backoff. */
  private pump(url: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let socket: SocketLike;
      try {
        socket = this.socketFactory(url);
      } catch (err) {
        // socketFactory is injected, so a caller can throw anything. The whole rejection path
        // here feeds the reconnect backoff, which reads `.message` — a non-Error would surface
        // as "undefined" in the log with no way back to the cause.
        reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      this.socket = socket;
      let settled = false;
      const done = (err?: Error): void => {
        if (settled) return;
        settled = true;
        this.socket = undefined;
        this.endCurrentSocket = undefined;
        try {
          socket.close();
        } catch {
          /* already closing */
        }
        if (err) reject(err);
        else resolve();
      };
      this.endCurrentSocket = () => done();

      socket.on("open", () => this.opts.log.info("[slack] socket mode: connected"));
      socket.on("close", () => done());
      socket.on("error", (err) => done(err instanceof Error ? err : new Error(String(err))));
      socket.on("message", (data) => {
        void this.onMessage(socket, data)
          .then((reconnect) => {
            if (reconnect) done();
          })
          .catch((err) => this.opts.log.warn(`[slack] socket message failed: ${(err as Error).message}`));
      });
    });
  }

  /** Handle one frame. Resolves true when Slack has asked us to reconnect. */
  private async onMessage(socket: SocketLike, data: unknown): Promise<boolean> {
    let frame: SlackEnvelope;
    try {
      frame = JSON.parse(typeof data === "string" ? data : String(data)) as SlackEnvelope;
    } catch {
      return false; // not JSON — nothing we can act on
    }

    if (frame.type === "hello") {
      this.backoffMs = MIN_BACKOFF_MS;
      return false;
    }
    // Routine: Slack rotates connections and warns before closing one. Not an error.
    if (frame.type === "disconnect") {
      this.opts.log.info(`[slack] socket mode: reconnecting (${frame.reason ?? "requested"})`);
      return true;
    }

    if (!frame.envelope_id) return false;
    // Ack EVERY envelope, including kinds we don't act on — an unacked envelope is redelivered.
    let payload: unknown;
    if (frame.type === "slash_commands" && frame.payload) {
      payload = await this.opts.onCommand(frame.payload).catch((err) => {
        this.opts.log.warn(`[slack] command failed: ${(err as Error).message}`);
        return undefined;
      });
    }
    const ack: Record<string, unknown> = { envelope_id: frame.envelope_id };
    if (payload !== undefined && frame.accepts_response_payload !== false) ack.payload = payload;
    socket.send(JSON.stringify(ack));
    return false;
  }

  private async handleFailure(err: Error): Promise<void> {
    const message = err.message;
    if (message === "invalid_auth" || message === "not_authed" || message === "token_expired") {
      this.opts.log.error(
        `[slack] socket mode: ${message} — DFIR_SLACK_APP_TOKEN must be an app-level token ` +
          `(starts "xapp-") with the connections:write scope, from Settings → Basic Information → App-Level Tokens.`,
      );
    } else {
      this.opts.log.warn(
        `[slack] socket mode: ${message}; retrying in ${Math.round(this.backoffMs / 1000)}s`,
      );
    }
    await this.sleepFn(this.backoffMs);
    this.backoffMs = Math.min(this.backoffMs * 2, MAX_BACKOFF_MS);
  }
}

export class SlackSocketError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SlackSocketError";
  }
}
