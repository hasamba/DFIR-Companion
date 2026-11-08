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
  /** Injected in tests to age a connection without waiting. */
  nowFn?: () => number;
}

const MIN_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 60_000;
/** A connection that stayed open at least this long counts as healthy: the next reconnect is
 *  immediate and the backoff resets. Anything shorter backs off, so a socket that keeps dropping
 *  right after it opens cannot turn into a hot loop of apps.connections.open calls (#2411). */
const HEALTHY_CONNECTION_MS = 30_000;
/** How many answered envelopes to remember for redelivery. Only answered entries are evicted. */
const ENVELOPE_CACHE_LIMIT = 500;

type Ack = Record<string, unknown>;
interface EnvelopeEntry {
  ack: Promise<Ack>;
  done: boolean;
}

export class SlackSocketMode {
  private readonly opts: SlackSocketModeOptions;
  private readonly fetchFn: typeof fetch;
  private readonly socketFactory: (url: string) => SocketLike;
  private readonly sleepFn: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private stopped = false;
  private socket: SocketLike | undefined;
  private loop: Promise<void> | undefined;
  private stopping: Promise<void> | undefined;
  /** Aborted by stop(): cancels a pending connections.open and wakes a backoff sleep. Fresh per run. */
  private stopController: AbortController | undefined;
  private backoffMs = MIN_BACKOFF_MS;
  /** Settles the in-flight pump(). stop() calls this directly rather than waiting for the socket to
   *  emit "close" — a half-open or wedged socket would otherwise hang shutdown indefinitely. */
  private endCurrentSocket: (() => void) | undefined;
  /** envelope_id → its (eventual) ack. Slack redelivers an envelope whose ack it did not see in
   *  time, possibly on a NEW connection; the command must still run only once (#2411). */
  private readonly envelopes = new Map<string, EnvelopeEntry>();

  constructor(options: SlackSocketModeOptions) {
    this.opts = options;
    this.fetchFn = options.fetchFn ?? fetch;
    this.socketFactory = options.socketFactory ?? ((url) => new WebSocket(url));
    this.sleepFn = options.sleepFn ?? ((ms) => new Promise((r) => setTimeout(r, ms).unref?.()));
    this.now = options.nowFn ?? Date.now;
  }

  /** Begin. Restart is `await stop(); start()` — a start() while a stop() is still unwinding is a
   *  no-op, like a second start(). */
  start(): void {
    if (this.loop) return;
    this.stopped = false;
    this.backoffMs = MIN_BACKOFF_MS;
    this.stopController = new AbortController();
    this.opts.log.info("[slack] socket mode: connecting (no inbound URL needed)");
    this.loop = this.run();
  }

  stop(): Promise<void> {
    this.stopping ??= this.shutdown().finally(() => {
      this.stopping = undefined;
    });
    return this.stopping;
  }

  private async shutdown(): Promise<void> {
    this.stopped = true;
    this.stopController?.abort();
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
      let openedAt: number | undefined;
      let failure: Error | undefined;
      try {
        const url = await this.openConnection();
        if (this.stopped) return; // stop() landed while connections.open was in flight
        // Resolves when Slack asks us to reconnect, or the socket drops.
        await this.pump(url, () => (openedAt = this.now()));
      } catch (err) {
        failure = err as Error;
      }
      if (this.stopped) return;
      const healthy = openedAt !== undefined && this.now() - openedAt >= HEALTHY_CONNECTION_MS;
      if (healthy) {
        this.backoffMs = MIN_BACKOFF_MS;
        if (!failure) continue; // routine rotation of a long-lived connection: reconnect at once
      }
      await this.backOff(failure);
    }
  }

  /** Trade the app-level token for a single-use wss:// URL. */
  private async openConnection(): Promise<string> {
    const base = (this.opts.apiBase ?? "https://slack.com/api").replace(/\/+$/, "");
    const timeout = AbortSignal.timeout(15_000);
    const stop = this.stopController?.signal;
    const res = await this.fetchFn(`${base}/apps.connections.open`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.opts.appToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      signal: stop ? AbortSignal.any([timeout, stop]) : timeout,
    });
    const body = (await res.json().catch(() => ({}))) as { ok?: boolean; url?: string; error?: string };
    if (!body.ok || !body.url) throw new SlackSocketError(body.error ?? `HTTP ${res.status}`);
    return body.url;
  }

  /** Run one socket to completion. Resolves on a clean reconnect request or a drop; rejects only
   *  on a socket-level error, which the caller turns into a backoff. */
  private pump(url: string, onOpen: () => void): Promise<void> {
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

      socket.on("open", () => {
        onOpen();
        this.opts.log.info("[slack] socket mode: connected");
      });
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

    if (frame.type === "hello") return false;
    // Routine: Slack rotates connections and warns before closing one. Not an error.
    if (frame.type === "disconnect") {
      this.opts.log.info(`[slack] socket mode: reconnecting (${frame.reason ?? "requested"})`);
      return true;
    }

    if (!frame.envelope_id) return false;
    // Ack EVERY envelope, including kinds we don't act on — an unacked envelope is redelivered.
    // A redelivery (same envelope_id) waits for the first run's answer and acks it on the socket it
    // arrived on, which may be a newer connection than the one the command came in on.
    const ack = await this.ackFor(frame.envelope_id, frame);
    socket.send(JSON.stringify(ack));
    return false;
  }

  /** The ack for an envelope, running its command at most once per envelope_id. Note the ack is
   *  still sent only after the command answers: this stops a redelivery from re-running a slow
   *  command, it does not make a slow command meet Slack's ack window. */
  private ackFor(envelopeId: string, frame: SlackEnvelope): Promise<Ack> {
    const known = this.envelopes.get(envelopeId);
    if (known) return known.ack;
    const entry: EnvelopeEntry = { ack: this.answer(envelopeId, frame), done: false };
    this.envelopes.set(envelopeId, entry);
    void entry.ack.then(() => {
      entry.done = true;
      this.evictAnswered();
    });
    return entry.ack;
  }

  /** Never rejects: a failing command is logged and acked silently, so it is not redelivered. */
  private async answer(envelopeId: string, frame: SlackEnvelope): Promise<Ack> {
    let payload: unknown;
    if (frame.type === "slash_commands" && frame.payload) {
      payload = await this.opts.onCommand(frame.payload).catch((err) => {
        this.opts.log.warn(`[slack] command failed: ${(err as Error).message}`);
        return undefined;
      });
    }
    const ack: Ack = { envelope_id: envelopeId };
    if (payload !== undefined && frame.accepts_response_payload !== false) ack.payload = payload;
    return ack;
  }

  /** Forget the oldest ANSWERED envelopes past the cap. A still-running one is never evicted —
   *  evicting it would let its redelivery run the command a second time. */
  private evictAnswered(): void {
    for (const [id, entry] of this.envelopes) {
      if (this.envelopes.size <= ENVELOPE_CACHE_LIMIT) return;
      if (entry.done) this.envelopes.delete(id);
    }
  }

  /** Wait out the current backoff (cut short by stop()), then double it. */
  private async backOff(failure: Error | undefined): Promise<void> {
    const wait = Math.round(this.backoffMs / 1000);
    const message = failure?.message;
    if (message === "invalid_auth" || message === "not_authed" || message === "token_expired") {
      this.opts.log.error(
        `[slack] socket mode: ${message} — DFIR_SLACK_APP_TOKEN must be an app-level token ` +
          `(starts "xapp-") with the connections:write scope, from Settings → Basic Information → App-Level Tokens.`,
      );
    } else if (failure) {
      this.opts.log.warn(`[slack] socket mode: ${message}; retrying in ${wait}s`);
    } else {
      this.opts.log.info(
        `[slack] socket mode: connection ended soon after opening; reconnecting in ${wait}s`,
      );
    }
    await this.pause(this.backoffMs);
    this.backoffMs = Math.min(this.backoffMs * 2, MAX_BACKOFF_MS);
  }

  private async pause(ms: number): Promise<void> {
    const signal = this.stopController?.signal;
    if (!signal || signal.aborted) return;
    let onAbort: (() => void) | undefined;
    const aborted = new Promise<void>((resolve) => {
      onAbort = resolve;
      signal.addEventListener("abort", onAbort, { once: true });
    });
    try {
      await Promise.race([this.sleepFn(ms), aborted]);
    } finally {
      if (onAbort) signal.removeEventListener("abort", onAbort);
    }
  }
}

export class SlackSocketError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SlackSocketError";
  }
}
