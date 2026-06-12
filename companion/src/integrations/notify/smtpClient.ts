import net from "node:net";
import tls from "node:tls";
import type { SmtpChannelConfig } from "../../analysis/notifications.js";

// A minimal, dependency-free SMTP client. The DIALOG (`sendSmtp`) is driven through an injectable
// `SmtpConnect`, so the whole state machine — EHLO, opportunistic STARTTLS, AUTH LOGIN, MAIL/RCPT/
// DATA, dot-stuffing — is unit-tested with a scripted fake socket and NEVER opens a real
// connection in tests (the project's no-network-in-tests invariant). `nodeSmtpConnect` is the thin
// real `net`/`tls` wrapper used at runtime. This mirrors the hand-rolled email IMPORT side
// (`parseMimeEmail`): no `nodemailer`.

export interface SmtpReply {
  code: number;
  lines: string[];
}

// The line-oriented duplex the SMTP dialog needs. The real impl buffers the socket; the test fake
// returns scripted replies.
export interface SmtpSocketLike {
  readonly secure: boolean;          // is the transport currently TLS?
  write(data: string): void;
  readReply(): Promise<SmtpReply>;   // read one complete (possibly multiline) SMTP reply
  startTls(opts: { host: string; rejectUnauthorized: boolean }): Promise<void>;  // STARTTLS upgrade
  close(): void;
}

export interface SmtpConnectOptions {
  host: string;
  port: number;
  secure: boolean;            // implicit TLS from the first byte (port 465)
  rejectUnauthorized: boolean;
  timeoutMs: number;
}

export type SmtpConnect = (opts: SmtpConnectOptions) => Promise<SmtpSocketLike>;

export class SmtpError extends Error {
  constructor(
    message: string,
    readonly kind: "connect" | "auth" | "protocol" | "timeout",
    readonly code?: number,
  ) {
    super(message);
    this.name = "SmtpError";
  }
}

export interface SendSmtpOptions {
  clientName?: string;   // EHLO hostname (default "dfir-companion")
  timeoutMs?: number;    // connect/read timeout (default 20s)
}

// Send one already-built RFC 5322 message (see emailFormat.buildRfc822Message) to the configured
// recipients. Best-effort STARTTLS when offered on a plain connection; AUTH LOGIN when credentials
// are present. Throws SmtpError on any non-success reply.
export async function sendSmtp(
  connect: SmtpConnect,
  config: SmtpChannelConfig,
  rawMessage: string,
  opts: SendSmtpOptions = {},
): Promise<void> {
  const clientName = opts.clientName ?? "dfir-companion";
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const rejectUnauthorized = config.rejectUnauthorized ?? true;

  const sock = await connect({ host: config.host, port: config.port, secure: config.secure, rejectUnauthorized, timeoutMs });
  try {
    await expect(sock, [220], "greeting");

    let caps = await ehlo(sock, clientName);

    // Opportunistic STARTTLS: if we're not already on TLS and the server offers it, upgrade before
    // sending credentials or content.
    if (!sock.secure && caps.has("STARTTLS")) {
      sock.write("STARTTLS\r\n");
      await expect(sock, [220], "STARTTLS");
      await sock.startTls({ host: config.host, rejectUnauthorized });
      caps = await ehlo(sock, clientName);
    }

    if (config.username && config.password) {
      if (!sock.secure) {
        // Refuse to send a plaintext password over an unencrypted link.
        throw new SmtpError("server does not support STARTTLS — refusing to send credentials in plaintext", "auth");
      }
      await authLogin(sock, config.username, config.password);
    }

    sock.write(`MAIL FROM:<${config.from}>\r\n`);
    await expect(sock, [250], "MAIL FROM");

    for (const rcpt of config.to) {
      sock.write(`RCPT TO:<${rcpt}>\r\n`);
      await expect(sock, [250, 251], `RCPT TO ${rcpt}`);
    }

    sock.write("DATA\r\n");
    await expect(sock, [354], "DATA");

    sock.write(`${dotStuff(rawMessage)}\r\n.\r\n`);
    await expect(sock, [250], "message body");

    sock.write("QUIT\r\n");
    // QUIT reply (221) is best-effort — some servers drop the connection immediately.
    await sock.readReply().catch(() => undefined);
  } finally {
    sock.close();
  }
}

// Send EHLO and return the advertised capability tokens (uppercased first word of each line, e.g.
// STARTTLS, AUTH, SIZE).
async function ehlo(sock: SmtpSocketLike, clientName: string): Promise<Set<string>> {
  sock.write(`EHLO ${clientName}\r\n`);
  const reply = await sock.readReply();
  if (reply.code !== 250) {
    // Fall back to HELO for ancient servers.
    sock.write(`HELO ${clientName}\r\n`);
    const helo = await sock.readReply();
    if (helo.code !== 250) throw new SmtpError(`EHLO/HELO refused: ${helo.code} ${helo.lines.join(" ")}`, "protocol", helo.code);
    return new Set();
  }
  const caps = new Set<string>();
  for (const line of reply.lines) {
    const token = line.trim().split(/\s+/)[0]?.toUpperCase();
    if (token) caps.add(token);
  }
  return caps;
}

async function authLogin(sock: SmtpSocketLike, username: string, password: string): Promise<void> {
  sock.write("AUTH LOGIN\r\n");
  await expect(sock, [334], "AUTH LOGIN");
  sock.write(`${Buffer.from(username, "utf8").toString("base64")}\r\n`);
  await expect(sock, [334], "AUTH username");
  sock.write(`${Buffer.from(password, "utf8").toString("base64")}\r\n`);
  const reply = await sock.readReply();
  if (reply.code !== 235) throw new SmtpError(`authentication failed: ${reply.code} ${reply.lines.join(" ")}`, "auth", reply.code);
}

async function expect(sock: SmtpSocketLike, codes: number[], stage: string): Promise<SmtpReply> {
  const reply = await sock.readReply();
  if (!codes.includes(reply.code)) {
    throw new SmtpError(`SMTP ${stage} failed: ${reply.code} ${reply.lines.join(" ")}`, "protocol", reply.code);
  }
  return reply;
}

// RFC 5321 dot-stuffing: a line that begins with "." gets an extra leading ".". Operates on CRLF
// lines (the message is already CRLF).
export function dotStuff(message: string): string {
  return message
    .split("\r\n")
    .map((line) => (line.startsWith(".") ? `.${line}` : line))
    .join("\r\n");
}

// Parse zero or more complete SMTP replies out of a text buffer. Returns the parsed replies and the
// leftover (incomplete) tail. A reply ends at a line of the form "NNN " (space after the 3-digit
// code); "NNN-" lines are continuations. Exported for the real reader + tests.
export function parseReplies(buffer: string): { replies: SmtpReply[]; rest: string } {
  const replies: SmtpReply[] = [];
  let lines = buffer.split("\r\n");
  const rest = lines.pop() ?? "";   // trailing partial line (no CRLF yet)

  let current: string[] = [];
  let code = 0;
  const consumed: string[] = [];
  for (const line of lines) {
    const m = /^(\d{3})([ -])(.*)$/.exec(line);
    if (!m) { current.push(line); consumed.push(line); continue; }
    code = Number(m[1]);
    current.push(m[3]);
    consumed.push(line);
    if (m[2] === " ") {
      replies.push({ code, lines: current });
      current = [];
    }
  }
  // If a reply is still mid-stream (continuation lines but no terminator), push those lines back
  // onto `rest` so the next chunk completes it.
  if (current.length) {
    const pending = consumed.slice(consumed.length - current.length);
    return { replies, rest: [...pending, rest].join("\r\n") };
  }
  return { replies, rest };
}

// ── Real net/tls transport (runtime only; tests inject their own connect) ────────────────────

class NodeSmtpSocket implements SmtpSocketLike {
  private buffer = "";
  private readonly queue: SmtpReply[] = [];
  private waiter: { resolve: (r: SmtpReply) => void; reject: (e: Error) => void } | null = null;
  private fatal: Error | null = null;

  constructor(private socket: net.Socket | tls.TLSSocket, public secure: boolean) {
    this.attach();
  }

  private attach(): void {
    this.socket.setEncoding("utf8");
    this.socket.on("data", (chunk: string) => this.onData(chunk));
    this.socket.on("error", (err: Error) => this.onFatal(err));
    this.socket.on("close", () => this.onFatal(new SmtpError("connection closed by server", "connect")));
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    const { replies, rest } = parseReplies(this.buffer);
    this.buffer = rest;
    for (const reply of replies) {
      if (this.waiter) { const w = this.waiter; this.waiter = null; w.resolve(reply); }
      else this.queue.push(reply);
    }
  }

  private onFatal(err: Error): void {
    if (this.fatal) return;
    this.fatal = err;
    if (this.waiter) { const w = this.waiter; this.waiter = null; w.reject(err); }
  }

  write(data: string): void {
    this.socket.write(data);
  }

  readReply(): Promise<SmtpReply> {
    if (this.queue.length) return Promise.resolve(this.queue.shift()!);
    if (this.fatal) return Promise.reject(this.fatal);
    return new Promise((resolve, reject) => { this.waiter = { resolve, reject }; });
  }

  startTls(opts: { host: string; rejectUnauthorized: boolean }): Promise<void> {
    return new Promise((resolve, reject) => {
      const plain = this.socket;
      plain.removeAllListeners("data");
      plain.removeAllListeners("error");
      plain.removeAllListeners("close");
      const secure = tls.connect(
        { socket: plain, servername: opts.host, rejectUnauthorized: opts.rejectUnauthorized },
        () => {
          this.socket = secure;
          this.secure = true;
          this.buffer = "";
          this.attach();
          resolve();
        },
      );
      secure.once("error", (err) => reject(new SmtpError(`STARTTLS upgrade failed: ${err.message}`, "connect")));
    });
  }

  close(): void {
    try { this.socket.end(); } catch { /* ignore */ }
    try { this.socket.destroy(); } catch { /* ignore */ }
  }
}

// Open a real connection. Implicit TLS when `secure`, else a plain socket (STARTTLS handled by the
// dialog). Times out the initial connect.
export const nodeSmtpConnect: SmtpConnect = (opts) =>
  new Promise<SmtpSocketLike>((resolve, reject) => {
    const onError = (err: Error): void => reject(new SmtpError(`connect failed: ${err.message}`, "connect"));
    if (opts.secure) {
      const socket = tls.connect(
        { host: opts.host, port: opts.port, rejectUnauthorized: opts.rejectUnauthorized, timeout: opts.timeoutMs },
        () => resolve(new NodeSmtpSocket(socket, true)),
      );
      socket.once("error", onError);
      socket.once("timeout", () => { socket.destroy(); reject(new SmtpError("connect timed out", "timeout")); });
    } else {
      const socket = net.createConnection({ host: opts.host, port: opts.port, timeout: opts.timeoutMs }, () =>
        resolve(new NodeSmtpSocket(socket, false)),
      );
      socket.once("error", onError);
      socket.once("timeout", () => { socket.destroy(); reject(new SmtpError("connect timed out", "timeout")); });
    }
  });
