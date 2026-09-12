import { createSocket } from "node:dgram";
import { createConnection } from "node:net";
import type { SyslogConfig } from "../../analysis/auditExport.js";
import type { SyslogSendFn } from "./auditSend.js";

// The syslog send half of the audit export (#929). This is the module that exists because #929's
// single "POST them to the configured endpoint" step cannot describe syslog: there is no HTTP
// request, no response body to check, and no status code — only a socket to a host and a port.
//
// Rejects on failure rather than returning a result, because that is the contract sendAuditBatch
// wraps: a rejection there becomes a failed send, which holds the durable position so the batch is
// retried. That matters most for UDP, where "sent" is the strongest guarantee available.

const CONNECT_TIMEOUT_MS = 10_000;

/** RFC 6587 §3.4.2 non-transparent framing: one LF-terminated message per record on the stream. */
const FRAME_SEPARATOR = "\n";

function sendUdp(lines: readonly string[], cfg: SyslogConfig): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = createSocket("udp4");
    let settled = false;
    const finish = (err?: Error): void => {
      if (settled) return;
      settled = true;
      socket.close(() => (err ? reject(err) : resolve()));
    };
    const timer = setTimeout(
      () => finish(new Error(`syslog UDP send to ${cfg.host}:${cfg.port} timed out`)),
      CONNECT_TIMEOUT_MS,
    );
    timer.unref?.();
    socket.on("error", (err) => {
      clearTimeout(timer);
      finish(err);
    });
    // One datagram per record: a datagram is the record boundary in UDP syslog, so concatenating
    // several into one packet would deliver them as a single malformed message.
    let pending = lines.length;
    if (pending === 0) {
      clearTimeout(timer);
      finish();
      return;
    }
    for (const line of lines) {
      socket.send(Buffer.from(line, "utf8"), cfg.port, cfg.host, (err) => {
        if (err) {
          clearTimeout(timer);
          finish(err);
          return;
        }
        pending -= 1;
        if (pending === 0) {
          clearTimeout(timer);
          finish();
        }
      });
    }
  });
}

function sendTcp(lines: readonly string[], cfg: SyslogConfig): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: cfg.host, port: cfg.port });
    let settled = false;
    const finish = (err?: Error): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (err) reject(err);
      else resolve();
    };
    socket.setTimeout(CONNECT_TIMEOUT_MS, () =>
      finish(new Error(`syslog TCP connection to ${cfg.host}:${cfg.port} timed out`)),
    );
    socket.on("error", finish);
    socket.on("connect", () => {
      const payload = lines.map((line) => `${line}${FRAME_SEPARATOR}`).join("");
      // end() flushes then half-closes; the callback fires once the bytes are handed to the OS.
      socket.end(payload, "utf8", () => finish());
    });
  });
}

/**
 * The real socket transport. Injected into the exporter from composition so every test above runs
 * with no network at all.
 */
export const syslogSend: SyslogSendFn = async (lines, cfg) => {
  if (lines.length === 0) return;
  await (cfg.protocol === "tcp" ? sendTcp(lines, cfg) : sendUdp(lines, cfg));
};
