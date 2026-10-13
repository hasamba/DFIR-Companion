import { createSocket } from "node:dgram";
import { createConnection } from "node:net";
import type { SyslogConfig } from "../../analysis/auditExport.js";
import { resolveLanHost, type PinnedAddress, type ResolveHost } from "../../routes/outboundTargetPolicy.js";
import type { SyslogSendFn } from "./auditSend.js";

// The syslog send half of the audit export (#929). This is the module that exists because #929's
// single "POST them to the configured endpoint" step cannot describe syslog: there is no HTTP
// request, no response body to check, and no status code — only a socket to a host and a port.
//
// Rejects on failure rather than returning a result, because that is the contract sendAuditBatch
// wraps: a rejection there becomes a failed send, which holds the durable position so the batch is
// retried. That matters most for UDP, where "sent" is the strongest guarantee available.
//
// The host is resolved and checked FIRST (#2147), under the same "LAN yes, metadata no" rule as the
// HTTP destinations: a cloud-metadata or link-local answer is refused, and so is a name that does
// not resolve (fail closed). The socket then goes to the CHECKED address, never to the name again,
// so a second lookup cannot answer differently (DNS rebinding). A forwarder on 127.0.0.1 and a
// collector on the LAN keep working.

const CONNECT_TIMEOUT_MS = 10_000;

/** RFC 6587 §3.4.2 non-transparent framing: one LF-terminated message per record on the stream. */
const FRAME_SEPARATOR = "\n";

export interface SyslogSendDeps {
  /** Injected by tests so they never touch real DNS. */
  resolveHost?: ResolveHost;
  /** Injected by tests so they never open a socket. */
  createConnection?: typeof createConnection;
  createUdpSocket?: typeof createSocket;
}

/** Where the bytes go: the checked address, and the name the admin typed for messages. */
interface SyslogTarget {
  address: PinnedAddress;
  label: string;
  port: number;
}

function sendUdp(lines: readonly string[], target: SyslogTarget, deps: SyslogSendDeps): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = (deps.createUdpSocket ?? createSocket)(target.address.family === 6 ? "udp6" : "udp4");
    let settled = false;
    const finish = (err?: Error): void => {
      if (settled) return;
      settled = true;
      socket.close(() => (err ? reject(err) : resolve()));
    };
    const timer = setTimeout(
      () => finish(new Error(`syslog UDP send to ${target.label}:${target.port} timed out`)),
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
    for (const line of lines) {
      socket.send(Buffer.from(line, "utf8"), target.port, target.address.address, (err) => {
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

function sendTcp(lines: readonly string[], target: SyslogTarget, deps: SyslogSendDeps): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = (deps.createConnection ?? createConnection)({
      host: target.address.address,
      port: target.port,
      family: target.address.family,
    });
    let settled = false;
    const finish = (err?: Error): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (err) reject(err);
      else resolve();
    };
    socket.setTimeout(CONNECT_TIMEOUT_MS, () =>
      finish(new Error(`syslog TCP connection to ${target.label}:${target.port} timed out`)),
    );
    socket.on("error", finish);
    socket.on("connect", () => {
      const payload = lines.map((line) => `${line}${FRAME_SEPARATOR}`).join("");
      // end() flushes then half-closes; the callback fires once the bytes are handed to the OS.
      socket.end(payload, "utf8", () => finish());
    });
  });
}

/** Resolve and check the host; prefer an IPv4 answer, which is what the transport used before. */
async function checkedAddress(host: string, deps: SyslogSendDeps): Promise<PinnedAddress> {
  try {
    const addresses = await resolveLanHost(host, { resolveHost: deps.resolveHost });
    return addresses.find((a) => a.family === 4) ?? addresses[0];
  } catch (err) {
    throw new Error(`syslog destination refused: ${(err as Error).message}`);
  }
}

/**
 * The real socket transport. Injected into the exporter from composition so every test above it
 * runs with no network at all; the deps here let this module's own tests do the same.
 */
export function createSyslogSend(deps: SyslogSendDeps = {}): SyslogSendFn {
  return async (lines, cfg: SyslogConfig) => {
    if (lines.length === 0) return;
    const target: SyslogTarget = {
      address: await checkedAddress(cfg.host, deps),
      label: cfg.host,
      port: cfg.port,
    };
    await (cfg.protocol === "tcp" ? sendTcp(lines, target, deps) : sendUdp(lines, target, deps));
  };
}

export const syslogSend: SyslogSendFn = createSyslogSend();
