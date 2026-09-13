import { describe, it, expect } from "vitest";
import { createSocket } from "node:dgram";
import { createServer, type Server } from "node:net";
import { syslogSend } from "../../src/integrations/audit/syslogTransport.js";

// Real sockets on loopback with an ephemeral port. A mocked dgram/net would prove only that the
// mock was called; what has to hold here is that a receiver gets one parseable record per entry.

function udpReceiver(): Promise<{ port: number; received: string[]; close: () => void }> {
  return new Promise((resolve) => {
    const received: string[] = [];
    const socket = createSocket("udp4");
    socket.on("message", (msg) => received.push(msg.toString("utf8")));
    socket.bind(0, "127.0.0.1", () =>
      resolve({ port: socket.address().port, received, close: () => socket.close() }),
    );
  });
}

function tcpReceiver(): Promise<{ port: number; chunks: string[]; server: Server }> {
  return new Promise((resolve) => {
    const chunks: string[] = [];
    const server = createServer((conn) => {
      conn.on("data", (d) => chunks.push(d.toString("utf8")));
    });
    server.listen(0, "127.0.0.1", () =>
      resolve({ port: (server.address() as { port: number }).port, chunks, server }),
    );
  });
}

const settle = () => new Promise((r) => setTimeout(r, 120));

describe("syslogSend over UDP", () => {
  it("sends one datagram per record, because the datagram IS the record boundary", async () => {
    const receiver = await udpReceiver();
    await syslogSend(["<110>1 first", "<110>1 second"], {
      host: "127.0.0.1",
      port: receiver.port,
      protocol: "udp",
    });
    await settle();
    receiver.close();
    expect(receiver.received.sort()).toEqual(["<110>1 first", "<110>1 second"]);
  });

  it("does nothing for an empty batch", async () => {
    const receiver = await udpReceiver();
    await syslogSend([], { host: "127.0.0.1", port: receiver.port, protocol: "udp" });
    await settle();
    receiver.close();
    expect(receiver.received).toEqual([]);
  });
});

describe("syslogSend over TCP", () => {
  it("frames each record with a trailing newline so the receiver can split the stream", async () => {
    const receiver = await tcpReceiver();
    await syslogSend(["<110>1 first", "<110>1 second"], {
      host: "127.0.0.1",
      port: receiver.port,
      protocol: "tcp",
    });
    await settle();
    receiver.server.close();
    const stream = receiver.chunks.join("");
    expect(stream).toBe("<110>1 first\n<110>1 second\n");
  });

  it("rejects when nothing is listening, so the batch is retried rather than lost", async () => {
    // Port 1 on loopback refuses immediately. A resolved promise here would advance the durable
    // position and drop the batch silently.
    await expect(syslogSend(["<110>1 x"], { host: "127.0.0.1", port: 1, protocol: "tcp" })).rejects.toThrow();
  });
});
