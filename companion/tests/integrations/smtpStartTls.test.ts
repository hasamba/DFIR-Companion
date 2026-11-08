import { EventEmitter } from "node:events";
import { describe, it, expect, vi } from "vitest";
import {
  createNodeSmtpConnect,
  sendSmtp,
  SmtpError,
  type SmtpSocketLike,
} from "../../src/integrations/notify/smtpClient.js";
import type { SmtpChannelConfig } from "../../src/analysis/notifications.js";

// Issue #2410: anything the server (or someone on the path) sends in plaintext after the STARTTLS
// `220` must never be read as a reply that came over the encrypted connection. The real socket
// refuses the upgrade when unread plaintext is waiting.

type FakeSocket = EventEmitter & {
  written: string[];
  destroyed: boolean;
  setEncoding: () => void;
  write: (d: string) => void;
  end: () => void;
  destroy: () => void;
};

function fakeSocket(): FakeSocket {
  const sock = new EventEmitter() as FakeSocket;
  sock.written = [];
  sock.destroyed = false;
  sock.setEncoding = () => {};
  sock.write = (d: string) => {
    sock.written.push(d);
  };
  sock.end = () => {};
  sock.destroy = () => {
    sock.destroyed = true;
  };
  return sock;
}

const resolveHost = async (): Promise<{ address: string; family: number }[]> => [
  { address: "10.0.0.25", family: 4 },
];

interface Rig {
  plain: FakeSocket;
  secure: FakeSocket;
  tlsConnect: ReturnType<typeof vi.fn>;
  open: () => Promise<SmtpSocketLike>;
}

function rig(): Rig {
  const plain = fakeSocket();
  const secure = fakeSocket();
  const tlsConnect = vi.fn((_opts: unknown, onSecure: () => void) => {
    setImmediate(onSecure);
    return secure;
  });
  const connect = createNodeSmtpConnect({
    resolveHost,
    createConnection: ((_o: unknown, onConnect: () => void) => {
      setImmediate(onConnect);
      return plain;
    }) as never,
    tlsConnect: tlsConnect as never,
  });
  const open = (): Promise<SmtpSocketLike> =>
    connect({ host: "mail.lan", port: 25, secure: false, rejectUnauthorized: true, timeoutMs: 1000 });
  return { plain, secure, tlsConnect, open };
}

const tlsOpts = { host: "mail.lan", rejectUnauthorized: true };

describe("NodeSmtpSocket.startTls — refuses plaintext left over before the upgrade (#2410)", () => {
  it("refuses when an extra reply arrived in the same chunk as the STARTTLS 220", async () => {
    const r = rig();
    const sock = await r.open();
    r.plain.emit("data", "220 go ahead\r\n250 STARTTLS\r\n");
    expect((await sock.readReply()).code).toBe(220);
    const err = await sock.startTls(tlsOpts).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SmtpError);
    expect((err as SmtpError).kind).toBe("protocol");
    expect((err as SmtpError).message).toMatch(/before the TLS upgrade/);
    expect(r.tlsConnect).not.toHaveBeenCalled();
    expect(sock.secure).toBe(false);
  });

  it("refuses when the extra reply arrived in a separate chunk", async () => {
    const r = rig();
    const sock = await r.open();
    r.plain.emit("data", "220 go ahead\r\n");
    expect((await sock.readReply()).code).toBe(220);
    r.plain.emit("data", "250 AUTH PLAIN\r\n");
    await expect(sock.startTls(tlsOpts)).rejects.toThrow(/before the TLS upgrade/);
    expect(r.tlsConnect).not.toHaveBeenCalled();
  });

  it("refuses when a partial line (no CRLF yet) is buffered", async () => {
    const r = rig();
    const sock = await r.open();
    r.plain.emit("data", "220 go ahead\r\n250 STA");
    await sock.readReply();
    await expect(sock.startTls(tlsOpts)).rejects.toThrow(/before the TLS upgrade/);
    expect(r.tlsConnect).not.toHaveBeenCalled();
  });

  it("refuses when an unfinished multiline reply ending in CRLF is buffered", async () => {
    const r = rig();
    const sock = await r.open();
    r.plain.emit("data", "220 go ahead\r\n250-mail.lan\r\n");
    await sock.readReply();
    await expect(sock.startTls(tlsOpts)).rejects.toThrow(/before the TLS upgrade/);
    expect(r.tlsConnect).not.toHaveBeenCalled();
  });

  it("refuses when the connection has already failed", async () => {
    const r = rig();
    const sock = await r.open();
    r.plain.emit("data", "220 go ahead\r\n");
    await sock.readReply();
    r.plain.emit("close");
    await expect(sock.startTls(tlsOpts)).rejects.toBeInstanceOf(SmtpError);
    expect(r.tlsConnect).not.toHaveBeenCalled();
  });

  it("upgrades a drained connection and reads later replies only from the TLS socket", async () => {
    const r = rig();
    const sock = await r.open();
    r.plain.emit("data", "220 go ahead\r\n");
    await sock.readReply();
    await sock.startTls(tlsOpts);
    expect(r.tlsConnect).toHaveBeenCalledOnce();
    expect((r.tlsConnect.mock.calls[0] as unknown[])[0]).toMatchObject({
      socket: r.plain,
      servername: "mail.lan",
      rejectUnauthorized: true,
    });
    expect(sock.secure).toBe(true);
    r.plain.emit("data", "250 forged\r\n"); // plaintext listener was detached
    r.secure.emit("data", "250 real\r\n");
    expect(await sock.readReply()).toEqual({ code: 250, lines: ["real"] });
  });

  it("rejects instead of hanging when the TLS socket closes during the handshake", async () => {
    const plain = fakeSocket();
    const secure = fakeSocket();
    const connect = createNodeSmtpConnect({
      resolveHost,
      createConnection: ((_o: unknown, onConnect: () => void) => {
        setImmediate(onConnect);
        return plain;
      }) as never,
      tlsConnect: (() => {
        setImmediate(() => secure.emit("close"));
        return secure;
      }) as never,
    });
    const sock = await connect({
      host: "mail.lan",
      port: 25,
      secure: false,
      rejectUnauthorized: true,
      timeoutMs: 1000,
    });
    await expect(sock.startTls(tlsOpts)).rejects.toThrow(/STARTTLS upgrade failed/);
  });
});

describe("sendSmtp over the real socket — injected pre-TLS reply aborts the send (#2410)", () => {
  it("sends no envelope or content and closes the connection", async () => {
    const r = rig();
    // Script the plaintext server: greeting, EHLO advertising STARTTLS, then a 220 with a forged
    // reply pipelined behind it.
    r.plain.write = (d: string) => {
      r.plain.written.push(d);
      setImmediate(() => {
        if (d.startsWith("EHLO")) r.plain.emit("data", "250-mail.lan\r\n250 STARTTLS\r\n");
        else if (d.startsWith("STARTTLS")) r.plain.emit("data", "220 ready\r\n250 forged-ehlo\r\n");
      });
    };
    const config: SmtpChannelConfig = {
      host: "mail.lan",
      port: 25,
      secure: false,
      from: "dfir@example.test",
      to: ["soc@example.test"],
    };
    const connect = createNodeSmtpConnect({
      resolveHost,
      createConnection: ((_o: unknown, onConnect: () => void) => {
        setImmediate(() => {
          onConnect();
          setImmediate(() => r.plain.emit("data", "220 mail.lan ESMTP\r\n"));
        });
        return r.plain;
      }) as never,
      tlsConnect: r.tlsConnect as never,
    });
    const err = await sendSmtp(connect, config, "Subject: t\r\n\r\nbody").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SmtpError);
    expect((err as SmtpError).message).toMatch(/before the TLS upgrade/);
    expect(r.tlsConnect).not.toHaveBeenCalled();
    const sent = [...r.plain.written, ...r.secure.written].join("");
    expect(sent).not.toMatch(/MAIL FROM|RCPT TO|DATA|AUTH|body/);
    expect(r.plain.destroyed).toBe(true);
  });
});
