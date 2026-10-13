import { describe, it, expect, vi } from "vitest";
import { createSocket } from "node:dgram";
import type { Dispatcher } from "undici";
import { createAuditHttpFetch, sendAuditBatch } from "../../src/integrations/audit/auditSend.js";
import { createSyslogSend } from "../../src/integrations/audit/syslogTransport.js";
import type { AuditDestination, AuditEvent, SyslogConfig } from "../../src/analysis/auditExport.js";
import type { PinnedAddress } from "../../src/routes/outboundTargetPolicy.js";

// Issue #2147, send side: a destination that reaches the store with a metadata target (saved before
// the save-time rule, or hand-edited into config.json) must not send, a collector's redirect must not
// be followed, and the syslog socket must go to an address that was checked.

const ev: AuditEvent = {
  id: "e1",
  timestamp: "2026-10-13T10:00:00.000Z",
  caseId: "case-7",
  category: "triage",
  action: "a",
  detail: "d",
  actor: "alice",
  actorVerified: false,
  outcome: "success",
};

const dest = (over: Partial<AuditDestination>): AuditDestination => ({
  id: "d1",
  type: "splunk",
  name: "SOC",
  enabled: true,
  createdAt: "",
  updatedAt: "",
  ...over,
});

const resolver =
  (map: Record<string, string[]>) =>
  async (host: string): Promise<PinnedAddress[]> =>
    (map[host] ?? ["192.168.1.20"]).map((address) => ({ address, family: address.includes(":") ? 6 : 4 }));

const transport = (fetchFn: unknown, syslogSend = vi.fn(async () => {})) => ({
  fetchFn: fetchFn as never,
  syslogSend,
  hostname: "companion-host",
});

const blocked = /blocked because it is a cloud-metadata or link-local address/;

describe("sendAuditBatch — stored metadata targets", () => {
  it("refuses a stored splunk metadata URL without calling fetch", async () => {
    const fetchFn = vi.fn();
    const r = await sendAuditBatch(
      dest({ splunk: { url: "http://169.254.169.254", token: "t" } }),
      [ev],
      transport(fetchFn),
    );
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(blocked);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("refuses a stored elastic metadata URL without calling fetch", async () => {
    const fetchFn = vi.fn();
    const r = await sendAuditBatch(
      dest({ type: "elastic", elastic: { url: "http://[fd00:ec2::254]:9200", index: "i" } }),
      [ev],
      transport(fetchFn),
    );
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(blocked);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("refuses a stored syslog metadata host without opening a socket", async () => {
    const syslogSend = vi.fn(async () => {});
    const r = await sendAuditBatch(
      dest({ type: "syslog", syslog: { host: "169.254.169.254", port: 514, protocol: "udp" } }),
      [ev],
      transport(vi.fn(), syslogSend),
    );
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(blocked);
    expect(syslogSend).not.toHaveBeenCalled();
  });
});

describe("sendAuditBatch — redirects", () => {
  it("does not follow a redirect from the collector, and says so", async () => {
    const fetchFn = vi.fn(
      async () => new Response(null, { status: 307, headers: { location: "http://169.254.169.254/" } }),
    );
    const r = await sendAuditBatch(
      dest({ splunk: { url: "https://splunk.lan:8088", token: "t" } }),
      [ev],
      transport(fetchFn),
    );
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/redirect \(HTTP 307\).*not followed/);
    expect(fetchFn).toHaveBeenCalledOnce();
    expect((fetchFn.mock.calls[0] as unknown[])[1]).toMatchObject({ redirect: "manual" });
  });
});

describe("createAuditHttpFetch — the pinned guard for splunk and elastic", () => {
  it("reports a name that resolves to the metadata address in plain words, before any connection", async () => {
    const fetchImpl = vi.fn();
    const fetchFn = createAuditHttpFetch({
      resolveHost: resolver({ "rebind.example": ["169.254.169.254"] }),
      fetchImpl: fetchImpl,
    });
    const r = await sendAuditBatch(
      dest({ splunk: { url: "http://rebind.example:8088", token: "t" } }),
      [ev],
      transport(fetchFn),
    );
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/resolves to a cloud-metadata or link-local address, which is blocked/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("keeps a LAN splunk collector working", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ text: "Success", code: 0 })));
    const fetchFn = createAuditHttpFetch({
      resolveHost: resolver({ "splunk.lan": ["10.1.2.3"] }),
      fetchImpl: fetchImpl,
      agentFactory: () => ({ close: async () => {} }) as unknown as Dispatcher,
    });
    const r = await sendAuditBatch(
      dest({ splunk: { url: "http://splunk.lan:8088", token: "t" } }),
      [ev],
      transport(fetchFn),
    );
    expect(r.ok).toBe(true);
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("keeps a whole Elasticsearch bulk response, however large, so a big batch is not misread", async () => {
    // 500 records answer with well over 64 KiB; truncating it would read as "unconfirmed" forever.
    const items = Array.from({ length: 500 }, (_, i) => ({
      create: { _index: "dfir-audit", _id: `id-${i}-${"x".repeat(150)}`, status: 201 },
    }));
    const body = JSON.stringify({ errors: false, items });
    expect(body.length).toBeGreaterThan(64 * 1024);
    const fetchImpl = vi.fn(async () => new Response(body, { status: 200 }));
    const fetchFn = createAuditHttpFetch({
      resolveHost: resolver({ "es.lan": ["10.1.2.4"] }),
      fetchImpl: fetchImpl,
      agentFactory: () => ({ close: async () => {} }) as unknown as Dispatcher,
    });
    const events = Array.from({ length: 500 }, (_, i) => ({ ...ev, id: `e${i}` }));
    const r = await sendAuditBatch(
      dest({ type: "elastic", elastic: { url: "http://es.lan:9200", index: "dfir-audit" } }),
      events,
      transport(fetchFn),
    );
    expect(r.error).toBeUndefined();
    expect(r.ok).toBe(true);
  });
});

describe("createSyslogSend — resolve, check, send to the checked address", () => {
  const cfg = (over: Partial<SyslogConfig> = {}): SyslogConfig => ({
    host: "syslog.lan",
    port: 514,
    protocol: "udp",
    ...over,
  });

  it("refuses a name that resolves into link-local space, before any socket opens", async () => {
    const createConnection = vi.fn();
    const createUdpSocket = vi.fn();
    const send = createSyslogSend({
      resolveHost: resolver({ "syslog.evil": ["169.254.169.254"] }),
      createConnection: createConnection as never,
      createUdpSocket: createUdpSocket as never,
    });
    for (const protocol of ["udp", "tcp"] as const) {
      await expect(send(["<110>1 x"], cfg({ host: "syslog.evil", protocol }))).rejects.toThrow(
        /cloud-metadata or link-local/,
      );
    }
    expect(createConnection).not.toHaveBeenCalled();
    expect(createUdpSocket).not.toHaveBeenCalled();
  });

  it("fails closed when the name cannot be resolved", async () => {
    const send = createSyslogSend({
      resolveHost: async () => {
        throw new Error("ENOTFOUND");
      },
    });
    await expect(send(["<110>1 x"], cfg())).rejects.toThrow(/could not be resolved/);
  });

  it("connects TCP to the resolved address, not the name", async () => {
    const createConnection = vi.fn(() => {
      throw new Error("stop here");
    });
    const send = createSyslogSend({
      resolveHost: resolver({ "syslog.lan": ["10.0.0.9"] }),
      createConnection: createConnection,
    });
    await send(["<110>1 x"], cfg({ protocol: "tcp" })).catch(() => {});
    expect(createConnection).toHaveBeenCalledOnce();
    expect((createConnection.mock.calls[0] as unknown[])[0]).toMatchObject({ host: "10.0.0.9", port: 514 });
  });

  it("delivers UDP to a loopback forwarder reached through a resolved name", async () => {
    const received: string[] = [];
    const socket = createSocket("udp4");
    socket.on("message", (m) => received.push(m.toString("utf8")));
    const port = await new Promise<number>((r) =>
      socket.bind(0, "127.0.0.1", () => r(socket.address().port)),
    );
    const send = createSyslogSend({ resolveHost: resolver({ "forwarder.local": ["127.0.0.1"] }) });
    await send(["<110>1 hello"], cfg({ host: "forwarder.local", port }));
    await new Promise((r) => setTimeout(r, 120));
    socket.close();
    expect(received).toEqual(["<110>1 hello"]);
  });
});
