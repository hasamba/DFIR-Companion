import { describe, it, expect, vi } from "vitest";
import type { Dispatcher } from "undici";
import { dispatchEvent, createNotifier } from "../../src/integrations/notify/notifyDispatch.js";
import {
  createNodeSmtpConnect,
  SmtpError,
  type SmtpConnect,
} from "../../src/integrations/notify/smtpClient.js";
import { createGuardedFetch } from "../../src/routes/outboundGuardedFetch.js";
import type { NotificationChannel, NotificationEvent } from "../../src/analysis/notifications.js";
import type { PinnedAddress } from "../../src/routes/outboundTargetPolicy.js";

// Issue #2146, send side: a channel that reaches the store with a metadata target (saved before the
// save-time rule, or hand-edited into config.json) must not send, a webhook redirect must not be
// followed, and the SMTP connection must go to an address that was checked.

function channel(over: Partial<NotificationChannel>): NotificationChannel {
  return {
    id: "c1",
    type: "slack",
    name: "Chan",
    enabled: true,
    minSeverity: "Info",
    events: { critical_finding: true, playbook_update: true, milestone: true, mention: true },
    createdAt: "2026-10-13T00:00:00Z",
    updatedAt: "2026-10-13T00:00:00Z",
    ...over,
  };
}

function event(): NotificationEvent {
  return {
    kind: "critical_finding",
    severity: "High",
    title: "New finding: t",
    lines: ["Case: c"],
    caseId: "c",
    at: "2026-10-13T00:00:00Z",
  };
}

const resolver =
  (map: Record<string, string[]>) =>
  async (host: string): Promise<PinnedAddress[]> =>
    (map[host] ?? ["192.168.1.20"]).map((address) => ({ address, family: address.includes(":") ? 6 : 4 }));

describe("webhook channels — send-time guard", () => {
  it("refuses a stored metadata URL without calling any fetch", async () => {
    const fetchFn = vi.fn();
    const webhookFetch = vi.fn();
    const [r] = await dispatchEvent([channel({ webhookUrl: "http://169.254.169.254/latest" })], event(), {
      fetchFn: fetchFn,
      webhookFetch: webhookFetch,
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/blocked because it is a cloud-metadata or link-local address/);
    expect(fetchFn).not.toHaveBeenCalled();
    expect(webhookFetch).not.toHaveBeenCalled();
  });

  it("sends webhook channels through the guarded fetch when one is wired", async () => {
    const fetchFn = vi.fn();
    const webhookFetch = vi.fn(async () => new Response("ok"));
    const [r] = await dispatchEvent([channel({ webhookUrl: "https://hooks.slack.com/x" })], event(), {
      fetchFn: fetchFn,
      webhookFetch: webhookFetch,
    });
    expect(r.ok).toBe(true);
    expect(webhookFetch).toHaveBeenCalledOnce();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("does not follow a redirect from the webhook, and says so", async () => {
    const fetchFn = vi.fn(
      async () => new Response(null, { status: 308, headers: { location: "http://169.254.169.254/" } }),
    );
    const [r] = await dispatchEvent([channel({ webhookUrl: "https://hooks.slack.com/x" })], event(), {
      fetchFn: fetchFn,
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/redirect \(HTTP 308\).*not followed/);
    expect(fetchFn).toHaveBeenCalledOnce();
    expect((fetchFn.mock.calls[0] as unknown[])[1]).toMatchObject({ redirect: "manual" });
  });

  it("reports a name that resolves to the metadata address in plain words (guarded fetch end to end)", async () => {
    const fetchImpl = vi.fn();
    const webhookFetch = createGuardedFetch({
      policy: "lan",
      maxRedirects: 0,
      resolveHost: resolver({ "rebind.example": ["169.254.169.254"] }),
      fetchImpl: fetchImpl,
    });
    const [r] = await dispatchEvent([channel({ webhookUrl: "http://rebind.example/hook" })], event(), {
      fetchFn: vi.fn(),
      webhookFetch,
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/resolves to a cloud-metadata or link-local address, which is blocked/);
    expect(r.error).not.toMatch(/network error/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("keeps a LAN webhook working through the guarded fetch", async () => {
    const fetchImpl = vi.fn(async () => new Response("ok"));
    const webhookFetch = createGuardedFetch({
      policy: "lan",
      maxRedirects: 0,
      resolveHost: resolver({}),
      fetchImpl: fetchImpl,
      agentFactory: () => ({ close: async () => {} }) as unknown as Dispatcher,
    });
    const [r] = await dispatchEvent(
      [channel({ type: "mattermost", webhookUrl: "http://mattermost.lan:8065/hooks/x" })],
      event(),
      { fetchFn: vi.fn(), webhookFetch },
    );
    expect(r.ok).toBe(true);
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("createNotifier passes the guarded fetch through to the webhook sends", async () => {
    const webhookFetch = vi.fn(async () => new Response("ok"));
    const store = { load: async () => [channel({ webhookUrl: "https://hooks.slack.com/x" })] };
    const notifier = createNotifier({
      store: store as never,
      fetchFn: vi.fn(),
      webhookFetch: webhookFetch,
    });
    const [r] = await notifier.test(undefined, "2026-10-13T00:00:00Z");
    expect(r.ok).toBe(true);
    expect(webhookFetch).toHaveBeenCalledOnce();
  });
});

describe("email channels — SMTP host", () => {
  const smtp = { port: 25, secure: false, from: "a@b.c", to: ["x@y.z"] };

  it("refuses a stored metadata SMTP host before connecting", async () => {
    const smtpConnect = vi.fn() as unknown as SmtpConnect;
    const [r] = await dispatchEvent(
      [channel({ type: "email", smtp: { ...smtp, host: "169.254.169.254" } })],
      event(),
      { fetchFn: vi.fn(), smtpConnect },
    );
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/blocked because it is a cloud-metadata or link-local address/);
    expect(smtpConnect).not.toHaveBeenCalled();
  });
});

describe("createNodeSmtpConnect — resolve, check, connect to the checked address", () => {
  const base = { port: 25, secure: false, rejectUnauthorized: true, timeoutMs: 1000 };

  it("refuses a host that resolves into link-local space, before any socket opens", async () => {
    const createConnection = vi.fn();
    const connect = createNodeSmtpConnect({
      resolveHost: resolver({ "smtp.evil": ["169.254.169.254"] }),
      createConnection: createConnection as never,
    });
    const err = await connect({ ...base, host: "smtp.evil" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SmtpError);
    expect((err as SmtpError).message).toMatch(/cloud-metadata or link-local/);
    expect(createConnection).not.toHaveBeenCalled();
  });

  it("connects a plain socket to the resolved address, not the name", async () => {
    const createConnection = vi.fn(() => {
      throw new Error("stop here");
    });
    const connect = createNodeSmtpConnect({
      resolveHost: resolver({ "mail.lan": ["10.0.0.25"] }),
      createConnection: createConnection,
    });
    await connect({ ...base, host: "mail.lan" }).catch(() => {});
    expect(createConnection).toHaveBeenCalledOnce();
    expect((createConnection.mock.calls[0] as unknown[])[0]).toMatchObject({ host: "10.0.0.25", port: 25 });
  });

  it("connects implicit TLS to the resolved address and keeps the name for SNI and the certificate", async () => {
    const tlsConnect = vi.fn(() => {
      throw new Error("stop here");
    });
    const connect = createNodeSmtpConnect({
      resolveHost: resolver({ "mail.lan": ["10.0.0.25"] }),
      tlsConnect: tlsConnect,
    });
    await connect({ ...base, secure: true, port: 465, host: "mail.lan" }).catch(() => {});
    expect((tlsConnect.mock.calls[0] as unknown[])[0]).toMatchObject({
      host: "10.0.0.25",
      servername: "mail.lan",
    });
  });
});
