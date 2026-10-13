import { describe, it, expect, vi } from "vitest";
import type { Dispatcher } from "undici";
import { fetchOutbound, OutboundUrlBlockedError } from "../../src/routes/outboundFetchGuard.js";
import { resolveLanHost, type PinnedAddress } from "../../src/routes/outboundTargetPolicy.js";
import { createGuardedFetch } from "../../src/routes/outboundGuardedFetch.js";

// Issue #2146: the "LAN yes, metadata no" mode of the outbound guard. Notification webhooks (and,
// in #2147, audit-export destinations) legitimately point at a self-hosted server on the LAN or on
// this machine, so the "public" policy's allowlist is wrong for them — but the all-or-nothing
// allowInternal opt-in also lets 169.254.169.254 through. policy:"lan" keeps the resolve-and-pin
// machinery and refuses only cloud-metadata and link-local targets.

const resolver =
  (map: Record<string, string[]>) =>
  async (host: string): Promise<PinnedAddress[]> =>
    (map[host] ?? ["192.168.1.20"]).map((address) => ({
      address,
      family: address.includes(":") ? 6 : 4,
    }));

const LAN = resolver({});

function fakeAgent(): Dispatcher & { closed: boolean } {
  const agent = {
    closed: false,
    close: async () => {
      agent.closed = true;
    },
  };
  return agent as unknown as Dispatcher & { closed: boolean };
}

describe('fetchOutbound — policy: "lan"', () => {
  it.each(["http://10.0.0.5/hook", "http://127.0.0.1:8065/hook", "https://mattermost.lan/hooks/x"])(
    "accepts %s and still pins the connection",
    async (raw) => {
      const pinsSeen: PinnedAddress[][] = [];
      const fetchImpl = vi.fn(async (_url: unknown, _init?: unknown) => new Response("ok", { status: 200 }));
      const r = await fetchOutbound(raw, {
        policy: "lan",
        resolveHost: resolver({ "10.0.0.5": ["10.0.0.5"], "127.0.0.1": ["127.0.0.1"] }),
        fetchImpl: fetchImpl as unknown as typeof fetch,
        agentFactory: (pins) => {
          pinsSeen.push(pins);
          return fakeAgent();
        },
      });
      expect(r.response.status).toBe(200);
      expect(pinsSeen).toHaveLength(1);
      expect(pinsSeen[0].length).toBeGreaterThan(0);
      const init = fetchImpl.mock.calls[0][1] as { dispatcher?: unknown };
      expect(init.dispatcher).toBeDefined();
      await r.dispose();
    },
  );

  it.each([
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:a9fe:a9fe]/",
    "http://[fd00:ec2::254]/",
    "http://100.100.100.200/",
    "http://[fe80::1]/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://2852039166/",
  ])("refuses the metadata / link-local literal %s before any lookup or connection", async (raw) => {
    const resolveHost = vi.fn(LAN);
    const fetchImpl = vi.fn();
    await expect(
      fetchOutbound(raw, { policy: "lan", resolveHost, fetchImpl: fetchImpl as unknown as typeof fetch }),
    ).rejects.toThrow(/blocked because it is a cloud-metadata or link-local address/);
    expect(resolveHost).not.toHaveBeenCalled();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it.each([["169.254.169.254"], ["fd00:ec2::254"], ["192.168.1.20", "169.254.169.254"]])(
    "refuses a hostname that resolves to %s (DNS rebinding / alias)",
    async (...answers) => {
      const fetchImpl = vi.fn();
      await expect(
        fetchOutbound("http://evil.example/hook", {
          policy: "lan",
          resolveHost: resolver({ "evil.example": answers }),
          fetchImpl: fetchImpl as unknown as typeof fetch,
        }),
      ).rejects.toThrow(/resolves to a cloud-metadata or link-local address/);
      expect(fetchImpl).not.toHaveBeenCalled();
    },
  );

  it("fails closed when the host does not resolve", async () => {
    await expect(
      fetchOutbound("http://nowhere.lan/hook", {
        policy: "lan",
        resolveHost: async () => {
          throw new Error("ENOTFOUND");
        },
        fetchImpl: vi.fn() as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
  });

  it("still refuses non-http schemes", async () => {
    await expect(fetchOutbound("ftp://10.0.0.5/x", { policy: "lan", resolveHost: LAN })).rejects.toThrow(
      /http/,
    );
  });

  it("does not follow a redirect when maxRedirects is 0, and says so", async () => {
    const fetchImpl = vi.fn(
      async () => new Response(null, { status: 307, headers: { location: "http://169.254.169.254/" } }),
    );
    const agents: Array<Dispatcher & { closed: boolean }> = [];
    await expect(
      fetchOutbound("http://10.0.0.5/hook", {
        policy: "lan",
        maxRedirects: 0,
        resolveHost: LAN,
        fetchImpl: fetchImpl as unknown as typeof fetch,
        agentFactory: () => {
          const a = fakeAgent();
          agents.push(a);
          return a;
        },
      }),
    ).rejects.toThrow(/redirect \(HTTP 307\).*not followed/);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(agents.every((a) => a.closed)).toBe(true);
  });

  it("hands the TLS options to the SAME agent that carries the pinned lookup", async () => {
    const seen: Array<{ pins: PinnedAddress[]; tls: unknown }> = [];
    const r = await fetchOutbound("https://mattermost.lan/hooks/x", {
      policy: "lan",
      resolveHost: LAN,
      tls: { ca: "PEM", rejectUnauthorized: true },
      fetchImpl: (async () => new Response("ok")) as unknown as typeof fetch,
      agentFactory: (pins, tls) => {
        seen.push({ pins, tls });
        return fakeAgent();
      },
    });
    expect(seen).toEqual([
      { pins: [{ address: "192.168.1.20", family: 4 }], tls: { ca: "PEM", rejectUnauthorized: true } },
    ]);
    await r.dispose();
  });

  it("passes the caller's method, headers and body through, and honours the caller's signal", async () => {
    const fetchImpl = vi.fn(async (_url: unknown, _init?: unknown) => new Response("ok"));
    const r = await fetchOutbound("http://10.0.0.5/hook", {
      policy: "lan",
      resolveHost: LAN,
      agentFactory: () => fakeAgent(),
      fetchImpl: fetchImpl as unknown as typeof fetch,
      request: { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
    });
    const init = fetchImpl.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(init.body).toBe("{}");
    expect(init.redirect).toBe("manual");
    await r.dispose();

    const ac = new AbortController();
    ac.abort();
    await expect(
      fetchOutbound("http://10.0.0.5/hook", {
        policy: "lan",
        resolveHost: LAN,
        signal: ac.signal,
        fetchImpl: vi.fn() as unknown as typeof fetch,
      }),
    ).rejects.toThrow();
  });

  it('leaves the default "public" policy as it was: a LAN target is still refused', async () => {
    await expect(fetchOutbound("https://10.0.0.5/hook", { resolveHost: LAN })).rejects.toBeInstanceOf(
      OutboundUrlBlockedError,
    );
  });
});

describe("resolveLanHost — the socket-level half (SMTP, and syslog in #2147)", () => {
  it("returns the checked addresses for a LAN or loopback host", async () => {
    expect(await resolveLanHost("mail.lan", { resolveHost: LAN })).toEqual([
      { address: "192.168.1.20", family: 4 },
    ]);
    expect(
      await resolveLanHost("127.0.0.1", { resolveHost: resolver({ "127.0.0.1": ["127.0.0.1"] }) }),
    ).toEqual([{ address: "127.0.0.1", family: 4 }]);
  });

  it("refuses a metadata literal without resolving it", async () => {
    const resolveHost = vi.fn(LAN);
    await expect(resolveLanHost("169.254.169.254", { resolveHost })).rejects.toThrow(
      /blocked because it is a cloud-metadata or link-local address/,
    );
    expect(resolveHost).not.toHaveBeenCalled();
  });

  it("refuses a name that resolves into link-local space", async () => {
    await expect(
      resolveLanHost("smtp.evil", { resolveHost: resolver({ "smtp.evil": ["169.254.169.254"] }) }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
  });

  it("fails closed on a lookup error, an empty answer, and a stalled lookup", async () => {
    await expect(
      resolveLanHost("x.lan", {
        resolveHost: async () => {
          throw new Error("SERVFAIL");
        },
      }),
    ).rejects.toThrow(/could not be resolved/);
    await expect(resolveLanHost("x.lan", { resolveHost: async () => [] })).rejects.toThrow(
      /could not be resolved/,
    );
    await expect(
      resolveLanHost("x.lan", { resolveHost: () => new Promise(() => {}), timeoutMs: 20 }),
    ).rejects.toThrow(/time budget/);
  });
});

describe("createGuardedFetch — a fetch-shaped wrapper for senders that take a FetchFn", () => {
  it("returns the response with its status and body, and tears the pinned agent down", async () => {
    const agents: Array<Dispatcher & { closed: boolean }> = [];
    const guarded = createGuardedFetch({
      policy: "lan",
      maxRedirects: 0,
      resolveHost: LAN,
      fetchImpl: async () => new Response("hello", { status: 202 }),
      agentFactory: () => {
        const a = fakeAgent();
        agents.push(a);
        return a;
      },
    });
    const res = await guarded("http://10.0.0.5/hook", { method: "POST", body: "{}" });
    expect(res.status).toBe(202);
    expect(await res.text()).toBe("hello");
    expect(agents).toHaveLength(1);
    expect(agents[0].closed).toBe(true);
  });

  it("caps the buffered body", async () => {
    const guarded = createGuardedFetch({
      policy: "lan",
      resolveHost: LAN,
      agentFactory: () => fakeAgent(),
      maxBodyBytes: 4,
      fetchImpl: async () => new Response("0123456789", { status: 500 }),
    });
    const res = await guarded("http://10.0.0.5/hook");
    expect(res.status).toBe(500);
    expect(await res.text()).toBe("0123");
  });

  it("throws OutboundUrlBlockedError for a refused target", async () => {
    const fetchImpl = vi.fn();
    const guarded = createGuardedFetch({
      policy: "lan",
      resolveHost: LAN,
      fetchImpl: fetchImpl,
    });
    await expect(guarded("http://169.254.169.254/x")).rejects.toBeInstanceOf(OutboundUrlBlockedError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
