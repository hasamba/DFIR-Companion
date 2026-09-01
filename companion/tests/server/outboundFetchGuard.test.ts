import { describe, it, expect, vi } from "vitest";
import {
  assertOutboundUrlAllowed,
  fetchOutbound,
  pinnedLookup,
  OutboundUrlBlockedError,
} from "../../src/routes/outboundFetchGuard.js";

// Resolver stub so the unit tests never touch real DNS. A host not listed here resolves to a
// public address, which is the "ordinary internet URL" case.
const resolver =
  (map: Record<string, string[]>) =>
  async (host: string): Promise<Array<{ address: string; family: number }>> =>
    (map[host] ?? ["93.184.216.34"]).map((address) => ({
      address,
      family: address.includes(":") ? 6 : 4,
    }));

const PUBLIC = resolver({});

function response(status: number, headers: Record<string, string> = {}): Response {
  return new Response(status === 204 || status >= 300 ? null : "{}", { status, headers });
}

describe("assertOutboundUrlAllowed", () => {
  it("accepts an ordinary https URL to a public host", async () => {
    const url = await assertOutboundUrlAllowed("https://www.cisa.gov/feed.json", {
      resolveHost: PUBLIC,
    });
    expect(url.href).toBe("https://www.cisa.gov/feed.json");
  });

  it("rejects a string that is not an absolute URL", async () => {
    await expect(assertOutboundUrlAllowed("not a url", { resolveHost: PUBLIC })).rejects.toBeInstanceOf(
      OutboundUrlBlockedError,
    );
  });

  it("rejects a non-http scheme", async () => {
    await expect(assertOutboundUrlAllowed("file:///etc/passwd", { resolveHost: PUBLIC })).rejects.toThrow(
      /https:/,
    );
  });

  it("rejects http:// by default", async () => {
    await expect(
      assertOutboundUrlAllowed("http://www.cisa.gov/feed.json", { resolveHost: PUBLIC }),
    ).rejects.toThrow(/https:/);
  });

  // The reason the issue was filed: cloud instance credentials one POST body away.
  it("rejects the cloud metadata address", async () => {
    await expect(
      assertOutboundUrlAllowed("https://169.254.169.254/latest/meta-data/", { resolveHost: PUBLIC }),
    ).rejects.toThrow(/link-local/i);
  });

  it.each([
    "https://127.0.0.1/x",
    "https://localhost/x",
    "https://grafana.localhost/x",
    "https://10.0.0.5/x",
    "https://192.168.1.10/x",
    "https://172.16.4.4/x",
    "https://100.64.0.1/x",
    "https://[::1]/x",
    "https://[fd00::1]/x",
  ])("rejects the literal internal target %s", async (raw) => {
    await expect(assertOutboundUrlAllowed(raw, { resolveHost: PUBLIC })).rejects.toBeInstanceOf(
      OutboundUrlBlockedError,
    );
  });

  // An IPv4-mapped IPv6 literal is the same address wearing a different spelling; iocValue.ts
  // carries the parser for it precisely so a guard cannot be walked around this way.
  it("rejects an IPv4-mapped IPv6 spelling of the metadata address", async () => {
    await expect(
      assertOutboundUrlAllowed("https://[::ffff:169.254.169.254]/", { resolveHost: PUBLIC }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
  });

  // A literal-only check stops at the URL text. This is the case that needs the resolver.
  it("rejects a public-looking hostname that RESOLVES to an internal address", async () => {
    await expect(
      assertOutboundUrlAllowed("https://metadata.evil.example/", {
        resolveHost: resolver({ "metadata.evil.example": ["169.254.169.254"] }),
      }),
    ).rejects.toThrow(/resolve/i);
  });

  it("rejects when ANY resolved address is internal, not just the first", async () => {
    await expect(
      assertOutboundUrlAllowed("https://split.example/", {
        resolveHost: resolver({ "split.example": ["93.184.216.34", "10.1.2.3"] }),
      }),
    ).rejects.toThrow(/resolve/i);
  });

  // Fails closed, because the ATTACKER decides when the lookup fails: the nameserver for their own
  // domain can answer SERVFAIL here and the metadata address to the lookup fetch makes next. Letting
  // an unresolvable host through skipped the resolved-address check and the pin together.
  it("refuses a host that cannot be resolved", async () => {
    await expect(
      assertOutboundUrlAllowed("https://nope.example/", {
        resolveHost: async () => {
          throw new Error("SERVFAIL");
        },
      }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
  });

  // Same hole, different shape: a resolver that returns nothing instead of throwing.
  it("refuses a host whose resolution returns no addresses", async () => {
    await expect(
      assertOutboundUrlAllowed("https://empty.example/", { resolveHost: async () => [] }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
  });

  it("names DNS as the cause, so an outage is not read as a policy block", async () => {
    const err: Error = await assertOutboundUrlAllowed("https://nope.example/", {
      resolveHost: async () => {
        throw new Error("SERVFAIL");
      },
    }).then(
      () => new Error("expected the URL to be blocked"),
      (e: unknown) => e as Error,
    );
    expect(err.message).toMatch(/could not be resolved/i);
  });

  // The blocked message must not name the address the host resolved to — that IS the internal
  // detail the guard exists to withhold.
  it("does not disclose the resolved internal address in the error", async () => {
    const err: Error = await assertOutboundUrlAllowed("https://metadata.evil.example/", {
      resolveHost: resolver({ "metadata.evil.example": ["169.254.169.254"] }),
    }).then(
      () => new Error("expected the URL to be blocked"),
      (e: unknown) => e as Error,
    );
    expect(err).toBeInstanceOf(OutboundUrlBlockedError);
    expect(err.message).not.toContain("169.254.169.254");
  });

  describe("allowInternal opt-in", () => {
    it("permits http:// to a private host", async () => {
      const url = await assertOutboundUrlAllowed("http://10.0.0.5/kev.json", {
        allowInternal: true,
        resolveHost: PUBLIC,
      });
      expect(url.href).toBe("http://10.0.0.5/kev.json");
    });

    it("still rejects a non-http scheme", async () => {
      await expect(
        assertOutboundUrlAllowed("file:///etc/passwd", { allowInternal: true, resolveHost: PUBLIC }),
      ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
    });
  });
});

describe("fetchOutbound", () => {
  it("returns the response and the URL it came from", async () => {
    const fetchImpl = vi.fn(async () => response(200));
    const { response: resp, url } = await fetchOutbound("https://www.cisa.gov/feed.json", {
      resolveHost: PUBLIC,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(resp.status).toBe(200);
    expect(url.href).toBe("https://www.cisa.gov/feed.json");
  });

  it("fetches with redirect: manual so no hop is followed unchecked", async () => {
    let init: RequestInit | undefined;
    const fetchImpl = (async (_url: unknown, given: RequestInit) => {
      init = given;
      return response(200);
    }) as unknown as typeof fetch;
    await fetchOutbound("https://www.cisa.gov/feed.json", { resolveHost: PUBLIC, fetchImpl });
    expect(init).toMatchObject({ redirect: "manual" });
  });

  // The half of the SSRF that a one-shot URL check misses entirely: cisa.gov answers 302 to the
  // metadata service and the guard never sees the address it actually connects to.
  it("re-validates each redirect hop and blocks one that lands internal", async () => {
    const fetchImpl = vi.fn(async () =>
      response(302, { location: "http://169.254.169.254/latest/meta-data/" }),
    );
    await expect(
      fetchOutbound("https://www.cisa.gov/feed.json", {
        resolveHost: PUBLIC,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
  });

  it("follows a redirect that stays public", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(response(302, { location: "https://mirror.example/feed.json" }))
      .mockResolvedValueOnce(response(200));
    const { url } = await fetchOutbound("https://www.cisa.gov/feed.json", {
      resolveHost: PUBLIC,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(url.href).toBe("https://mirror.example/feed.json");
  });

  it("resolves a relative Location against the hop that sent it", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(response(302, { location: "/other/feed.json" }))
      .mockResolvedValueOnce(response(200));
    const { url } = await fetchOutbound("https://www.cisa.gov/feed.json", {
      resolveHost: PUBLIC,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(url.href).toBe("https://www.cisa.gov/other/feed.json");
  });

  it("stops after maxRedirects rather than looping forever", async () => {
    const fetchImpl = vi.fn(async () => response(302, { location: "https://mirror.example/again" }));
    await expect(
      fetchOutbound("https://www.cisa.gov/feed.json", {
        maxRedirects: 2,
        resolveHost: PUBLIC,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/redirect/i);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it("rejects a redirect with no Location header", async () => {
    const fetchImpl = vi.fn(async () => response(302));
    await expect(
      fetchOutbound("https://www.cisa.gov/feed.json", {
        resolveHost: PUBLIC,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
  });

  // One budget for the chain. A per-hop timeout would let five hops spend five times the cap.
  it("spends ONE timeout signal across every hop", async () => {
    const signals: unknown[] = [];
    const fetchImpl = vi
      .fn()
      .mockImplementationOnce(async (_u: unknown, init: RequestInit) => {
        signals.push(init.signal);
        return response(302, { location: "https://mirror.example/feed.json" });
      })
      .mockImplementationOnce(async (_u: unknown, init: RequestInit) => {
        signals.push(init.signal);
        return response(200);
      });
    await fetchOutbound("https://www.cisa.gov/feed.json", {
      resolveHost: PUBLIC,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(signals).toHaveLength(2);
    expect(signals[0]).toBe(signals[1]);
  });
});

// ── DNS rebinding ────────────────────────────────────────────────────────────
// Checks 1-3 all describe a NAME. The socket is opened by a second resolution inside fetch, and a
// record with a one-second TTL can answer public to the check and 169.254.169.254 to the connect.
// Pinning the connection to the address that was checked is what makes that impossible, so these
// tests assert the pin itself rather than the name check that precedes it.
describe("fetchOutbound — connection pinning (DNS rebinding)", () => {
  it("pins the connection to the address the guard approved", async () => {
    const pins: Array<{ address: string; family: number }> = [];
    const fetchImpl = (async () => response(200)) as unknown as typeof fetch;
    await fetchOutbound("https://feed.example/x.json", {
      resolveHost: resolver({ "feed.example": ["93.184.216.9"] }),
      agentFactory: (given) => {
        pins.push(...given);
        return { close: async () => {} } as never;
      },
      fetchImpl,
    });
    expect(pins).toEqual([{ address: "93.184.216.9", family: 4 }]);
  });

  it("passes the pinned dispatcher to fetch, so the socket cannot re-resolve", async () => {
    const agent = { close: async () => {} } as never;
    let init: (RequestInit & { dispatcher?: unknown }) | undefined;
    const fetchImpl = (async (_u: unknown, given: RequestInit) => {
      init = given;
      return response(200);
    }) as unknown as typeof fetch;
    await fetchOutbound("https://feed.example/x.json", {
      resolveHost: PUBLIC,
      agentFactory: () => agent,
      fetchImpl,
    });
    expect(init?.dispatcher).toBe(agent);
  });

  // The lookup handed to undici must ignore the hostname entirely — that is the whole mechanism.
  // Both call shapes are covered because undici uses `{ all: true }` on some paths and not others,
  // and answering the wrong shape throws in the connect rather than failing closed.
  it("answers the pinned address whatever hostname the connect asks for", () => {
    const look = pinnedLookup([{ address: "93.184.216.9", family: 4 }]);

    let plain: unknown[] = [];
    look("attacker.example", {}, (...args: unknown[]) => (plain = args));
    expect(plain).toEqual([null, "93.184.216.9", 4]);

    let all: unknown[] = [];
    look("attacker.example", { all: true }, (...args: unknown[]) => (all = args));
    expect(all).toEqual([null, [{ address: "93.184.216.9", family: 4 }]]);
  });

  it("pins each redirect hop to its own checked address", async () => {
    const pins: string[] = [];
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(response(302, { location: "https://second.example/feed.json" }))
      .mockResolvedValueOnce(response(200));
    await fetchOutbound("https://first.example/feed.json", {
      resolveHost: resolver({ "first.example": ["93.184.216.1"], "second.example": ["93.184.216.2"] }),
      agentFactory: (given) => {
        pins.push(given[0].address);
        return { close: async () => {} } as never;
      },
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(pins).toEqual(["93.184.216.1", "93.184.216.2"]);
  });

  it("closes every pinned connection when dispose is called", async () => {
    let closed = 0;
    const fetchImpl = (async () => response(200)) as unknown as typeof fetch;
    const { dispose } = await fetchOutbound("https://feed.example/x.json", {
      resolveHost: PUBLIC,
      agentFactory: () =>
        ({
          close: async () => {
            closed += 1;
          },
        }) as never,
      fetchImpl,
    });
    await dispose();
    expect(closed).toBe(1);
  });

  // A blocked hop must not leak the socket opened by the hop before it.
  it("closes pinned connections when a later hop is refused", async () => {
    let closed = 0;
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(response(302, { location: "https://evil.example/feed.json" }));
    await expect(
      fetchOutbound("https://first.example/feed.json", {
        resolveHost: resolver({ "first.example": ["93.184.216.1"], "evil.example": ["169.254.169.254"] }),
        agentFactory: () =>
          ({
            close: async () => {
              closed += 1;
            },
          }) as never,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
    expect(closed).toBe(1);
  });

  // The operator said this companion may talk to its own network, so there is no approved address
  // to pin to and no rebinding threat to defend against.
  it("does not pin when the operator opted into internal targets", async () => {
    let made = 0;
    const fetchImpl = (async () => response(200)) as unknown as typeof fetch;
    await fetchOutbound("http://10.0.0.5/kev.json", {
      allowInternal: true,
      resolveHost: PUBLIC,
      agentFactory: () => {
        made += 1;
        return { close: async () => {} } as never;
      },
      fetchImpl,
    });
    expect(made).toBe(0);
  });
});

// The invariant the module header states, asserted end to end: outside the operator opt-in, no
// request is ever sent without a pin. These cover the paths that used to send one.
describe("fetchOutbound — no unpinned request escapes", () => {
  it("sends nothing when the first hop cannot be resolved", async () => {
    let called = false;
    const fetchImpl = (async () => {
      called = true;
      return response(200);
    }) as unknown as typeof fetch;
    await expect(
      fetchOutbound("https://nope.example/x.json", {
        resolveHost: async () => {
          throw new Error("SERVFAIL");
        },
        fetchImpl,
      }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
    expect(called).toBe(false);
  });

  it("sends nothing further when a REDIRECT target cannot be resolved", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(response(302, { location: "https://gone.example/feed.json" }))
      .mockResolvedValueOnce(response(200));
    await expect(
      fetchOutbound("https://first.example/feed.json", {
        resolveHost: async (host: string) => {
          if (host === "gone.example") throw new Error("SERVFAIL");
          return [{ address: "93.184.216.1", family: 4 }];
        },
        agentFactory: () => ({ close: async () => {} }) as never,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  // Belt and braces on the invariant itself: a resolver that somehow yields no pin must not produce
  // an unpinned fetch, whatever else changes in this file.
  it("refuses rather than fetching unpinned if a pin is ever missing", async () => {
    let called = false;
    const fetchImpl = (async () => {
      called = true;
      return response(200);
    }) as unknown as typeof fetch;
    await expect(
      fetchOutbound("https://feed.example/x.json", {
        resolveHost: async () => [],
        fetchImpl,
      }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
    expect(called).toBe(false);
  });
});

describe("fetchOutbound — reserved ranges reached through DNS", () => {
  it.each(["240.0.0.1", "198.18.0.1", "192.0.0.1", "255.255.255.255"])(
    "refuses a host that resolves to %s",
    async (address) => {
      let called = false;
      const fetchImpl = (async () => {
        called = true;
        return response(200);
      }) as unknown as typeof fetch;
      await expect(
        fetchOutbound("https://feed.example/x.json", {
          resolveHost: resolver({ "feed.example": [address] }),
          fetchImpl,
        }),
      ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
      expect(called).toBe(false);
    },
  );

  // A host answering with one public and one reserved address must not be reachable at all: the pin
  // would pick the safe one now and the resolver could order them the other way next time.
  it("refuses a host whose answer mixes public and reserved addresses", async () => {
    await expect(
      fetchOutbound("https://mixed.example/x.json", {
        resolveHost: resolver({ "mixed.example": ["93.184.216.34", "240.0.0.1"] }),
        fetchImpl: (async () => response(200)) as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
  });
});

// ── The three findings from review ───────────────────────────────────────────
describe("fetchOutbound — the deadline covers DNS", () => {
  // The header advertised one budget for the whole chain, and the signal only ever reached the
  // fetches. dns.promises.lookup takes no AbortSignal, so whoever runs the authoritative server for
  // the name decided how long /kev/import-url stayed open.
  it("gives up on a stalled lookup instead of waiting past the budget", async () => {
    let called = false;
    const started = Date.now();
    await expect(
      fetchOutbound("https://slow.example/x.json", {
        timeoutMs: 120,
        resolveHost: () => new Promise(() => {}), // never settles, like a black-holed nameserver
        fetchImpl: (async () => {
          called = true;
          return response(200);
        }) as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
    expect(called, "nothing should be sent when the name never resolved").toBe(false);
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it("says the budget ran out, not that the host does not exist", async () => {
    const err: Error = await fetchOutbound("https://slow.example/x.json", {
      timeoutMs: 60,
      resolveHost: () => new Promise(() => {}),
      fetchImpl: (async () => response(200)) as unknown as typeof fetch,
    }).then(
      () => new Error("expected a refusal"),
      (e: unknown) => e as Error,
    );
    expect(err.message).toMatch(/time budget/i);
  });

  // The budget is for the CHAIN. A redirect chain of slow lookups must not get a fresh one each hop.
  it("spends one budget across the lookups of every hop", async () => {
    const started = Date.now();
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(response(302, { location: "https://next.example/feed.json" }));
    await expect(
      fetchOutbound("https://first.example/feed.json", {
        timeoutMs: 300,
        maxRedirects: 5,
        resolveHost: async (host: string) => {
          if (host === "first.example") return [{ address: "93.184.216.1", family: 4 }];
          await new Promise((r) => setTimeout(r, 5_000)); // each later hop stalls
          return [{ address: "93.184.216.2", family: 4 }];
        },
        agentFactory: () => ({ close: async () => {} }) as never,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it("still refuses a genuinely unresolvable host with the DNS wording", async () => {
    const err: Error = await fetchOutbound("https://nope.example/x.json", {
      resolveHost: async () => {
        throw new Error("SERVFAIL");
      },
      fetchImpl: (async () => response(200)) as unknown as typeof fetch,
    }).then(
      () => new Error("expected a refusal"),
      (e: unknown) => e as Error,
    );
    expect(err.message).toMatch(/could not be resolved/i);
  });
});

describe("fetchOutbound — every checked address is offered, not just the first", () => {
  // Pinning one address of a checked set removed undici's address fallback: a dual-stack feed whose
  // AAAA sorts first became unreachable on an IPv4-only host even though its A record was checked.
  it("hands the whole validated set to the dispatcher", async () => {
    let given: Array<{ address: string; family: number }> = [];
    await fetchOutbound("https://dual.example/x.json", {
      resolveHost: async () => [
        { address: "2606:4700::1111", family: 6 },
        { address: "93.184.216.34", family: 4 },
      ],
      agentFactory: (pins) => {
        given = pins;
        return { close: async () => {} } as never;
      },
      fetchImpl: (async () => response(200)) as unknown as typeof fetch,
    });
    expect(given).toEqual([
      { address: "2606:4700::1111", family: 6 },
      { address: "93.184.216.34", family: 4 },
    ]);
  });

  it("answers the connect with every approved address when it asks for all of them", () => {
    const look = pinnedLookup([
      { address: "2606:4700::1111", family: 6 },
      { address: "93.184.216.34", family: 4 },
    ]);
    let all: unknown[] = [];
    look("dual.example", { all: true }, (...args: unknown[]) => (all = args));
    expect(all).toEqual([
      null,
      [
        { address: "2606:4700::1111", family: 6 },
        { address: "93.184.216.34", family: 4 },
      ],
    ]);

    // The single-answer shape can only carry one; undici's constraint, so it gets the first.
    let one: unknown[] = [];
    look("dual.example", {}, (...args: unknown[]) => (one = args));
    expect(one).toEqual([null, "2606:4700::1111", 6]);
  });

  // The fallback must not become a way back in: one internal address in the answer still refuses
  // the whole host, so there is never a rejected address left in the set to fall back onto.
  it("offers nothing at all when any address in the answer is not public", async () => {
    let made = 0;
    await expect(
      fetchOutbound("https://mixed.example/x.json", {
        resolveHost: async () => [
          { address: "93.184.216.34", family: 4 },
          { address: "169.254.169.254", family: 4 },
        ],
        agentFactory: () => {
          made += 1;
          return { close: async () => {} } as never;
        },
        fetchImpl: (async () => response(200)) as unknown as typeof fetch,
      }),
    ).rejects.toBeInstanceOf(OutboundUrlBlockedError);
    expect(made).toBe(0);
  });
});
