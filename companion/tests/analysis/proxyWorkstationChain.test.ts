// #993 (proxy -> workstation half, part of #933 item 1): a web/proxy-log event's own
// network.source.address, and (scoped to canonical.web rows) its own authenticated
// canonical.account.name, each resolved against hostBinding.ts's own host-identity index (#1156)
// -- zero, one, or an explicitly ambiguous set of candidate hosts, never picked down to one by
// any heuristic, and never silently merged across the two identity paths when they disagree.
// Never claims "the workstation" unconditionally -- see the module's own header.
import { describe, it, expect } from "vitest";
import { createCanonicalEvent, type CanonicalEventCategory } from "../../src/analysis/canonicalEvent.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import { resolveProxyHostIdentity } from "../../src/analysis/proxyWorkstationChain.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const EMPTY_ALIAS = buildHostAliasIndex([], {});
let seq = 0;

function logonEvent(o: {
  sessionHost: string;
  clientName?: string;
  ip?: string;
  ts: string;
  outcome?: "success" | "failed";
  category?: CanonicalEventCategory;
  // Account-presence half (hostBinding.ts's byAccount index): needs an INTERACTIVE-family
  // logonType (2/7/10/11), never the default network logonType 3 the IP half uses.
  accountName?: string;
  accountDomain?: string;
  logonType?: number;
}): ForensicEvent {
  seq += 1;
  return {
    id: `logon-${seq}`,
    timestamp: o.ts,
    description: `Windows Security logon @ ${o.sessionHost}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: o.sessionHost,
    canonical: createCanonicalEvent({
      event: { category: o.category ?? "authentication", type: "logon", outcome: o.outcome ?? "success" },
      target: { kind: "host", name: o.sessionHost },
      authentication: { logonType: o.logonType ?? 3 },
      ...(o.clientName ? { session: { terminal: o.clientName } } : {}),
      ...(o.ip ? { network: { source: { address: o.ip } } } : {}),
      ...(o.accountName
        ? { account: { name: o.accountName, ...(o.accountDomain ? { domain: o.accountDomain } : {}) } }
        : {}),
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "test", locator: `row:${seq}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

/** A web-chain-shaped event carrying canonical.network.source.address (the #1032 chain envelope's
 * own `web` block detail isn't needed here -- eligibility never reads it). */
function webChainEvent(o: { ip: string; ts: string; locator?: string }): ForensicEvent {
  seq += 1;
  return {
    id: `web-${seq}`,
    timestamp: o.ts,
    description: `GET / from ${o.ip}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "web-request" },
      network: { source: { address: o.ip } },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "zeek-http", locator: o.locator ?? `row:${seq}` }] },
      producer: { importer: "zeek", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

/** A Squid/combined-access-log-shaped event: carries network.source.address but NO canonical.web
 * -- must still be eligible for the IP join (combinedLogImport.ts:491's own real behavior). */
function combinedLogEvent(o: { ip: string; ts: string }): ForensicEvent {
  seq += 1;
  return {
    id: `combined-${seq}`,
    timestamp: o.ts,
    description: `${o.ip} - - [request]`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "web-request" },
      network: { source: { address: o.ip } },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "combined-access-log", locator: `row:${seq}` }] },
      producer: { importer: "combined-log", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

/** A combined-log row carrying Squid's `%u` authenticated user (combinedLogImport.ts's own
 * `account: { name: user }` wiring, #993) -- ALWAYS carries canonical.web, the account path's
 * own eligibility scope. `ip` is optional so the account-only join can be tested in isolation. */
function proxyAccountEvent(o: { account: string; ip?: string; ts: string }): ForensicEvent {
  seq += 1;
  return {
    id: `proxyacct-${seq}`,
    timestamp: o.ts,
    description: `GET / [${o.account}]`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: createCanonicalEvent({
      event: { category: "network", type: "web-request" },
      ...(o.ip ? { network: { source: { address: o.ip } } } : {}),
      account: { name: o.account },
      web: {
        method: "GET",
        target: "/",
        targetForm: "origin",
        responseState: "recorded",
        bodies: [],
        bodiesTotal: 0,
        records: 1,
      },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "combined-access-log", locator: `row:${seq}` }] },
      producer: { importer: "combined-log", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

/** An event carrying canonical.account.name but NO canonical.web -- e.g. an EDR process-create.
 * The account path must never read this: it isn't a proxy log naming its client. */
function nonWebAccountEvent(o: { account: string; ts: string }): ForensicEvent {
  seq += 1;
  return {
    id: `nonweb-${seq}`,
    timestamp: o.ts,
    description: `process create by ${o.account}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: createCanonicalEvent({
      event: { category: "process", type: "process-create" },
      account: { name: o.account },
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "edr", locator: `row:${seq}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

describe("resolveProxyHostIdentity", () => {
  it("matches a web-chain request's own source IP to the client host a 4624 logon names", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const web = webChainEvent({ ip: "10.0.0.5", ts: "2026-06-10T12:05:00Z" });
    const results = resolveProxyHostIdentity([logon, web], EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      eventId: web.id,
      address: "10.0.0.5",
      outcome: "matched",
      toleranceMs: 21_600_000,
    });
    expect(results[0].hosts).toEqual([
      { host: "ws-042", sampleTime: "2026-06-10T12:00:00Z", evidenceEventIds: [logon.id], via: ["address"] },
    ]);
    expect(results[0].caveats.length).toBeGreaterThan(0);
  });

  it("also matches a combined-access-log (Squid) row -- eligibility is network.source.address, never canonical.web", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const combined = combinedLogEvent({ ip: "10.0.0.5", ts: "2026-06-10T12:05:00Z" });
    const results = resolveProxyHostIdentity([logon, combined], EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0].outcome).toBe("matched");
    expect(results[0].hosts).toEqual([
      { host: "ws-042", sampleTime: "2026-06-10T12:00:00Z", evidenceEventIds: [logon.id], via: ["address"] },
    ]);
  });

  it("reports no-match explicitly when no host-binding evidence exists in the window", () => {
    const events = [webChainEvent({ ip: "10.0.0.9", ts: "2026-06-10T12:05:00Z" })];
    const results = resolveProxyHostIdentity(events, EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({ outcome: "no-match", hosts: [], address: "10.0.0.9" });
  });

  it("does NOT report ambiguous when the SAME host logged on more than once in the window (ordinary re-auth)", () => {
    const logon1 = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T11:00:00Z",
    });
    const logon2 = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T11:30:00Z",
    });
    const web = webChainEvent({ ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" });
    const results = resolveProxyHostIdentity([logon1, logon2, web], EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0].outcome).toBe("matched");
    expect(results[0].hosts).toHaveLength(1);
    expect(results[0].hosts[0].host).toBe("ws-042");
    expect(results[0].hosts[0].evidenceEventIds.sort()).toEqual([logon1.id, logon2.id].sort());
  });

  it("reports ambiguous -- two workstations behind one proxy address -- and names both, never picking one", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T11:00:00Z" }),
      logonEvent({ sessionHost: "fs-02", clientName: "ws-099", ip: "10.0.0.5", ts: "2026-06-10T13:00:00Z" }),
      webChainEvent({ ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
    ];
    const results = resolveProxyHostIdentity(events, EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0].outcome).toBe("ambiguous");
    expect(results[0].hosts.map((h) => h.host).sort()).toEqual(["ws-042", "ws-099"]);
  });

  it("never joins outside the declared tolerance window", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-01T00:00:00Z" }),
      webChainEvent({ ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
    ];
    const results = resolveProxyHostIdentity(events, EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0].outcome).toBe("no-match");
  });

  it("never emits an entry for a logon event itself, even though it also carries network.source.address", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
    ];
    expect(resolveProxyHostIdentity(events, EMPTY_ALIAS, 21_600_000)).toEqual([]);
  });

  it("mirrors hostBinding.ts's OWN exclusion set exactly (type===logon && outcome===success), not category", () => {
    // A FAILED logon (never indexed by buildHostBindingIndex) is real, eligible evidence -- an
    // attacker's own source IP on a rejected auth attempt must not be silently dropped.
    const failedLogon = logonEvent({
      sessionHost: "fs-01",
      ip: "10.0.0.9",
      ts: "2026-06-10T12:00:00Z",
      outcome: "failed",
    });
    const results = resolveProxyHostIdentity([failedLogon], EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({ eventId: failedLogon.id, outcome: "no-match" });

    // A successful type:"logon" event under a DIFFERENT category is still indexed by
    // buildHostBindingIndex (which never reads category) -- it must still be excluded here, or it
    // would trivially self-match.
    const oddCategoryLogon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
      category: "other",
    });
    expect(resolveProxyHostIdentity([oddCategoryLogon], EMPTY_ALIAS, 21_600_000)).toEqual([]);
  });

  it("surfaces every rawRecords locator on an aggregated web-chain row, not just one", () => {
    const event: ForensicEvent = {
      id: "agg-1",
      timestamp: "2026-06-10T12:00:00Z",
      description: "GET / from 10.0.0.5 (x2)",
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      count: 2,
      canonical: createCanonicalEvent({
        event: { category: "network", type: "web-request" },
        network: { source: { address: "10.0.0.5" } },
        time: { observed: "2026-06-10T12:00:00Z", normalized: "2026-06-10T12:00:00Z" },
        evidence: {
          rawRecords: [
            { source: "zeek-http", locator: "row:1" },
            { source: "zeek-http", locator: "row:2" },
          ],
        },
        producer: { importer: "zeek", parserVersion: "1", mappingVersion: "1" },
      }),
    };
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T11:59:00Z",
    });
    const results = resolveProxyHostIdentity([logon, event], EMPTY_ALIAS, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0].locators).toEqual([
      { source: "zeek-http", locator: "row:1" },
      { source: "zeek-http", locator: "row:2" },
    ]);
  });

  it("ignores an event with no network.source.address at all", () => {
    seq += 1;
    const noAddress: ForensicEvent = {
      id: "no-addr",
      timestamp: "2026-06-10T12:00:00Z",
      description: "unrelated",
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    };
    expect(resolveProxyHostIdentity([noAddress], EMPTY_ALIAS, 21_600_000)).toEqual([]);
  });

  it("folds two spellings of the same real host (short name vs FQDN) to ONE match, never ambiguous", () => {
    // A logon's own session.terminal ("ws-042") is one spelling; the case's own fleet inventory
    // also knows this same machine's FQDN. Both must resolve to the same canonical host.
    const alias = buildHostAliasIndex([{ hostname: "ws-042", fqdn: "ws-042.corp.local" }], {});
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T12:00:00Z",
    });
    const web = webChainEvent({ ip: "10.0.0.5", ts: "2026-06-10T12:05:00Z" });
    const results = resolveProxyHostIdentity([logon, web], alias, 21_600_000);
    expect(results).toHaveLength(1);
    expect(results[0].outcome).toBe("matched");
    expect(results[0].hosts).toHaveLength(1);
    expect(results[0].hosts[0].host).toBe("ws-042.corp.local");
  });

  it("matches exactly at the tolerance boundary (inclusive)", () => {
    const logon = logonEvent({
      sessionHost: "fs-01",
      clientName: "ws-042",
      ip: "10.0.0.5",
      ts: "2026-06-10T06:00:00Z",
    });
    const web = webChainEvent({ ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }); // exactly 6h later
    const results = resolveProxyHostIdentity([logon, web], EMPTY_ALIAS, 21_600_000);
    expect(results[0].outcome).toBe("matched");
  });

  // ── Account path (#993, "an authenticated user present in both") ─────────────────────────
  describe("the account path", () => {
    it("matches a proxy row's own authenticated user to the interactive logon evidence names it present at", () => {
      const logon = logonEvent({
        sessionHost: "ws-042", // RDP/interactive: the account is present AT this host itself
        ts: "2026-06-10T11:00:00Z",
        accountName: "alice",
        logonType: 2,
      });
      const proxy = proxyAccountEvent({ account: "alice", ts: "2026-06-10T11:05:00Z" });
      const results = resolveProxyHostIdentity([logon, proxy], EMPTY_ALIAS, 21_600_000);
      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        eventId: proxy.id,
        account: "alice",
        address: "",
        outcome: "matched",
      });
      expect(results[0].hosts).toEqual([
        {
          host: "ws-042",
          sampleTime: "2026-06-10T11:00:00Z",
          evidenceEventIds: [logon.id],
          via: ["account"],
        },
      ]);
      expect(results[0].caveats.some((c) => c.includes("shared or reused credential"))).toBe(true);
      // The address-only caveats must not fire for an account-only match.
      expect(results[0].caveats.some((c) => c.includes("DHCP-lease"))).toBe(false);
    });

    it("never reads canonical.account.name off a non-web event -- it isn't a proxy log naming its client", () => {
      const logon = logonEvent({
        sessionHost: "ws-042",
        ts: "2026-06-10T11:00:00Z",
        accountName: "alice",
        logonType: 2,
      });
      const proc = nonWebAccountEvent({ account: "alice", ts: "2026-06-10T11:05:00Z" });
      expect(resolveProxyHostIdentity([logon, proc], EMPTY_ALIAS, 21_600_000)).toEqual([]);
    });

    it("a NETWORK logon (type 3) never feeds the account index -- the account only authenticated ACROSS to that host", () => {
      const logon = logonEvent({
        sessionHost: "fileserver-01",
        ts: "2026-06-10T11:00:00Z",
        accountName: "alice",
        logonType: 3, // the default -- a network logon, not "present at" fileserver-01
      });
      const proxy = proxyAccountEvent({ account: "alice", ts: "2026-06-10T11:05:00Z" });
      const results = resolveProxyHostIdentity([logon, proxy], EMPTY_ALIAS, 21_600_000);
      expect(results).toHaveLength(1);
      expect(results[0].outcome).toBe("no-match");
    });

    it("agreement: both paths naming the SAME host merge into one entry with via: [address, account]", () => {
      const logon = logonEvent({
        sessionHost: "ws-042",
        clientName: "ws-042",
        ip: "10.0.0.5",
        ts: "2026-06-10T11:00:00Z",
        accountName: "alice",
        logonType: 2,
      });
      const proxy = proxyAccountEvent({ account: "alice", ip: "10.0.0.5", ts: "2026-06-10T11:05:00Z" });
      const results = resolveProxyHostIdentity([logon, proxy], EMPTY_ALIAS, 21_600_000);
      expect(results).toHaveLength(1);
      expect(results[0].outcome).toBe("matched");
      expect(results[0].hosts).toHaveLength(1);
      expect(results[0].hosts[0].host).toBe("ws-042");
      expect(results[0].hosts[0].via.sort()).toEqual(["account", "address"]);
      // Both identity classes of caveat apply when both paths contributed.
      expect(results[0].caveats.some((c) => c.includes("DHCP-lease"))).toBe(true);
      expect(results[0].caveats.some((c) => c.includes("shared or reused credential"))).toBe(true);
    });

    it("disagreement: the address names one host and the account names another -- BOTH surface, never picked", () => {
      const addressLogon = logonEvent({
        sessionHost: "fs-01",
        clientName: "ws-proxy-exit", // the address resolves to the proxy's own egress host
        ip: "10.0.0.5",
        ts: "2026-06-10T11:00:00Z",
      });
      const accountLogon = logonEvent({
        sessionHost: "ws-alice-laptop",
        ts: "2026-06-10T11:00:00Z",
        accountName: "alice",
        logonType: 2,
      });
      const proxy = proxyAccountEvent({ account: "alice", ip: "10.0.0.5", ts: "2026-06-10T11:05:00Z" });
      const results = resolveProxyHostIdentity([addressLogon, accountLogon, proxy], EMPTY_ALIAS, 21_600_000);
      expect(results).toHaveLength(1);
      expect(results[0].outcome).toBe("ambiguous");
      const byHost = Object.fromEntries(results[0].hosts.map((h) => [h.host, h.via]));
      expect(byHost).toEqual({ "ws-proxy-exit": ["address"], "ws-alice-laptop": ["account"] });
    });
  });
});
