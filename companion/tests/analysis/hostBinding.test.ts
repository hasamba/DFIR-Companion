import { describe, it, expect } from "vitest";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import {
  buildHostBindingIndex,
  canonicalAccount,
  canonicalIp,
  resolveAccountAtTime,
  resolveIpAtTime,
} from "../../src/analysis/hostBinding.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;
function logonEvent(o: {
  sessionHost: string; // the machine that recorded the logon (canonical.target.name / event.asset)
  clientName?: string; // Workstation Name — the remote client's own name
  ip?: string; // network.source.address — the remote client's IP
  accountName?: string;
  accountDomain?: string;
  logonType?: number; // defaults to 3 (Network) — the shape a proxy/SMB-style join needs
  ts: string;
  outcome?: "success" | "failed";
}): ForensicEvent {
  seq += 1;
  return {
    id: `id-${seq}`,
    timestamp: o.ts,
    description: `Windows Security logon @ ${o.sessionHost}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: o.sessionHost,
    canonical: createCanonicalEvent({
      event: { category: "authentication", type: "logon", outcome: o.outcome ?? "success" },
      ...(o.accountName
        ? {
            actor: {
              kind: "account",
              name: o.accountName,
              ...(o.accountDomain ? { domain: o.accountDomain } : {}),
            },
            account: { name: o.accountName, ...(o.accountDomain ? { domain: o.accountDomain } : {}) },
          }
        : {}),
      target: { kind: "host", name: o.sessionHost },
      authentication: { logonType: o.logonType ?? 3 },
      ...(o.clientName ? { session: { terminal: o.clientName } } : {}),
      ...(o.ip ? { network: { source: { address: o.ip } } } : {}),
      time: { observed: o.ts, normalized: o.ts },
      evidence: { rawRecords: [{ source: "test", locator: `row:${seq}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  };
}

describe("canonicalIp", () => {
  it("lowercases and trims", () => {
    expect(canonicalIp("  10.0.0.5  ")).toBe("10.0.0.5");
  });

  it("folds IPv6 forms that mean the same address", () => {
    expect(canonicalIp("::1")).toBe(canonicalIp("0:0:0:0:0:0:0:1"));
  });

  it("folds an IPv4-mapped IPv6 address to its dotted-quad form", () => {
    expect(canonicalIp("::ffff:10.0.0.5")).toBe("10.0.0.5");
  });

  it("strips a zone suffix from a link-local address", () => {
    expect(canonicalIp("fe80::1%eth0")).toBe(canonicalIp("fe80::1"));
  });
});

describe("canonicalAccount", () => {
  it("keeps domain\\name shape, case-folded", () => {
    expect(canonicalAccount("CORP", "Alice")).toBe("corp\\alice");
  });

  it("is a bare lowercased name with no domain", () => {
    expect(canonicalAccount(undefined, "Alice")).toBe("alice");
  });
});

describe("buildHostBindingIndex + resolveIpAtTime (IP -> client host)", () => {
  it("binds the source IP to the CLIENT name (Workstation Name), not the session host", () => {
    // A workstation authenticates over SMB to a file server: the file server records the 4624,
    // asset/target = the SERVER, source IP + Workstation Name = the CLIENT. The binding must name
    // the client, or a proxy/SMB IP join would mislabel every hit with the server's own name.
    const events = [
      logonEvent({
        sessionHost: "fs-01",
        clientName: "ws-042",
        ip: "10.0.0.5",
        ts: "2026-06-10T12:00:00Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    const hits = resolveIpAtTime(index, "10.0.0.5", "2026-06-10T12:00:00Z", 1_000);
    expect(hits).toHaveLength(1);
    expect(hits[0].host).toBe("ws-042");
    expect(hits[0].sourceKind).toBe("logon-sample");
    expect(hits[0].evidenceEventId).toBe(events[0].id);
  });

  it("contributes no IP binding when Workstation Name is absent, even with a real source IP", () => {
    const events = [logonEvent({ sessionHost: "fs-01", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" })];
    const index = buildHostBindingIndex(events);
    expect(index.byIp.size).toBe(0);
  });

  it("contributes no IP binding for a dash/placeholder Workstation Name (unpopulated field)", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "-", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
      logonEvent({ sessionHost: "fs-01", clientName: "*", ip: "10.0.0.6", ts: "2026-06-10T12:00:00Z" }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byIp.size).toBe(0);
  });

  it("stores a whitespace-padded Workstation Name trimmed, so alias/name comparisons still match", () => {
    const events = [
      logonEvent({
        sessionHost: "fs-01",
        clientName: "  ws-042  ",
        ip: "10.0.0.5",
        ts: "2026-06-10T12:00:00Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    const hits = resolveIpAtTime(index, "10.0.0.5", "2026-06-10T12:00:00Z", 1_000);
    expect(hits).toHaveLength(1);
    expect(hits[0].host).toBe("ws-042");
  });

  it("surfaces both hosts when one IP was bound to two clients in non-overlapping windows", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-001", ip: "10.0.0.9", ts: "2026-06-10T08:00:00Z" }),
      logonEvent({ sessionHost: "fs-01", clientName: "ws-002", ip: "10.0.0.9", ts: "2026-06-10T20:00:00Z" }),
    ];
    const index = buildHostBindingIndex(events);

    const both = resolveIpAtTime(index, "10.0.0.9", "2026-06-10T14:00:00Z", 6 * 3_600_000);
    expect(both.map((b) => b.host).sort()).toEqual(["ws-001", "ws-002"]);

    const onlyEarly = resolveIpAtTime(index, "10.0.0.9", "2026-06-10T08:00:00Z", 1_000);
    expect(onlyEarly.map((b) => b.host)).toEqual(["ws-001"]);
  });

  it("returns no candidates for an IP never seen in the case", () => {
    const index = buildHostBindingIndex([]);
    expect(resolveIpAtTime(index, "10.0.0.9", "2026-06-10T08:00:00Z", 1_000)).toEqual([]);
  });

  it("excludes a failed logon (4625-shaped: outcome failed)", () => {
    const events = [
      logonEvent({
        sessionHost: "fs-01",
        clientName: "ws-042",
        ip: "10.0.0.5",
        ts: "2026-06-10T12:00:00Z",
        outcome: "failed",
      }),
    ];
    const index = buildHostBindingIndex(events);
    expect(resolveIpAtTime(index, "10.0.0.5", "2026-06-10T12:00:00Z", 1_000)).toEqual([]);
  });

  it("excludes loopback / no-network IP values from the IP index", () => {
    const events = [
      logonEvent({ sessionHost: "ws-042", clientName: "ws-042", ip: "-", ts: "2026-06-10T12:00:00Z" }),
      logonEvent({ sessionHost: "ws-042", clientName: "ws-042", ip: "::1", ts: "2026-06-10T12:00:01Z" }),
      logonEvent({
        sessionHost: "ws-042",
        clientName: "ws-042",
        ip: "127.0.0.1",
        ts: "2026-06-10T12:00:02Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byIp.size).toBe(0);
  });

  it("excludes IPv6 link-local addresses (fe80::/10) from the IP index, zoned or not", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "fe80::1", ts: "2026-06-10T12:00:00Z" }),
      logonEvent({
        sessionHost: "fs-01",
        clientName: "ws-042",
        ip: "fe80::1%eth0",
        ts: "2026-06-10T12:00:01Z",
      }),
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "febf::1", ts: "2026-06-10T12:00:02Z" }),
      logonEvent({
        sessionHost: "fs-01",
        clientName: "ws-042",
        ip: "fe80:0:0:0:0:0:0:1",
        ts: "2026-06-10T12:00:03Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byIp.size).toBe(0);
  });

  it("still admits fec0::1, one step past the excluded fe80::/10 range, as identifying", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "fec0::1", ts: "2026-06-10T12:00:00Z" }),
    ];
    const index = buildHostBindingIndex(events);
    const hits = resolveIpAtTime(index, "fec0::1", "2026-06-10T12:00:00Z", 1_000);
    expect(hits).toHaveLength(1);
  });

  it("excludes IPv4 link-local / APIPA (169.254.0.0/16) from the IP index, the same as its IPv6 analog", () => {
    const events = [
      logonEvent({
        sessionHost: "fs-01",
        clientName: "ws-042",
        ip: "169.254.1.1",
        ts: "2026-06-10T12:00:00Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byIp.size).toBe(0);
  });

  it("still admits a ULA (fc00::/7) address as identifying, matching how RFC1918 IPv4 is treated", () => {
    const events = [
      logonEvent({
        sessionHost: "fs-01",
        clientName: "ws-042",
        ip: "fd12:3456::1",
        ts: "2026-06-10T12:00:00Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    const hits = resolveIpAtTime(index, "fd12:3456::1", "2026-06-10T12:00:00Z", 1_000);
    expect(hits).toHaveLength(1);
    expect(hits[0].host).toBe("ws-042");
  });

  it("resolves the client name through a supplied HostAliasIndex, distinct from a differently-spelled input", () => {
    const aliasIndex = buildHostAliasIndex(
      [{ clientId: "C.1", hostname: "ws-042", fqdn: "ws-042.corp.local" }],
      {},
    );
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
    ];
    const index = buildHostBindingIndex(events, aliasIndex);
    const hits = resolveIpAtTime(index, "10.0.0.5", "2026-06-10T12:00:00Z", 1_000);
    // The event names the short spelling; the alias index resolves it to the canonical FQDN, which
    // proves the alias parameter is actually consulted rather than the raw spelling passing through.
    expect(hits[0].host).toBe("ws-042.corp.local");
  });
});

describe("buildHostBindingIndex + resolveAccountAtTime (account -> session host)", () => {
  it("binds an account to the session host on an interactive-family logon (RDP)", () => {
    const events = [
      logonEvent({
        sessionHost: "ws-042",
        accountName: "alice",
        accountDomain: "CORP",
        logonType: 10, // RemoteInteractive/RDP — the account is actually using ws-042
        ts: "2026-06-10T12:00:00Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    const hits = resolveAccountAtTime(index, "CORP\\alice", "2026-06-10T12:00:00Z", 1_000);
    expect(hits).toHaveLength(1);
    expect(hits[0].host).toBe("ws-042");
  });

  it("does NOT bind an account to a file server merely authenticated to over the network (LogonType 3)", () => {
    const events = [
      logonEvent({
        sessionHost: "fs-01",
        accountName: "alice",
        accountDomain: "CORP",
        logonType: 3, // Network — alice accessed a share on fs-01, was never "using" fs-01
        ts: "2026-06-10T12:00:00Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byAccount.size).toBe(0);
  });

  it("returns no candidates for an account never seen in the case", () => {
    const index = buildHostBindingIndex([]);
    expect(resolveAccountAtTime(index, "nobody", "2026-06-10T08:00:00Z", 1_000)).toEqual([]);
  });

  it("excludes machine accounts and well-known non-human principals from the account index", () => {
    const events = [
      logonEvent({ sessionHost: "ws-042", accountName: "WS-042$", logonType: 2, ts: "2026-06-10T12:00:00Z" }),
      logonEvent({ sessionHost: "ws-042", accountName: "SYSTEM", logonType: 2, ts: "2026-06-10T12:00:01Z" }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byAccount.size).toBe(0);
  });

  it("folds account key case and domain shape when resolving", () => {
    const events = [
      logonEvent({
        sessionHost: "ws-042",
        accountName: "Alice",
        accountDomain: "Corp",
        logonType: 2,
        ts: "2026-06-10T12:00:00Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    expect(resolveAccountAtTime(index, "corp\\ALICE", "2026-06-10T12:00:00Z", 1_000)).toHaveLength(1);
  });
});
