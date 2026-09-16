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
  host: string;
  ip?: string;
  accountName?: string;
  accountDomain?: string;
  ts: string;
  outcome?: "success" | "failed";
}): ForensicEvent {
  seq += 1;
  return {
    id: `id-${seq}`,
    timestamp: o.ts,
    description: `Windows Security logon @ ${o.host}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: o.host,
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
      target: { kind: "host", name: o.host },
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
});

describe("canonicalAccount", () => {
  it("keeps domain\\name shape, case-folded", () => {
    expect(canonicalAccount("CORP", "Alice")).toBe("corp\\alice");
  });

  it("is a bare lowercased name with no domain", () => {
    expect(canonicalAccount(undefined, "Alice")).toBe("alice");
  });
});

describe("buildHostBindingIndex + resolveIpAtTime", () => {
  it("builds a binding from a single successful logon", () => {
    const events = [logonEvent({ host: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" })];
    const index = buildHostBindingIndex(events);
    const hits = resolveIpAtTime(index, "10.0.0.5", "2026-06-10T12:00:00Z", 1_000);
    expect(hits).toHaveLength(1);
    expect(hits[0].host).toBe("ws-042");
    expect(hits[0].sourceKind).toBe("logon-sample");
    expect(hits[0].evidenceEventId).toBe(events[0].id);
  });

  it("builds an account -> host binding from the same event", () => {
    const events = [
      logonEvent({ host: "ws-042", accountName: "alice", accountDomain: "CORP", ts: "2026-06-10T12:00:00Z" }),
    ];
    const index = buildHostBindingIndex(events);
    const hits = resolveAccountAtTime(index, "CORP\\alice", "2026-06-10T12:00:00Z", 1_000);
    expect(hits).toHaveLength(1);
    expect(hits[0].host).toBe("ws-042");
  });

  it("surfaces both hosts when one IP was bound to two hosts in non-overlapping windows", () => {
    const events = [
      logonEvent({ host: "ws-001", ip: "10.0.0.9", ts: "2026-06-10T08:00:00Z" }),
      logonEvent({ host: "ws-002", ip: "10.0.0.9", ts: "2026-06-10T20:00:00Z" }),
    ];
    const index = buildHostBindingIndex(events);

    const both = resolveIpAtTime(index, "10.0.0.9", "2026-06-10T14:00:00Z", 6 * 3_600_000);
    expect(both.map((b) => b.host).sort()).toEqual(["ws-001", "ws-002"]);

    const onlyEarly = resolveIpAtTime(index, "10.0.0.9", "2026-06-10T08:00:00Z", 1_000);
    expect(onlyEarly.map((b) => b.host)).toEqual(["ws-001"]);
  });

  it("returns no candidates for an IP or account never seen in the case", () => {
    const index = buildHostBindingIndex([]);
    expect(resolveIpAtTime(index, "10.0.0.9", "2026-06-10T08:00:00Z", 1_000)).toEqual([]);
    expect(resolveAccountAtTime(index, "nobody", "2026-06-10T08:00:00Z", 1_000)).toEqual([]);
  });

  it("excludes a failed logon (4625-shaped: outcome failed)", () => {
    const events = [
      logonEvent({ host: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z", outcome: "failed" }),
    ];
    const index = buildHostBindingIndex(events);
    expect(resolveIpAtTime(index, "10.0.0.5", "2026-06-10T12:00:00Z", 1_000)).toEqual([]);
  });

  it("excludes loopback / no-network IP values from the IP index", () => {
    const events = [
      logonEvent({ host: "ws-042", ip: "-", ts: "2026-06-10T12:00:00Z" }),
      logonEvent({ host: "ws-042", ip: "::1", ts: "2026-06-10T12:00:01Z" }),
      logonEvent({ host: "ws-042", ip: "127.0.0.1", ts: "2026-06-10T12:00:02Z" }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byIp.size).toBe(0);
  });

  it("excludes machine accounts and well-known non-human principals from the account index", () => {
    const events = [
      logonEvent({ host: "ws-042", accountName: "WS-042$", ts: "2026-06-10T12:00:00Z" }),
      logonEvent({ host: "ws-042", accountName: "SYSTEM", ts: "2026-06-10T12:00:01Z" }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byAccount.size).toBe(0);
  });

  it("resolves the canonical host through a supplied HostAliasIndex", () => {
    const aliasIndex = buildHostAliasIndex(
      [{ clientId: "C.1", hostname: "ws-042", fqdn: "ws-042.corp.local" }],
      {},
    );
    const events = [logonEvent({ host: "ws-042.corp.local", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" })];
    const index = buildHostBindingIndex(events, aliasIndex);
    const hits = resolveIpAtTime(index, "10.0.0.5", "2026-06-10T12:00:00Z", 1_000);
    expect(hits[0].host).toBe("ws-042.corp.local");
  });

  it("folds account key case and domain shape when resolving", () => {
    const events = [
      logonEvent({ host: "ws-042", accountName: "Alice", accountDomain: "Corp", ts: "2026-06-10T12:00:00Z" }),
    ];
    const index = buildHostBindingIndex(events);
    expect(resolveAccountAtTime(index, "corp\\ALICE", "2026-06-10T12:00:00Z", 1_000)).toHaveLength(1);
  });
});
