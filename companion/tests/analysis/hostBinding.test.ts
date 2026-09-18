import { describe, it, expect } from "vitest";
import { createCanonicalEvent, upgradeForensicEvent } from "../../src/analysis/canonicalEvent.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";
import {
  buildHostBindingIndex,
  canonicalAccount,
  canonicalIp,
  resolveAccountAtTime,
  resolveIpAtTime,
  type IpExclusionReason,
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
  /** #1292: omit the `provenance: "edge-observed"` stamp — the shape a writer outside #1184's
   * audited allowlist would produce. The default stamps it, matching every real 4624 writer. */
  unprovenanced?: boolean;
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
      ...(o.ip
        ? {
            network: {
              source: { address: o.ip, ...(o.unprovenanced ? {} : { provenance: "edge-observed" as const }) },
            },
          }
        : {}),
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

  // #1246: the admission gate (hasNoDomain) already treated '-'/'*' as absent, but the index KEY
  // still spelled it out ("-\\alice") — a domain a caller would never query, making the binding
  // unreachable. Both must fold the same placeholder convention.
  it("folds a placeholder domain ('-' or '*') to a bare name, same as an absent domain", () => {
    expect(canonicalAccount("-", "Alice")).toBe("alice");
    expect(canonicalAccount("*", "Alice")).toBe("alice");
    expect(canonicalAccount("-", "Alice")).toBe(canonicalAccount(undefined, "Alice"));
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

  // #1236: buildHostBindingIndex had zero exclusion observability — no way for an analyst to tell
  // "no logon evidence existed" from "evidence existed but was policy-excluded". The optional
  // `excluded` sink counts by reason without changing the return shape or any existing caller.
  it("counts policy-excluded IPs by reason in the optional excluded sink, when one is given", () => {
    const events = [
      logonEvent({ sessionHost: "ws-042", clientName: "ws-042", ip: "-", ts: "2026-06-10T12:00:00Z" }),
      logonEvent({
        sessionHost: "ws-042",
        clientName: "ws-042",
        ip: "127.0.0.5",
        ts: "2026-06-10T12:00:01Z",
      }),
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "fe80::1", ts: "2026-06-10T12:00:02Z" }),
      logonEvent({
        sessionHost: "fs-01",
        clientName: "ws-042",
        ip: "169.254.1.1",
        ts: "2026-06-10T12:00:03Z",
      }),
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T12:00:04Z" }),
    ];
    const excluded = new Map<IpExclusionReason, number>();
    buildHostBindingIndex(events, undefined, excluded);
    expect(Object.fromEntries(excluded)).toEqual({
      placeholder: 1,
      "loopback-v4": 1,
      "link-local-v6": 1,
      "link-local-v4": 1,
    });
  });

  it("never touches the excluded sink for an identifying IP, and costs nothing when no sink is given", () => {
    const events = [
      logonEvent({ sessionHost: "fs-01", clientName: "ws-042", ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
    ];
    const excluded = new Map<IpExclusionReason, number>();
    buildHostBindingIndex(events, undefined, excluded);
    expect(excluded.size).toBe(0);
    expect(() => buildHostBindingIndex(events)).not.toThrow();
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

  // #1246: an accountDomain of '-' admits as human (hasNoDomain) but must ALSO key the index under
  // the bare name, not "-\\alice" — otherwise resolveAccountAtTime("alice", ...) would never find it.
  it("indexes an account with a placeholder ('-') domain under the bare name, reachable by it", () => {
    const events = [
      logonEvent({
        sessionHost: "ws-042",
        accountName: "alice",
        accountDomain: "-",
        logonType: 10,
        ts: "2026-06-10T12:00:00Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    const hits = resolveAccountAtTime(index, "alice", "2026-06-10T12:00:00Z", 1_000);
    expect(hits).toHaveLength(1);
    expect(hits[0].host).toBe("ws-042");
  });

  // #1253: a UPN-form account.name (winAccountRoles.ts's entity() now sets domain to the
  // separately-recorded real domain, but name stays the raw UPN) must still be reachable by the
  // domain\user spelling a same-session 4624 binding elsewhere would produce, not stay keyed under
  // its own un-split realm\user@realm form.
  it("indexes a UPN-form account.name under the bare local part, reachable by domain\\user", () => {
    const events = [
      logonEvent({
        sessionHost: "ws-042",
        accountName: "jdoe@corp.com",
        accountDomain: "CORP",
        logonType: 10,
        ts: "2026-06-10T12:00:00Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    const hits = resolveAccountAtTime(index, "CORP\\jdoe", "2026-06-10T12:00:00Z", 1_000);
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

  it("excludes an un-domained built-in local account (Administrator/Guest) from the account index", () => {
    const events = [
      logonEvent({
        sessionHost: "ws-042",
        accountName: "Administrator",
        logonType: 2,
        ts: "2026-06-10T12:00:00Z",
      }),
      logonEvent({ sessionHost: "ws-043", accountName: "Guest", logonType: 2, ts: "2026-06-10T12:00:01Z" }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byAccount.size).toBe(0);
  });

  it("also excludes an Administrator logon whose domain is a placeholder ('-' or '*'), not just absent", () => {
    const events = [
      logonEvent({
        sessionHost: "ws-042",
        accountName: "Administrator",
        accountDomain: "-",
        logonType: 2,
        ts: "2026-06-10T12:00:00Z",
      }),
      logonEvent({
        sessionHost: "ws-043",
        accountName: "Administrator",
        accountDomain: "*",
        logonType: 2,
        ts: "2026-06-10T12:00:01Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byAccount.size).toBe(0);
  });

  it("excludes localized Administrator/Guest names and the non-localized DefaultAccount/WDAGUtilityAccount built-ins", () => {
    const events = [
      logonEvent({
        sessionHost: "ws-042",
        accountName: "Administrateur",
        logonType: 2,
        ts: "2026-06-10T12:00:00Z",
      }),
      logonEvent({ sessionHost: "ws-043", accountName: "Gast", logonType: 2, ts: "2026-06-10T12:00:01Z" }),
      logonEvent({
        sessionHost: "ws-044",
        accountName: "Administrador",
        logonType: 2,
        ts: "2026-06-10T12:00:02Z",
      }),
      logonEvent({
        sessionHost: "ws-045",
        accountName: "DefaultAccount",
        logonType: 2,
        ts: "2026-06-10T12:00:03Z",
      }),
      logonEvent({
        sessionHost: "ws-046",
        accountName: "WDAGUtilityAccount",
        logonType: 2,
        ts: "2026-06-10T12:00:04Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byAccount.size).toBe(0);
  });

  it("still admits a DOMAINED Administrator account as identifying (a specific domain principal)", () => {
    const events = [
      logonEvent({
        sessionHost: "ws-042",
        accountName: "Administrator",
        accountDomain: "CORP",
        logonType: 2,
        ts: "2026-06-10T12:00:00Z",
      }),
    ];
    const index = buildHostBindingIndex(events);
    expect(resolveAccountAtTime(index, "corp\\administrator", "2026-06-10T12:00:00Z", 1_000)).toHaveLength(1);
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

  it("does not double the domain prefix when account.name already carries it (the real winAccountRoles.ts / legacy-upgrade shape)", () => {
    // winAccountRoles.ts's own entity() and this module's own legacy-prose upgrade both put the
    // FULL "domain\name" string into account.name AND repeat the domain in account.domain — the
    // shape logonEvent()'s own test helper above never simulates (it always passes a bare name).
    const events: ForensicEvent[] = [
      {
        id: "id-domain-prefixed",
        timestamp: "2026-06-10T12:00:00Z",
        description: "Windows Security logon @ ws-042",
        severity: "Low",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        asset: "ws-042",
        canonical: createCanonicalEvent({
          event: { category: "authentication", type: "logon", outcome: "success" },
          actor: { kind: "account", name: "CORP\\jdoe", domain: "CORP" },
          account: { name: "CORP\\jdoe", domain: "CORP" },
          target: { kind: "host", name: "ws-042" },
          authentication: { logonType: 2 },
          time: { observed: "2026-06-10T12:00:00Z", normalized: "2026-06-10T12:00:00Z" },
          evidence: { rawRecords: [{ source: "test", locator: "row:domain-prefixed" }] },
          producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
        }),
      },
    ];
    const index = buildHostBindingIndex(events);
    expect([...index.byAccount.keys()]).toEqual(["corp\\jdoe"]);
    expect(resolveAccountAtTime(index, "corp\\jdoe", "2026-06-10T12:00:00Z", 1_000)).toHaveLength(1);
  });

  it("keeps a domain-qualified account.name intact when NO separate domain field confirms it (e.g. ecarImport.ts's raw, unprocessed principal field)", () => {
    const events: ForensicEvent[] = [
      {
        id: "id-qualified-no-domain-field",
        timestamp: "2026-06-10T12:00:00Z",
        description: "EDR logon @ ws-042",
        severity: "Low",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        asset: "ws-042",
        canonical: createCanonicalEvent({
          event: { category: "authentication", type: "logon", outcome: "success" },
          actor: { kind: "account", name: "CORP\\jdoe" },
          account: { name: "CORP\\jdoe" }, // no domain field — the whole string IS the only identity
          target: { kind: "host", name: "ws-042" },
          authentication: { logonType: 2 },
          time: { observed: "2026-06-10T12:00:00Z", normalized: "2026-06-10T12:00:00Z" },
          evidence: { rawRecords: [{ source: "test", locator: "row:qualified-no-domain" }] },
          producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
        }),
      },
    ];
    const index = buildHostBindingIndex(events);
    // Stripping here would collapse to bare "jdoe", discarding the only copy of the domain and
    // risking a collision with an unrelated un-domained local "jdoe" on another host.
    expect([...index.byAccount.keys()]).toEqual(["corp\\jdoe"]);
  });

  it("still recognizes NT AUTHORITY\\SYSTEM as non-human when account.name is domain-prefixed", () => {
    const events: ForensicEvent[] = [
      {
        id: "id-system-domained",
        timestamp: "2026-06-10T12:00:00Z",
        description: "Windows Security logon @ ws-042",
        severity: "Low",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        asset: "ws-042",
        canonical: createCanonicalEvent({
          event: { category: "authentication", type: "logon", outcome: "success" },
          actor: { kind: "account", name: "NT AUTHORITY\\SYSTEM", domain: "NT AUTHORITY" },
          account: { name: "NT AUTHORITY\\SYSTEM", domain: "NT AUTHORITY" },
          target: { kind: "host", name: "ws-042" },
          authentication: { logonType: 2 },
          time: { observed: "2026-06-10T12:00:00Z", normalized: "2026-06-10T12:00:00Z" },
          evidence: { rawRecords: [{ source: "test", locator: "row:system-domained" }] },
          producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
        }),
      },
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byAccount.size).toBe(0);
  });
});

// #1162: buildHostBindingIndex silently skips any event with no canonical envelope. stateStore.ts's
// own load-time upgrade behavior (mapping upgradeForensicEvent over the forensic timeline before
// any consumer sees it) is already independently pinned by
// tests/analysis/stateStore.test.ts's own "upgrades legacy timeline rows on load" test — this test
// does not re-prove that seam. What it DOES pin is the module-boundary contract this file is
// otherwise silent on: given an already-upgraded legacy, prose-only event (the shape stateStore.ts
// guarantees every consumer receives), buildHostBindingIndex produces real bindings through the
// actual prose-parsing path, not just through a hand-built envelope like every test above.
describe("buildHostBindingIndex through the legacy prose-upgrade path (#1162)", () => {
  it("binds IP -> client host and account -> session host from a legacy, envelope-less event", () => {
    const legacy: ForensicEvent = {
      id: "legacy-1",
      timestamp: "2026-07-30T10:00:00Z",
      description:
        "Windows Security Successful logon (EID 4624) - CORP\\jdoe - LogonType=3 - " +
        "IpAddress=10.0.0.5 - WorkstationName=WS-042 @ SRV-01 [Network]",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "SRV-01",
    };
    // The 4624 above is LogonType 3 (Network), which does not qualify for account -> host
    // presence (see ACCOUNT_PRESENCE_LOGON_TYPES) — a second, interactive-family legacy event
    // proves that half of the contract too.
    const legacyInteractive: ForensicEvent = {
      id: "legacy-2",
      timestamp: "2026-07-30T10:05:00Z",
      description: "Windows Security Successful logon (EID 4624) - CORP\\jdoe - LogonType=2 @ WS-042",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "WS-042",
    };

    expect(legacy.canonical).toBeUndefined();
    const upgraded = [legacy, legacyInteractive].map(upgradeForensicEvent);
    expect(upgraded[0].canonical).toBeDefined();

    const index = buildHostBindingIndex(upgraded);
    const ipHits = resolveIpAtTime(index, "10.0.0.5", "2026-07-30T10:00:00Z", 1_000);
    expect(ipHits).toHaveLength(1);
    expect(ipHits[0].host).toBe("WS-042");

    const accountHits = resolveAccountAtTime(index, "corp\\jdoe", "2026-07-30T10:05:00Z", 1_000);
    expect(accountHits).toHaveLength(1);
    expect(accountHits[0].host).toBe("WS-042");
  });
});

// #1292: #1265 made proxyWorkstationChain.ts's READER of network.source.address fail closed on the
// `provenance: "edge-observed"` stamp, but the INDEX that reader (and five other consumers)
// resolves against was still built from any address at all. A future writer stamping the field
// from a client-forgeable header without being audited into the allowlist would have poisoned every
// consumer at once. The index now mirrors the reader: no stamp, no IP binding — the account -> host
// half is untouched, exactly as the reader nulls only the address and never the account.
describe("buildHostBindingIndex requires the edge-observed provenance stamp (#1292)", () => {
  it("does not bind IP -> host from an address with no provenance stamp", () => {
    const events = [
      logonEvent({
        sessionHost: "SRV-01",
        clientName: "WS-042",
        ip: "10.0.0.5",
        ts: "2026-07-30T10:00:00Z",
        unprovenanced: true,
      }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byIp.size).toBe(0);
    expect(resolveIpAtTime(index, "10.0.0.5", "2026-07-30T10:00:00Z", 1_000)).toEqual([]);
  });

  it("still binds IP -> host from a stamped address (every real 4624 writer stamps it)", () => {
    const events = [
      logonEvent({ sessionHost: "SRV-01", clientName: "WS-042", ip: "10.0.0.5", ts: "2026-07-30T10:00:00Z" }),
    ];
    const hits = resolveIpAtTime(buildHostBindingIndex(events), "10.0.0.5", "2026-07-30T10:00:00Z", 1_000);
    expect(hits).toHaveLength(1);
    expect(hits[0].host).toBe("WS-042");
  });

  it("nulls only the address: account -> host still binds from an unstamped event", () => {
    const events = [
      logonEvent({
        sessionHost: "WS-042",
        accountName: "jdoe",
        accountDomain: "CORP",
        logonType: 2,
        ip: "10.0.0.5",
        ts: "2026-07-30T10:00:00Z",
        unprovenanced: true,
      }),
    ];
    const index = buildHostBindingIndex(events);
    expect(index.byIp.size).toBe(0);
    const hits = resolveAccountAtTime(index, "corp\\jdoe", "2026-07-30T10:00:00Z", 1_000);
    expect(hits).toHaveLength(1);
    expect(hits[0].host).toBe("WS-042");
  });

  it("counts the unstamped address in the excluded sink as its own reason, so the gate is observable", () => {
    const events = [
      logonEvent({
        sessionHost: "SRV-01",
        clientName: "WS-042",
        ip: "10.0.0.5",
        ts: "2026-07-30T10:00:00Z",
        unprovenanced: true,
      }),
      logonEvent({ sessionHost: "SRV-01", clientName: "WS-043", ip: "10.0.0.6", ts: "2026-07-30T10:01:00Z" }),
    ];
    const excluded = new Map<IpExclusionReason, number>();
    const index = buildHostBindingIndex(events, undefined, excluded);
    expect(excluded.get("not-edge-observed")).toBe(1);
    expect(index.byIp.size).toBe(1);
  });
});
