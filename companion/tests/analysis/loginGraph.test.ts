import { describe, it, expect } from "vitest";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  parseLoginEvent, displayAccountName, isNoiseAccount,
  buildLoginGraph, loginEdgeEvents, DEFAULT_MAX_EDGES,
} from "../../src/analysis/loginGraph.js";

// Minimal ForensicEvent factory — only description/asset/timestamp vary per test.
export const ev = (over: Partial<ForensicEvent> & { description: string }): ForensicEvent => ({
  id: over.id ?? `id-${Math.abs(hash(over.description))}`,
  timestamp: "2026-06-10T12:00:00Z",
  severity: "Low",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});
function hash(s: string): number { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0; return h; }

const LOGON = (acct: string, host: string, type: number, o: { failed?: boolean; ip?: string; count?: number; ts?: string; endTs?: string } = {}) =>
  ev({
    description: `Windows Security ${o.failed ? "Failed logon (EID 4625)" : "Successful logon (EID 4624)"} - ${acct} - LogonType=${type}${o.ip ? ` - IpAddress=${o.ip}` : ""} @ ${host}`,
    asset: host,
    ...(o.count ? { count: o.count } : {}),
    ...(o.ts ? { timestamp: o.ts } : {}),
    ...(o.endTs ? { endTimestamp: o.endTs } : {}),
    id: `id-${Math.random().toString(36).slice(2)}`,
  });

describe("parseLoginEvent", () => {
  it("parses a successful domain-account logon with type, source ip and workstation", () => {
    const p = parseLoginEvent(ev({
      description: "Windows Security Successful logon (EID 4624) - CORP\\jdoe - LogonType=10 - IpAddress=203.0.113.7 - WorkstationName=WKSTN-02 @ SRV-01 [RemoteInteractive/RDP from 203.0.113.7]",
      asset: "SRV-01",
    }));
    expect(p).toEqual({
      account: "CORP\\jdoe", host: "SRV-01", logonType: 10,
      typeName: "RemoteInteractive/RDP", outcome: "success",
      sourceIp: "203.0.113.7", workstation: "WKSTN-02",
    });
  });

  it("parses a failed logon (4625) as outcome failed", () => {
    const p = parseLoginEvent(ev({
      description: "Windows Security Failed logon (EID 4625) - CORP\\admin - LogonType=3 - IpAddress=10.0.0.9 @ DC-01",
      asset: "DC-01",
    }));
    expect(p?.outcome).toBe("failed");
    expect(p?.typeName).toBe("Network");
  });

  it("parses NT AUTHORITY pseudo-accounts (space in domain)", () => {
    const p = parseLoginEvent(ev({
      description: "Windows Security Successful logon (EID 4624) - NT AUTHORITY\\SYSTEM - LogonType=5 @ WKSTN-01",
      asset: "WKSTN-01",
    }));
    expect(p?.account).toBe("NT AUTHORITY\\SYSTEM");
    expect(p?.typeName).toBe("Service");
  });

  it("takes the FIRST account (the logon target) when subject account is also rendered", () => {
    const p = parseLoginEvent(ev({
      description: "Windows Security Successful logon (EID 4624) - CORP\\jdoe, CORP\\WKSTN-02$ - LogonType=3 @ SRV-01",
      asset: "SRV-01",
    }));
    expect(p?.account).toBe("CORP\\jdoe");
  });

  it("decodes an unknown numeric logon type as `type N` and a missing one as Unknown", () => {
    const withNum = parseLoginEvent(ev({
      description: "Windows Security Successful logon (EID 4624) - CORP\\jdoe - LogonType=13 @ SRV-01", asset: "SRV-01",
    }));
    expect(withNum?.typeName).toBe("type 13");
    const noType = parseLoginEvent(ev({
      description: "Windows Security Successful logon (EID 4624) - CORP\\jdoe @ SRV-01", asset: "SRV-01",
    }));
    expect(noType?.typeName).toBe("Unknown");
  });

  it("rejects a marker embedded in a field value (log-content injection)", () => {
    expect(parseLoginEvent(ev({
      description: "Sysmon Process create (EID 1) - CommandLine=echo Successful logon (EID 4624) - EVIL\\fake @ x - Image=C:\\evil.exe @ HOST1",
      asset: "HOST1",
    }))).toBeNull();
  });

  it("returns null for: non-logon rows, rows with no account segment, rows with no asset", () => {
    expect(parseLoginEvent(ev({ description: "Sysmon Process create (EID 1) - CommandLine=cmd.exe @ H1", asset: "H1" }))).toBeNull();
    expect(parseLoginEvent(ev({ description: "Windows Security Successful logon (EID 4624) - LogonType=3 @ H1", asset: "H1" }))).toBeNull();
    expect(parseLoginEvent(ev({ description: "Windows Security Successful logon (EID 4624) - CORP\\jdoe - LogonType=3" }))).toBeNull();
  });
});

describe("displayAccountName", () => {
  it("shortens service domains, keeps real domains", () => {
    expect(displayAccountName("NT AUTHORITY\\SYSTEM")).toBe("SYSTEM");
    expect(displayAccountName("Window Manager\\DWM-1")).toBe("DWM-1");
    expect(displayAccountName("Font Driver Host\\UMFD-0")).toBe("UMFD-0");
    expect(displayAccountName("CORP\\jdoe")).toBe("CORP\\jdoe");
    expect(displayAccountName("jdoe@corp.example")).toBe("jdoe@corp.example");
  });
});

describe("isNoiseAccount", () => {
  it("flags machine accounts, window-manager accounts and ANONYMOUS LOGON", () => {
    expect(isNoiseAccount("CORP\\WKSTN-01$")).toBe(true);
    expect(isNoiseAccount("Window Manager\\DWM-1")).toBe(true);
    expect(isNoiseAccount("Font Driver Host\\UMFD-0")).toBe(true);
    expect(isNoiseAccount("NT AUTHORITY\\ANONYMOUS LOGON")).toBe(true);
    expect(isNoiseAccount("NT AUTHORITY\\SYSTEM")).toBe(false);   // meaningful, not noise
    expect(isNoiseAccount("CORP\\jdoe")).toBe(false);
  });
});

describe("buildLoginGraph", () => {
  it("aggregates edges by (account, host, type, outcome), summing row counts", () => {
    const g = buildLoginGraph([
      LOGON("CORP\\jdoe", "SRV-01", 2, { ts: "2026-06-10T12:00:00Z" }),
      LOGON("CORP\\jdoe", "SRV-01", 2, { count: 3, ts: "2026-06-11T09:00:00Z", endTs: "2026-06-11T10:00:00Z" }),
      LOGON("CORP\\jdoe", "SRV-01", 3, {}),                     // different type → separate edge
      LOGON("CORP\\jdoe", "SRV-01", 3, { failed: true }),       // failed → separate edge
    ]);
    expect(g.nodes.map((n) => n.id).sort()).toEqual(["account:corp\\jdoe", "host:srv-01"]);
    expect(g.edges).toHaveLength(3);
    const interactive = g.edges.find((e) => e.logonType === "Interactive");
    expect(interactive).toMatchObject({
      source: "account:corp\\jdoe", target: "host:srv-01", outcome: "success",
      count: 4, firstSeen: "2026-06-10T12:00:00Z", lastSeen: "2026-06-11T10:00:00Z",
    });
    expect(g.edges.find((e) => e.outcome === "failed")?.count).toBe(1);
  });

  it("directs edges account → host and separates account/host namespaces", () => {
    const g = buildLoginGraph([LOGON("NT AUTHORITY\\SYSTEM", "WKSTN-01", 5)]);
    const acct = g.nodes.find((n) => n.type === "account");
    const host = g.nodes.find((n) => n.type === "host");
    expect(acct).toMatchObject({ id: "account:nt authority\\system", name: "SYSTEM", isNoise: false });
    expect(host).toMatchObject({ id: "host:wkstn-01", name: "WKSTN-01" });
    expect(g.edges[0]).toMatchObject({ source: acct!.id, target: host!.id });
  });

  it("grades edge risk via logonRisk: external RDP medium, internal RDP none", () => {
    const g = buildLoginGraph([
      LOGON("CORP\\a", "SRV-01", 10, { ip: "203.0.113.7" }),
      LOGON("CORP\\b", "SRV-01", 10, { ip: "10.0.0.5" }),
    ]);
    expect(g.edges.find((e) => e.source === "account:corp\\a")?.risk).toBe("medium");
    expect(g.edges.find((e) => e.source === "account:corp\\b")?.risk).toBe("none");
  });

  it("flags noise account nodes", () => {
    const g = buildLoginGraph([LOGON("CORP\\WKSTN-01$", "DC-01", 3)]);
    expect(g.nodes.find((n) => n.type === "account")?.isNoise).toBe(true);
  });

  it("caps at maxEdges by count, reports totals, drops orphaned nodes — no silent truncation", () => {
    const rows = [
      LOGON("CORP\\a", "H1", 2, { count: 9 }),
      LOGON("CORP\\b", "H2", 2, { count: 5 }),
      LOGON("CORP\\c", "H3", 2, { count: 1 }),
    ];
    const g = buildLoginGraph(rows, 2);
    expect(g.edges).toHaveLength(2);
    expect(g.totalEdges).toBe(3);
    expect(g.truncated).toBe(true);
    expect(g.edges.map((e) => e.count)).toEqual([9, 5]);           // kept the busiest
    expect(g.nodes.some((n) => n.id === "account:corp\\c")).toBe(false);   // orphan dropped
    const full = buildLoginGraph(rows);
    expect(full.truncated).toBe(false);
    expect(DEFAULT_MAX_EDGES).toBe(500);
  });

  it("skips non-logon and malformed rows silently", () => {
    const g = buildLoginGraph([
      ev({ description: "Sysmon Network connection (EID 3) - DestinationIp=1.2.3.4 @ H1", asset: "H1" }),
      LOGON("CORP\\jdoe", "SRV-01", 2),
    ]);
    expect(g.edges).toHaveLength(1);
  });
});

describe("loginEdgeEvents", () => {
  it("returns the events behind one edge, honoring limit, with total", () => {
    const rows = [
      LOGON("CORP\\jdoe", "SRV-01", 2, { ip: "10.0.0.5", ts: "2026-06-10T12:00:00Z" }),
      LOGON("CORP\\jdoe", "SRV-01", 2, { ts: "2026-06-09T08:00:00Z" }),
      LOGON("CORP\\jdoe", "SRV-01", 3, {}),                    // different type — excluded
      LOGON("CORP\\other", "SRV-01", 2, {}),                   // different account — excluded
    ];
    const r = loginEdgeEvents(rows, { account: "corp\\jdoe", host: "srv-01", type: "Interactive", outcome: "success", limit: 1 });
    expect(r.total).toBe(2);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].timestamp).toBe("2026-06-09T08:00:00Z");  // sorted ascending
    expect(r.events[0]).toHaveProperty("id");
    expect(r.events[0]).toHaveProperty("description");
  });
});
