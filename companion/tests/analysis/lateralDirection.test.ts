import { describe, it, expect } from "vitest";
import { buildEvidenceGraph, buildLateralPaths } from "../../src/analysis/evidenceGraph.js";
import { buildSharedHostLinks } from "../../src/analysis/sharedHostLinks.js";
import { createCanonicalEvent } from "../../src/analysis/canonicalEvent.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #3085: lateral-movement paths are built from DIRECTION evidence the target recorded (a network
// logon naming its source, a remote-execution service installed on it), never from two hosts merely
// sharing a binary or an account. Synthetic hosts and TEST-NET addresses only.

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "",
    description: "",
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const T = (hhmm: string) => `2026-05-20T${hhmm}:00Z`;

// A 4624 in the exact mapWindows legacy shape the canonical upgrader reads (IpAddress= is stamped
// edge-observed, WorkstationName= becomes the session terminal).
function logon(
  id: string,
  target: string,
  at: string,
  o: { ws?: string; ip?: string; account?: string; type?: number; failed?: boolean } = {},
): ForensicEvent {
  const parts = [
    `Windows Security ${o.failed ? "Failed" : "Successful"} logon (EID ${o.failed ? 4625 : 4624})`,
    o.account ?? "CORP\\opsuser",
    `LogonType=${o.type ?? 3}`,
    ...(o.ip ? [`IpAddress=${o.ip}`] : []),
    ...(o.ws ? [`WorkstationName=${o.ws}`] : []),
  ];
  return ev({
    id,
    asset: target,
    timestamp: T(at),
    description: `${parts.join(" - ")} @ ${target} [Network]`,
  });
}

function serviceInstall(
  id: string,
  host: string,
  at: string,
  name = "PSEXESVC",
  source?: { hostname?: string; address?: string },
): ForensicEvent {
  return ev({
    id,
    asset: host,
    severity: "Medium",
    timestamp: T(at),
    description: "service installed",
    canonical: createCanonicalEvent({
      event: { category: "service", type: "service" },
      target: { kind: "host", name: host },
      service: { name, executable: `%SystemRoot%\\${name}.exe` },
      ...(source ? { network: { source: { ...source, provenance: "edge-observed" as const } } } : {}),
      time: { observed: T(at), normalized: T(at) },
      evidence: { rawRecords: [{ source: "test", locator: `row:${id}` }] },
      producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
    }),
  });
}

// Any event that makes `host` a host the case knows.
const seen = (id: string, host: string, at = "07:00") =>
  ev({ id, asset: host, timestamp: T(at), description: "PsExec.exe started", processName: "PsExec.exe" });

function caseOf(...events: ForensicEvent[]): InvestigationState {
  const s = emptyState("c1");
  s.forensicTimeline.push(...events);
  return s;
}

const routes = (s: InvestigationState) => buildLateralPaths(s).map((p) => p.hostIds.join(" > "));
const hopPairs = (s: InvestigationState) =>
  buildLateralPaths(s).flatMap((p) => p.hops.map((h) => `${h.from} > ${h.to}`));

describe("directed lateral hops — the issue's fan-out (#3085)", () => {
  // The repro from the issue: the source runs PsExec.exe; each target logs a PSEXESVC install and a
  // type-3 logon from the source; no account is shared.
  const fanOut = () =>
    caseOf(
      seen("src", "HOST-SRC"),
      logon("la", "HOST-A", "08:00", { ws: "HOST-SRC", ip: "192.0.2.10", account: "CORP\\alpha" }),
      serviceInstall("sa", "HOST-A", "08:01"),
      logon("lb", "HOST-B", "08:30", { ws: "HOST-SRC", ip: "192.0.2.10", account: "CORP\\bravo" }),
      serviceInstall("sb", "HOST-B", "08:31"),
    );

  it("draws SRC → A and SRC → B as separate hops, never A → B", () => {
    const s = fanOut();
    expect(routes(s).sort()).toEqual(["host:host-src > host:host-a", "host:host-src > host:host-b"]);
    expect(hopPairs(s)).not.toContain("host:host-a > host:host-b");
    expect(hopPairs(s)).not.toContain("host:host-b > host:host-a");
  });

  it("names the remote service, grades it high, and cites the target's records", () => {
    const hop = buildLateralPaths(fanOut()).find((p) => p.hostIds[1] === "host:host-a")!.hops[0];
    expect(hop).toMatchObject({
      rule: "remote-service",
      confidence: "high",
      actor: "PSEXESVC.exe",
      actorKind: "binary",
    });
    expect(hop.eventIds).toEqual(expect.arrayContaining(["la", "sa"]));
    expect(hop.fromTimestamp).toBe(T("08:00"));
    expect(hop.toTimestamp).toBe(T("08:00"));
  });

  it("keeps a shared account as a link between the targets, not a hop", () => {
    const s = caseOf(
      seen("src", "HOST-SRC"),
      logon("la", "HOST-A", "08:00", { ws: "HOST-SRC", account: "CORP\\shared" }),
      logon("lb", "HOST-B", "08:30", { ws: "HOST-SRC", account: "CORP\\shared" }),
    );
    expect(hopPairs(s)).not.toContain("host:host-a > host:host-b");
    const link = buildSharedHostLinks(s).find((l) => l.actor === "CORP\\shared")!;
    expect(link.actorKind).toBe("account");
    expect(link.hostIds).toEqual(["host:host-a", "host:host-b"]);
  });

  it("puts directed edges in the evidence graph and marks shared links undirected", () => {
    const s = fanOut();
    s.forensicTimeline.push(
      ev({
        id: "h1",
        asset: "HOST-A",
        sha256: "ab".repeat(32),
        path: "D:\\drop\\tool.exe",
        timestamp: T("09:00"),
      }),
      ev({
        id: "h2",
        asset: "HOST-B",
        sha256: "ab".repeat(32),
        path: "D:\\drop\\tool.exe",
        timestamp: T("09:05"),
      }),
    );
    const lateral = buildEvidenceGraph(s).edges.filter((e) => e.type === "lateral_move");
    const directed = lateral.filter((e) => !e.undirected);
    expect(directed.map((e) => `${e.source} > ${e.target}`).sort()).toEqual([
      "host:host-src > host:host-a",
      "host:host-src > host:host-b",
    ]);
    expect(directed.every((e) => e.rule === "remote-service" && e.confidence === "high")).toBe(true);
    const shared = lateral.filter((e) => e.rule === "shared-hash");
    expect(shared.length).toBeGreaterThan(0);
    expect(shared.every((e) => e.undirected === true)).toBe(true);
  });
});

describe("directed lateral hops — resolving the source host", () => {
  it("resolves a source IP through a record that pairs it with a workstation name", () => {
    const s = caseOf(
      seen("src", "HOST-SRC"),
      // A logon elsewhere states 192.0.2.10 was HOST-SRC (RDP, so not itself a hop).
      logon("bind", "HOST-X", "07:50", { ws: "HOST-SRC", ip: "192.0.2.10", type: 10 }),
      logon("la", "HOST-A", "08:00", { ip: "192.0.2.10" }),
    );
    const hop = buildLateralPaths(s)[0].hops[0];
    expect([hop.from, hop.to, hop.rule, hop.confidence]).toEqual([
      "host:host-src",
      "host:host-a",
      "network-logon",
      "medium",
    ]);
    expect(hop.eventIds).toEqual(["la", "bind"]);
  });

  it("draws no hop when nothing pairs the source IP with a host", () => {
    expect(
      routes(caseOf(seen("src", "HOST-SRC"), logon("la", "HOST-A", "08:00", { ip: "192.0.2.10" }))),
    ).toEqual([]);
  });

  it("draws no hop when the IP is bound to two hosts", () => {
    const s = caseOf(
      seen("s1", "HOST-SRC"),
      seen("s2", "HOST-OTHER"),
      logon("b1", "HOST-X", "07:50", { ws: "HOST-SRC", ip: "192.0.2.10", type: 10 }),
      logon("b2", "HOST-X", "08:10", { ws: "HOST-OTHER", ip: "192.0.2.10", type: 10 }),
      logon("la", "HOST-A", "08:00", { ip: "192.0.2.10" }),
    );
    expect(routes(s)).toEqual([]);
  });

  it("draws no hop when the IP is bound to a machine the case does not know", () => {
    const s = caseOf(
      seen("s1", "HOST-SRC"),
      logon("b1", "HOST-X", "07:50", { ws: "HOST-SRC", ip: "192.0.2.10", type: 10 }),
      logon("b2", "HOST-X", "08:10", { ws: "UNKNOWN-PC", ip: "192.0.2.10", type: 10 }),
      logon("la", "HOST-A", "08:00", { ip: "192.0.2.10" }),
    );
    expect(routes(s)).toEqual([]);
  });

  it("draws no hop when the workstation name and the IP disagree", () => {
    const s = caseOf(
      seen("s1", "HOST-SRC"),
      seen("s2", "HOST-OTHER"),
      logon("b1", "HOST-X", "07:50", { ws: "HOST-OTHER", ip: "192.0.2.20", type: 10 }),
      logon("la", "HOST-A", "08:00", { ws: "HOST-SRC", ip: "192.0.2.20" }),
    );
    expect(routes(s)).toEqual([]);
  });

  it("draws no hop when the workstation is not a host the case knows", () => {
    expect(routes(caseOf(logon("la", "HOST-A", "08:00", { ws: "UNKNOWN-PC" })))).toEqual([]);
  });

  it("matches a short workstation name to the case's FQDN, but never across two domains", () => {
    const ok = caseOf(
      seen("src", "host-src.corp.example"),
      logon("la", "HOST-A", "08:00", { ws: "HOST-SRC" }),
    );
    expect(routes(ok)).toEqual(["host:host-src.corp.example > host:host-a"]);
    const clash = caseOf(
      seen("src", "srv.a.example"),
      logon("la", "HOST-A", "08:00", { ws: "srv.b.example" }),
    );
    expect(routes(clash)).toEqual([]);
  });

  it("knows a source host seen only outside the time window", () => {
    const s = caseOf(seen("src", "HOST-SRC", "01:00"), logon("la", "HOST-A", "08:00", { ws: "HOST-SRC" }));
    const scoped = buildLateralPaths(s, { from: T("07:00"), until: T("09:00") });
    expect(scoped.map((p) => p.hostIds.join(" > "))).toEqual(["host:host-src > host:host-a"]);
  });
});

describe("directed lateral hops — what is not direction evidence", () => {
  const known = () => seen("src", "HOST-SRC");

  it("ignores failed logons, non-network logon types and machine/anonymous accounts", () => {
    for (const bad of [
      logon("x", "HOST-A", "08:00", { ws: "HOST-SRC", failed: true }),
      logon("x", "HOST-A", "08:00", { ws: "HOST-SRC", type: 10 }),
      logon("x", "HOST-A", "08:00", { ws: "HOST-SRC", account: "CORP\\HOST-SRC$" }),
      logon("x", "HOST-A", "08:00", { ws: "HOST-SRC", account: "NT AUTHORITY\\ANONYMOUS LOGON" }),
    ]) {
      expect(routes(caseOf(known(), bad)), bad.description).toEqual([]);
    }
  });

  it("ignores a logon whose outcome is not recorded as success", () => {
    const unknown = ev({
      id: "x",
      asset: "HOST-A",
      timestamp: T("08:00"),
      canonical: createCanonicalEvent({
        event: { category: "authentication", type: "logon" },
        target: { kind: "host", name: "HOST-A" },
        account: { name: "CORP\\opsuser" },
        authentication: { logonType: 3 },
        session: { terminal: "HOST-SRC" },
        time: { observed: T("08:00"), normalized: T("08:00") },
        evidence: { rawRecords: [{ source: "test", locator: "row:x" }] },
        producer: { importer: "test", parserVersion: "1", mappingVersion: "1" },
      }),
    });
    expect(routes(caseOf(known(), unknown))).toEqual([]);
  });

  it("never draws a host connecting to itself", () => {
    expect(routes(caseOf(logon("x", "HOST-A", "08:00", { ws: "HOST-A" })))).toEqual([]);
  });

  it("draws nothing from a PSEXESVC install alone — it names no source", () => {
    expect(routes(caseOf(known(), serviceInstall("sa", "HOST-A", "08:00")))).toEqual([]);
  });

  it("does not take an unstamped srcIp on a PSEXESVC sighting as the source", () => {
    const s = caseOf(
      known(),
      logon("bind", "HOST-X", "07:50", { ws: "HOST-SRC", ip: "192.0.2.10", type: 10 }),
      ev({
        id: "f",
        asset: "HOST-A",
        timestamp: T("08:00"),
        path: "c:\\windows\\psexesvc.exe",
        srcIp: "192.0.2.10",
      }),
    );
    expect(routes(s)).toEqual([]);
  });
});

describe("directed lateral hops — pairing a service install with a logon", () => {
  const base = () => [seen("src", "HOST-SRC"), logon("la", "HOST-A", "08:00", { ws: "HOST-SRC" })];

  it("takes the source named on the service record itself", () => {
    const hop = buildLateralPaths(
      caseOf(
        seen("src", "HOST-SRC"),
        serviceInstall("sa", "HOST-A", "08:00", "PSEXESVC", { hostname: "HOST-SRC" }),
      ),
    )[0].hops[0];
    expect([hop.from, hop.rule, hop.confidence]).toEqual(["host:host-src", "remote-service", "high"]);
  });

  // #3085 review: a service record that names a source the case cannot resolve must never borrow a
  // nearby logon's source — the logon shows a connection, not who installed the service.
  it("does not swap an unknown source on the service record for a nearby logon's", () => {
    const s = caseOf(
      ...base(),
      serviceInstall("sa", "HOST-A", "08:01", "PSEXESVC", { hostname: "UNKNOWN-PC" }),
    );
    const hop = buildLateralPaths(s)[0].hops[0];
    expect([hop.rule, hop.confidence]).toEqual(["network-logon", "medium"]);
    expect(hop.eventIds).toEqual(["la"]);
  });

  it("does not pair a service record whose hostname and IP disagree", () => {
    const s = caseOf(
      ...base(),
      seen("o", "HOST-OTHER"),
      logon("bind", "HOST-X", "07:50", { ws: "HOST-OTHER", ip: "192.0.2.30", type: 10 }),
      serviceInstall("sa", "HOST-A", "08:01", "PSEXESVC", { hostname: "HOST-SRC", address: "192.0.2.30" }),
    );
    const hop = buildLateralPaths(s).find((p) => p.hostIds[1] === "host:host-a")!.hops[0];
    expect([hop.from, hop.rule, hop.confidence]).toEqual(["host:host-src", "network-logon", "medium"]);
    expect(hop.eventIds).toEqual(["la"]);
  });

  it("does not pair a service record whose address the case cannot map", () => {
    const s = caseOf(
      ...base(),
      serviceInstall("sa", "HOST-A", "08:01", "PSEXESVC", { address: "192.0.2.99" }),
    );
    const hop = buildLateralPaths(s)[0].hops[0];
    expect([hop.rule, hop.confidence]).toEqual(["network-logon", "medium"]);
  });

  it("does not pair a service install more than ten minutes from the logon", () => {
    const hop = buildLateralPaths(caseOf(...base(), serviceInstall("sa", "HOST-A", "08:20")))[0].hops[0];
    expect([hop.rule, hop.confidence]).toEqual(["network-logon", "medium"]);
    expect(hop.eventIds).toEqual(["la"]);
  });

  it("does not attribute the install when another logon in the window has no known source", () => {
    const s = caseOf(
      ...base(),
      logon("lu", "HOST-A", "08:02", { ws: "UNKNOWN-PC" }),
      serviceInstall("sa", "HOST-A", "08:03"),
    );
    const hop = buildLateralPaths(s)[0].hops[0];
    expect([hop.rule, hop.confidence]).toEqual(["network-logon", "medium"]);
  });

  it("lets an ordinary service install corroborate a logon without raising it to high", () => {
    const hop = buildLateralPaths(caseOf(...base(), serviceInstall("sa", "HOST-A", "08:02", "UpdaterSvc")))[0]
      .hops[0];
    expect([hop.rule, hop.confidence]).toEqual(["network-logon", "medium"]);
    expect(hop.eventIds).toEqual(["la", "sa"]);
    expect(hop.basis).toContain("service UpdaterSvc installed");
  });

  it("lets a PSEXESVC file sighting corroborate a logon", () => {
    const sighting = ev({
      id: "f",
      asset: "HOST-A",
      timestamp: T("08:01"),
      path: "c:\\windows\\psexesvc.exe",
    });
    const hop = buildLateralPaths(caseOf(...base(), sighting))[0].hops[0];
    expect([hop.rule, hop.confidence]).toEqual(["network-logon", "medium"]);
    expect(hop.eventIds).toEqual(["la", "f"]);
  });
});

describe("directed lateral hops — episodes and chains", () => {
  it("keeps a later return to the same host pair as its own hop, so the chain C → A → B survives", () => {
    const s = caseOf(
      seen("a0", "HOST-A"),
      seen("c0", "HOST-C"),
      logon("ab1", "HOST-B", "08:00", { ws: "HOST-A" }),
      logon("ca", "HOST-A", "10:00", { ws: "HOST-C" }),
      logon("ab2", "HOST-B", "10:05", { ws: "HOST-A" }),
    );
    expect(routes(s)).toContain("host:host-c > host:host-a > host:host-b");
    const edges = buildEvidenceGraph(s).edges.filter((e) => e.id === "lateral|dir:host:host-a|host:host-b");
    expect(edges).toHaveLength(1);
    expect(edges[0].eventIds.sort()).toEqual(["ab1", "ab2"]);
  });

  it("folds repeated logons inside one episode into one hop", () => {
    const s = caseOf(
      seen("src", "HOST-SRC"),
      logon("l1", "HOST-A", "08:00", { ws: "HOST-SRC" }),
      logon("l2", "HOST-A", "08:20", { ws: "HOST-SRC" }),
      logon("l3", "HOST-A", "08:50", { ws: "HOST-SRC" }),
    );
    const paths = buildLateralPaths(s);
    expect(paths).toHaveLength(1);
    expect(paths[0].hops[0].eventIds).toEqual(["l1", "l2", "l3"]);
  });
});
