import { describe, it, expect } from "vitest";
import { parseChainsawReport } from "../../src/analysis/chainsawImport.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1922: one image's Sysmon EID 3 rows — three mDNS multicasts, one TCP connection to a C2 server,
// the same three multicasts again — were bridged into ONE row by a file record of the same image
// seen within 2 s (Amcache). Path matching is pairwise and the union-find is transitive, so every
// connection the bridge touched became one component, and the longest description (an mDNS row)
// won. The C2 connection left both timelines. The destination is now a union-guard fact.
const HOST = "WKS-ALPHA";
const IMAGE = "C:\\Users\\Public\\updater.exe";
const C2 = { ip: "198.51.100.7", port: 8888 };

let recordId = 4000;
function sysmonNetRow(utc: string, ip: string, port: number, protocol: string): object {
  recordId++;
  return {
    EventTime: utc,
    Detection: "Suspicious Program Location with Network Connections",
    Severity: "high",
    "Rule Group": "Sigma",
    Computer: HOST,
    Channel: "Microsoft-Windows-Sysmon/Operational",
    EventID: 3,
    SystemData: {
      Channel: "Microsoft-Windows-Sysmon/Operational",
      Computer: HOST,
      EventID: 3,
      EventRecordID: recordId,
      TimeCreated_attributes: { SystemTime: utc },
    },
    EventData: {
      UtcTime: utc.replace("T", " ").replace("Z", ""),
      Image: IMAGE,
      Protocol: protocol,
      Initiated: true,
      SourceIp: "192.0.2.10",
      SourcePort: 50000 + recordId,
      DestinationIp: ip,
      DestinationPort: port,
      DestinationHostname: "-",
      User: "EXAMPLE\\analyst",
    },
  };
}

function mdnsBurst(base: string): object[] {
  return [
    sysmonNetRow(`${base}.100Z`, "224.0.0.251", 5353, "udp"),
    sysmonNetRow(`${base}.101Z`, "192.0.2.10", 5353, "udp"),
    sysmonNetRow(`${base}.102Z`, "ff02::fb", 5353, "udp"),
  ];
}

function amcacheRow(ts: string): ForensicEvent {
  return {
    id: "amcache-1",
    timestamp: ts,
    description: "DetectRaptor Amcache detection: Suspicious Location — updater.exe",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Velociraptor"],
    path: IMAGE.toLowerCase(),
    asset: HOST,
  };
}

function chainsawEvents(rows: object[]): ForensicEvent[] {
  return parseChainsawReport(JSON.stringify(rows)).events.map((e, i) => ({
    ...e,
    id: `cs-${i}`,
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: e.mitreTechniques ?? [],
  }));
}

const isConn = (e: ForensicEvent): boolean => /EID 3|Network connection/i.test(e.description);

describe("a file record of the same image never folds distinct network connections together (#1922)", () => {
  const burst = [
    ...mdnsBurst("2026-10-01T10:00:06"),
    sysmonNetRow("2026-10-01T10:00:07.050Z", C2.ip, C2.port, "tcp"),
  ];

  it("keeps the TCP C2 connection as its own row, with its own peer", () => {
    const cs = chainsawEvents(burst);
    expect(cs.filter(isConn)).toHaveLength(4);
    const merged = correlateEvents([...cs, amcacheRow("2026-10-01T10:00:07Z")]);
    const conns = merged.filter(isConn);
    expect(conns).toHaveLength(4);
    const c2 = conns.find((e) => e.description.includes(C2.ip));
    expect(c2, "the C2 row survives correlation").toBeDefined();
    expect(c2!.description).toContain(String(C2.port));
    expect(c2!.canonical?.network?.destination).toMatchObject({ address: C2.ip, port: C2.port });
    expect(c2!.canonical?.network?.protocol?.toLowerCase()).toBe("tcp");
  });

  it("keeps each aggregated multicast peer apart after the later repeat", () => {
    // The importer folds a repeat of one connection (same image and peer) into one counted row,
    // so 7 records are 4 rows: 3 multicast peers seen twice each, and the C2 connection.
    const rows = [...burst, ...mdnsBurst("2026-10-01T10:19:40")];
    const cs = chainsawEvents(rows);
    expect(cs.filter(isConn)).toHaveLength(4);
    const merged = correlateEvents([...cs, amcacheRow("2026-10-01T10:00:07Z")]);
    const conns = merged.filter(isConn);
    expect(conns).toHaveLength(4);
    expect(conns.filter((e) => e.description.includes(C2.ip))).toHaveLength(1);
    // The bridge row still attaches to one connection rather than standing alone.
    const withAmcache = merged.filter((e) => e.sources?.includes("Velociraptor"));
    expect(withAmcache).toHaveLength(1);
    expect(isConn(withAmcache[0])).toBe(true);
  });
});

describe("the peer guard keeps the merges it must not break", () => {
  const base = (over: Partial<ForensicEvent> & { id: string }): ForensicEvent => ({
    timestamp: "2026-10-01T10:00:07Z",
    description: "event",
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: HOST,
    ...over,
  });

  it("a Hayabusa reading with only the address merges with a Chainsaw reading of the same record (#688)", () => {
    const record = "evtx:microsoft-windows-sysmon/operational:4986";
    const hayabusa = base({
      id: "h1",
      description: "Hayabusa: Net Conn (Sysmon Alert) (EID 3 Sysmon) — Proto=tcp",
      sources: ["Hayabusa"],
      sourceRecordId: record,
      dstIp: C2.ip,
      canonical: { network: { destination: { address: C2.ip } } } as ForensicEvent["canonical"],
    });
    const chainsaw = base({
      id: "c1",
      description: "Chainsaw/Sigma: Sysmon Network connection (EID 3)",
      severity: "High",
      sources: ["Chainsaw"],
      sourceRecordId: record,
      dstIp: C2.ip,
      port: C2.port,
      canonical: {
        network: { destination: { address: C2.ip, port: C2.port }, protocol: "tcp" },
      } as ForensicEvent["canonical"],
    });
    const merged = correlateEvents([hayabusa, chainsaw]);
    expect(merged).toHaveLength(1);
    expect(merged[0].sources?.sort()).toEqual(["Chainsaw", "Hayabusa"]);
  });

  it("two tools' rows for the same connection still merge on path", () => {
    const a = base({
      id: "a1",
      description: "Tool A: connection from updater.exe",
      sources: ["Hayabusa"],
      path: IMAGE,
      dstIp: C2.ip,
      port: C2.port,
    });
    const b = base({
      id: "b1",
      description: "Tool B: connection from updater.exe",
      sources: ["Chainsaw"],
      path: IMAGE,
      dstIp: C2.ip,
      port: C2.port,
    });
    expect(correlateEvents([a, b])).toHaveLength(1);
  });
});
