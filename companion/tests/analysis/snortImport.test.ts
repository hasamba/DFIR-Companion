import { describe, it, expect } from "vitest";
import { parseSnortLog, looksLikeSnort, mapSnortLine } from "../../src/analysis/snortImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

const SQLI = "05/14-12:26:09.500 [**] [1:2009714:9] ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT [**] [Classification: web-application-attack] [Priority: 1] {TCP} 145.78.103.167:60278 -> 45.83.220.5:80";
const PING = "05/14-12:08:14.605 [**] [1:366:1] PROTOCOL-ICMP PING BSDtype [**] [Classification: icmp-event] [Priority: 3] {ICMP} 37.75.195.175 -> 45.83.220.5";

describe("looksLikeSnort", () => {
  it("recognizes a fast-alert log and rejects other logs", () => {
    expect(looksLikeSnort([SQLI, PING].join("\n"))).toBe(true);
    expect(looksLikeSnort("May 14 12:00:48 FW %ASA-6-302013: Built inbound TCP connection")).toBe(false);
    expect(looksLikeSnort('{"@timestamp":"x","message":"y"}')).toBe(false);
  });
});

describe("mapSnortLine", () => {
  it("maps Priority 1 → High with SID, classification, flow, and a public-IP IOC", () => {
    const sink = new Map<string, SiemIoc>();
    const m = mapSnortLine(SQLI, 2024, sink)!;
    expect(m.severity).toBe("High");
    expect(m.timestamp).toBe("2024-05-14T12:26:09.500Z");
    expect(m.description).toContain("Possible SQL Injection");
    expect(m.description).toContain("SID 1:2009714:9");
    expect(m.srcIp).toBe("145.78.103.167");
    expect(m.dstIp).toBe("45.83.220.5");
    expect(m.port).toBe(80);
    expect(m.sources).toEqual(["Snort"]);
    const ips = [...sink.values()].filter((i) => i.type === "ip").map((i) => i.value);
    expect(ips).toContain("145.78.103.167");
    expect(ips).toContain("45.83.220.5");
  });

  it("maps Priority 3 → Low and handles a port-less ICMP flow", () => {
    const m = mapSnortLine(PING, 2024, new Map())!;
    expect(m.severity).toBe("Low");
    expect(m.description).toContain("[ICMP]");
    expect(m.port).toBeUndefined();
  });

  it("returns null for a non-alert line", () => {
    expect(mapSnortLine("just a normal log line", 2024, new Map())).toBeNull();
  });
});

describe("parseSnortLog", () => {
  it("parses + aggregates a multi-line log, stamping the assumed year", () => {
    const dup = `${SQLI}\n${SQLI}\n${PING}`;
    const r = parseSnortLog(dup, { assumeYear: 2024 });
    expect(r.total).toBe(3);
    expect(r.events).toHaveLength(2);                 // the two identical SQLi alerts collapse
    const sqli = r.events.find((e) => e.severity === "High")!;
    expect(sqli.count).toBe(2);
    expect(sqli.timestamp.startsWith("2024-05-14")).toBe(true);
    expect(r.format).toBe("snort-fast");
  });

  it("respects a minSeverity floor", () => {
    const r = parseSnortLog([SQLI, PING].join("\n"), { assumeYear: 2024, minSeverity: "Medium" });
    expect(r.events).toHaveLength(1);                 // the Low ICMP ping is dropped
    expect(r.events[0].severity).toBe("High");
  });
});
