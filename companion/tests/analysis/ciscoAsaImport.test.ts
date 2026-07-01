import { describe, it, expect } from "vitest";
import { looksLikeCiscoAsa, mapCiscoAsaLine, parseCiscoAsaLog } from "../../src/analysis/ciscoAsaImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

const BUILT = "<166>May 15 06:42:06 fw01 %ASA-6-302013: Built outbound TCP connection 1209723 for inside:10.30.20.30/45083 (45.62.114.1/21267) to outside:185.143.62.40/443 (185.143.62.40/443)";
const TEARDOWN = "<166>May 15 06:42:09 fw01 %ASA-6-302014: Teardown TCP connection 1209723 for inside:10.30.20.30/45083 to outside:185.143.62.40/443 duration 0:00:03 bytes 23625 TCP FINs";
const DENY = '<164>May 14 19:02:58 fw01 %ASA-4-106023: Deny tcp src inside:10.30.10.27/60228 dst outside:42.5.45.223/23 by access-group "inside_access_in" [0xa9d4, 0xa8e5]';
const NAT_BUILT = "<166>May 14 19:00:02 fw01 %ASA-6-305011: Built dynamic TCP translation from inside:10.30.20.30/42449 to outside:45.62.114.1/34951";
const NAT_TEARDOWN = "<166>May 14 19:00:03 fw01 %ASA-6-305012: Teardown dynamic TCP translation from inside:10.30.20.30/42449 to outside:45.62.114.1/34951 duration 0:00:01";

describe("looksLikeCiscoAsa", () => {
  it("recognizes a %ASA-tagged syslog export and rejects other logs", () => {
    expect(looksLikeCiscoAsa([BUILT, TEARDOWN, DENY].join("\n"))).toBe(true);
    expect(looksLikeCiscoAsa("Jan  1 00:00:01 host sshd[1]: Failed password for root")).toBe(false);
    expect(looksLikeCiscoAsa('{"@timestamp":"x","message":"y"}')).toBe(false);
  });
});

describe("mapCiscoAsaLine", () => {
  it("maps a Built connection to Info with a public destination IP IOC", () => {
    const sink = new Map<string, SiemIoc>();
    const m = mapCiscoAsaLine(BUILT, 2024, sink)!;
    expect(m.severity).toBe("Info");
    expect(m.timestamp).toBe("2024-05-15T06:42:06.000Z");
    expect(m.description).toContain("Built TCP connection");
    expect(m.description).toContain("10.30.20.30:45083");
    expect(m.description).toContain("185.143.62.40:443");
    expect(m.srcIp).toBe("10.30.20.30");
    expect(m.dstIp).toBe("185.143.62.40");
    expect(m.port).toBe(443);
    expect(m.sources).toEqual(["Cisco ASA"]);
    const ips = [...sink.values()].filter((i) => i.type === "ip").map((i) => i.value);
    expect(ips).toEqual(["185.143.62.40"]); // internal src NOT added as an IOC
  });

  it("maps a Teardown connection, carrying duration + bytes", () => {
    const m = mapCiscoAsaLine(TEARDOWN, 2024, new Map())!;
    expect(m.severity).toBe("Info");
    expect(m.description).toContain("Teardown TCP connection");
    expect(m.description).toContain("duration 0:00:03, 23625b");
  });

  it("maps a Deny to Low severity with a public destination IOC", () => {
    const sink = new Map<string, SiemIoc>();
    const m = mapCiscoAsaLine(DENY, 2024, sink)!;
    expect(m.severity).toBe("Low");
    expect(m.description).toContain("Denied TCP connection");
    expect(m.dstIp).toBe("42.5.45.223");
    expect([...sink.values()].map((i) => i.value)).toContain("42.5.45.223");
  });

  it("drops dynamic-NAT-translation messages as pure noise (no destination IP)", () => {
    expect(mapCiscoAsaLine(NAT_BUILT, 2024, new Map())).toBeNull();
    expect(mapCiscoAsaLine(NAT_TEARDOWN, 2024, new Map())).toBeNull();
  });

  it("returns null for a non-ASA line", () => {
    expect(mapCiscoAsaLine("just a normal log line", 2024, new Map())).toBeNull();
  });
});

describe("parseCiscoAsaLog", () => {
  it("parses the northpeak exfil sequence, dropping NAT noise, stamping the assumed year", () => {
    const text = [BUILT, TEARDOWN, DENY, NAT_BUILT, NAT_TEARDOWN].join("\n");
    const r = parseCiscoAsaLog(text, { assumeYear: 2024 });
    expect(r.total).toBe(5);           // all 5 are recognized ASA lines
    expect(r.events).toHaveLength(3);  // NAT_BUILT/NAT_TEARDOWN dropped
    expect(r.format).toBe("cisco-asa");
    const ips = r.iocs.map((i) => i.value);
    expect(ips).toContain("185.143.62.40");
    expect(ips).toContain("42.5.45.223");
  });

  it("respects a minSeverity floor", () => {
    const r = parseCiscoAsaLog([BUILT, DENY].join("\n"), { assumeYear: 2024, minSeverity: "Low" });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Low");
  });

  it("aggregates repeated identical connections into one counted row", () => {
    const r = parseCiscoAsaLog([BUILT, BUILT, BUILT].join("\n"), { assumeYear: 2024 });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(3);
  });
});
