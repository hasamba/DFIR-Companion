import { describe, it, expect } from "vitest";
import { parseWazuhAlerts } from "../../src/analysis/wazuhImport.js";

function alert(over: object = {}): object {
  return {
    timestamp: "2024-01-15T10:30:00.123+0000",
    rule: {
      level: 10,
      description: "Multiple authentication failures",
      id: "5712",
      groups: ["authentication_failures", "pam"],
      mitre: { technique: ["T1110"] },
    },
    agent: { id: "001", name: "web-server-01" },
    data: { srcip: "203.0.113.10", dstip: "10.0.0.5" },
    ...over,
  };
}

const j = (...alerts: object[]): string => JSON.stringify(alerts);
const ndjson = (...alerts: object[]): string => alerts.map((a) => JSON.stringify(a)).join("\n");

describe("parseWazuhAlerts — severity mapping", () => {
  it("level ≥13 → Critical", () => {
    const r = parseWazuhAlerts(j(alert({ rule: { level: 14, description: "Rootkit detected", id: "550" } })));
    expect(r.events[0].severity).toBe("Critical");
  });

  it("level ≥10 → High", () => {
    const r = parseWazuhAlerts(j(alert()));
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1110");
  });

  it("level ≥7 → Medium", () => {
    const r = parseWazuhAlerts(j(alert({ rule: { level: 8, description: "Suspicious activity", id: "9999" } })));
    expect(r.events[0].severity).toBe("Medium");
  });

  it("level <7 → Info", () => {
    const r = parseWazuhAlerts(j(alert({ rule: { level: 4, description: "Low priority event", id: "1001" } })));
    expect(r.events[0].severity).toBe("Info");
  });
});

describe("parseWazuhAlerts — field extraction", () => {
  it("reads agent.name as asset", () => {
    const r = parseWazuhAlerts(j(alert()));
    expect(r.events[0].asset).toBe("web-server-01");
  });

  it("reads timestamp from alert's own timestamp field", () => {
    const r = parseWazuhAlerts(j(alert()));
    expect(r.events[0].timestamp).toBe("2024-01-15T10:30:00.123Z");
  });

  it("includes rule description in event description", () => {
    const r = parseWazuhAlerts(j(alert()));
    expect(r.events[0].description).toContain("Multiple authentication failures");
  });

  it("includes rule id in description", () => {
    const r = parseWazuhAlerts(j(alert()));
    expect(r.events[0].description).toContain("[rule 5712]");
  });

  it("includes agent name in description", () => {
    const r = parseWazuhAlerts(j(alert()));
    expect(r.events[0].description).toContain("@ web-server-01");
  });

  it("tags source as Wazuh", () => {
    const r = parseWazuhAlerts(j(alert()));
    expect(r.events[0].sources).toContain("Wazuh");
  });

  it("extracts MITRE technique IDs", () => {
    const r = parseWazuhAlerts(j(alert()));
    expect(r.events[0].mitreTechniques).toEqual(["T1110"]);
  });

  it("handles array of MITRE techniques", () => {
    const a = alert({ rule: { level: 10, description: "x", id: "1", mitre: { technique: ["T1059", "T1078.004"] } } });
    const r = parseWazuhAlerts(j(a));
    expect(r.events[0].mitreTechniques).toContain("T1059");
    expect(r.events[0].mitreTechniques).toContain("T1078.004");
  });

  it("ignores invalid MITRE ids", () => {
    const a = alert({ rule: { level: 10, description: "x", id: "1", mitre: { technique: ["not-a-technique", "T1059"] } } });
    const r = parseWazuhAlerts(j(a));
    expect(r.events[0].mitreTechniques).toEqual(["T1059"]);
  });
});

describe("parseWazuhAlerts — IOC extraction", () => {
  it("extracts srcip as IP IOC", () => {
    const r = parseWazuhAlerts(j(alert()));
    expect(r.iocs.find((i) => i.value === "203.0.113.10")).toBeTruthy();
    expect(r.iocs.find((i) => i.value === "203.0.113.10")?.type).toBe("ip");
  });

  it("extracts md5 as hash IOC", () => {
    const a = alert({ data: { md5: "d41d8cd98f00b204e9800998ecf8427e" } });
    const r = parseWazuhAlerts(j(a));
    expect(r.iocs.find((i) => i.type === "hash")?.value).toBe("d41d8cd98f00b204e9800998ecf8427e");
  });

  it("extracts sha256 as hash IOC", () => {
    const sha256 = "a".repeat(64);
    const a = alert({ data: { sha256 } });
    const r = parseWazuhAlerts(j(a));
    expect(r.iocs.find((i) => i.type === "hash")?.value).toBe(sha256);
  });

  it("extracts URL IOC", () => {
    const a = alert({ data: { url: "http://malware.example.com/payload.exe" } });
    const r = parseWazuhAlerts(j(a));
    expect(r.iocs.find((i) => i.type === "url")?.value).toBe("http://malware.example.com/payload.exe");
  });

  it("drops loopback IPs", () => {
    const a = alert({ data: { srcip: "127.0.0.1" } });
    const r = parseWazuhAlerts(j(a));
    expect(r.iocs.filter((i) => i.type === "ip")).toHaveLength(0);
  });
});

describe("parseWazuhAlerts — input formats", () => {
  it("reads a JSON array", () => {
    const r = parseWazuhAlerts(j(alert(), alert()));
    expect(r.total).toBe(2);
    expect(r.format).toBe("array");
  });

  it("reads NDJSON", () => {
    const r = parseWazuhAlerts(ndjson(alert(), alert()));
    expect(r.total).toBe(2);
    expect(r.format).toBe("ndjson");
  });

  it("reads Wazuh API export { data: { affected_items: [...] } }", () => {
    const apiExport = { data: { affected_items: [alert(), alert()], total_affected_items: 2 } };
    const r = parseWazuhAlerts(JSON.stringify(apiExport));
    expect(r.format).toBe("api-export");
    expect(r.total).toBe(2);
    expect(r.events.length).toBeGreaterThan(0);
  });

  it("returns empty for non-Wazuh input", () => {
    const r = parseWazuhAlerts(JSON.stringify({ foo: "bar" }));
    expect(r.events).toHaveLength(0);
    expect(r.kept).toBe(0);
  });

  it("returns empty for empty input", () => {
    const r = parseWazuhAlerts("");
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
});

describe("parseWazuhAlerts — noise filtering", () => {
  it("drops alerts with rule.level < 3 (default minLevel) by default", () => {
    const a = alert({ rule: { level: 2, description: "Noise event", id: "100" } });
    const r = parseWazuhAlerts(j(a));
    expect(r.events).toHaveLength(0);
  });

  it("overriding minLevel to 0 includes level-2 alerts", () => {
    const a = alert({ rule: { level: 2, description: "Noise event", id: "100" } });
    const r = parseWazuhAlerts(j(a), { minLevel: 0 });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Info");
  });

  it("applies severity floor option", () => {
    const r = parseWazuhAlerts(j(
      alert({ rule: { level: 14, description: "High severity", id: "1" } }), // Critical
      alert({ rule: { level: 4, description: "Low severity", id: "2" } }),   // Info
    ), { minSeverity: "High" });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Critical");
  });
});

describe("parseWazuhAlerts — aggregation and hostname", () => {
  it("reports dominant hostname", () => {
    const r = parseWazuhAlerts(j(alert(), alert(), alert({ agent: { id: "002", name: "other-host" } })));
    expect(r.hostname).toBe("web-server-01");
  });

  it("aggregates identical events", () => {
    const r = parseWazuhAlerts(j(alert(), alert(), alert()));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(3);
  });

  it("reports kept and total counts correctly", () => {
    const r = parseWazuhAlerts(j(alert(), alert()));
    expect(r.total).toBe(2);
    expect(r.kept).toBe(1); // aggregated to 1
    expect(r.groups).toBe(1);
  });
});
