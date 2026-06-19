import { describe, it, expect } from "vitest";
import { parseSecurityOnion, securityOnionSeverity } from "../../src/analysis/securityOnionImport.js";

// Security Onion Console (SOC) events as the browser extension pushes them: each row is one
// EventRecord.payload (flattened ECS, FLAT dotted keys) with the extension's _id/_index metadata
// and a _Source stamp ("Security Onion <view>").
function soAlert(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    _id: "ru5",
    _index: "so:.ds-logs-suricata-so-2026.06.19-000001",
    _Source: "Security Onion Alerts",
    "@timestamp": "2026-06-19T20:08:15.970Z",
    "event.module": "suricata",
    "event.severity_label": "high",
    "rule.name": "ET MALWARE Agent Tesla CnC Exfil via TCP",
    "rule.uuid": "2063399",
    "source.ip": "10.0.0.5",
    "source.port": 51000,
    "destination.ip": "203.0.113.9",
    "destination.port": 443,
    ...over,
  };
}

describe("securityOnionSeverity", () => {
  it("maps event.severity_label to a forensic severity", () => {
    expect(securityOnionSeverity({ "event.severity_label": "critical" })).toBe("Critical");
    expect(securityOnionSeverity({ "event.severity_label": "high" })).toBe("High");
    expect(securityOnionSeverity({ "event.severity_label": "medium" })).toBe("Medium");
    expect(securityOnionSeverity({ "event.severity_label": "low" })).toBe("Low");
    expect(securityOnionSeverity({ "event.severity_label": "informational" })).toBe("Info");
  });
  it("falls back to the numeric Suricata priority (event.severity), then a sensible default", () => {
    expect(securityOnionSeverity({ "event.severity": 1, "rule.name": "x" })).toBe("High");
    expect(securityOnionSeverity({ "event.severity": 3, "rule.name": "x" })).toBe("Low");
    expect(securityOnionSeverity({ "rule.name": "x" })).toBe("Medium"); // an alert fired, no label
    expect(securityOnionSeverity({})).toBe("Info");                      // no signal at all
  });
});

describe("parseSecurityOnion", () => {
  it("preserves the alert's own severity from event.severity_label (the bug: was Info)", () => {
    const r = parseSecurityOnion(JSON.stringify([soAlert()]));
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("High");
    expect(e.description).toContain("ET MALWARE Agent Tesla CnC Exfil via TCP");
    expect(e.description).toContain("10.0.0.5:51000 → 203.0.113.9:443");
    expect(e.sources).toEqual(["Security Onion"]);
    expect(e.timestamp).toBe("2026-06-19T20:08:15.970Z");
    expect(e.srcIp).toBe("10.0.0.5");
    expect(e.dstIp).toBe("203.0.113.9");
    const ips = r.iocs.filter((i) => i.type === "ip").map((i) => i.value);
    expect(ips).toContain("10.0.0.5");
    expect(ips).toContain("203.0.113.9");
  });

  it("keeps per-row severity across a mixed batch (high + medium)", () => {
    const rows = [
      soAlert(),
      soAlert({ "event.severity_label": "medium", "rule.name": "ET SCAN Potential SSH Scan OUTBOUND", "rule.uuid": "2003068" }),
    ];
    const r = parseSecurityOnion(JSON.stringify(rows));
    const sevs = r.events.map((e) => e.severity).sort();
    expect(sevs).toEqual(["High", "Medium"]);
  });

  it("extracts MITRE from ECS threat fields and app-layer IOCs (dns/url/hash)", () => {
    const r = parseSecurityOnion(JSON.stringify([soAlert({
      "threat.technique.id": ["T1071.001"],
      "dns.query": "evil-c2.example.com",
      "url.full": "http://evil-c2.example.com/a",
      "file.hash.sha256": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    })]));
    const e = r.events[0];
    expect(e.mitreTechniques).toContain("T1071.001");
    expect(r.iocs.some((i) => i.type === "domain" && i.value === "evil-c2.example.com")).toBe(true);
    expect(r.iocs.some((i) => i.type === "url")).toBe(true);
    expect(r.iocs.some((i) => i.type === "hash")).toBe(true);
  });

  it("returns no events for an empty batch", () => {
    expect(parseSecurityOnion("[]").events).toHaveLength(0);
  });
});
