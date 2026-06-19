import { describe, it, expect } from "vitest";
import { parseSocrates } from "../../src/analysis/socratesImport.js";

const suricataAlert = {
  timestamp: "2017-12-01T08:00:00.123456+0000",
  event_type: "alert",
  src_ip: "10.0.0.5", src_port: 51000, dest_ip: "203.0.113.9", dest_port: 443, proto: "TCP",
  alert: { signature: "ET MALWARE Cobalt Strike Beacon", category: "A Network Trojan was detected", signature_id: 2027000, severity: 1, metadata: { mitre_technique_id: ["T1071.001"] } },
};
const suricataDns = { timestamp: "2017-12-01T08:00:01+0000", event_type: "dns", src_ip: "10.0.0.5", dns: { rrname: "evil-c2.example.com", rrtype: "A" } };
const yaraFileAlert = {
  event_type: "filealerts", timestamp: "2017-12-01T08:00:02+0000",
  filealerts: { rule_name: "Windows_Trojan_CobaltStrike", tags: ["malware", "attack.t1055"], author: "x",
    sha256: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", meta: { filename: "beacon.exe" } },
};
const sigmaAlert = { timestamp: "2024-01-02T03:04:05Z", rule_title: "Suspicious PowerShell Download", rule_id: "abc-123", severity: "high", level: "high", logsource: "windows/powershell", tags: "attack.execution,attack.t1059.001", mitre_techniques: "T1059.001" };

describe("parseSocrates", () => {
  it("maps a Suricata alert to a timeline event tagged SO-CRATES + Suricata", () => {
    const r = parseSocrates(JSON.stringify([suricataAlert]));
    expect(r.format).toBe("suricata");
    expect(r.alerts).toBe(1);
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("ET MALWARE Cobalt Strike Beacon");
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1071.001");
    expect(e.sources).toEqual(["SO-CRATES", "Suricata"]);
    expect(r.iocs.some((i) => i.type === "ip" && i.value === "203.0.113.9")).toBe(true);
  });

  it("maps a YARA filealert to a Medium event + hash/file IOCs tagged SO-CRATES + YARA", () => {
    const r = parseSocrates(JSON.stringify([yaraFileAlert]));
    expect(r.format).toBe("yara");
    expect(r.yara).toBe(1);
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("YARA: Windows_Trojan_CobaltStrike on beacon.exe");
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1055");
    expect(e.sources).toEqual(["SO-CRATES", "YARA"]);
    expect(e.sha256).toBe("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    expect(r.iocs.some((i) => i.type === "hash" && i.value === yaraFileAlert.filealerts.sha256)).toBe(true);
    expect(r.iocs.some((i) => i.type === "file" && i.value === "beacon.exe")).toBe(true);
  });

  it("maps a Sigma alert verdict-first to an event with severity + MITRE tagged SO-CRATES + Sigma", () => {
    const r = parseSocrates(JSON.stringify([sigmaAlert]));
    expect(r.format).toBe("sigma");
    expect(r.sigma).toBe(1);
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("Sigma: Suspicious PowerShell Download");
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1059.001");
    expect(e.sources).toEqual(["SO-CRATES", "Sigma"]);
  });

  it("extracts IOCs from telemetry but adds no timeline event (telemetry-only)", () => {
    const r = parseSocrates(JSON.stringify([suricataDns]));
    expect(r.events).toHaveLength(0);
    expect(r.iocs.some((i) => i.type === "domain" && i.value === "evil-c2.example.com")).toBe(true);
  });

  it("returns the empty result for no records", () => {
    const r = parseSocrates("[]");
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
    expect(r.total).toBe(0);
  });
});
