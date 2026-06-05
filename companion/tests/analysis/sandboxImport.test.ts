import { describe, it, expect } from "vitest";
import { parseSandboxReport } from "../../src/analysis/sandboxImport.js";

// ── A minimal CAPEv2 report.json ────────────────────────────────────────────
function capeReport(): object {
  return {
    info: { id: 42, score: 9.2, started: "2023-09-01 10:00:00" },
    target: { category: "file", file: { name: "invoice.exe", sha256: "a".repeat(64), md5: "b".repeat(32), type: "PE32" } },
    malscore: 9.2,
    malfamily: "AgentTesla",
    signatures: [
      { name: "injection_runpe", description: "Executed a process and injected code into it", severity: 3, ttp: { "T1055": { signature: "x" } } },
      { name: "antidbg_devices", description: "Checks for debugging devices", severity: 1 },
    ],
    network: {
      hosts: ["203.0.113.40", "10.0.0.1"],
      domains: [{ domain: "exfil.example.com", ip: "203.0.113.41" }],
      http: [{ host: "exfil.example.com", uri: "http://exfil.example.com/gate.php" }],
    },
    dropped: [{ name: "C:\\Users\\v\\AppData\\evil.dll", sha256: "c".repeat(64) }],
  };
}

// ── A minimal CrowdStrike Falcon Sandbox summary ────────────────────────────
function falconReport(): object {
  return {
    job_id: "abc", sha256: "d".repeat(64), md5: "e".repeat(32), submit_name: "dropper.doc",
    environment_id: 160, verdict: "malicious", threat_score: 95, vx_family: "Emotet",
    analysis_start_time: "2023-09-02T08:00:00Z",
    mitre_attcks: [{ tactic: "Execution", technique: "PowerShell", attck_id: "T1059.001" }],
    signatures: [
      { name: "Contacts C2", description: "Connects to a known C2", threat_level: 2, threat_level_human: "malicious", attck_id: "T1071" },
      { name: "Reads config", description: "Reads its own config", threat_level: 0, threat_level_human: "informative" },
    ],
    hosts: ["198.51.100.7"],
    domains: ["bad.example.net"],
    extracted_files: [{ name: "payload.bin", sha256: "f".repeat(64) }],
  };
}

describe("parseSandboxReport — CAPEv2", () => {
  it("maps the verdict + signatures and harvests hashes/network IOCs", () => {
    const r = parseSandboxReport(JSON.stringify(capeReport()));
    expect(r.format).toBe("capev2");
    expect(r.signatures).toBe(2);
    const sample = r.events.find((e) => e.description.startsWith("CAPE sandbox:"));
    expect(sample?.severity).toBe("High");                 // malscore 9.2/10
    expect(sample?.description).toContain("AgentTesla");
    expect(sample?.sha256).toBe("a".repeat(64));
    expect(sample?.timestamp).toBe("2023-09-01T10:00:00Z");

    const inj = r.events.find((e) => e.description.includes("injection_runpe"));
    expect(inj?.severity).toBe("High");                    // CAPE severity 3
    expect(inj?.mitreTechniques).toContain("T1055");
    const antidbg = r.events.find((e) => e.description.includes("antidbg_devices"));
    expect(antidbg?.severity).toBe("Low");                 // CAPE severity 1

    const iocs = r.iocs;
    expect(iocs.some((i) => i.type === "hash" && i.value === "a".repeat(64))).toBe(true);
    expect(iocs.some((i) => i.type === "hash" && i.value === "c".repeat(64))).toBe(true); // dropped
    expect(iocs.some((i) => i.type === "ip" && i.value === "203.0.113.40")).toBe(true);
    expect(iocs.some((i) => i.type === "domain" && i.value === "exfil.example.com")).toBe(true);
    expect(iocs.some((i) => i.type === "url")).toBe(true);
  });
});

describe("parseSandboxReport — Falcon Sandbox", () => {
  it("maps the verdict + signatures, MITRE from mitre_attcks, and IOCs", () => {
    const r = parseSandboxReport(JSON.stringify(falconReport()));
    expect(r.format).toBe("falcon");
    const sample = r.events.find((e) => e.description.startsWith("Falcon Sandbox:"));
    expect(sample?.severity).toBe("High");                 // verdict malicious
    expect(sample?.description).toContain("Emotet");
    expect(sample?.mitreTechniques).toContain("T1059.001");
    expect(sample?.sha256).toBe("d".repeat(64));
    expect(sample?.timestamp).toBe("2023-09-02T08:00:00Z");

    const c2 = r.events.find((e) => e.description.includes("Contacts C2"));
    expect(c2?.severity).toBe("High");                     // threat_level 2 / malicious
    expect(c2?.mitreTechniques).toContain("T1071");
    const cfg = r.events.find((e) => e.description.includes("Reads config"));
    expect(cfg?.severity).toBe("Info");                    // informative

    expect(r.iocs.some((i) => i.type === "ip" && i.value === "198.51.100.7")).toBe(true);
    expect(r.iocs.some((i) => i.type === "domain" && i.value === "bad.example.net")).toBe(true);
    expect(r.iocs.some((i) => i.type === "hash" && i.value === "f".repeat(64))).toBe(true);
  });
});

describe("parseSandboxReport — options & edges", () => {
  it("applies a severity floor (keeps the High verdict + High signature, drops Low/Info)", () => {
    const r = parseSandboxReport(JSON.stringify(capeReport()), { minSeverity: "High" });
    expect(r.events.every((e) => e.severity === "High")).toBe(true);
    expect(r.events.some((e) => e.description.includes("antidbg_devices"))).toBe(false);
  });

  it("accepts an array of reports (mixed CAPE + Falcon)", () => {
    const r = parseSandboxReport(JSON.stringify([capeReport(), falconReport()]));
    expect(r.format).toBe("mixed");
    expect(r.total).toBe(2);
    expect(r.events.some((e) => e.sources?.[0] === "CAPEv2")).toBe(true);
    expect(r.events.some((e) => e.sources?.[0] === "Falcon Sandbox")).toBe(true);
  });

  it("reports empty for a non-sandbox JSON", () => {
    const r = parseSandboxReport(JSON.stringify({ foo: "bar" }));
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
});
