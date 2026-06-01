import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

describe("renderMarkdownReport", () => {
  it("renders all four sections", () => {
    const state = emptyState("c1");
    state.lastSummary = "Host WIN-01 compromised via phishing.";
    state.findings.push({ id: "f1", severity: "Critical", title: "Ransomware", description: "encryptor dropped",
      relatedIocs: ["i1"], mitreTechniques: ["T1486"], sourceScreenshots: ["000005_t.webp"],
      firstSeen: "2026-05-28T10:00:00.000Z", lastUpdated: "2026-05-28T10:05:00.000Z", status: "confirmed" });
    state.iocs.push({ id: "i1", type: "hash", value: "abc123", firstSeen: "2026-05-28T10:00:00.000Z" });
    state.timeline.push({ timestamp: "2026-05-28T10:00:00.000Z", windowSequence: 1,
      description: "Reviewed file system", sourceScreenshots: ["000005_t.webp"] });
    state.mitreTechniques.push({ id: "T1486", name: "Data Encrypted for Impact", findingIds: ["f1"] });

    const md = renderMarkdownReport(state);
    expect(md).toContain("## Executive Summary");
    expect(md).toContain("Host WIN-01 compromised");
    expect(md).toContain("## Investigation Log");
    expect(md).toContain("Reviewed file system");
    expect(md).toContain("## Findings");
    expect(md).toContain("Ransomware");
    expect(md).toContain("## MITRE ATT&CK");
    expect(md).toContain("T1486");
  });

  it("renders the attacker path and forensic timeline ordered by event time", () => {
    const state = emptyState("c1");
    state.attackerPath = "Initial access via phishing, then PsExec lateral movement, then ransomware.";
    state.forensicTimeline.push(
      { id: "e2", timestamp: "2026-05-20T15:00:00Z", description: "Ransomware encryptor executed",
        severity: "Critical", mitreTechniques: ["T1486"], relatedFindingIds: ["f1"], sourceScreenshots: ["s2.webp"] },
      { id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "Phishing email opened",
        severity: "High", mitreTechniques: ["T1566"], relatedFindingIds: [], sourceScreenshots: ["s1.webp"] },
    );

    const md = renderMarkdownReport(state);
    expect(md).toContain("## Attacker Path");
    expect(md).toContain("PsExec lateral movement");
    expect(md).toContain("## Forensic Timeline");
    expect(md).toContain("Phishing email opened");
    expect(md).toContain("Ransomware encryptor executed");
    // earlier event (09:00) must render before the later one (15:00)
    expect(md.indexOf("Phishing email opened")).toBeLessThan(md.indexOf("Ransomware encryptor executed"));
  });

  it("escapes pipe characters in MITRE table cells", () => {
    const state = emptyState("c2");
    state.mitreTechniques.push({ id: "T1003", name: "OS Credential Dumping | LSASS", findingIds: ["f1"] });
    const md = renderMarkdownReport(state);
    expect(md).toContain("OS Credential Dumping \\| LSASS");
  });

  it("sorts findings by severity (Critical first)", () => {
    const state = emptyState("c1");
    const mk = (id: string, sev: "Critical" | "Low") => ({ id, severity: sev, title: id, description: "",
      relatedIocs: [], mitreTechniques: [], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" as const });
    state.findings.push(mk("low1", "Low"), mk("crit1", "Critical"));
    const md = renderMarkdownReport(state);
    expect(md.indexOf("crit1")).toBeLessThan(md.indexOf("low1"));
  });
});
