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

  it("renders key investigative questions and an IOC section", () => {
    const state = emptyState("c1");
    state.keyQuestions.push(
      { id: "q1", question: "What was the initial access vector?", status: "answered", answer: "phishing email", pointer: "finding f3" },
      { id: "q2", question: "Was there lateral movement?", status: "unknown", answer: "", pointer: "collect 4624 logs on targets" },
    );
    state.iocs.push({ id: "i1", type: "ip", value: "10.0.0.5", firstSeen: "2026-05-20T09:00:00Z" });

    const md = renderMarkdownReport(state);
    expect(md).toContain("## Key Investigative Questions");
    expect(md).toContain("What was the initial access vector?");
    expect(md).toContain("collect 4624 logs on targets");   // pointer for an unknown
    expect(md).toContain("## Indicators of Compromise (IOCs)");
    expect(md).toContain("10.0.0.5");
  });

  it("renders recommended next steps with priority, action and pointer", () => {
    const state = emptyState("c1");
    state.nextSteps.push(
      { id: "n1", priority: "critical", action: "Pull Security.evtx on ALClient07", rationale: "confirm initial access", pointer: "event e3" },
      { id: "n2", priority: "high", action: "Detonate Bubeus.exe", rationale: "find C2", pointer: "ioc i2" },
    );
    const md = renderMarkdownReport(state);
    expect(md).toContain("## Recommended Next Steps");
    expect(md).toContain("CRITICAL");
    expect(md).toContain("Pull Security.evtx on ALClient07");
    expect(md).toContain("confirm initial access");
    expect(md).toContain("Detonate Bubeus.exe");
  });

  it("renders investigation threads split into open and closed", () => {
    const state = emptyState("c1");
    state.openThreads.push(
      { id: "t1", description: "trace lateral movement", status: "open", openedAt: "2026-05-20T10:00:00Z", closedAt: null },
      { id: "t2", description: "identify C2 domain", status: "closed", openedAt: "2026-05-20T10:00:00Z", closedAt: "2026-05-20T12:00:00Z" },
    );
    const md = renderMarkdownReport(state);
    expect(md).toContain("## Investigation Threads");
    expect(md).toContain("**Open (still being chased):**");
    expect(md).toContain("trace lateral movement");
    expect(md).toContain("**Closed (resolved):**");
    expect(md).toContain("identify C2 domain");
    expect(md).toContain("closed 2026-05-20T12:00:00Z");
  });
});
