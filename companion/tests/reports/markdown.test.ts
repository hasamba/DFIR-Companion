import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

describe("renderMarkdownReport", () => {
  it("renders the derived technical sections under the template structure", () => {
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
    expect(md).toContain("# Incident Investigation Report");
    expect(md).toContain("## 2 Executive summary");
    expect(md).toContain("Host WIN-01 compromised");
    expect(md).toContain("### 3.2 Investigation timeline");
    expect(md).toContain("Reviewed file system");
    expect(md).toContain("### 4.2 Findings");
    expect(md).toContain("Ransomware");
    expect(md).toContain("### 4.4 MITRE ATT&CK");
    expect(md).toContain("T1486");
    // Attachments auto-indexes referenced evidence files.
    expect(md).toContain("## 6 Attachments");
    expect(md).toContain("`000005_t.webp`");
  });

  it("includes every template chapter and shows placeholders for empty human sections", () => {
    const md = renderMarkdownReport(emptyState("c9"));
    for (const heading of [
      "## 1.1 Report revisions",
      "## 1.3 Disclaimer and reading guide",
      "## 1.4 Intended audience",
      "## 2 Executive summary",
      "## 2.1 Business Impact Analysis",
      "## 2.2 Investigation limitations",
      "## 2.3 Investigation goals and targets",
      "## 2.4 Glossary of terms",
      "## 3 Timeline of events",
      "### 3.1 Incident timeline",
      "## 4 Investigation",
      "## 5 Conclusions and recommendations",
      "## 6 Attachments",
    ]) {
      expect(md).toContain(heading);
    }
    // Empty human-only sections get the to-be-completed placeholder.
    expect(md).toContain("To be completed by the investigator");
    // Incident ID is optional — omitted entirely when not set (no case-id fallback).
    expect(md).not.toContain("**Incident ID:**");
    // Distribution list is optional — omitted entirely when empty.
    expect(md).not.toContain("## 1.2 Distribution list");
    // Revisions auto-seed a 1.0 row even with no human input.
    expect(md).toContain("| 1.0 |");
  });

  it("makes incident ID and distribution optional, and supports multiple people", () => {
    const meta = emptyReportMeta();
    meta.investigators = ["Jane Doe", "John Roe"];
    meta.reviewer = "Riley Reviewer";
    meta.incidentManager = "Morgan Manager";

    const md = renderMarkdownReport(emptyState("c1"), meta);
    expect(md).toContain("**Investigators:** Jane Doe, John Roe");
    expect(md).toContain("**Reviewer:** Riley Reviewer");
    expect(md).toContain("**Incident manager:** Morgan Manager");
    expect(md).not.toContain("**Incident ID:**");

    // With an incident id and a single investigator, the label is singular and the line shows.
    const meta2 = emptyReportMeta();
    meta2.incidentId = "INC-42";
    meta2.investigators = ["Solo Investigator"];
    meta2.distribution = [{ name: "Ellie", role: "CISO", method: "email" }];
    const md2 = renderMarkdownReport(emptyState("c1"), meta2);
    expect(md2).toContain("**Incident ID:** INC-42");
    expect(md2).toContain("**Investigator:** Solo Investigator");
    expect(md2).toContain("## 1.2 Distribution list");
    expect(md2).toContain("| Ellie | CISO | email |");
  });

  it("auto-calculates the glossary from the report text unless overridden", () => {
    const state = emptyState("c1");
    state.attackerPath = "Initial access via phishing, credentials dumped from LSASS, then ransomware deployed.";
    const md = renderMarkdownReport(state);
    expect(md).toContain("## 2.4 Glossary of terms");
    expect(md).toContain("| LSASS |");
    expect(md).toContain("| phishing |");
    expect(md).toContain("| ransomware |");

    // A human glossary overrides the auto-derived one.
    const meta = emptyReportMeta();
    meta.glossary = [{ term: "CUSTOM", explanation: "only this" }];
    const overridden = renderMarkdownReport(state, meta);
    expect(overridden).toContain("| CUSTOM | only this |");
    expect(overridden).not.toContain("| LSASS |");
  });

  it("lets human ReportMeta override the executive summary and add recommendations", () => {
    const state = emptyState("c1");
    state.lastSummary = "AI-generated summary that should be overridden.";
    const meta = emptyReportMeta();
    meta.organization = "ExampleCorp";
    meta.investigators = ["Jane Doe"];
    meta.executiveSummary = "Human-authored executive summary.";
    meta.recommendations = ["Deploy EDR to all endpoints", "Rotate domain admin credentials"];
    meta.glossary = [{ term: "EDR", explanation: "Endpoint Detection and Response" }];

    const md = renderMarkdownReport(state, meta);
    expect(md).toContain("**Organization:** ExampleCorp");
    expect(md).toContain("**Investigator:** Jane Doe");
    expect(md).toContain("Human-authored executive summary.");
    expect(md).not.toContain("AI-generated summary that should be overridden.");
    expect(md).toContain("Deploy EDR to all endpoints");
    expect(md).toContain("| EDR | Endpoint Detection and Response |");
  });

  it("renders the disclaimer by default and omits it when turned off", () => {
    const withDisclaimer = renderMarkdownReport(emptyState("c1"));
    expect(withDisclaimer).toContain("Statements of probability");

    const meta = emptyReportMeta();
    meta.includeDisclaimer = false;
    const without = renderMarkdownReport(emptyState("c1"), meta);
    expect(without).not.toContain("Statements of probability");
  });

  it("renders the attacker path and incident timeline ordered by event time", () => {
    const state = emptyState("c1");
    state.attackerPath = "Initial access via phishing, then PsExec lateral movement, then ransomware.";
    state.forensicTimeline.push(
      { id: "e2", timestamp: "2026-05-20T15:00:00Z", description: "Ransomware encryptor executed",
        severity: "Critical", mitreTechniques: ["T1486"], relatedFindingIds: ["f1"], sourceScreenshots: ["s2.webp"] },
      { id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "Phishing email opened",
        severity: "High", mitreTechniques: ["T1566"], relatedFindingIds: [], sourceScreenshots: ["s1.webp"] },
    );

    const md = renderMarkdownReport(state);
    expect(md).toContain("### 4.1 Attacker path");
    expect(md).toContain("PsExec lateral movement");
    expect(md).toContain("### 3.1 Incident timeline");
    expect(md).toContain("Phishing email opened");
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

  it("renders key investigative questions and the IOC section", () => {
    const state = emptyState("c1");
    state.keyQuestions.push(
      { id: "q1", question: "What was the initial access vector?", status: "answered", answer: "phishing email", pointer: "finding f3" },
      { id: "q2", question: "Was there lateral movement?", status: "unknown", answer: "", pointer: "collect 4624 logs on targets" },
    );
    state.iocs.push({ id: "i1", type: "ip", value: "10.0.0.5", firstSeen: "2026-05-20T09:00:00Z" });

    const md = renderMarkdownReport(state);
    expect(md).toContain("### 4.6 Key investigative questions");
    expect(md).toContain("What was the initial access vector?");
    expect(md).toContain("collect 4624 logs on targets");
    expect(md).toContain("### 4.3 Indicators of compromise");
    expect(md).toContain("10.0.0.5");
  });

  it("falls back to recommended next steps as draft recommendations when none are authored", () => {
    const state = emptyState("c1");
    state.nextSteps.push(
      { id: "n1", priority: "critical", action: "Pull Security.evtx on ALClient07", rationale: "confirm initial access", pointer: "event e3" },
      { id: "n2", priority: "high", action: "Detonate Bubeus.exe", rationale: "find C2", pointer: "ioc i2" },
    );
    const md = renderMarkdownReport(state);
    expect(md).toContain("## 5 Conclusions and recommendations");
    expect(md).toContain("CRITICAL");
    expect(md).toContain("Pull Security.evtx on ALClient07");
    expect(md).toContain("Detonate Bubeus.exe");
  });

  it("renders investigation threads split into open and closed", () => {
    const state = emptyState("c1");
    state.openThreads.push(
      { id: "t1", description: "trace lateral movement", status: "open", openedAt: "2026-05-20T10:00:00Z", closedAt: null },
      { id: "t2", description: "identify C2 domain", status: "closed", openedAt: "2026-05-20T10:00:00Z", closedAt: "2026-05-20T12:00:00Z" },
    );
    const md = renderMarkdownReport(state);
    expect(md).toContain("### 4.5 Investigation threads");
    expect(md).toContain("**Open (still being chased):**");
    expect(md).toContain("trace lateral movement");
    expect(md).toContain("**Closed (resolved):**");
    expect(md).toContain("identify C2 domain");
    expect(md).toContain("closed 2026-05-20T12:00:00Z");
  });
});
