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
    expect(md).toContain("### 3.1 Incident timeline");
    expect(md).toContain("### 4.3 Findings");
    expect(md).toContain("Ransomware");
    expect(md).toContain("### 4.5 Customer exposure");
    expect(md).toContain("### 4.6 MITRE ATT&CK");
    expect(md).toContain("T1486");
    // The investigation timeline and the attachments section are no longer in the report.
    expect(md).not.toContain("Investigation timeline");
    expect(md).not.toContain("## 6 Attachments");
    // The incident timeline no longer carries an Evidence column.
    expect(md).not.toContain("| Time | Count | Severity | Event | MITRE | Findings | Evidence |");
  });

  it("renders the adversary-group hints subsection (4.6.1) with the not-attribution caveat", () => {
    const state = emptyState("c1");
    // Common techniques several real groups share → at least one hint clears the 3-overlap default.
    state.findings.push({ id: "f1", severity: "High", title: "intrusion", description: "",
      relatedIocs: [], mitreTechniques: ["T1566", "T1059.001", "T1078", "T1003", "T1021", "T1053"],
      sourceScreenshots: [], firstSeen: "2026-05-28T10:00:00.000Z", lastUpdated: "2026-05-28T10:00:00.000Z", status: "open" });

    const md = renderMarkdownReport(state);
    expect(md).toContain("#### 4.6.1 Adversary group hints");
    expect(md).toContain("not attribution");
    expect(md).toContain("| Group | Aliases | Overlap (exact) | Overlapping techniques |");
    expect(md).toContain("exact sub-technique match"); // the legend explaining bold
    expect(md).toMatch(/https:\/\/attack\.mitre\.org\/groups\/G\d{4}\//);
  });

  it("renders a complete-silence timeline gap in the §3.3 coverage section", () => {
    const state = emptyState("c1");
    // Dense one-minute cadence, then a 2-hour blackout, then activity resumes — one source.
    let ms = Date.parse("2026-05-28T08:00:00.000Z");
    for (let i = 0; i < 8; i++) {
      state.forensicTimeline.push({ id: `a${i}`, timestamp: new Date(ms).toISOString(), description: "logon",
        severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], sources: ["EventLog"] });
      ms += 60_000;
    }
    state.forensicTimeline.push({ id: "b0", timestamp: "2026-05-28T10:07:00.000Z", description: "logon",
      severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], sources: ["EventLog"] });

    const md = renderMarkdownReport(state);
    expect(md).toContain("### 3.3 Timeline coverage");
    expect(md).toContain("complete silence");
    expect(md).toContain("lead, not proof"); // the caveat
    expect(md).toContain("| Severity | Gap | Duration | Silent sources | Still active |");
  });

  it("shows a placeholder for adversary hints when the case has no techniques", () => {
    const md = renderMarkdownReport(emptyState("c9"));
    expect(md).toContain("#### 4.6.1 Adversary group hints");
    expect(md).toContain("No techniques identified yet");
  });

  it("includes every template chapter and shows placeholders for empty human sections", () => {
    const md = renderMarkdownReport(emptyState("c9"));
    for (const heading of [
      "## 1 Report metadata",
      "## 1.1 Report revisions",
      "## 1.3 Disclaimer and reading guide",
      "### 1.3.1 Timestamps",
      "### 1.3.2 Statements of probability",
      "### 1.3.3 Statements of confidence",
      "## 1.4 Intended audience",
      "## 2 Executive summary",
      "## 2.2 Investigation limitations",
      "## 2.3 Investigation goals and targets",
      "## 2.4 Glossary of terms",
      "## 3 Timeline of events",
      "### 3.1 Incident timeline",
      "### 3.2 Narrative timeline",
      "### 3.3 Timeline coverage",
      "## 4 Investigation",
      "## 5 Conclusions and recommendations",
    ]) {
      expect(md).toContain(heading);
    }
    // Empty human-only sections get the to-be-completed placeholder.
    expect(md).toContain("To be completed by the investigator");
    // Incident ID is optional — omitted entirely when not set (no case-id fallback).
    expect(md).not.toContain("**Incident ID:**");
    // Distribution list is optional — omitted entirely when empty.
    expect(md).not.toContain("## 1.2 Distribution list");
    // Business Impact Analysis is human-only and optional — omitted when not written.
    expect(md).not.toContain("## 2.1 Business Impact Analysis");
    // These sections were dropped from the report entirely.
    expect(md).not.toContain("Investigation timeline");
    expect(md).not.toContain("Investigation threads");
    expect(md).not.toContain("## 6 Attachments");
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

  it("renders the optional company name and logo on the title page (above the title)", () => {
    const logo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
    const meta = emptyReportMeta();
    meta.companyName = "Acme DFIR";
    meta.companyLogo = logo;
    const md = renderMarkdownReport(emptyState("c1"), meta);
    expect(md).toContain(`![Acme DFIR logo](${logo})`);
    expect(md).toContain("**Acme DFIR**");
    // Branding sits before the report title.
    expect(md.indexOf(logo)).toBeLessThan(md.indexOf("# Incident Investigation Report"));

    // Both are optional — a default (empty) meta emits no image and no company line.
    const plain = renderMarkdownReport(emptyState("c1"));
    expect(plain).not.toContain("![");
    expect(plain).not.toContain("data:image/");
  });

  it("lists compromised assets with their related IoCs (4.2)", () => {
    const s = emptyState("c1");
    const hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    s.iocs.push({ id: "i1", type: "hash", value: hash, firstSeen: "" });
    s.findings.push({ id: "f1", severity: "Critical", title: "RW", description: "", relatedIocs: ["i1"],
      sourceScreenshots: [], mitreTechniques: [], firstSeen: "", lastUpdated: "", status: "confirmed" });
    s.forensicTimeline.push({ id: "e1", timestamp: "", description: "encryptor", severity: "Critical",
      mitreTechniques: [], relatedFindingIds: ["f1"], sourceScreenshots: [], asset: "WIN-01", sha256: hash });

    const md = renderMarkdownReport(s);
    expect(md).toContain("### 4.2 Compromised assets");
    expect(md).toContain("| WIN-01 | host |");
    expect(md).toContain(hash);                              // related IoC value listed

    // Empty case shows the placeholder, not a table.
    expect(renderMarkdownReport(emptyState("c9"))).toContain("_No compromised assets identified yet._");
  });

  it("includes the Business Impact Analysis only when the investigator writes one", () => {
    expect(renderMarkdownReport(emptyState("c1"))).not.toContain("## 2.1 Business Impact Analysis");
    const meta = emptyReportMeta();
    meta.businessImpact = "Email and file services were down for 6 hours.";
    const md = renderMarkdownReport(emptyState("c1"), meta);
    expect(md).toContain("## 2.1 Business Impact Analysis");
    expect(md).toContain("Email and file services were down for 6 hours.");
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

  it("renders the attack path and incident timeline ordered by event time", () => {
    const state = emptyState("c1");
    state.attackerPath = "Initial access via phishing, then PsExec lateral movement, then ransomware.";
    state.forensicTimeline.push(
      { id: "e2", timestamp: "2026-05-20T15:00:00Z", description: "Ransomware encryptor executed",
        severity: "Critical", mitreTechniques: ["T1486"], relatedFindingIds: ["f1"], sourceScreenshots: ["s2.webp"] },
      { id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "Phishing email opened",
        severity: "High", mitreTechniques: ["T1566"], relatedFindingIds: [], sourceScreenshots: ["s1.webp"] },
    );

    const md = renderMarkdownReport(state);
    expect(md).toContain("### 4.1 Attack path");
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
    expect(md).toContain("### 4.7 Key investigative questions");
    expect(md).toContain("What was the initial access vector?");
    expect(md).toContain("collect 4624 logs on targets");
    expect(md).toContain("### 4.4 Indicators of compromise");
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

  it("does not render investigation threads (removed from the report)", () => {
    const state = emptyState("c1");
    state.openThreads.push(
      { id: "t1", description: "trace lateral movement", status: "open", openedAt: "2026-05-20T10:00:00Z", closedAt: null },
      { id: "t2", description: "identify C2 domain", status: "closed", openedAt: "2026-05-20T10:00:00Z", closedAt: "2026-05-20T12:00:00Z" },
    );
    const md = renderMarkdownReport(state);
    expect(md).not.toContain("Investigation threads");
    expect(md).not.toContain("trace lateral movement");
    expect(md).not.toContain("identify C2 domain");
  });

  it("does not render the answered-questions block in conclusions", () => {
    const state = emptyState("c1");
    state.keyQuestions.push(
      { id: "q1", question: "What was the initial access vector?", status: "answered", answer: "phishing email", pointer: "f3" },
    );
    const md = renderMarkdownReport(state);
    expect(md).not.toContain("Answered investigation questions");
  });

  it("includes customer exposure when provided", () => {
    const md = renderMarkdownReport(emptyState("c1"), undefined, {
      checkedAt: "2026-06-08T12:00:00Z",
      providers: ["Have I Been Pwned"],
      targets: { domains: ["example.com"], emails: ["alice@example.com"] },
      results: [{
        provider: "Have I Been Pwned",
        targetType: "email",
        target: "alice@example.com",
        email: "alice@example.com",
        breach: "Adobe",
        breachDate: "2013-10-04",
        exposedData: ["Email addresses", "Passwords"],
        secretPresent: true,
      }],
      errors: [],
    });

    expect(md).toContain("### 4.5 Customer exposure");
    expect(md).toContain("Have I Been Pwned");
    expect(md).toContain("credential material present");
  });

  it("renders the §4.9 beacon candidates section — placeholder when none, a row for a periodic channel", () => {
    const empty = emptyState("c1");
    const mdEmpty = renderMarkdownReport(empty);
    expect(mdEmpty).toContain("### 4.9 Beacon candidates");
    expect(mdEmpty).toContain("_No periodic outbound channels detected in the network events._");

    const beaconing = emptyState("c1");
    const start = Date.parse("2026-05-28T00:00:00.000Z");
    for (let i = 0; i < 6; i++) {
      beaconing.forensicTimeline.push({
        id: `n${i}`,
        timestamp: new Date(start + i * 60_000).toISOString(),
        description: "WIN-01 → 185.10.20.30",
        severity: "Info",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        asset: "WIN-01",
        dstIp: "185.10.20.30",
        port: 443,
        action: "network_send",
      });
    }
    const md = renderMarkdownReport(beaconing);
    expect(md).toContain("### 4.9 Beacon candidates");
    expect(md).toContain("185.10.20.30:443");
    expect(md).toContain("WIN-01");
    expect(md).not.toContain("_No periodic outbound channels detected");
  });

  it("renders the narrative timeline section from state when populated, placeholder when empty", () => {
    const empty = emptyState("c1");
    const mdEmpty = renderMarkdownReport(empty);
    expect(mdEmpty).toContain("### 3.2 Narrative timeline");
    expect(mdEmpty).toContain("_Narrative not yet generated");

    const withNarrative = emptyState("c1");
    withNarrative.narrativeTimeline = "At 09:00 UTC the attacker sent a phishing email.\n\nThis led to execution of a malicious macro.";
    const mdWithNarrative = renderMarkdownReport(withNarrative);
    expect(mdWithNarrative).toContain("### 3.2 Narrative timeline");
    expect(mdWithNarrative).toContain("At 09:00 UTC the attacker sent a phishing email.");
    expect(mdWithNarrative).not.toContain("_Narrative not yet generated");
  });
});
