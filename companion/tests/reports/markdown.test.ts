import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

describe("renderMarkdownReport uncertainty ledger (#73)", () => {
  it("renders the uncertainty ledger, weakest status first, with basis and gap", () => {
    const state = emptyState("c1");
    state.uncertainties = [
      { topic: "credential theft", status: "confirmed", basis: "Mimikatz on DC01", gap: "" },
      { topic: "attribution", status: "speculated", basis: "TTP overlap", gap: "pivot the C2 infra via CTI" },
    ];
    const md = renderMarkdownReport(state);
    expect(md).toContain("### Analytical confidence — uncertainty ledger");
    expect(md).toContain("🟠 Speculated");
    expect(md).toContain("✅ Confirmed");
    expect(md).toContain("pivot the C2 infra via CTI");
    // Weakest status (speculated) must appear before the confirmed row.
    expect(md.indexOf("attribution")).toBeLessThan(md.indexOf("credential theft"));
  });

  it("shows a placeholder when no uncertainties were assessed", () => {
    const md = renderMarkdownReport(emptyState("c1"));
    expect(md).toContain("### Analytical confidence — uncertainty ledger");
    expect(md).toContain("Not assessed yet — run synthesis.");
  });
});

describe("renderMarkdownReport", () => {
  it("cites each finding's supporting forensic events as a numbered footnote list (#222)", () => {
    const state = emptyState("c1");
    state.findings.push({ id: "f1", severity: "High", title: "Lateral movement", description: "PsExec used",
      relatedIocs: [], mitreTechniques: [], sourceScreenshots: [], firstSeen: "2026-05-28T10:00:00.000Z",
      lastUpdated: "2026-05-28T10:00:00.000Z", status: "open", relatedEventIds: ["e1", "e2"] });
    state.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-28T09:00:00.000Z", description: "PsExec service installed on DC01",
        severity: "High", mitreTechniques: [], relatedFindingIds: ["f1"], sourceScreenshots: [] },
      { id: "e2", timestamp: "2026-05-28T09:05:00.000Z", description: "PsExec connected to FS01",
        severity: "High", mitreTechniques: [], relatedFindingIds: ["f1"], sourceScreenshots: [] },
    );

    const md = renderMarkdownReport(state);
    expect(md).toContain("Cited events: [1] e1, [2] e2");
    expect(md).toContain("[1] 2026-05-28T09:00:00.000Z [High] PsExec service installed on DC01");
    expect(md).toContain("[2] 2026-05-28T09:05:00.000Z [High] PsExec connected to FS01");
  });

  it("falls back to the reverse relatedFindingIds link when a finding has no relatedEventIds of its own (#222)", () => {
    const state = emptyState("c1");
    state.findings.push({ id: "f1", severity: "High", title: "Legacy finding", description: "no citations field",
      relatedIocs: [], mitreTechniques: [], sourceScreenshots: [], firstSeen: "2026-05-28T10:00:00.000Z",
      lastUpdated: "2026-05-28T10:00:00.000Z", status: "open" });
    state.forensicTimeline.push(
      { id: "e9", timestamp: "2026-05-28T09:00:00.000Z", description: "legacy backlinked event",
        severity: "High", mitreTechniques: [], relatedFindingIds: ["f1"], sourceScreenshots: [] },
    );

    const md = renderMarkdownReport(state);
    expect(md).toContain("Cited events: [1] e9");
  });

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

  it("shows only found exposure rows — clean 'checked, no breach' rows are dropped", () => {
    const md = renderMarkdownReport(emptyState("c1"), undefined, {
      checkedAt: "2026-06-08T12:00:00Z",
      providers: ["Have I Been Pwned"],
      targets: { domains: [], emails: ["alice@example.com", "bob@example.com"] },
      results: [
        { provider: "Have I Been Pwned", targetType: "email", target: "alice@example.com", email: "alice@example.com", breach: "Adobe" },
        { provider: "Have I Been Pwned", targetType: "email", target: "bob@example.com", email: "bob@example.com" }, // clean → dropped
      ],
      errors: [],
    });

    // Assert on the table-row form (`email:<target>`), which only appears in a rendered row —
    // both addresses also appear in the "Customer emails:" targets line, so a bare contains is ambiguous.
    expect(md).toContain("email:alice@example.com");
    expect(md).not.toContain("email:bob@example.com");
  });

  it("renders 'no exposures found' when every checked target is clean", () => {
    const md = renderMarkdownReport(emptyState("c1"), undefined, {
      checkedAt: "2026-06-08T12:00:00Z",
      providers: ["Have I Been Pwned"],
      targets: { domains: [], emails: ["clean@example.com"] },
      results: [{ provider: "Have I Been Pwned", targetType: "email", target: "clean@example.com", email: "clean@example.com" }],
      errors: [],
    });

    expect(md).toContain("_No customer exposures found._");
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

  it("renders the Hypotheses section when hypotheses are passed (#140), concluded ones first", () => {
    const s = emptyState("c1");
    const now = "2026-06-22T00:00:00.000Z";
    const hyp = [
      { id: "h1", title: "Open lead", description: "", expectedOutcome: "proxy logs showing a click",
        status: "open" as const, relatedTechniques: ["T1566"], relatedEventIds: ["e1"], relatedIocIds: [],
        assignee: "", notes: "", source: "analyst" as const, analystTouched: true, createdAt: now, updatedAt: now },
      { id: "h2", title: "Initial access was phishing", description: "macro-laden attachment",
        expectedOutcome: "", status: "supported" as const, relatedTechniques: [], relatedEventIds: ["e2", "e3"],
        relatedIocIds: ["i1"], assignee: "", notes: "confirmed via prefetch", source: "synthesis" as const,
        analystTouched: false, sourceKey: "synth:abc", createdAt: now, updatedAt: now },
    ];
    const md = renderMarkdownReport(s, undefined, undefined, undefined, undefined, undefined, undefined, undefined, hyp);
    expect(md).toContain("## Hypotheses");
    expect(md).toContain("### Initial access was phishing — Supported");
    expect(md).toContain("**Expected outcome (what would prove or disprove this):** proxy logs showing a click");
    expect(md).toContain("**Analyst notes:** confirmed via prefetch");
    expect(md).toContain("2 supporting events");
    // Concluded (supported) hypothesis is rendered before the still-open one.
    expect(md.indexOf("Initial access was phishing")).toBeLessThan(md.indexOf("Open lead"));
  });

  it("omits the Hypotheses section when there are none", () => {
    expect(renderMarkdownReport(emptyState("c1"))).not.toContain("## Hypotheses");
  });

  describe("geographic distribution section (#133)", () => {
    it("renders a §4.10 table for geo-located IPs", () => {
      const s = emptyState("c1");
      s.iocs.push({
        id: "i1",
        type: "ip",
        value: "8.8.8.8",
        firstSeen: "2026-01-01T00:00:00Z",
        enrichments: [{
          source: "GeoIP",
          verdict: "unknown",
          fetchedAt: "2026-01-01T00:00:00Z",
          lat: 37.4,
          lon: -122.1,
          country: "US",
          city: "Mountain View",
          tags: ["AS15169"],
        }],
      });
      s.forensicTimeline.push({
        id: "e1",
        timestamp: "2026-01-02T10:00:00Z",
        description: "Suspicious outbound connection to 8.8.8.8",
        severity: "High",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        dstIp: "8.8.8.8",
        sources: ["Suricata"],
      });
      const md = renderMarkdownReport(s);
      expect(md).toContain("### 4.10 Geographic distribution");
      expect(md).toContain("8.8.8.8");
      expect(md).toContain("US");
    });

    it("renders a placeholder when there are no geo-located IPs", () => {
      const md = renderMarkdownReport(emptyState("c1"));
      expect(md).toContain("### 4.10 Geographic distribution");
      expect(md).toContain("No geo-located IP addresses");
    });

    it("renders country-level in the City cell for an approximate (no city) marker", () => {
      const s = emptyState("c1");
      s.iocs.push({
        id: "i1",
        type: "ip",
        value: "1.2.3.4",
        firstSeen: "2026-01-01T00:00:00Z",
        enrichments: [{
          source: "GeoIP",
          verdict: "unknown",
          fetchedAt: "2026-01-01T00:00:00Z",
          country: "DE",
        }],
      });
      const md = renderMarkdownReport(s);
      expect(md).toContain("### 4.10 Geographic distribution");
      expect(md).toContain("country-level");
    });
  });

  describe("IOC composite risk column (#63)", () => {
    it("renders a Risk column with the tier + top factor", () => {
      const s = emptyState("c1");
      s.iocs.push({ id: "i1", type: "ip", value: "9.9.9.9", firstSeen: "t0", enrichments: [
        { source: "VirusTotal", verdict: "malicious", fetchedAt: "" },
        { source: "AbuseIPDB", verdict: "malicious", fetchedAt: "" },
      ] });
      s.forensicTimeline.push({ id: "e1", timestamp: "2026-01-01T00:00:00Z", description: "C2 to 9.9.9.9",
        severity: "Critical", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], srcIp: "9.9.9.9", sources: ["EDR", "FW"] });
      const md = renderMarkdownReport(s);
      expect(md).toContain("| ID | Type | Value | First seen | Sources | Risk |");
      expect(md).toContain("**critical**");
    });
  });

  describe("synthesis coverage footnote (#62)", () => {
    const coverage = { inWindow: 412, considered: 287, omittedBudget: 120, omittedLegitimate: 5, omittedScope: 0, omittedHighSeverity: 8, promptTokensEstimate: 61000 };

    it("renders the coverage section when a snapshot is passed", () => {
      const md = renderMarkdownReport(emptyState("c1"), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, [], coverage);
      expect(md).toContain("### 3.4 Synthesis coverage");
      expect(md).toContain("considered 287 of 412");
      expect(md).toContain("safety-net backfill");
    });

    it("omits the coverage section by default (no snapshot passed)", () => {
      const md = renderMarkdownReport(emptyState("c1"));
      expect(md).not.toContain("### 3.4 Synthesis coverage");
    });
  });

  describe("model performance footnote (#74)", () => {
    const modelPerf = { synthModel: "anthropic/claude-sonnet-5", findingsCount: 12, highSeverityBackfillCount: 2, parseRetries: 1 };

    it("renders the model-performance section when a snapshot is passed", () => {
      const md = renderMarkdownReport(emptyState("c1"), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, [], undefined, modelPerf);
      expect(md).toContain("### 3.5 Model performance");
      expect(md).toContain("anthropic/claude-sonnet-5");
      expect(md).toContain("12 findings");
      expect(md).toContain("safety net");
    });

    it("adds the second-opinion agreement clause when recorded", () => {
      const withSecondOpinion = {
        ...modelPerf,
        secondOpinionPerf: { modelA: "anthropic/claude-sonnet-5", modelB: "openai/gpt-5", agreementCount: 8, deltaCount: 2, agreementRate: 0.8, at: "2026-07-18T10:05:00.000Z" },
      };
      const md = renderMarkdownReport(emptyState("c1"), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, [], undefined, withSecondOpinion);
      expect(md).toContain("openai/gpt-5");
      expect(md).toContain("80% agreement");
    });

    it("omits the model-performance section by default (no snapshot passed)", () => {
      const md = renderMarkdownReport(emptyState("c1"));
      expect(md).not.toContain("### 3.5 Model performance");
    });
  });
});
