import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FragmentsApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-fragments.js — data in, escaped markup string out (#415).
//
// The one contract worth testing hardest here is escaping. Every one of these renders content that
// came off the wire or out of evidence, and every one reaches the page through innerHTML. #387
// exists because of unsafe DOM sinks, so each builder gets a "what happens with a payload in it"
// case rather than only a happy path.

const f = loadDashboardModule<FragmentsApi>("dashboard-fragments.js", [
  "dashboard-escape.js",
  "dashboard-time.js",
  "dashboard-values.js",
  // proseHtml calls proseParagraphs. Bare, resolved as a global at call time in the browser; here
  // the file has to actually be present.
  "dashboard-text.js",
]);

const XSS = "<img src=x onerror=alert(1)>";
const ATTR_BREAK = '" onmouseover="alert(1)';

// The body of the three AI-prose panels. The split itself is pinned in dashboardText.test.ts; what
// matters here is that the text reaches innerHTML escaped, and that nothing renders for nothing.
describe("proseHtml", () => {
  it("wraps each paragraph in its own <p>", () => {
    expect(f.proseHtml("First para.\n\nSecond para.")).toBe("<p>First para.</p><p>Second para.</p>");
  });

  it("escapes model output before it reaches innerHTML", () => {
    expect(f.proseHtml(XSS)).toBe("<p>&lt;img src=x onerror=alert(1)&gt;</p>");
  });

  // An empty <p> would leave a blank line under a heading on a case that has no summary yet.
  it("renders nothing for nothing", () => {
    expect(f.proseHtml("")).toBe("");
    expect(f.proseHtml(null)).toBe("");
  });
});

// The Executive Summary panel: a fact strip read from the case, the AI summary on the left, and the
// synthesis's own known-vs-unknown ledger on the right. Everything here is built from state the
// dashboard already holds, so no AI call and no re-synthesis is needed to get the layout.
describe("execSummaryHtml", () => {
  const ev = (over: Record<string, unknown>) => ({
    id: String(Math.random()),
    timestamp: "2026-09-24T08:49:00Z",
    description: "x",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  });
  const account = (name: string) => ({ actor: { kind: "account", name } });

  it("keeps the dash placeholder for a case with nothing yet", () => {
    expect(f.execSummaryHtml({})).toBe('<div class="prose">—</div>');
    expect(f.execSummaryHtml(null)).toBe('<div class="prose">—</div>');
  });

  it("shows the summary alone when there are no events and no ledger", () => {
    const html = f.execSummaryHtml({ lastSummary: "One.\n\nTwo." });
    expect(html).toContain("<p>One.</p><p>Two.</p>");
    expect(html).not.toContain("exec-facts");
    expect(html).not.toContain("exec-assess");
  });

  it("builds the fact strip from the High+ events: hosts, accounts, window and span", () => {
    const html = f.execSummaryHtml({
      lastSummary: "s",
      forensicTimeline: [
        ev({ asset: "DESKTOP-1", timestamp: "2026-09-24T08:49:00Z", canonical: account("vagrant") }),
        ev({ asset: "DESKTOP-1", timestamp: "2026-09-24T09:00:00Z", canonical: account("vagrant") }),
        ev({ asset: "SRV-2", timestamp: "2026-09-24T08:55:00Z", endTimestamp: "2026-09-24T09:04:47Z" }),
        // Medium rows fall outside the attack window and do not name hosts.
        ev({ asset: "NOISE", severity: "Medium", timestamp: "2026-09-20T00:00:00Z" }),
      ],
    });
    expect(html).toContain("DESKTOP-1, SRV-2");
    expect(html).not.toContain("NOISE");
    expect(html).toContain("vagrant");
    expect(html).toContain("2026-09-24 08:49:00 → 09:04:47 UTC");
    expect(html).toContain("15 min");
  });

  it("falls back to every event when none is High or Critical", () => {
    const html = f.execSummaryHtml({
      lastSummary: "s",
      forensicTimeline: [ev({ asset: "HOST-A", severity: "Low" })],
    });
    expect(html).toContain("HOST-A");
  });

  it("names the first two hosts and counts the rest", () => {
    const html = f.execSummaryHtml({
      lastSummary: "s",
      forensicTimeline: ["A", "B", "C", "D"].map((h) => ev({ asset: h })),
    });
    expect(html).toContain("A, B +2");
  });

  it("puts the day on both ends of a window that crosses midnight", () => {
    const html = f.execSummaryHtml({
      lastSummary: "s",
      forensicTimeline: [
        ev({ timestamp: "2026-09-24T23:50:00Z" }),
        ev({ timestamp: "2026-09-26T01:10:00Z" }),
      ],
    });
    expect(html).toContain("2026-09-24 23:50:00 → 2026-09-26 01:10:00 UTC");
    expect(html).toContain("1 d 1 h");
  });

  it("counts Critical and High findings, but not dismissed ones", () => {
    const html = f.execSummaryHtml({
      lastSummary: "s",
      findings: [
        { severity: "Critical", status: "open" },
        { severity: "High", status: "confirmed" },
        { severity: "High", status: "dismissed" },
        { severity: "Medium", status: "open" },
      ],
    });
    expect(html).toContain("1 Critical · 1 High");
  });

  it("splits the ledger: confirmed/inferred are the assessment, speculated/unknown are still open", () => {
    const html = f.execSummaryHtml({
      lastSummary: "s",
      uncertainties: [
        { topic: "Adversary emulation", status: "inferred", basis: "sim script", gap: "" },
        { topic: "Credential dumping", status: "confirmed", basis: "LSASS dump", gap: "" },
        { topic: "Initial access", status: "unknown", basis: "", gap: "No VPN or mail logs" },
        { topic: "C2", status: "speculated", basis: "", gap: "No network capture" },
      ],
    });
    const [assess, open] = html.split("Still unconfirmed");
    expect(assess).toContain("Adversary emulation");
    expect(assess).toContain("Credential dumping");
    expect(assess).not.toContain("Initial access");
    expect(open).toContain("Initial access");
    expect(open).toContain("No VPN or mail logs");
    expect(open).toContain("C2");
    // Confirmed sorts ahead of inferred, so the strongest claim reads first.
    expect(assess.indexOf("Credential dumping")).toBeLessThan(assess.indexOf("Adversary emulation"));
  });

  it("escapes every model- and evidence-derived string", () => {
    const html = f.execSummaryHtml({
      lastSummary: XSS,
      forensicTimeline: [ev({ asset: XSS, canonical: account(XSS) })],
      uncertainties: [{ topic: XSS, status: "unknown", basis: ATTR_BREAK, gap: XSS }],
    });
    expect(html).not.toContain("<img");
    expect(html).not.toContain('" onmouseover');
  });
});

// The Narrative Timeline: the model writes one moment per paragraph and opens most of them with a
// time ("At 08:49, …"). The rail moves that time into its own column and links it to the first
// event of that minute, so the story becomes an index into the evidence. No AI change: it reads the
// text as written, and text it cannot read keeps its old prose layout.
describe("narrativeHtml", () => {
  const ev = (id: string, timestamp: string, severity = "High") => ({ id, timestamp, severity });
  const events = [
    ev("e1", "2026-09-24T08:49:12Z", "Medium"),
    ev("e2", "2026-09-24T08:49:40Z", "Critical"),
    ev("e3", "2026-09-24T08:58:00Z"),
    ev("e4", "2026-09-24T09:04:15Z"),
    // Same time of day on another date: must not be picked once the text names the day.
    ev("other-day", "2026-09-23T08:49:00Z", "Critical"),
  ];
  const story = [
    "On 24 September 2026, a workstation went through a scripted attack. The activity was real.",
    "At 08:49 and again at 08:58, the script turned off Defender. It copied tools into C:\\e.",
    "From 08:55 onward, it kept trying weak passwords.",
    "At 09:04:15 the attacker started stealing credentials.",
  ].join("\n\n");

  it("keeps plain prose when fewer than two paragraphs open with a time", () => {
    const text = "At 08:49, one thing happened.\n\nThen another.";
    expect(f.narrativeHtml(text, events)).toBe(f.proseHtml(text));
    expect(f.narrativeHtml("—", events)).toBe("<p>—</p>");
  });

  it("moves each opening time into the rail and restarts the sentence with a capital", () => {
    const html = f.narrativeHtml(story, events);
    expect(html).toContain('class="nt-rail"');
    expect(html).toContain("24 Sep 2026");
    expect(html).not.toContain("At 08:49");
    expect(html).not.toContain("From 08:55");
    expect(html).toContain('<span class="nt-lede">The script turned off Defender.</span> It copied tools');
    expect(html).toContain('<span class="nt-lede">A workstation went through a scripted attack.</span>');
    expect(html).toContain("onward");
  });

  it("links a time to the most severe event of that minute on the day the text names", () => {
    const html = f.narrativeHtml(story, events);
    expect(html).toMatch(/data-act="narrativeJumpToEvent" data-id="e2"[^>]*>(?:<b>)?08:49</);
    expect(html).toMatch(/data-id="e3"[^>]*>(?:<b>)?08:58</);
    expect(html).not.toContain("other-day");
  });

  it("matches a time with seconds to that second", () => {
    expect(f.narrativeHtml(story, events)).toMatch(/data-id="e4"[^>]*>(?:<b>)?09:04:15</);
  });

  it("leaves a time with no event as plain text", () => {
    const html = f.narrativeHtml(story, events);
    expect(html).not.toMatch(/data-act="narrativeJumpToEvent"[^>]*>(?:<b>)?08:55</);
    expect(html).toContain("08:55");
  });

  it("colors the dot with the most severe event at that time", () => {
    const html = f.narrativeHtml(story, events);
    expect(html).toContain("nt-spine nt-sev-critical");
  });

  it("explains each dot in a tooltip", () => {
    const html = f.narrativeHtml(story, events);
    expect(html).toContain('nt-spine nt-sev-critical" title="Most severe event at 08:49: Critical"');
    expect(html).toContain('title="No event in the forensic timeline at 08:55"');
    // The story's first paragraph opens with a date only.
    expect(html).toContain('title="Starts with a date but no time, so there is no event to match"');
    // A paragraph that opens with no time. A time later in the sentence does not count.
    const loose = f.narrativeHtml(`${story}\n\nThe script ran again at 09:10.`, events);
    expect(loose).toContain('title="Does not start with a time, so there is no event to match"');
  });

  it("finds the day from the case's events when the text never names one", () => {
    const text = "At 08:58, one.\n\nAt 09:04:15, two.";
    const html = f.narrativeHtml(text, events);
    expect(html).toMatch(/data-id="e3"/);
    expect(html).toMatch(/data-id="e4"/);
  });

  it("escapes the text and the event ids", () => {
    const text = `At 08:49, ${XSS}.\n\nAt 08:58, two.`;
    const html = f.narrativeHtml(text, [ev(ATTR_BREAK, "2026-09-24T08:49:00Z")]);
    expect(html).not.toContain("<img");
    expect(html).not.toContain('" onmouseover');
  });
});

describe("narrativeLead", () => {
  it("reads the common opening shapes", () => {
    expect(f.narrativeLead("At 08:49, x")).toMatchObject({ times: ["08:49"], rest: "X" });
    expect(f.narrativeLead("At 08:49 and again at 08:58, x")).toMatchObject({ times: ["08:49", "08:58"] });
    expect(f.narrativeLead("Shortly after 09:04 the host rebooted")).toMatchObject({
      times: ["09:04"],
      rest: "The host rebooted",
    });
    expect(f.narrativeLead("On 2026-09-24 at 08:49, x")).toMatchObject({
      date: "2026-09-24",
      times: ["08:49"],
    });
    expect(f.narrativeLead("On September 24, 2026, x")).toMatchObject({ date: "2026-09-24", times: [] });
  });

  it("does not read a time that is not at the start", () => {
    expect(f.narrativeLead("The script ran at 08:49.")).toBeNull();
    expect(f.narrativeLead("At home, the user slept.")).toBeNull();
  });
});

describe("mentionHtml", () => {
  it("chips a handle", () => {
    expect(f.mentionHtml("ping @bob")).toBe('ping <span class="mention-chip">@bob</span>');
  });

  // Both boundaries are deliberate and both have a concrete counterexample in the data: an email
  // address is not a mention, and a mention at the end of a sentence must not swallow the period.
  it("leaves an email address alone", () => {
    expect(f.mentionHtml("mail bob@example.com")).not.toContain("mention-chip");
  });

  it("stops the handle before trailing punctuation", () => {
    expect(f.mentionHtml("ping @bob.")).toBe('ping <span class="mention-chip">@bob</span>.');
  });

  it("escapes before chipping, so a comment cannot inject markup", () => {
    expect(f.mentionHtml(`${XSS} @bob`)).toContain("&lt;img");
    expect(f.mentionHtml(`${XSS} @bob`)).not.toContain("<img");
  });
});

describe("ticketPushChips", () => {
  it("renders both destinations carrying the finding id", () => {
    const html = f.ticketPushChips("fnd-1");
    expect(html).toContain('data-jira-fid="fnd-1"');
    expect(html).toContain('data-snow-fid="fnd-1"');
  });

  it("escapes the id out of the attribute", () => {
    expect(f.ticketPushChips(ATTR_BREAK)).not.toContain('" onmouseover=');
    expect(f.ticketPushChips(ATTR_BREAK)).toContain("&quot;");
  });
});

describe("renderVqlRows", () => {
  const rows = [
    { name: "a", pid: 1 },
    { name: "b", extra: { nested: true } },
  ];

  it("unions the columns across rows and renders a cell per column", () => {
    const html = f.renderVqlRows({ rows, total: 2 });
    expect(html).toContain("<th>name</th>");
    expect(html).toContain("<th>pid</th>");
    expect(html).toContain("<th>extra</th>");
    expect(html).toContain("<td>a</td>");
  });

  // esc() escapes quotes too since #1004, so the JSON's own quotes come out as &quot; — which the
  // browser decodes back to `"` in text content.
  it("JSON-encodes an object cell rather than rendering [object Object]", () => {
    expect(f.renderVqlRows({ rows, total: 2 })).toContain("<td>{&quot;nested&quot;:true}</td>");
  });

  it("says so plainly when there are no rows", () => {
    expect(f.renderVqlRows({ rows: [] })).toContain("0 rows.");
    expect(f.renderVqlRows({})).toContain("0 rows.");
  });

  // Two independent caps, and the footer says which one bit. A VQL result set is arbitrary
  // server-side data; rendering 200,000 rows into innerHTML hangs the tab.
  it("caps at 200 rows and 12 columns, and reports the column cap", () => {
    const many = Array.from({ length: 300 }, (_, i) => ({ n: i }));
    expect((f.renderVqlRows({ rows: many, total: 300 }).match(/<tr>/g) ?? []).length).toBe(201); // + header
    const wide = [Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`c${i}`, i]))];
    const html = f.renderVqlRows({ rows: wide, total: 1 });
    expect((html.match(/<th>/g) ?? []).length).toBe(12);
    expect(html).toContain("first 12 columns");
  });

  it("marks a server-truncated result", () => {
    expect(f.renderVqlRows({ rows, total: 999, truncated: true })).toContain("(capped)");
  });

  it("escapes a column name, which is whatever the query selected", () => {
    expect(f.renderVqlRows({ rows: [{ [XSS]: 1 }], total: 1 })).not.toContain("<img");
  });
});

describe("askStatusBadge", () => {
  it.each([
    ["answered", "#6bcB77"],
    ["partial", "#ffd93b"],
    ["unknown", "#9aa4b2"],
  ])("colours %s", (status, fg) => expect(f.askStatusBadge(status)).toContain(fg));

  it("falls back to unknown, and labels it", () => {
    expect(f.askStatusBadge(undefined)).toContain("unknown");
    expect(f.askStatusBadge("something-else")).toContain("#9aa4b2");
  });
});

describe("jobRowHtml", () => {
  const view = {
    job: { id: "j1", kind: "import", label: "evtx", status: "running" },
    detail: "3/10",
    cancel: true,
    resume: false,
  };

  it("shows the view's status text for a gate hold (#1801)", () => {
    const held = { ...view, job: { ...view.job, status: "cancelled" }, statusText: "held for analyst" };
    expect(f.jobRowHtml(held)).toContain('<span class="job-st job-cancelled">held for analyst</span>');
  });

  it("renders the job's identity and offers only the actions the view allows", () => {
    const html = f.jobRowHtml(view);
    expect(html).toContain('data-job-id="j1"');
    expect(html).toContain("job-running");
    expect(html).toContain("Cancel");
    expect(html).not.toContain("Resume");
  });

  // A drop sweep covers many files; the row lists them all behind a fold, escaped.
  it("lists a job's files behind a fold, escaped", () => {
    const html = f.jobRowHtml({ ...view, job: { ...view.job, files: ["a.csv", XSS] } });
    expect(html).toContain('<details class="job-files">');
    expect(html).toContain("2 files");
    expect(html).toContain("<li>a.csv</li>");
    expect(html).not.toContain("<img");
  });

  it("draws no file list for a job without files", () => {
    expect(f.jobRowHtml(view)).not.toContain("job-files");
  });

  it("hides the detail span when there is no detail", () => {
    expect(f.jobRowHtml({ ...view, detail: "" })).toContain('data-safe-style="display:none"');
  });

  // #1601: the server's served-version label wins over the bare alias; the alias is the fallback.
  it("shows the served-version label, falling back to the alias", () => {
    const labelled = { ...view.job, model: "sonnet", modelLabel: "sonnet → Sonnet 5" };
    expect(f.jobRowHtml({ ...view, job: labelled })).toContain("sonnet → Sonnet 5</span>");
    expect(f.jobRowHtml({ ...view, job: { ...view.job, model: "sonnet" } })).toContain(">sonnet</span>");
  });

  it("escapes a model label", () => {
    expect(f.jobRowHtml({ ...view, job: { ...view.job, model: "m", modelLabel: XSS } })).not.toContain(
      "<img",
    );
  });

  it("escapes a label, which comes from an imported filename", () => {
    expect(f.jobRowHtml({ ...view, job: { ...view.job, label: XSS } })).not.toContain("<img");
  });

  // The bar (#1428). A running job with progress draws it at the right width; one without progress
  // still emits the node — hidden — so the in-place patch has something to fill once progress arrives.
  it("draws a progress bar sized to the job's progress", () => {
    const html = f.jobRowHtml({ ...view, job: { ...view.job, progress: { done: 3, total: 10 } } });
    expect(html).toMatch(/class="job-bar"[^>]*role="progressbar"/);
    expect(html).toContain('aria-valuenow="30"');
    expect(html).toMatch(/class="job-bar-fill"[^>]*width:30%/);
  });

  it("emits the bar hidden when the job carries no progress", () => {
    expect(f.jobRowHtml(view)).toMatch(/class="job-bar"[^>]*display:none/);
  });
});

describe("qaSpan", () => {
  it("carries the value in both the attribute and the text", () => {
    expect(f.qaSpan("ip", "10.0.0.1")).toBe(
      '<span class="qa-val" data-vtype="ip" data-val="10.0.0.1">10.0.0.1</span>',
    );
  });

  it("adds evidence and IOC ids only when the context has them", () => {
    expect(f.qaSpan("ip", "x", { evid: 1, iocid: 2 })).toContain('data-evid="1" data-iocid="2"');
    expect(f.qaSpan("ip", "x", {})).not.toContain("data-evid");
    // Explicitly `!= null`, so id 0 survives — an id-by-index scheme starts at zero.
    expect(f.qaSpan("ip", "x", { evid: 0 })).toContain('data-evid="0"');
  });

  // The value lands in an attribute AND in text. Only the attribute copy needs its quotes escaped
  // — esc() deliberately leaves quotes alone in text, where they cannot break out of anything —
  // so the assertion is about the attribute, not about the string as a whole.
  it("escapes the value out of the attribute it is embedded in", () => {
    const html = f.qaSpan("ip", ATTR_BREAK);
    expect(html).toContain('data-val="&quot; onmouseover=&quot;alert(1)"');
    expect(html).not.toMatch(/data-val="[^"]*" onmouseover/);
  });
});

describe("citeFindings", () => {
  it("numbers the citations from one, de-duplicating", () => {
    const html = f.citeFindings(["a", "b", "a"]);
    expect(html).toContain("[1]");
    expect(html).toContain("[2]");
    expect(html).not.toContain("[3]");
  });

  it("renders nothing for no ids", () => {
    expect(f.citeFindings([])).toBe("");
    expect(f.citeFindings(null)).toBe("");
    expect(f.citeFindings([""])).toBe("");
  });

  // `.map(String).filter(Boolean)` in that order, so a null id survives as the four-character
  // string "null" and gets its own citation badge pointing at finding "null". Pinned rather than
  // fixed: the badge is a dead link, not a wrong one, and reordering the two calls changes what
  // the narrative renders.
  it("turns a null id into a citation for the literal string null", () => {
    expect(f.citeFindings([null])).toContain('data-fid="null"');
  });
});

describe("complianceDueBadge", () => {
  it("names the state and shows the date", () => {
    expect(f.complianceDueBadge({ status: "overdue", dueAt: "2026-03-01T00:00:00Z" })).toContain("OVERDUE");
    expect(
      f.complianceDueBadge({ status: "due-soon", remainingDays: 2, dueAt: "2026-03-01T00:00:00Z" }),
    ).toContain("2d left");
    expect(
      f.complianceDueBadge({ status: "open", remainingDays: 30, dueAt: "2026-03-01T00:00:00Z" }),
    ).toContain("due 2026-03-01");
  });

  it("renders nothing when there is no deadline", () => {
    expect(f.complianceDueBadge(null)).toBe("");
  });
});

describe("ceChip", () => {
  it("offers a remove control for a manual entry and not for an auto-discovered one", () => {
    expect(f.ceChip("host1", "asset", false)).toContain("×");
    expect(f.ceChip("host1", "asset", true)).toContain("auto");
    expect(f.ceChip("host1", "asset", true)).not.toContain('class="x"');
  });

  it("escapes the value out of the data attributes it is embedded in", () => {
    expect(f.ceChip(ATTR_BREAK, "asset", false)).toContain('data-val="&quot; onmouseover=&quot;alert(1)"');
  });
});

describe("evidenceLinks", () => {
  it("links each file under the case, URL-encoding the filename", () => {
    const html = f.evidenceLinks("case 1", ["a b.evtx"]);
    expect(html).toContain("/cases/case%201/evidence/a%20b.evtx");
    expect(html).toContain('rel="noopener"');
  });

  it("de-duplicates and drops falsy filenames", () => {
    expect((f.evidenceLinks("c", ["a", "a", "", null]).match(/<a /g) ?? []).length).toBe(1);
  });

  it("renders nothing without a case or without files", () => {
    expect(f.evidenceLinks("", ["a"])).toBe("");
    expect(f.evidenceLinks("c", [])).toBe("");
    expect(f.evidenceLinks("c", null)).toBe("");
  });
});

describe("cockpitCardControls", () => {
  it("offers only Open for a card that is neither a lead nor a hypothesis", () => {
    const html = f.cockpitCardControls({ id: "c1", kind: "alert" }, false);
    expect(html).toContain("Open");
    expect(html).not.toContain("Pin");
  });

  it("offers the full action set for a live lead", () => {
    const html = f.cockpitCardControls({ id: "c1", kind: "lead" }, false);
    for (const action of ["Pin", "Dismiss", "Defer", "Assign"]) expect(html).toContain(action);
  });

  it("offers the full action set for a recommended next step (#1424)", () => {
    const html = f.cockpitCardControls({ id: "step:s1", kind: "step" }, false);
    for (const action of ["Pin", "Dismiss", "Defer", "Assign"]) expect(html).toContain(action);
  });

  it("collapses a parked card to Open plus Restore", () => {
    const html = f.cockpitCardControls({ id: "c1", kind: "lead" }, true);
    expect(html).toContain("Restore");
    expect(html).not.toContain("Dismiss");
  });

  it("reads Unpin when pinned, and Reassign when already owned", () => {
    expect(f.cockpitCardControls({ id: "c1", kind: "lead", pinned: true }, false)).toContain("Unpin");
    expect(f.cockpitCardControls({ id: "c1", kind: "lead", assignee: "ada" }, false)).toContain("Reassign");
  });

  it("adds a Fleet collection jump beside Open on an import-evidence card", () => {
    const html = f.cockpitCardControls(
      { id: "gap:import-evidence", kind: "gap", target: { panel: "import" } },
      false,
    );
    expect(html).toContain('data-act="cockpitOpenTarget"');
    expect(html).toContain('data-act="openFleetCollection"');
    expect(html).toContain("Fleet collection");
  });

  it("keeps the Fleet collection jump off every other card", () => {
    const html = f.cockpitCardControls({ id: "c1", kind: "gap", target: { panel: "findings" } }, false);
    expect(html).not.toContain("openFleetCollection");
    expect(f.cockpitCardControls({ id: "c2", kind: "alert" }, false)).not.toContain("openFleetCollection");
  });
});

describe("cockpitCardHtml", () => {
  const NOW = Date.parse("2026-03-01T12:00:00.000Z");
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });
  afterEach(() => vi.useRealTimers());

  it("renders the card and reaches across to dashboard-time for the age", () => {
    const html = f.cockpitCardHtml(
      {
        id: "c1",
        kind: "lead",
        title: "T",
        summary: "S",
        action: "A",
        severity: "High",
        occurredAt: new Date(NOW - 3_600_000).toISOString(),
      },
      false,
    );
    expect(html).toContain("sev-High");
    expect(html).toContain("Next → A");
    expect(html).toContain("1h ago"); // cockpitAge, from the sibling module
  });

  it("caps the evidence buttons at three", () => {
    const html = f.cockpitCardHtml(
      { id: "c1", kind: "lead", title: "T", evidenceIds: ["1", "2", "3", "4"] },
      false,
    );
    expect((html.match(/now-evidence/g) ?? []).length).toBe(3);
  });

  it("shows confidence at zero, which a falsy check would have dropped", () => {
    expect(f.cockpitCardHtml({ id: "c1", kind: "lead", title: "T", confidence: 0 }, false)).toContain(
      "0% confidence",
    );
  });

  it("escapes the title, which is model-generated text", () => {
    expect(f.cockpitCardHtml({ id: "c1", kind: "lead", title: XSS }, false)).not.toContain("<img");
  });
});

describe("rvAnnotationRows", () => {
  const workflow = {
    versionId: "v1",
    annotations: [
      {
        id: "a1",
        category: "accuracy",
        impact: "high",
        targetType: "finding",
        targetId: "f1",
        message: "check this",
      },
      {
        id: "a2",
        category: "clarity",
        impact: "low",
        targetType: "finding",
        targetId: "f2",
        message: "ok",
        resolvedAt: "x",
        resolvedByDisplayName: "Ada",
      },
    ],
  };

  it("offers Resolve only on the unresolved rows", () => {
    const html = f.rvAnnotationRows(workflow);
    expect((html.match(/data-rv-resolve/g) ?? []).length).toBe(1);
    expect(html).toContain("resolved by Ada");
    expect(html).toContain("unresolved");
  });

  it("names an anonymous resolver rather than rendering undefined", () => {
    expect(f.rvAnnotationRows({ versionId: "v", annotations: [{ id: "a", resolvedAt: "x" }] })).toContain(
      "resolved by investigator",
    );
  });

  it("renders nothing for a workflow with no annotations", () => {
    expect(f.rvAnnotationRows(undefined)).toBe("");
    expect(f.rvAnnotationRows({ annotations: [] })).toBe("");
  });
});

describe("wizRenderFields", () => {
  it("renders a password input for a secret and a text input otherwise", () => {
    expect(f.wizRenderFields([{ key: "K", label: "L", secret: true }])).toContain('type="password"');
    expect(f.wizRenderFields([{ key: "K", label: "L" }])).toContain('autocomplete="off"');
  });

  it("ties the input id to the env key via wizFieldId, from the sibling module", () => {
    expect(f.wizRenderFields([{ key: "ANTHROPIC_API_KEY", label: "L" }])).toContain(
      'id="wizf-ANTHROPIC_API_KEY"',
    );
  });

  it("escapes the label and hint", () => {
    expect(f.wizRenderFields([{ key: "K", label: XSS, hint: XSS }])).not.toContain("<img");
  });
});

describe("caseStatsBarChart", () => {
  const days = [
    { date: "2026-02-01", imports: 1, rows: 10 },
    { date: "2026-02-02", imports: 3, rows: 100 },
  ];

  it("scales the bars to the busiest day and labels both ends", () => {
    const svg = f.caseStatsBarChart(days);
    expect((svg.match(/<rect /g) ?? []).length).toBe(2);
    expect(svg).toContain("2026-02-01");
    expect(svg).toContain("2026-02-02");
    expect(svg).toContain("3 imports, 100 rows");
    expect(svg).toContain("1 import,"); // singular
  });

  it("gives a zero-row day a visible stub rather than a bar of no height", () => {
    expect(f.caseStatsBarChart([{ date: "d", imports: 0, rows: 0 }])).toContain('height="2"');
  });

  it("says so when there is nothing to chart", () => {
    expect(f.caseStatsBarChart([])).toContain("no imports yet");
  });
});

describe("ntfTargetSummary", () => {
  it("summarises an SMTP target and flags a stored password", () => {
    const ch = { type: "email", smtp: { host: "mail", port: 587, to: ["a@b"], hasPassword: true } };
    expect(f.ntfTargetSummary(ch)).toBe("mail:587 → a@b 🔑");
  });

  it("reports a missing credential loudly for both credentialled types", () => {
    expect(f.ntfTargetSummary({ type: "telegram", telegram: { chatId: "5" } })).toContain("no token");
    expect(f.ntfTargetSummary({ type: "slack" })).toContain("no webhook URL");
    expect(f.ntfTargetSummary({ type: "slack", hasWebhookUrl: true })).toBe("webhook configured");
  });

  // hasBotToken/hasPassword/hasWebhookUrl — the summary is built from booleans the server sends
  // instead of the secrets themselves, so a redacted value can never be rendered as a real one.
  it("never renders a secret, only whether one is stored", () => {
    const ch = { type: "telegram", telegram: { hasBotToken: true, botToken: "SECRET", chatId: "5" } };
    expect(f.ntfTargetSummary(ch)).toBe("token configured → chat: 5");
    expect(f.ntfTargetSummary(ch)).not.toContain("SECRET");
  });

  // A borrowed war-room token is still a working channel, so it must not read as "no token" — but
  // it says WHERE it came from, so nobody hunts for a token they never typed here.
  it("names the .env token when the channel borrows the war-room bot's", () => {
    const ch = { type: "telegram", telegram: { hasBotToken: true, usesEnvBotToken: true, chatId: "5" } };
    expect(f.ntfTargetSummary(ch)).toBe("token from .env → chat: 5");
  });
});
