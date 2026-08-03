import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-fragments.js — data in, escaped markup string out (#415).
//
// The one contract worth testing hardest here is escaping. Every one of these renders content that
// came off the wire or out of evidence, and every one reaches the page through innerHTML. #387
// exists because of unsafe DOM sinks, so each builder gets a "what happens with a payload in it"
// case rather than only a happy path.

const f = loadDashboardModule("dashboard-fragments.js", [
  "dashboard-escape.js",
  "dashboard-time.js",
  "dashboard-values.js",
]);

const XSS = "<img src=x onerror=alert(1)>";
const ATTR_BREAK = '" onmouseover="alert(1)';

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

  // esc() escapes `& < >` and NOT quotes — escAttr is the one that adds those, and this is text
  // content rather than an attribute value, so the JSON keeps its own quotes.
  it("JSON-encodes an object cell rather than rendering [object Object]", () => {
    expect(f.renderVqlRows({ rows, total: 2 })).toContain('<td>{"nested":true}</td>');
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

  it("renders the job's identity and offers only the actions the view allows", () => {
    const html = f.jobRowHtml(view);
    expect(html).toContain('data-job-id="j1"');
    expect(html).toContain("job-running");
    expect(html).toContain("Cancel");
    expect(html).not.toContain("Resume");
  });

  it("hides the detail span when there is no detail", () => {
    expect(f.jobRowHtml({ ...view, detail: "" })).toContain('data-safe-style="display:none"');
  });

  it("escapes a label, which comes from an imported filename", () => {
    expect(f.jobRowHtml({ ...view, job: { ...view.job, label: XSS } })).not.toContain("<img");
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

  it("collapses a parked card to Open plus Restore", () => {
    const html = f.cockpitCardControls({ id: "c1", kind: "lead" }, true);
    expect(html).toContain("Restore");
    expect(html).not.toContain("Dismiss");
  });

  it("reads Unpin when pinned, and Reassign when already owned", () => {
    expect(f.cockpitCardControls({ id: "c1", kind: "lead", pinned: true }, false)).toContain("Unpin");
    expect(f.cockpitCardControls({ id: "c1", kind: "lead", assignee: "ada" }, false)).toContain("Reassign");
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
});
