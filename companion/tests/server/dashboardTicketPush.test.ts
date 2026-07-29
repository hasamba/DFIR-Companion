import { describe, it, expect, beforeAll } from "vitest";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// The dashboard is a single hand-written HTML file with inline JS and no DOM test harness in this
// repo, so behaviour cannot be asserted here (see dashboardCustodySection.test.ts). What CAN be
// asserted is the wiring that makes the Jira/ServiceNow push buttons real rather than decorative:
// markup with no handler, a handler hitting the wrong route, or a control that shows up even when
// the integration is unconfigured — the "one-click" framing #272 promised and #297 tracks.

let html: string;

beforeAll(async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  html = await readFile(join(here, "..", "..", "..", "public", "dashboard.html"), "utf8");
});

describe("Jira / ServiceNow push buttons in the finding panel (#297)", () => {
  it("puts a push chip for each ticket system on every finding row", () => {
    expect(html).toContain("function ticketPushChips(");
    const chips = html.slice(html.indexOf("function ticketPushChips("), html.indexOf("function ticketPushChips(") + 900);
    expect(chips).toContain("jira-push-btn");
    expect(chips).toContain("snow-push-btn");
    // The row template has to actually call it, or the helper is dead code.
    expect(html).toContain("${ticketPushChips(f.id)}");
  });

  it("hides both chips until the server says the integration is configured", () => {
    // Status arrives asynchronously, after findings may already have rendered — so visibility is a
    // CSS switch on <body>, not a render-time branch that a late answer could never reach.
    expect(html).toMatch(/\.jira-push-btn[^{]*\{[^}]*display:\s*none/);
    expect(html).toMatch(/\.snow-push-btn[^{]*\{[^}]*display:\s*none/);
    expect(html).toMatch(/body\.has-jira[^{]*\{[^}]*display:\s*inline/);
    expect(html).toMatch(/body\.has-servicenow[^{]*\{[^}]*display:\s*inline/);
    expect(html).toContain('fetch("/jira/status")');
    expect(html).toContain('fetch("/servicenow/status")');
    expect(html).toContain('document.body.classList.add("has-jira")');
    expect(html).toContain('document.body.classList.add("has-servicenow")');
  });

  it("pushes a single finding to the per-finding route", () => {
    const fn = html.slice(html.indexOf("function pushFindingToTicket("), html.indexOf("function bulkPushFindingsToTicket("));
    expect(fn).toContain("/push/${target}`");
    expect(fn).toContain("findingId");
    expect(fn).toContain('method: "POST"');
  });

  it("offers a bulk push in the finding bulk bar, hitting the bulk route", () => {
    expect(html).toContain('id="findingBulkJiraBtn"');
    expect(html).toContain('id="findingBulkSnowBtn"');
    const fn = html.slice(html.indexOf("function bulkPushFindingsToTicket("));
    expect(fn.slice(0, 1600)).toContain("/push/${target}/bulk`");
    expect(fn.slice(0, 1600)).toContain("findingIds");
  });

  it("wires every button to a handler", () => {
    expect(html).toContain('e.target.closest(".jira-push-btn")');
    expect(html).toContain('e.target.closest(".snow-push-btn")');
    expect(html).toContain('e.target.id === "findingBulkJiraBtn"');
    expect(html).toContain('e.target.id === "findingBulkSnowBtn"');
  });

  it("reports per-finding failures from a bulk push instead of claiming success", () => {
    // The route answers 200 with skipped>0 + warnings when some findings could not be filed; a UI
    // that only reads created/updated would tell the analyst everything went out.
    const fn = html.slice(html.indexOf("function bulkPushFindingsToTicket("));
    expect(fn.slice(0, 1600)).toContain("skipped");
    expect(fn.slice(0, 1600)).toContain("warnings");
  });
});
