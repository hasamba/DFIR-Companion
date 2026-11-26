// AI Agent Forensics panel (#2690): the matched text is an instruction an attacker planted, so the
// panel may only ever write it as text. And the panel is wired everywhere §8 lists.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { DASHBOARD_SECTION_IDS, BUILT_IN_DASHBOARD_VIEWS } from "../../src/analysis/dashboardViews.js";

const PUBLIC = join(import.meta.dirname, "..", "..", "..", "public");
const js = readFileSync(join(PUBLIC, "js", "dashboard-ai-agent.js"), "utf8");
const html = readFileSync(join(PUBLIC, "dashboard.html"), "utf8");
const css = readFileSync(join(PUBLIC, "css", "dashboard-toolbar.css"), "utf8");

describe("AI Agent Forensics panel", () => {
  it("never writes HTML from data", () => {
    const code = js.replace(/^\s*\/\/.*$/gm, ""); // the header says "never innerHTML"
    expect(code).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
  });

  it("links only to the pinned GitHub rule and to the Velociraptor collection", () => {
    expect(js).toContain("/^https:\\/\\/github\\.com\\//.test(h.link)");
    expect(js).toContain('rel = "noopener noreferrer"');
  });

  it("is a registered section, in the visibility editor and in Triage, Hunt Prep and Deep-Dive", () => {
    expect(DASHBOARD_SECTION_IDS).toContain("sec-aiagent");
    expect(html).toContain('<section id="sec-aiagent"');
    expect(html).toContain('{ id: "sec-aiagent", label: "AI Agent Forensics" }');
    const inViews = BUILT_IN_DASHBOARD_VIEWS.filter((v) => v.sections.includes("sec-aiagent")).map(
      (v) => v.id,
    );
    expect(inViews).toEqual(expect.arrayContaining(["triage", "hunt-prep", "deep-dive"]));
  });

  it("has a toolbar button with a ::before icon, so it survives the icons-only collapse", () => {
    expect(html).toContain('id="aiAgentBtn"');
    expect(css).toMatch(/#aiAgentBtn::before \{ background-image/);
    expect(css).toMatch(/#cloudCollectBtn::before, #aiAgentBtn::before,/);
  });

  it("labels grades provisional and every run sensitive", () => {
    expect(js).toContain(
      "Severity grades are a first estimate: they have not yet been checked against real developer machines, so some may change.",
    );
    expect(js).toContain("SENSITIVE");
  });

  it("lists rules not run only in a run's report, never in the panel before a run, and shows a refusal as a warning", () => {
    // The pre-run list was the same every time and read as a failure (user decision, 2026-11-24).
    expect(js).not.toContain("notRunBlock(rules.notRun");
    expect(js).toContain("notRunBlock(r.notRun)");
    expect(js).toContain('msg.classList.toggle("aa-warn", !r.ok)');
  });

  it("lists a case's endpoints through the case route, and explains a 403 accurately (#2725)", () => {
    expect(js).toContain("/ai-agent/endpoints`");
    expect(js).toContain("Only an administrator can list endpoints");
    expect(js).toContain("You need write access to this case to list its endpoints");
    // The Settings advice is for an empty inventory, never for a refusal: a non-admin cannot open Settings.
    const refusal = js.slice(js.indexOf("inv.status === 403"), js.indexOf("Only an administrator") + 100);
    expect(refusal).not.toContain("Settings");
  });

  it("endpoint picker: filters the whole list, caps only the drawn rows, says so, and keeps picks (#2887)", () => {
    const picker = js.slice(js.indexOf("async function endpointPicker"), js.indexOf("function scopeBoxes"));
    expect(picker).not.toContain(".slice(0, 2000)");
    expect(picker).toContain(
      "veloPickerRows(clients, filter.value, undefined, { onlineOnly: online.checked })",
    );
    expect(picker).toContain("veloPickerNote(view)");
    // A list the server cut at its row limit says so above the picker.
    expect(picker).toContain("veloClientsCutNotice(inv.body)");
    // A pick survives a filter that hides its row: the picks live in a Set, not in the drawn checkboxes.
    expect(picker).toContain("const picked = new Set()");
    expect(picker).toContain("box.checked = picked.has(c.clientId)");
    expect(picker).toContain("selected: () => [...picked]");
    expect(picker).not.toContain("input:checked");
  });

  it("endpoint picker: Refresh re-reads the list through the right route, Online only filters it (#2898)", () => {
    const picker = js.slice(js.indexOf("async function endpointPicker"), js.indexOf("function scopeBoxes"));
    // Inside a case the case route (case writers); with no case the administrator's fleet refresh.
    expect(picker).toContain(
      'const refreshUrl = caseId ? `${listUrl}/refresh` : "/velociraptor/clients/refresh"',
    );
    expect(picker).toContain("await post(refreshUrl)");
    expect(picker).toContain('el("button", "Refresh", "aa-refresh")');
    expect(picker).toContain("Online only (seen in the last 15 min)");
    expect(picker).toContain('online.addEventListener("change", draw)');
    // Each row says when the endpoint was last seen; picks survive a refresh (one Set for the panel).
    expect(picker).toContain("veloSeenAgo(c)");
    expect(picker.match(/new Set\(\)/g)).toHaveLength(1);
    // A failed refresh keeps the list shown and says why, instead of wiping it.
    expect(picker).toContain("Refresh failed: ");
    // The panel no longer sends the analyst to Settings to refresh.
    expect(picker).not.toContain("Settings → Velociraptor");
  });

  it("run card: a live status line, where results go, and plain-English labels (#2898)", () => {
    const card = js.slice(js.indexOf("function runCard"), js.indexOf("async function renderPanel"));
    expect(card).toContain("/status`");
    expect(card).toContain("Status: ");
    expect(card).toContain(
      "added to this case's forensic timeline automatically about 30 minutes after the run started",
    );
    expect(card).toContain("Download report (Markdown)");
    expect(card).toContain("Download findings (spreadsheet)");
    expect(card).toContain("Download rule coverage (spreadsheet)");
    expect(card).not.toContain("Report .${fmt}");
    expect(card).not.toContain("scopes: ${run.scopes");
    expect(card).toContain("Copies of the AI-agent files saved in Velociraptor");
  });

  it("asks Velociraptor automatically only for the newest run cards (#2898)", () => {
    expect(js).toContain("const AUTO_STATUS_CARDS = 3;");
    expect(js).toContain("if (autoStatus) void checkStatus();");
    expect(js).toContain('el("button", "Check status")');
  });

  it("shows warnings stored by older runs in the new plain wording (#2898)", () => {
    expect(js).toContain("function plainWarning(w)");
    expect(js).toContain("plainWarning(w)");
    expect(js).toContain("does not know where AI coding agents keep their files");
  });

  it("turns the standard 401 locked answer into an unlock hint (#2798)", () => {
    expect(js).toContain('res.status === 401 && body && body.error === "locked"');
    expect(js).toContain("is locked — unlock it first.");
  });

  it("shows both hashes, the check, and the rule-by-endpoint Sigma table (#2722)", () => {
    expect(js).toContain("function hashCell(h)");
    expect(js).toContain('h.hashCheck || "not recorded"');
    expect(js).toContain("function sigmaTable(report)");
    // Codex review: the YARA read is not hashed, so "same" claims only "unchanged since hashing".
    expect(js).toContain("same: unchanged between hashing and preservation");
    expect(js).toContain("differs: changed between hashing and preservation");
    expect(js).toContain("The bytes YARA read are not separately hashed");
    expect(js).not.toContain("the file changed after the scan");
    expect(js).toContain('cell ? `${cell.status}, ${cell.hits} hit(s)` : "not recorded"');
    expect(js).toContain('["sigma-coverage.csv", "Download rule coverage (spreadsheet)"');
  });
});
