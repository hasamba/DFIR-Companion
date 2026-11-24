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
    expect(js).toContain("/sigma-coverage.csv`");
  });
});
