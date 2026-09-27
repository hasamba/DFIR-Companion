import { describe, expect, it } from "vitest";
import type { AttackPathApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-attack-path.js — the Attack Path panel as a step list (with a host-hop line)
// and as host swimlanes, switched by two tabs. The model writes the path in two shapes: a numbered
// Markdown list, or one paragraph of clauses joined by semicolons. Both must turn into steps, and
// text in neither shape must keep the plain prose layout.

const ap = loadDashboardModule<AttackPathApi>("dashboard-attack-path.js", [
  "dashboard-escape.js",
  "dashboard-text.js",
  "dashboard-fragments.js",
]);

const XSS = "<img src=x onerror=alert(1)>";

const LIST = [
  "1. **Initial Access (T1566.001)** — May 15 09:14: Spear-phishing email delivered to jsmith@example.com.",
  "2. **Execution (T1204.002 / T1059.001)** — May 15 09:48: Excel macro executed, spawning powershell.exe.",
  "3. **C2 Deployment (T1105 / T1071.001)** — May 15 09:49–09:51: Cobalt Strike beacon to 203.0.113.47:443.",
  "4. **Lateral Movement to DC01 (T1021.002)** — May 16 08:22: PsExec to DC01.",
  "5. **Credential Dumping (T1003.001)** — May 16 08:45: Mimikatz on the domain controller.",
].join("\n");

const ev = (id: string, timestamp: string, asset: string, severity = "High") => ({
  id,
  timestamp,
  asset,
  severity,
});
const EVENTS = [
  ev("e1", "2026-05-15T09:14:30Z", "WKSTN-JSMITH"),
  ev("e2", "2026-05-15T09:48:10Z", "WKSTN-JSMITH", "Critical"),
  ev("e4", "2026-05-16T08:22:00Z", "DC01"),
  ev("fs", "2026-05-17T10:00:00Z", "FS01"),
];

describe("attackSteps", () => {
  it("reads the numbered-list shape", () => {
    const steps = ap.attackSteps(LIST);
    expect(steps).toHaveLength(5);
    expect(steps[0]).toMatchObject({
      title: "Initial Access",
      techniques: ["T1566.001"],
      month: 5,
      day: 15,
      time: "09:14",
      desc: "Spear-phishing email delivered to jsmith@example.com.",
    });
    expect(steps[1].techniques).toEqual(["T1204.002", "T1059.001"]);
    expect(steps[2]).toMatchObject({ time: "09:49", timeEnd: "09:51" });
  });

  it("reads the semicolon shape and names each step by its tactic", () => {
    const steps = ap.attackSteps(
      "Initial access at 2026-05-15 09:14 via a phishing email; then execution of powershell.exe at 09:48; persistence via a scheduled task at 10:15.",
    );
    expect(steps.map((s) => s.title)).toEqual(["Initial Access", "Execution", "Persistence"]);
    expect(steps[0]).toMatchObject({ year: 2026, month: 5, day: 15, time: "09:14" });
    expect(steps[1]).toMatchObject({ time: "09:48", desc: "Execution of powershell.exe at 09:48" });
  });

  it("labels a step that names no tactic with its own words, without the time", () => {
    const steps = ap.attackSteps(
      "Initial access at 02:03:38 via a dropped script; at 09:04:18 the script copied PsTools and a scanner into C:\\e and started them with elevated rights; files were encrypted at 09:04:21.",
    );
    expect(steps[1].title).toBe("");
    expect(steps[1].label).toBe("The script copied PsTools and a scanner into C:\\e and…");
    expect(steps[0].label).toBe("Initial Access");
  });

  it("finds no steps in plain prose", () => {
    expect(ap.attackSteps("The attacker got in and moved around.")).toHaveLength(0);
  });
});

describe("attackPathHtml", () => {
  it("keeps plain prose when the text has fewer than two steps", () => {
    const text = "The attacker got in and moved around.";
    expect(ap.attackPathHtml(text, EVENTS, "steps")).toBe(`<p>${text}</p>`);
    expect(ap.attackPathHtml("—", EVENTS, "steps")).toBe("<p>—</p>");
  });

  it("offers two tabs and opens the one it is given", () => {
    const html = ap.attackPathHtml(LIST, EVENTS, "hosts");
    expect(html).toContain('data-ap-view="hosts"');
    expect(html).toMatch(/data-act="attackPathView" data-view="steps" aria-selected="false"/);
    expect(html).toMatch(/data-act="attackPathView" data-view="hosts" aria-selected="true"/);
    expect(ap.attackPathHtml(LIST, EVENTS, "nonsense")).toContain('data-ap-view="steps"');
  });

  it("links a step's time to the most severe event of that minute, with a day header", () => {
    const html = ap.attackPathHtml(LIST, EVENTS, "steps");
    expect(html).toMatch(/data-act="attackPathJumpToEvent" data-id="e1"[^>]*>09:14</);
    expect(html).toContain("15 May 2026");
    expect(html).toContain("16 May 2026");
    expect(html).toContain('<span class="ap-tt">T1566.001</span>');
  });

  it("draws the host-hop line in the order the attacker reached each host", () => {
    const html = ap.attackPathHtml(LIST, EVENTS, "steps");
    const hops = html.slice(
      html.indexOf('class="ap-hops"'),
      html.indexOf("</div>", html.indexOf('class="ap-hops"')),
    );
    expect(hops.indexOf("WKSTN-JSMITH")).toBeGreaterThan(-1);
    expect(hops.indexOf("WKSTN-JSMITH")).toBeLessThan(hops.indexOf("DC01"));
    // The C2 address from the C2 step sits outside the hosts.
    expect(hops).toContain("203.0.113.47");
  });

  it("places a step by its event, then by a host its text names, then by the step before it", () => {
    const html = ap.attackPathHtml(LIST, EVENTS, "hosts");
    const lanes = html.slice(html.indexOf('class="ap-lanes"'));
    // Step 5 has no event at 08:45 and names no known host: it stays on DC01, marked as assumed.
    expect(lanes).toMatch(/ap-card[^"]*ap-assumed" title="[^"]*DC01[^"]*"/);
    // FS01 is a case host but no step reached it, so it gets no lane.
    expect(lanes).not.toContain("FS01");
  });

  it("colors each step by its tactic group and says so in a tooltip", () => {
    const html = ap.attackPathHtml(LIST, EVENTS, "steps");
    expect(html).toContain('ap-n ap-g-entry" title="Entry into the environment"');
    expect(html).toContain('ap-n ap-g-move" title="Movement between hosts"');
    expect(html).toContain('ap-n ap-g-harm" title="Credential theft, data theft or impact"');
  });

  it("never draws an empty card or an empty heading", () => {
    const text =
      "Initial access at 02:03:38 via a script; at 09:04:18 the script copied tools; files were encrypted at 09:04:21.";
    const html = ap.attackPathHtml(text, EVENTS, "hosts");
    expect(html).not.toMatch(/<b><\/b>/);
    expect(html).toContain("<b>The script copied tools</b>");
  });

  it("escapes the model's text", () => {
    const text = `1. **Execution (T1059)** — May 15 09:48: ${XSS}\n2. **Impact (T1486)** — May 15 10:00: done`;
    const html = ap.attackPathHtml(text, [ev('" onmouseover="x', "2026-05-15T09:48:00Z", XSS)], "hosts");
    expect(html).not.toContain("<img");
    expect(html).not.toContain('" onmouseover');
  });
});
