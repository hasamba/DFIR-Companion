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

  it("keeps the tactic and what happened apart, with the time taken out of the words", () => {
    const steps = ap.attackSteps(
      "Initial access at 02:03:38 via a dropped script; at 09:04:18 the script copied PsTools and a scanner into C:\\e and started them with elevated rights; files were encrypted at 09:04:21.",
    );
    expect(steps[0]).toMatchObject({
      title: "Initial Access",
      summary: "Initial access via a dropped script",
    });
    expect(steps[1]).toMatchObject({
      title: "",
      summary: "The script copied PsTools and a scanner into C:\\e and started them with elevated rights",
    });
    expect(steps[2]).toMatchObject({ title: "Impact", summary: "Files were encrypted" });
  });

  it("cuts a long summary at a word", () => {
    const long = `at 09:00 ${"word ".repeat(40)}end; at 09:05 x ran.`;
    const [first] = ap.attackSteps(long);
    expect(first.summary.length).toBeLessThanOrEqual(91);
    expect(first.summary.endsWith("word…")).toBe(true);
  });

  it("reads the tactic from well-known tool and log names", () => {
    const steps = ap.attackSteps(
      "at 09:04:20 LaZagne 'all' ran; at 09:04:46 wevtutil cleared the Security log.",
    );
    expect(steps.map((x) => x.title)).toEqual(["Credential Access", "Defense Evasion"]);
  });

  it("hides a description with no letter or digit in it (#3023)", () => {
    const item = (n: number, tail: string) => `${n}. **Lateral Movement (T1021.002)** — May 16 10:00${tail}`;
    for (const tail of [".", ": …", ": — —", ":", ": /"]) {
      const steps = ap.attackSteps(
        `${item(1, tail)}\n2. **Impact (T1486)** — May 16 11:00: Files encrypted.`,
      );
      expect(steps).toHaveLength(2);
      expect(steps[0]).toMatchObject({ title: "Lateral Movement", time: "10:00", desc: "", summary: "" });
      expect(steps[1].desc).toBe("Files encrypted.");
    }
  });

  it("keeps a description written in any script, or in digits alone (#3023)", () => {
    const steps = ap.attackSteps(
      "1. **Execution (T1059)** — May 15 09:48: Запуск powershell.\n2. **Impact (T1486)** — May 15 10:00: 847",
    );
    expect(steps.map((x) => x.desc)).toEqual(["Запуск powershell.", "847"]);
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

  it("shows a card's tactic as a label beside what happened, and never an empty card", () => {
    const text =
      "Initial access at 02:03:38 via a script; at 09:04:18 the script copied tools; files were encrypted at 09:04:21.";
    const html = ap.attackPathHtml(text, EVENTS, "hosts");
    expect(html).toContain(
      '<span class="ap-tac">Impact</span><span class="ap-txt">Files were encrypted</span>',
    );
    expect(html).toContain('</span><span class="ap-txt">The script copied tools</span>');
    expect(html).not.toMatch(/<span class="ap-txt"><\/span>/);
    expect(html).not.toMatch(/<b><\/b>/);
  });

  it("prints no description row for a step whose description is only punctuation (#3023)", () => {
    const text =
      "1. **Lateral Movement to DC01 (T1021.002)** — May 16 08:22: PsExec to DC01.\n" +
      "2. **Lateral Movement (T1021.002)** — May 16 10:00.\n" +
      "3. **Impact (T1486)** — May 16 11:00: …";
    const steps = ap.attackPathHtml(text, EVENTS, "steps");
    expect(steps).toContain('<div class="ap-desc">PsExec to DC01.</div>');
    expect(steps.match(/class="ap-desc"/g)).toHaveLength(1);
    expect(steps).not.toMatch(/<div class="ap-desc">[.…\s]*<\/div>/);
    const hosts = ap.attackPathHtml(text, EVENTS, "hosts");
    expect(hosts).not.toMatch(/<span class="ap-txt">[.…\s]*<\/span>/);
  });

  describe("a step that names several hosts (#3082)", () => {
    // The Hosts-table row of one host, so an assertion can never match the Steps view.
    const lane = (html: string, host: string): string => {
      const start = html.indexOf(`<th scope="row"><span class="ap-host">${host}</span>`);
      return start < 0 ? "" : html.slice(start, html.indexOf("</tr>", start));
    };
    const jumps = (row: string): string[] =>
      [...row.matchAll(/data-act="attackPathJumpToEvent" data-id="([^"]*)"/g)].map((m) => m[1]);
    const hopLine = (html: string): string => {
      const at = html.indexOf('class="ap-hops"');
      return html.slice(at, html.indexOf("</div>", at));
    };
    const path = (move: string, time = "08:22") =>
      "1. **Initial Access (T1566.001)** — May 16 08:00: Phishing on WKSTN-JSMITH.\n" +
      `2. **Lateral Movement (T1021.002)** — May 16 ${time}: ${move}`;
    const W0 = ev("w0", "2026-05-16T08:00:00Z", "WKSTN-JSMITH");
    const A1 = ev("a1", "2026-05-16T08:22:05Z", "HOST-A");
    const B1 = ev("b1", "2026-05-16T08:22:40Z", "HOST-B");

    it("puts the step under every host it names, each linking that host's event", () => {
      const html = ap.attackPathHtml(path("PsExec to HOST-A and HOST-B."), [W0, A1, B1], "hosts");
      expect(jumps(lane(html, "HOST-A"))).toEqual(["a1"]);
      expect(jumps(lane(html, "HOST-B"))).toEqual(["b1"]);
      // The hop line and the Steps-view target still name the step's one destination.
      expect(hopLine(html)).not.toContain("HOST-A");
      expect(html).toContain('<span class="ap-host">→ HOST-B</span>');
    });

    it("handles three destinations and a repeated mention with one card per host", () => {
      const events = [W0, A1, B1, ev("c1", "2026-05-16T08:22:50Z", "HOST-C")];
      const html = ap.attackPathHtml(
        path("PsExec to HOST-A, HOST-B and HOST-C, then HOST-A again."),
        events,
        "hosts",
      );
      expect(jumps(lane(html, "HOST-A"))).toEqual(["a1"]);
      expect(jumps(lane(html, "HOST-B"))).toEqual(["b1"]);
      expect(jumps(lane(html, "HOST-C"))).toEqual(["c1"]);
    });

    it("links the most severe event of that minute on that host", () => {
      const events = [
        W0,
        ev("x", "2026-05-16T08:22:01Z", "HOST-B", "Critical"),
        A1,
        ev("a2", "2026-05-16T08:22:30Z", "  HOST-A ", "Critical"),
        B1,
      ];
      const html = ap.attackPathHtml(path("PsExec to HOST-A and HOST-B."), events, "hosts");
      expect(jumps(lane(html, "HOST-A"))).toEqual(["a2"]);
      expect(jumps(lane(html, "HOST-B"))).toEqual(["x"]);
    });

    it("falls back to the step's own event when a named host has none at that time", () => {
      const events = [W0, A1, ev("b0", "2026-05-15T10:00:00Z", "HOST-B")];
      const html = ap.attackPathHtml(path("PsExec to HOST-A and HOST-B."), events, "hosts");
      expect(jumps(lane(html, "HOST-A"))).toEqual(["a1"]);
      expect(jumps(lane(html, "HOST-B"))).toEqual(["a1"]);
    });

    it("matches to the second when the step gives seconds", () => {
      const events = [W0, A1, ev("a3", "2026-05-16T08:22:40Z", "HOST-A"), B1];
      const html = ap.attackPathHtml(path("PsExec to HOST-A and HOST-B.", "08:22:40"), events, "hosts");
      expect(jumps(lane(html, "HOST-A"))).toEqual(["a3"]);
      expect(jumps(lane(html, "HOST-B"))).toEqual(["b1"]);
    });

    it("looks for a host's event across the step's whole time range", () => {
      const events = [
        W0,
        A1,
        ev("b5", "2026-05-16T08:25:30Z", "HOST-B"),
        ev("b9", "2026-05-16T08:27:00Z", "HOST-B"),
      ];
      const html = ap.attackPathHtml(path("PsExec to HOST-A and HOST-B.", "08:22–08:26"), events, "hosts");
      expect(jumps(lane(html, "HOST-A"))).toEqual(["a1"]);
      expect(jumps(lane(html, "HOST-B"))).toEqual(["b5"]);
    });

    it("prints a plain time in every lane when no event matches", () => {
      const events = [
        W0,
        ev("a0", "2026-05-16T09:00:00Z", "HOST-A"),
        ev("b0", "2026-05-16T09:00:00Z", "HOST-B"),
      ];
      const html = ap.attackPathHtml(path("PsExec to HOST-A and HOST-B."), events, "hosts");
      expect(lane(html, "HOST-A")).toContain('<span class="ap-ct">08:22</span>');
      expect(lane(html, "HOST-B")).toContain('<span class="ap-ct">08:22</span>');
    });

    it("also shows a move under the host it came from", () => {
      const events = [W0, ev("w1", "2026-05-16T08:22:10Z", "WKSTN-JSMITH"), B1];
      const html = ap.attackPathHtml(path("PsExec from WKSTN-JSMITH to HOST-B."), events, "hosts");
      expect(jumps(lane(html, "WKSTN-JSMITH"))).toEqual(["w0", "w1"]);
      expect(jumps(lane(html, "HOST-B"))).toEqual(["b1"]);
      expect(html).toContain('<span class="ap-host">→ HOST-B</span>');
    });

    it("keeps a non-move step on its event's host as well as the hosts it names", () => {
      const text =
        "1. **Initial Access (T1566.001)** — May 16 08:00: Phishing.\n" +
        "2. **Discovery (T1018)** — May 16 08:22: Scanned HOST-A and HOST-B.";
      const events = [W0, ev("w1", "2026-05-16T08:22:00Z", "WKSTN-JSMITH", "Critical"), A1, B1];
      const html = ap.attackPathHtml(text, events, "hosts");
      expect(jumps(lane(html, "WKSTN-JSMITH"))).toEqual(["w0", "w1"]);
      expect(jumps(lane(html, "HOST-A"))).toEqual(["a1"]);
      expect(jumps(lane(html, "HOST-B"))).toEqual(["b1"]);
    });

    it("adds no lane for a short name two case hosts share, but does for a full name", () => {
      const events = [
        W0,
        ev("s1", "2026-05-16T08:22:05Z", "srv.a.example"),
        ev("s2", "2026-05-16T08:22:06Z", "srv.b.example"),
        ev("d1", "2026-05-16T08:22:07Z", "DC01"),
      ];
      const short = ap.attackPathHtml(path("PsExec to srv and DC01."), events, "hosts");
      expect(lane(short, "srv.a.example")).toBe("");
      expect(lane(short, "srv.b.example")).toBe("");
      const full = ap.attackPathHtml(path("PsExec to srv.b.example and DC01."), events, "hosts");
      expect(jumps(lane(full, "srv.b.example"))).toEqual(["s2"]);
      expect(lane(full, "srv.a.example")).toBe("");
      expect(jumps(lane(full, "DC01"))).toEqual(["d1"]);
    });
  });

  it("escapes the model's text", () => {
    const text = `1. **Execution (T1059)** — May 15 09:48: ${XSS}\n2. **Impact (T1486)** — May 15 10:00: done`;
    const html = ap.attackPathHtml(text, [ev('" onmouseover="x', "2026-05-15T09:48:00Z", XSS)], "hosts");
    expect(html).not.toContain("<img");
    expect(html).not.toContain('" onmouseover');
  });
});
