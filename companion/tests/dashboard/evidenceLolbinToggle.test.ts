import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// "LOLBIN chains" toggle in the Evidence Chain panel (#2113). The server marks nodes; the browser
// only filters. Filter order: type toggles -> LOLBIN subset -> severity floor (-> text filter in
// the graph view).

interface N {
  id: string;
  kind: string;
  maxSeverity: string;
  lolbin?: "hit" | "context";
}
interface E {
  source: string;
  target: string;
  type: string;
  launcher?: true;
}
interface Api {
  evSelectGraph(
    data: { nodes: N[]; edges: E[] },
    opts: { types: Set<string>; lolbinOnly: boolean; minSev: string },
  ): { nodes: N[]; edges: E[] };
}

const api = () =>
  loadDashboardModule<Api>("dashboard-evidence-graph.js", ["dashboard-escape.js"], {
    fetch: () => new Promise(() => {}),
    document: { getElementById: () => null, querySelectorAll: () => [], querySelector: () => null },
    DfirTimelineView: { timeQuery: () => "" },
  });

// Windows CI checks files out with CRLF, so normalise before matching.
const read = (p: string) =>
  readFileSync(new URL(`../../../${p}`, import.meta.url), "utf8").replace(/\r\n/g, "\n");

const n = (id: string, maxSeverity: string, lolbin?: "hit" | "context"): N => ({
  id,
  kind: id.startsWith("host") ? "host" : "process",
  maxSeverity,
  ...(lolbin ? { lolbin } : {}),
});
const sp = (source: string, target: string, launcher?: true): E => ({
  source,
  target,
  type: "spawned",
  ...(launcher ? { launcher } : {}),
});
const ran = (target: string): E => ({ source: "host:h", target, type: "ran_on" });

const DATA = {
  nodes: [
    n("host:h", "Info"),
    n("winword", "Info", "context"),
    n("powershell", "Low", "hit"),
    n("whoami", "Info", "context"),
    n("explorer", "Info"),
    n("calc", "Low"),
  ],
  edges: [
    ran("winword"),
    sp("winword", "powershell", true),
    sp("powershell", "whoami"),
    ran("explorer"),
    sp("explorer", "calc"),
  ],
};
const TYPES = new Set(["spawned"]);
const ids = (r: { nodes: N[] }) => r.nodes.map((x) => x.id).sort();

describe("evSelectGraph — LOLBIN chains toggle", () => {
  it("keeps only the marked chain and its host when on, flags preserved", () => {
    const r = api().evSelectGraph(DATA, { types: TYPES, lolbinOnly: true, minSev: "Info" });
    expect(ids(r)).toEqual(["host:h", "powershell", "whoami", "winword"]);
    expect(r.edges.some((e) => e.launcher)).toBe(true);
    expect(r.nodes.find((x) => x.id === "powershell")?.lolbin).toBe("hit");
  });

  it("is identical to the unfiltered graph when off", () => {
    const off = api().evSelectGraph(DATA, { types: TYPES, lolbinOnly: false, minSev: "Info" });
    expect(ids(off)).toEqual(["calc", "explorer", "host:h", "powershell", "whoami", "winword"]);
    expect(off.edges).toHaveLength(DATA.edges.length);
  });

  it("applies the severity floor after the subset", () => {
    const r = api().evSelectGraph(DATA, { types: TYPES, lolbinOnly: true, minSev: "Low" });
    expect(ids(r)).toEqual(["powershell"]);
  });

  it("applies the type toggles before the subset", () => {
    const r = api().evSelectGraph(DATA, { types: new Set(), lolbinOnly: true, minSev: "Info" });
    expect(r.nodes).toHaveLength(0);
  });

  it("returns nothing when no node is marked", () => {
    const none = {
      nodes: DATA.nodes.map((x) => ({ id: x.id, kind: x.kind, maxSeverity: x.maxSeverity })),
      edges: DATA.edges,
    };
    expect(api().evSelectGraph(none, { types: TYPES, lolbinOnly: true, minSev: "Info" }).nodes).toHaveLength(
      0,
    );
  });
});

describe("LOLBIN chains markup and empty message", () => {
  it("adds an unchecked checkbox inside the Show group, not a type toggle", () => {
    const html = read("public/dashboard.html");
    const tag = html.match(/<input[^>]*id="evLolbinOnly"[^>]*>/)?.[0] ?? "";
    expect(tag).toContain('type="checkbox"');
    expect(tag).not.toContain("checked");
    expect(tag).not.toContain("ev-type-toggle");
  });

  it("shows the empty message only when the toggle is on and no node is a hit", () => {
    const js = read("public/js/dashboard-evidence-graph.js");
    expect(js).toContain("No LOLBIN chains in this case");
    expect(js).toMatch(/evLolbinOnly && !evHasLolbinHit\(evGraphData\)/);
  });

  it("renders the outline and launcher marks only while the toggle is on (off = today's graph)", () => {
    // Codex review: the server flags reached the elements unconditionally, so the styles applied
    // with the toggle off. Both element fields must be gated on evLolbinOnly.
    const js = read("public/js/dashboard-evidence-graph.js");
    expect(js).toMatch(/lolbin: evLolbinOnly \? n\.lolbin \|\| null : null/);
    expect(js).toMatch(/launcher: evLolbinOnly && e\.launcher \? true : null/);
  });
});

describe("manual", () => {
  it("documents the toggle, the rule and the Info limit in the Evidence Chain section", () => {
    const md = read("mkdocs-docs/reference/dashboard.md");
    const sec = md.slice(md.indexOf("## Evidence Chain"));
    expect(sec).toContain("LOLBIN chains");
    expect(sec).toContain("Info-graded");
  });
});
