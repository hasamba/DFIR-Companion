import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { AiAgentHitsApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-ai-agent-hits.js — the AI Agent Forensics findings table's filters (#2911).
// A real run listed dozens of hits of one rule with no way to narrow them; the analyst asked for
// filters by grade, rule and machine (the machine filter only when the run has more than one).
const hitsApi = loadDashboardModule<AiAgentHitsApi>("dashboard-ai-agent-hits.js", []);

const hit = (severity: string, rule: string, host: string) => ({ severity, rule, host, path: "C:/x" });
const hits = [
  hit("Medium", "Rule_B", "ws-02"),
  hit("High", "Rule_A", "ws-01"),
  hit("High", "Rule_B", "ws-01"),
  hit("Info", "Rule_A", "ws-02"),
  hit("Critical", "Rule_C", "ws-01"),
];

describe("aaHitFilterOptions", () => {
  it("offers grades most severe first, rules and endpoints alphabetically, each once", () => {
    expect(hitsApi.aaHitFilterOptions(hits)).toEqual({
      grades: ["Critical", "High", "Medium", "Info"],
      rules: ["Rule_A", "Rule_B", "Rule_C"],
      hosts: ["ws-01", "ws-02"],
    });
    expect(hitsApi.aaHitFilterOptions(null)).toEqual({ grades: [], rules: [], hosts: [] });
  });
});

describe("aaFilterHits", () => {
  it("keeps every hit when nothing is chosen, and combines the choices", () => {
    expect(hitsApi.aaFilterHits(hits, {})).toHaveLength(5);
    expect(hitsApi.aaFilterHits(hits, { grade: "High" })).toHaveLength(2);
    expect(hitsApi.aaFilterHits(hits, { grade: "High", rule: "Rule_B" })).toEqual([hits[2]]);
    expect(hitsApi.aaFilterHits(hits, { host: "ws-02", rule: "Rule_A" })).toEqual([hits[3]]);
    expect(hitsApi.aaFilterHits(hits, { grade: "Low" })).toEqual([]);
  });
});

describe("shortened cells", () => {
  it("says how many findings a filter shows", () => {
    expect(hitsApi.aaHitCountNote(2, 40)).toBe("Showing 2 of 40 findings");
    expect(hitsApi.aaHitCountNote(40, 40)).toBe("40 finding(s)");
  });

  it("cuts the middle of a long path and keeps the file name", () => {
    const long = `C:/Users/analyst/AppData/Roaming/Tool/sessions/${"d".repeat(80)}/local_session_file.json`;
    const short = hitsApi.aaShortPath(long, 70);
    expect(short).toHaveLength(70);
    expect(short.startsWith("C:/Users/analyst")).toBe(true);
    expect(short.endsWith("local_session_file.json")).toBe(true);
    expect(short).toContain("…");
    expect(hitsApi.aaShortPath("C:/short.json")).toBe("C:/short.json");
  });

  it("shows the first 12 characters of a hash, or none", () => {
    expect(hitsApi.aaShortHash("a".repeat(64))).toBe(`${"a".repeat(12)}…`);
    expect(hitsApi.aaShortHash("")).toBe("none");
    expect(hitsApi.aaShortHash(undefined)).toBe("none");
  });
});

describe("the findings table on the run card", () => {
  const js = readFileSync(join(__dirname, "..", "..", "..", "public", "js", "dashboard-ai-agent.js"), "utf8");
  const table = js.slice(js.indexOf("function hitRow"), js.indexOf("function endpointLines"));

  it("filters by grade and rule, and by endpoint only when there is more than one", () => {
    expect(table).toContain('hitFilter("Grade"');
    expect(table).toContain('hitFilter("Rule"');
    expect(table).toMatch(/if \(multiHost\) bar\.appendChild\(hitFilter\("Endpoint"/);
    expect(table).toContain("multiHost = opts.hosts.length > 1");
  });

  it("names the rule author column apart from the rule, and keeps full values on hover", () => {
    expect(table).toContain('"Rule source"');
    expect(table).toContain("file.title = h.path");
    expect(table).not.toMatch(/"File SHA-256 after scan \/ preserved", "Rule"\]/);
  });

  it("is loaded before the panel script", () => {
    const html = readFileSync(join(__dirname, "..", "..", "..", "public", "dashboard.html"), "utf8");
    expect(html.indexOf("/js/dashboard-ai-agent-hits.js")).toBeGreaterThan(0);
    expect(html.indexOf("/js/dashboard-ai-agent-hits.js")).toBeLessThan(
      html.indexOf("/js/dashboard-ai-agent.js"),
    );
  });
});
