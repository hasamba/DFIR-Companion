import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState, type LabIntelRecord } from "../../src/analysis/stateTypes.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import {
  BUILT_IN_REPORT_TEMPLATES,
  normalizeReportTemplate,
  normalizeSections,
  REPORT_SECTION_DEFS,
} from "../../src/reports/reportTemplate.js";

// #932 item 5 part C: the "Sandbox reports" section. Incident-neutral — it says what each sample did
// in a lab and whether the sample was SEEN in the collected evidence, and never that the behaviour
// happened on a host.

const SHA = "a".repeat(64);
const rec = (over: Partial<LabIntelRecord> = {}): LabIntelRecord => ({
  sha256: SHA,
  source: "CAPEv2",
  runId: "42",
  verdict: "malicious",
  score: 9.2,
  family: "Emotet",
  signatures: ["injection_explorer", "c2_beacon"],
  detonatedAt: "2026-09-10T10:00:00.000Z",
  importedAt: "2026-09-10T11:00:00.000Z",
  ...over,
});

const sandboxOnly = normalizeReportTemplate({
  id: "t",
  name: "sandbox only",
  sections: REPORT_SECTION_DEFS.map((s) => ({ key: s.key, enabled: s.key === "sandboxReports" })),
});

const render = (labIntel: LabIntelRecord[], sighting?: { host: string; time: string }): string => {
  const state = emptyState("INC-1");
  state.labIntel = labIntel;
  if (sighting) {
    state.forensicTimeline.push({
      id: "h1",
      timestamp: sighting.time,
      description: "process create invoice.exe",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sha256: SHA.toUpperCase(), // matching is on the normalised hash
      asset: sighting.host,
    });
  }
  return renderMarkdownReport(
    state,
    emptyReportMeta(),
    undefined,
    undefined,
    undefined,
    undefined,
    sandboxOnly,
  );
};

describe("sandbox reports section", () => {
  it("is offered as a toggleable report section", () => {
    expect(REPORT_SECTION_DEFS.map((s) => s.key)).toContain("sandboxReports");
  });

  it("renders each detonation with its sighting when the sample was seen in the case", () => {
    const md = render([rec()], { host: "WS-01", time: "2023-03-15T08:00:00.000Z" });
    expect(md).toContain("## Sandbox reports");
    expect(md).toMatch(/aaaaaaaaaaaa…/);
    expect(md).toContain("CAPEv2");
    expect(md).toContain("malicious");
    expect(md).toContain("Emotet");
    expect(md).toContain("seen on WS-01 at 2023-03-15T08:00:00.000Z");
    expect(md).not.toMatch(/on WS-01.*inject/); // never narrated as host behaviour
  });

  it("says a sample was not observed when no collected event carries its hash", () => {
    expect(render([rec()])).toContain("not observed in collected evidence");
  });

  // A report can be imported and produce super-timeline rows with NO registry record (no usable
  // SHA-256), so the empty state must not deny an import that happened.
  it("has an honest empty state", () => {
    const md = render([]);
    expect(md).toContain("No hash-addressable sandbox records");
    expect(md).not.toMatch(/none were imported/i);
  });

  it("shows the newest runs first and counts the older ones it does not show", () => {
    const runs = [1, 2, 3, 4, 5].map((n) => rec({ runId: `r${n}`, detonatedAt: `2026-09-0${n}T00:00:00Z` }));
    const md = render(runs);
    expect(md).toContain("| r5 |");
    expect(md).toContain("+2 older run(s) not shown");
    expect(md).not.toContain("| r1 |");
  });
});

describe("template compatibility for a section added after templates were saved", () => {
  it("a fresh template with no section list gets it enabled like every other section", () => {
    expect(normalizeSections([]).find((s) => s.key === "sandboxReports")?.enabled).toBe(true);
  });

  // The failure this guards: a client-facing Executive override saved before this section existed
  // would otherwise sprout technical detonation detail on upgrade.
  it("an existing saved template that predates the section gets it DISABLED", () => {
    const saved = normalizeSections([
      { key: "executiveSummary", enabled: true },
      { key: "timeline", enabled: true },
    ]);
    expect(saved.find((s) => s.key === "sandboxReports")?.enabled).toBe(false);
    expect(saved.find((s) => s.key === "conclusions")?.enabled).toBe(true); // other appended keys keep the old rule
  });

  it("the built-in Executive Brief lists it explicitly disabled", () => {
    const exec = BUILT_IN_REPORT_TEMPLATES.find((t) => t.id === "executive-brief")!;
    expect(exec.sections.find((s) => s.key === "sandboxReports")?.enabled).toBe(false);
  });
});
