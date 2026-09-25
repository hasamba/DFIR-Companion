import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { findingsCsv } from "../../src/reports/csv.js";
import { renderInteractiveHtmlReport } from "../../src/reports/interactiveHtml.js";
import { applySimulationVerdict, SIMULATED_LABEL } from "../../src/analysis/simulationVerdict.js";
import {
  emptyState,
  type Finding,
  type InvestigationState,
  type Severity,
} from "../../src/analysis/stateTypes.js";

// #1595: every export that prints a capped severity prints the live-intrusion severity beside it.

const T = "2026-09-24T09:04:00.000Z";

const finding = (id: string, severity: Severity, title: string, confidence = 90): Finding => ({
  id,
  severity,
  confidence,
  title,
  description: "d",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: [],
  relatedEventIds: [`e-${id}`],
  firstSeen: T,
  lastUpdated: T,
  status: "open",
});

function simulatedCase(): InvestigationState {
  const s = emptyState("c1");
  s.lastSummary = "summary";
  s.forensicTimeline = ["e-f1", "e-f14"].map((id) => ({
    id,
    timestamp: T,
    description: "row",
    severity: "High" as const,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "ws-01.example.com",
  }));
  s.findings = applySimulationVerdict(
    [
      finding("f1", "Critical", "Mimikatz executed against LSASS"),
      finding("f14", "Info", "Activity is likely an authorized attack-simulation exercise", 85),
    ],
    s.forensicTimeline,
  );
  return s;
}

let caseStore: CaseStore;
let stateStore: StateStore;

beforeEach(async () => {
  caseStore = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-sim-report-")));
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(caseStore);
  await stateStore.save(simulatedCase());
});

describe("simulation verdict in the exports (#1595)", () => {
  it("Markdown and HTML headings show the capped and the live-intrusion severity", async () => {
    const paths = await new ReportWriter(caseStore, stateStore).writeAll("c1");
    const md = await readFile(paths.markdown, "utf8");
    expect(md).toContain(
      `#### [Medium] [${SIMULATED_LABEL}; live-intrusion severity: Critical] [90% confidence] Mimikatz executed against LSASS (f1)`,
    );
    expect(md).toContain("#### [Critical] [simulation verdict; raised from Info] [85% confidence]");
    const html = await readFile(paths.html, "utf8");
    expect(html).toContain("live-intrusion severity: Critical");
  });

  it("the findings CSV carries the live-intrusion severity and the label", () => {
    const rows = findingsCsv(simulatedCase()).trim().split("\n");
    expect(rows[0]).toMatch(/,status,liveIntrusionSeverity,simulation$/);
    const f1 = rows.find((r) => r.startsWith('"f1"'))!;
    expect(f1).toMatch(/^"f1","Medium",/);
    expect(f1).toMatch(
      /,"Critical","simulated — pending owner confirmation; live-intrusion severity: Critical"$/,
    );
  });

  it("an untouched finding leaves both new CSV columns empty", () => {
    const s = emptyState("c1");
    s.findings = [finding("f9", "High", "Mimikatz executed")];
    expect(findingsCsv(s).trim().split("\n")[1]).toMatch(/,"",""$/);
  });

  it("the interactive HTML card carries the label beside the severity", () => {
    const html = renderInteractiveHtmlReport(simulatedCase());
    expect(html).toContain("live-intrusion severity: Critical");
  });
});
