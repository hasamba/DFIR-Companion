import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { FindingOutcomeStore } from "../../src/analysis/findingOutcome.js";
import { emptyState, type Finding } from "../../src/analysis/stateTypes.js";

// The analyst's attack-outcome statement (#930 item 8) must reach the written report through the
// one projection every report surface reads (reports/filteredState.ts), and it must survive the
// thing that wipes every other conclusion: a rebuilt finding list.

let caseStore: CaseStore;
let stateStore: StateStore;

const finding = (over: Partial<Finding>): Finding => ({
  id: "f-1",
  severity: "High",
  title: "Payload dropped and executed on WS-01",
  description: "d",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: [],
  firstSeen: "2026-05-28T09:00:00Z",
  lastUpdated: "2026-05-28T09:00:00Z",
  status: "open",
  ...over,
});

beforeEach(async () => {
  caseStore = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-fout-report-")));
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(caseStore);
  const state = emptyState("c1");
  state.lastSummary = "summary text";
  state.findings.push(finding({ confidence: 70 }));
  await stateStore.save(state);
});

describe("finding outcome in the written report", () => {
  it("renders nothing extra for a finding nobody has said anything about", async () => {
    const paths = await new ReportWriter(caseStore, stateStore).writeAll("c1");
    const md = await readFile(paths.markdown, "utf8");
    const heading = md.split("\n").find((l) => l.startsWith("#### [High]"));
    expect(heading).toBe("#### [High] [70% confidence] Payload dropped and executed on WS-01 (f-1)");
  });

  it("renders BOTH axes the analyst set, attributed, and never a single-word verdict", async () => {
    await new FindingOutcomeStore(caseStore).patch("c1", "f-1", {
      execution: "observed",
      control: "remediated",
      updatedBy: "Alice",
    });
    const paths = await new ReportWriter(caseStore, stateStore).writeAll("c1");
    const md = await readFile(paths.markdown, "utf8");
    expect(md).toContain(
      "[70% confidence] [execution observed · control remediated (analyst)] Payload dropped",
    );
    expect(md).not.toMatch(/\bprevented\b/);
  });

  // replaceConclusions builds findings from an empty base; simulate its effect by saving a state
  // whose finding carries no outcome fields at all. The analyst's statement must still render.
  it("survives a rebuilt finding list — the side file is not in the state synthesis rewrites", async () => {
    await new FindingOutcomeStore(caseStore).patch("c1", "f-1", { control: "blocked" });
    const rebuilt = emptyState("c1");
    rebuilt.lastSummary = "re-synthesised";
    rebuilt.findings.push(finding({})); // same id, fresh object, no outcome — as synthesis would leave it
    await stateStore.save(rebuilt);
    const md = await readFile(
      (await new ReportWriter(caseStore, stateStore).writeAll("c1")).markdown,
      "utf8",
    );
    expect(md).toContain("[control blocked (analyst)]");
  });

  it("lets the analyst override one axis while the machine's value on the other survives", async () => {
    const state = await stateStore.load("c1");
    state.findings[0] = finding({ execution: "unknown", control: "allowed" }); // machine-set
    await stateStore.save(state);
    await new FindingOutcomeStore(caseStore).patch("c1", "f-1", { execution: "observed" });
    const md = await readFile(
      (await new ReportWriter(caseStore, stateStore).writeAll("c1")).markdown,
      "utf8",
    );
    expect(md).toContain("[execution observed · control allowed (analyst)]");
  });
});
