import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { StateStore } from "../analysis/stateStore.js";
import { NO_SCOPE, type ScopeStore } from "../analysis/scope.js";
import { projectScope } from "../analysis/scopeProject.js";
import { applyLegitimate, filterLegitimateEvents, type LegitimateStore } from "../analysis/legitimate.js";
import { renderMarkdownReport } from "./markdown.js";
import { findingsCsv, iocsCsv, timelineCsv, forensicTimelineCsv } from "./csv.js";

export interface ReportPaths {
  markdown: string;
  findingsCsv: string;
  iocsCsv: string;
  timelineCsv: string;
  forensicTimelineCsv: string;
  stateJson: string;
}

export class ReportWriter {
  constructor(
    private readonly cases: CaseStore,
    private readonly state: StateStore,
    private readonly scope?: ScopeStore,
    private readonly legitimate?: LegitimateStore,
  ) {}

  async writeAll(caseId: string): Promise<ReportPaths> {
    const loaded = await this.state.load(caseId);
    // Reports respect the investigation scope deterministically: drop out-of-scope
    // events AND the findings/IOCs/MITRE supported only by them — so a report is
    // scope-consistent even if AI re-synthesis hasn't run (or kept stale items).
    const scoped = projectScope(loaded, this.scope ? await this.scope.load(caseId) : NO_SCOPE);
    // Then exclude client-confirmed legitimate items: drop legit forensic events
    // from the timeline (matching the dashboard view) and, as a safety net, any
    // findings/IOCs matching legit markers the AI may not have re-derived away.
    const markers = this.legitimate ? await this.legitimate.load(caseId) : [];
    const state = applyLegitimate(
      { ...scoped, forensicTimeline: filterLegitimateEvents(scoped.forensicTimeline, markers) },
      markers,
    );
    const dir = this.cases.reportsDir(caseId);
    const paths: ReportPaths = {
      markdown: join(dir, "report.md"),
      findingsCsv: join(dir, "findings.csv"),
      iocsCsv: join(dir, "iocs.csv"),
      timelineCsv: join(dir, "timeline.csv"),
      forensicTimelineCsv: join(dir, "forensic-timeline.csv"),
      stateJson: join(dir, "state-export.json"),
    };
    await writeFile(paths.markdown, renderMarkdownReport(state), "utf8");
    await writeFile(paths.findingsCsv, findingsCsv(state), "utf8");
    await writeFile(paths.iocsCsv, iocsCsv(state), "utf8");
    await writeFile(paths.timelineCsv, timelineCsv(state), "utf8");
    await writeFile(paths.forensicTimelineCsv, forensicTimelineCsv(state), "utf8");
    await writeFile(paths.stateJson, JSON.stringify(state, null, 2), "utf8");
    return paths;
  }
}
