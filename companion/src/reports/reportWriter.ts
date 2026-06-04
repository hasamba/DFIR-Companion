import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { StateStore } from "../analysis/stateStore.js";
import { NO_SCOPE, type ScopeStore } from "../analysis/scope.js";
import { projectScope } from "../analysis/scopeProject.js";
import { applyLegitimate, filterLegitimateEvents, type LegitimateStore } from "../analysis/legitimate.js";
import { renderMarkdownReport } from "./markdown.js";
import { renderHtmlReport } from "./html.js";
import { emptyReportMeta, type ReportMetaStore } from "./reportMeta.js";
import { findingsCsv, iocsCsv, timelineCsv, forensicTimelineCsv } from "./csv.js";
import { buildAssetGraph, type AssetGraph } from "../analysis/assetGraph.js";
import type { InvestigationState } from "../analysis/stateTypes.js";

export interface ReportPaths {
  markdown: string;
  html: string;
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
    private readonly reportMeta?: ReportMetaStore,
  ) {}

  // Load the case state with the same deterministic report filters applied: drop
  // out-of-scope events (and the findings/IOCs/MITRE supported only by them) and exclude
  // client-confirmed legitimate items — so every export is scope/legit-consistent even if
  // AI re-synthesis hasn't run. Shared by the full report and single-section exports.
  private async loadFilteredState(caseId: string): Promise<InvestigationState> {
    const loaded = await this.state.load(caseId);
    const scoped = projectScope(loaded, this.scope ? await this.scope.load(caseId) : NO_SCOPE);
    const markers = this.legitimate ? await this.legitimate.load(caseId) : [];
    return applyLegitimate(
      { ...scoped, forensicTimeline: filterLegitimateEvents(scoped.forensicTimeline, markers) },
      markers,
    );
  }

  // Export just the incident (forensic) timeline as CSV, on demand — without writing the
  // full report. Uses the same scope/legitimate filtering so it matches the report's 3.1.
  async incidentTimelineCsv(caseId: string): Promise<string> {
    return forensicTimelineCsv(await this.loadFilteredState(caseId));
  }

  // The asset ↔ IoC graph for the case (same scope/legitimate filtering as the report).
  async assetGraph(caseId: string): Promise<AssetGraph> {
    return buildAssetGraph(await this.loadFilteredState(caseId));
  }

  async writeAll(caseId: string): Promise<ReportPaths> {
    const state = await this.loadFilteredState(caseId);
    const dir = this.cases.reportsDir(caseId);
    const paths: ReportPaths = {
      markdown: join(dir, "report.md"),
      html: join(dir, "report.html"),
      findingsCsv: join(dir, "findings.csv"),
      iocsCsv: join(dir, "iocs.csv"),
      timelineCsv: join(dir, "timeline.csv"),
      forensicTimelineCsv: join(dir, "forensic-timeline.csv"),
      stateJson: join(dir, "state-export.json"),
    };
    const meta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    await writeFile(paths.markdown, renderMarkdownReport(state, meta), "utf8");
    await writeFile(paths.html, renderHtmlReport(state, meta), "utf8");
    await writeFile(paths.findingsCsv, findingsCsv(state), "utf8");
    await writeFile(paths.iocsCsv, iocsCsv(state), "utf8");
    await writeFile(paths.timelineCsv, timelineCsv(state), "utf8");
    await writeFile(paths.forensicTimelineCsv, forensicTimelineCsv(state), "utf8");
    await writeFile(paths.stateJson, JSON.stringify(state, null, 2), "utf8");
    return paths;
  }
}
