import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { StateStore } from "../analysis/stateStore.js";
import { filterEventsByScope, NO_SCOPE, type ScopeStore } from "../analysis/scope.js";
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
  ) {}

  async writeAll(caseId: string): Promise<ReportPaths> {
    const loaded = await this.state.load(caseId);
    // Reports respect the investigation scope: the forensic timeline export shows
    // only in-scope events (findings/IOCs are already scoped by synthesis).
    const scope = this.scope ? await this.scope.load(caseId) : NO_SCOPE;
    const state = { ...loaded, forensicTimeline: filterEventsByScope(loaded.forensicTimeline, scope) };
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
