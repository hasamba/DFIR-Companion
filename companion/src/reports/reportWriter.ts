import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { StateStore } from "../analysis/stateStore.js";
import { NO_SCOPE, type ScopeStore } from "../analysis/scope.js";
import { projectScope } from "../analysis/scopeProject.js";
import { applyLegitimate, filterLegitimateEvents, type LegitimateStore } from "../analysis/legitimate.js";
import { renderMarkdownReport } from "./markdown.js";
import { renderHtmlReport } from "./html.js";
import { renderDocxReport } from "./docx.js";
import { emptyReportMeta, type ReportMetaStore } from "./reportMeta.js";
import { findingsCsv, iocsCsv, timelineCsv, forensicTimelineCsv } from "./csv.js";
import { buildAttackLayer, type NavigatorLayer } from "./attackLayer.js";
import { toTimesketchJsonl } from "../integrations/timesketch/timesketchMap.js";
import { buildAssetGraph, type AssetGraph } from "../analysis/assetGraph.js";
import { buildEvidenceGraph, type EvidenceGraph } from "../analysis/evidenceGraph.js";
import { buildAttackPhases, DEFAULT_GAP_SECONDS, type AttackPhase } from "../analysis/burstDetect.js";
import { buildSwimlaneData, type SwimlaneData, type SwimlaneGroupBy } from "../analysis/swimlane.js";
import { deriveIocSources } from "../analysis/iocCorroboration.js";
import { buildAdversaryHintsResult, type AdversaryHintsResult } from "../analysis/adversaryHints.js";
import { loadAdversaryGroupsDataset, adversaryHintEnvOptions } from "../analysis/adversaryGroupsData.js";
import { buildStixBundle, type StixBundle } from "./stix.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import { CustomerExposureStore, type CustomerExposureSummary } from "../analysis/customerExposure.js";
import type { NotebookStore, NotebookEntry } from "../analysis/notebookStore.js";
import type { PlaybookStore } from "../analysis/playbookStore.js";
import type { PlaybookTask } from "../analysis/playbook.js";
import { AssetOverridesStore, applyAssetOverrides, emptyOverrides } from "../analysis/assetOverrides.js";

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
    private readonly customerExposure?: CustomerExposureStore,
    private readonly notebook?: NotebookStore,
    private readonly assetOverrides?: AssetOverridesStore,
    private readonly playbook?: PlaybookStore,
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

  private async loadNotebook(caseId: string): Promise<NotebookEntry[] | undefined> {
    if (!this.notebook) return undefined;
    const entries = await this.notebook.load(caseId);
    return entries.length ? entries : undefined;
  }

  private async loadPlaybook(caseId: string): Promise<PlaybookTask[] | undefined> {
    if (!this.playbook) return undefined;
    const tasks = await this.playbook.load(caseId);
    return tasks.length ? tasks : undefined;
  }

  // Build the Word (.docx) export on demand. Uses the same scope/legitimate filtering as
  // the canonical report so the .docx matches report.md and report.html exactly. NOT added
  // to writeAll: the .docx is a snapshot deliverable, and writing a binary into the
  // (often-Dropbox-synced) cases/ folder on every report regeneration causes sync churn.
  async docx(caseId: string): Promise<Buffer> {
    const state = await this.loadFilteredState(caseId);
    const meta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    return renderDocxReport(state, meta, await this.loadExposure(caseId));
  }

  private async loadExposure(caseId: string): Promise<CustomerExposureSummary | undefined> {
    if (!this.customerExposure) return undefined;
    const exposure = await this.customerExposure.load(caseId);
    return exposure.checkedAt ? exposure : undefined;
  }

  // Export just the incident (forensic) timeline as CSV, on demand — without writing the
  // full report. Uses the same scope/legitimate filtering so it matches the report's 3.1.
  async incidentTimelineCsv(caseId: string): Promise<string> {
    return forensicTimelineCsv(await this.loadFilteredState(caseId));
  }

  // Build a MITRE ATT&CK Navigator layer for the case (same scope/legitimate filtering as the
  // report) — the JSON drops straight into the Navigator's "Open Existing Layer" upload. The
  // stamped ATT&CK version follows DFIR_ATTACK_VERSION (default DEFAULT_ATTACK_VERSION) so a new
  // ATT&CK release doesn't make the Navigator prompt to upgrade every exported layer.
  async attackLayer(caseId: string): Promise<NavigatorLayer> {
    const attackVersion = process.env.DFIR_ATTACK_VERSION?.trim() || undefined;
    return buildAttackLayer(await this.loadFilteredState(caseId), attackVersion ? { attackVersion } : {});
  }

  // Export the forensic timeline as Timesketch-compatible JSONL (same scope/legitimate filtering).
  // Used by the "Export Timesketch JSONL" download and as the payload for the Timesketch push.
  async timesketchJsonl(caseId: string): Promise<string> {
    return toTimesketchJsonl(await this.loadFilteredState(caseId));
  }

  // The case state with the report's scope/legitimate filters applied — so the Timesketch push
  // uploads exactly the timeline the report (and the JSONL export) show.
  async filteredState(caseId: string): Promise<InvestigationState> {
    return this.loadFilteredState(caseId);
  }

  // The asset ↔ IoC graph for the case (same scope/legitimate filtering as the report),
  // with any analyst overrides (renames, additions, suppressions) applied on top.
  async assetGraph(caseId: string): Promise<AssetGraph> {
    const state = await this.loadFilteredState(caseId);
    const graph = buildAssetGraph(state);
    const overrides = this.assetOverrides ? await this.assetOverrides.load(caseId) : emptyOverrides();
    return applyAssetOverrides(graph, overrides);
  }

  // The causal evidence chain graph (process trees + lateral movement) for the case,
  // derived on demand with the same scope/legitimate filtering as the report.
  async evidenceGraph(caseId: string): Promise<EvidenceGraph> {
    return buildEvidenceGraph(await this.loadFilteredState(caseId));
  }

  // Temporal attack phases (bursts of activity grouped by time gap) for the case, derived on
  // demand with the same scope/legitimate filtering as the report. The burst gap threshold is
  // configurable via DFIR_PHASE_GAP_S (seconds; default 5 min).
  async phases(caseId: string): Promise<AttackPhase[]> {
    const state = await this.loadFilteredState(caseId);
    const gapSeconds = Number(process.env.DFIR_PHASE_GAP_S) || DEFAULT_GAP_SECONDS;
    return buildAttackPhases(state.forensicTimeline, { gapSeconds });
  }

  // Swimlane data for the visual timeline chart — events grouped into lanes by the chosen
  // groupBy axis (asset | severity | tactic). Same scope/legitimate filtering as the report.
  async swimlane(caseId: string, groupBy: SwimlaneGroupBy = "asset"): Promise<SwimlaneData> {
    const state = await this.loadFilteredState(caseId);
    return buildSwimlaneData(state.forensicTimeline, groupBy);
  }

  // Per-IOC corroboration: iocId → distinct tools that observed the indicator (derived by matching
  // the IOC value against the forensic events' `sources`). Same scope/legitimate filtering as the
  // report. Powers the dashboard's "⊕ N sources" badge on IOCs.
  async iocSources(caseId: string): Promise<Record<string, string[]>> {
    const state = await this.loadFilteredState(caseId);
    return deriveIocSources(state.iocs, state.forensicTimeline);
  }

  // Adversary group hints (#46): rank known ATT&CK groups by how much their technique set overlaps
  // the case's identified techniques — offline hypothesis fuel, NOT attribution. Derived on demand
  // from the bundled dataset with the same scope/legitimate filtering as the report.
  async adversaryHints(caseId: string): Promise<AdversaryHintsResult> {
    const state = await this.loadFilteredState(caseId);
    return buildAdversaryHintsResult(state, loadAdversaryGroupsDataset(), adversaryHintEnvOptions());
  }

  // Build a STIX 2.1 bundle for the case (same scope/legitimate filtering as the report) — the
  // portable, vendor-neutral export every TIP (OpenCTI, MISP, Anomali…) ingests. The victim
  // identity, producing firm, and incident id come from the human-authored report metadata.
  async stixBundle(caseId: string): Promise<StixBundle> {
    const state = await this.loadFilteredState(caseId);
    const meta = this.reportMeta ? await this.reportMeta.load(caseId) : emptyReportMeta();
    return buildStixBundle(state, {
      organization: meta.organization,
      producer: meta.companyName,
      incidentId: meta.incidentId,
    });
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
    const exposure = await this.loadExposure(caseId);
    const notebookEntries = await this.loadNotebook(caseId);
    const playbookTasks = await this.loadPlaybook(caseId);
    const overrides = this.assetOverrides ? await this.assetOverrides.load(caseId) : emptyOverrides();
    const graph = applyAssetOverrides(buildAssetGraph(state), overrides);
    await writeFile(paths.markdown, renderMarkdownReport(state, meta, exposure, graph, notebookEntries, playbookTasks), "utf8");
    await writeFile(paths.html, renderHtmlReport(state, meta, exposure, graph, notebookEntries, playbookTasks), "utf8");
    await writeFile(paths.findingsCsv, findingsCsv(state), "utf8");
    await writeFile(paths.iocsCsv, iocsCsv(state), "utf8");
    await writeFile(paths.timelineCsv, timelineCsv(state), "utf8");
    await writeFile(paths.forensicTimelineCsv, forensicTimelineCsv(state), "utf8");
    await writeFile(paths.stateJson, JSON.stringify(state, null, 2), "utf8");
    return paths;
  }
}
